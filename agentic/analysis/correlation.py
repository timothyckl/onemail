"""Local, normalised campaign correlation without retaining message bytes."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from pathlib import Path
from typing import Tuple
from urllib.parse import urlsplit, urlunsplit

from .models import Analysis, Batch, Evidence, Observation, Trace


DEFAULT_CORRELATION_DB = Path.home() / ".onemail" / "correlation.sqlite3"


class SQLiteCorrelator:
    """Compare hashes and indicators with earlier local investigations."""

    def __init__(self, path: Path = DEFAULT_CORRELATION_DB) -> None:
        self._path = path

    @classmethod
    def from_env(cls) -> "SQLiteCorrelator":
        return cls(
            Path(os.environ.get("ONEMAIL_CORRELATION_DB", DEFAULT_CORRELATION_DB)).expanduser()
        )

    def correlate(self, analysis: Analysis) -> Batch:
        started = time.monotonic()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        database = sqlite3.connect(self._path, timeout=5)
        try:
            self._initialise(database)
            exact = self._exact_artifacts(database, analysis)
            similar = self._similar_artifacts(database, analysis)
            indicators = self._indicator_matches(database, analysis)
            self._record(database, analysis)
            database.commit()
        finally:
            database.close()

        duration = int((time.monotonic() - started) * 1000)
        trace_id = _identifier("trace", analysis.detection.sha256, "correlation")
        evidence_id = _identifier("evidence", analysis.detection.sha256, "correlation")
        trace = Trace(
            id=trace_id,
            task="correlate",
            artifact="email",
            tool="SQLiteCorrelator",
            version="1",
            status="success",
            duration_ms=duration,
            exit_code=0,
        )
        value = {
            "database": "local-normalised-intelligence",
            "exact_artifact_matches": exact,
            "similar_artifact_matches": similar,
            "indicator_matches": indicators,
            "raw_message_stored": False,
        }
        evidence = Evidence(
            id=evidence_id,
            origin="analysis",
            kind="correlation",
            value=value,
            artifact="email",
            trace=trace_id,
        )
        count = len(exact) + len(similar) + len(indicators)
        summary = (
            f"Local correlation found {count} prior campaign relationship(s)"
            if count
            else "Local correlation found no relationships with prior investigations"
        )
        observation = Observation(
            id=_identifier("observation", analysis.detection.sha256, "correlation"),
            summary=summary,
            evidence=(evidence_id,),
        )
        return Batch(traces=(trace,), evidence=(evidence,), observations=(observation,))

    @staticmethod
    def _initialise(database: sqlite3.Connection) -> None:
        database.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                sha256 TEXT PRIMARY KEY,
                file TEXT NOT NULL,
                recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS artifacts (
                case_sha256 TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                similarity_hash TEXT,
                name TEXT NOT NULL,
                PRIMARY KEY (case_sha256, sha256, name)
            );
            CREATE INDEX IF NOT EXISTS artifacts_sha256 ON artifacts (sha256);
            CREATE INDEX IF NOT EXISTS artifacts_similarity ON artifacts (similarity_hash);
            CREATE TABLE IF NOT EXISTS indicators (
                case_sha256 TEXT NOT NULL,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                PRIMARY KEY (case_sha256, kind, value)
            );
            CREATE INDEX IF NOT EXISTS indicators_value ON indicators (kind, value);
            """
        )

    @staticmethod
    def _exact_artifacts(database: sqlite3.Connection, analysis: Analysis) -> list[dict[str, str]]:
        matches = []
        current = analysis.detection.sha256
        for artifact in analysis.artifacts:
            rows = database.execute(
                "SELECT artifacts.case_sha256, cases.file, artifacts.name FROM artifacts "
                "JOIN cases ON cases.sha256 = artifacts.case_sha256 "
                "WHERE artifacts.sha256 = ? AND case_sha256 != ? LIMIT 20",
                (artifact.sha256, current),
            ).fetchall()
            matches.extend(
                {
                    "artifact": artifact.id,
                    "prior_case": row[0],
                    "prior_file": row[1],
                    "prior_name": row[2],
                }
                for row in rows
            )
        return matches[:100]

    @staticmethod
    def _similar_artifacts(database: sqlite3.Connection, analysis: Analysis) -> list[dict[str, object]]:
        matches = []
        current = analysis.detection.sha256
        for artifact in analysis.artifacts:
            if artifact.similarity_hash in {None, "0000000000000000"}:
                continue
            rows = database.execute(
                "SELECT artifacts.case_sha256, cases.file, artifacts.name, "
                "artifacts.similarity_hash, artifacts.sha256 FROM artifacts "
                "JOIN cases ON cases.sha256 = artifacts.case_sha256 "
                "WHERE similarity_hash IS NOT NULL AND case_sha256 != ? LIMIT 1000",
                (current,),
            ).fetchall()
            source = int(artifact.similarity_hash, 16)
            for case_sha, file_name, prior_name, fuzzy, exact_sha in rows:
                if exact_sha == artifact.sha256:
                    continue
                distance = (source ^ int(fuzzy, 16)).bit_count()
                if distance <= 6:
                    matches.append(
                        {
                            "artifact": artifact.id,
                            "prior_case": case_sha,
                            "prior_file": file_name,
                            "prior_name": prior_name,
                            "distance": distance,
                        }
                    )
        return sorted(matches, key=lambda item: int(item["distance"]))[:100]

    @staticmethod
    def _indicator_matches(database: sqlite3.Connection, analysis: Analysis) -> list[dict[str, str]]:
        matches = []
        current = analysis.detection.sha256
        for kind, value in _indicators(analysis):
            rows = database.execute(
                "SELECT indicators.case_sha256, cases.file FROM indicators "
                "JOIN cases ON cases.sha256 = indicators.case_sha256 "
                "WHERE kind = ? AND value = ? AND case_sha256 != ? LIMIT 20",
                (kind, value, current),
            ).fetchall()
            matches.extend(
                {
                    "type": kind,
                    "value": value,
                    "prior_case": row[0],
                    "prior_file": row[1],
                }
                for row in rows
            )
        return matches[:100]

    @staticmethod
    def _record(database: sqlite3.Connection, analysis: Analysis) -> None:
        case_sha = analysis.detection.sha256
        database.execute(
            "INSERT OR REPLACE INTO cases (sha256, file) VALUES (?, ?)",
            (case_sha, analysis.detection.file[:500]),
        )
        database.executemany(
            "INSERT OR REPLACE INTO artifacts "
            "(case_sha256, sha256, similarity_hash, name) VALUES (?, ?, ?, ?)",
            (
                (case_sha, item.sha256, item.similarity_hash, item.name[:500])
                for item in analysis.artifacts
            ),
        )
        database.executemany(
            "INSERT OR REPLACE INTO indicators (case_sha256, kind, value) VALUES (?, ?, ?)",
            ((case_sha, kind, value) for kind, value in _indicators(analysis)),
        )


def _indicators(analysis: Analysis) -> Tuple[Tuple[str, str], ...]:
    observables = analysis.detection.observables
    values = set()
    for domain in (
        getattr(observables, "from_domain", None),
        getattr(observables, "reply_to_domain", None),
        *getattr(observables, "url_hosts", ()),
    ):
        if domain:
            values.add(("domain", str(domain).lower()[:2048]))
    for url in getattr(observables, "urls", ()):
        parsed = urlsplit(str(url))
        normalised = urlunsplit(
            (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, "", "")
        )
        if normalised:
            values.add(("url", normalised[:2048]))
    return tuple(sorted(values))


def _identifier(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:16]
