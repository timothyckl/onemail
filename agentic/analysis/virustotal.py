"""Hash-only VirusTotal enrichment through a bounded host-side broker."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .models import Artifact, Batch, Evidence, Gap, Observation, Trace


DEFAULT_BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_CACHE_PATH = Path.home() / ".onemail" / "virustotal.sqlite3"
DEFAULT_CACHE_TTL = 24 * 60 * 60
DEFAULT_TIMEOUT = 15
DEFAULT_MIN_INTERVAL = 16.0
MAX_RESPONSE_BYTES = 1024 * 1024


class _NoRedirects(HTTPRedirectHandler):
    """Prevent forwarding the API key to a redirected destination."""

    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


_DEFAULT_OPENER = build_opener(_NoRedirects()).open


@dataclass(frozen=True)
class VirusTotalConfig:
    """Configuration for existing-report lookups; uploads are unsupported."""

    api_key: str
    base_url: str = DEFAULT_BASE_URL
    cache_path: Path = DEFAULT_CACHE_PATH
    cache_ttl: int = DEFAULT_CACHE_TTL
    timeout: int = DEFAULT_TIMEOUT
    min_interval: float = DEFAULT_MIN_INTERVAL

    def __post_init__(self) -> None:
        if not self.api_key.strip():
            raise ValueError("VirusTotal API key cannot be empty")
        if not self.base_url.startswith("https://"):
            raise ValueError("VirusTotal base URL must use HTTPS")
        if self.cache_ttl < 0 or self.timeout <= 0 or self.min_interval < 0:
            raise ValueError("VirusTotal limits must be non-negative and timeout positive")


class VirusTotalClient:
    """Look up file reports by SHA-256 without transmitting file bytes."""

    _request_lock = threading.Lock()
    _last_request = 0.0

    def __init__(
        self,
        config: VirusTotalConfig,
        *,
        opener: Callable[..., object] = _DEFAULT_OPENER,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._config = config
        self._opener = opener
        self._clock = clock
        self._sleeper = sleeper

    @classmethod
    def from_env(cls) -> Optional["VirusTotalClient"]:
        api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
        if not api_key:
            return None
        return cls(
            VirusTotalConfig(
                api_key=api_key,
                base_url=os.environ.get("VIRUSTOTAL_BASE_URL", DEFAULT_BASE_URL),
                cache_path=Path(
                    os.environ.get("VIRUSTOTAL_CACHE_DB", DEFAULT_CACHE_PATH)
                ).expanduser(),
                cache_ttl=int(
                    os.environ.get("VIRUSTOTAL_CACHE_TTL", DEFAULT_CACHE_TTL)
                ),
                timeout=int(os.environ.get("VIRUSTOTAL_TIMEOUT", DEFAULT_TIMEOUT)),
                min_interval=float(
                    os.environ.get(
                        "VIRUSTOTAL_MIN_INTERVAL", DEFAULT_MIN_INTERVAL
                    )
                ),
            )
        )

    def lookup(self, artifact: Artifact) -> Batch:
        """Return grounded report evidence, or a gap when no report is available."""

        if re.fullmatch(r"[0-9a-f]{64}", artifact.sha256) is None:
            raise ValueError("VirusTotal lookup requires a lowercase SHA-256 digest")
        started = self._clock()
        cached = self._cache_read(artifact.sha256)
        if cached is not None:
            return self._batch(
                artifact,
                cached,
                duration_ms=self._elapsed(started),
                cached=True,
            )

        result = self._request(artifact.sha256)
        if result["status"] in {"found", "not_found"}:
            self._cache_write(artifact.sha256, result)
        return self._batch(
            artifact,
            result,
            duration_ms=self._elapsed(started),
            cached=False,
        )

    def _request(self, digest: str) -> dict[str, object]:
        url = self._config.base_url.rstrip("/") + "/files/" + digest
        request = Request(
            url,
            headers={
                "Accept": "application/json",
                "X-Apikey": self._config.api_key,
                "User-Agent": "OneMail/0.1 hash-only-enrichment",
            },
        )
        try:
            with self._request_lock:
                delay = self._config.min_interval - (
                    self._clock() - type(self)._last_request
                )
                if delay > 0:
                    self._sleeper(delay)
                try:
                    response = self._opener(request, timeout=self._config.timeout)
                    try:
                        raw = response.read(MAX_RESPONSE_BYTES + 1)  # type: ignore[attr-defined]
                    finally:
                        close = getattr(response, "close", None)
                        if callable(close):
                            close()
                finally:
                    type(self)._last_request = self._clock()
        except HTTPError as error:
            try:
                if error.code == 404:
                    return {"status": "not_found"}
                if error.code == 429:
                    return {"status": "rate_limited"}
                return {"status": "error", "reason": f"HTTP {error.code}"}
            finally:
                error.close()
        except (URLError, TimeoutError, OSError) as error:
            return {"status": "error", "reason": type(error).__name__}

        if len(raw) > MAX_RESPONSE_BYTES:
            return {"status": "error", "reason": "response exceeded size limit"}
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            return {"status": "error", "reason": "invalid JSON response"}
        return self._normalise(payload, digest)

    @staticmethod
    def _normalise(payload: object, digest: str) -> dict[str, object]:
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
            return {"status": "error", "reason": "missing report data"}
        data = payload["data"]
        identifier = str(data.get("id", "")).lower()
        if identifier != digest:
            return {"status": "error", "reason": "report digest mismatch"}
        attributes = data.get("attributes")
        if not isinstance(attributes, dict):
            return {"status": "error", "reason": "missing report attributes"}

        raw_stats = attributes.get("last_analysis_stats")
        stats = {}
        if isinstance(raw_stats, dict):
            for name in (
                "malicious",
                "suspicious",
                "undetected",
                "harmless",
                "timeout",
                "failure",
                "type-unsupported",
                "confirmed-timeout",
            ):
                value = raw_stats.get(name, 0)
                stats[name] = (
                    value
                    if isinstance(value, int) and not isinstance(value, bool) and value >= 0
                    else 0
                )
        total = sum(stats.values())
        names = attributes.get("names")
        tags = attributes.get("tags")
        return {
            "status": "found",
            "sha256": digest,
            "last_analysis_stats": stats,
            "engines_total": total,
            "last_analysis_date": _timestamp(attributes.get("last_analysis_date")),
            "first_submission_date": _timestamp(attributes.get("first_submission_date")),
            "last_submission_date": _timestamp(attributes.get("last_submission_date")),
            "reputation": _integer(attributes.get("reputation")),
            "size": _integer(attributes.get("size")),
            "type_description": _text(attributes.get("type_description"), 200),
            "meaningful_name": _text(attributes.get("meaningful_name"), 500),
            "names": _strings(names, 20, 500),
            "tags": _strings(tags, 30, 100),
            "permalink": f"https://www.virustotal.com/gui/file/{digest}",
            "lookup": "hash-only",
            "file_uploaded_by_onemail": False,
        }

    def _batch(
        self,
        artifact: Artifact,
        result: dict[str, object],
        *,
        duration_ms: int,
        cached: bool,
    ) -> Batch:
        status = str(result.get("status", "error"))
        trace_id = _identifier("trace", "virustotal", artifact.id, artifact.sha256)
        trace = Trace(
            id=trace_id,
            task="virustotal_hash",
            artifact=artifact.id,
            tool="VirusTotal API v3",
            version="v3",
            status=(
                "success" if status == "found"
                else "not_found" if status == "not_found"
                else "rate_limited" if status == "rate_limited"
                else "failure"
            ),
            duration_ms=duration_ms,
            exit_code=None,
        )
        if status != "found":
            reason = {
                "not_found": "VirusTotal has no existing file report for this SHA-256",
                "rate_limited": "VirusTotal rate limit was reached",
            }.get(status, f"VirusTotal lookup failed: {result.get('reason', 'unknown error')}")
            return Batch(
                traces=(trace,),
                gaps=(Gap(scope=f"virustotal_hash:{artifact.id}", reason=reason),),
            )

        value = dict(result)
        value.pop("status", None)
        value["cached"] = cached
        evidence_id = _identifier("evidence", "virustotal", artifact.id, artifact.sha256)
        evidence = Evidence(
            id=evidence_id,
            origin="analysis",
            kind="virustotal",
            value=value,
            artifact=artifact.id,
            trace=trace_id,
        )
        stats = value.get("last_analysis_stats")
        stats = stats if isinstance(stats, dict) else {}
        malicious = _integer(stats.get("malicious")) or 0
        suspicious = _integer(stats.get("suspicious")) or 0
        total = _integer(value.get("engines_total")) or 0
        observation = Observation(
            id=_identifier("observation", "virustotal", artifact.id, artifact.sha256),
            summary=(
                "VirusTotal's existing report recorded "
                f"{malicious} malicious and {suspicious} suspicious engine result(s) "
                f"out of {total} for {artifact.name}"
            ),
            evidence=(evidence_id,),
        )
        return Batch(
            traces=(trace,),
            evidence=(evidence,),
            observations=(observation,),
        )

    def _cache_read(self, digest: str) -> Optional[dict[str, object]]:
        if self._config.cache_ttl == 0 or not self._config.cache_path.is_file():
            return None
        try:
            database = sqlite3.connect(self._config.cache_path, timeout=3)
            try:
                self._initialise(database)
                row = database.execute(
                    "SELECT fetched_at, payload FROM file_reports WHERE sha256 = ?",
                    (digest,),
                ).fetchone()
            finally:
                database.close()
        except (OSError, sqlite3.Error):
            return None
        if row is None or time.time() - float(row[0]) > self._config.cache_ttl:
            return None
        try:
            value = json.loads(row[1])
        except (TypeError, ValueError):
            return None
        return value if isinstance(value, dict) else None

    def _cache_write(self, digest: str, payload: dict[str, object]) -> None:
        try:
            self._config.cache_path.parent.mkdir(parents=True, exist_ok=True)
            database = sqlite3.connect(self._config.cache_path, timeout=3)
            try:
                self._initialise(database)
                database.execute(
                    "INSERT OR REPLACE INTO file_reports (sha256, fetched_at, payload) "
                    "VALUES (?, ?, ?)",
                    (digest, time.time(), json.dumps(payload, sort_keys=True)),
                )
                database.commit()
            finally:
                database.close()
        except (OSError, sqlite3.Error):
            return

    @staticmethod
    def _initialise(database: sqlite3.Connection) -> None:
        database.execute(
            "CREATE TABLE IF NOT EXISTS file_reports ("
            "sha256 TEXT PRIMARY KEY, fetched_at REAL NOT NULL, payload TEXT NOT NULL)"
        )

    def _elapsed(self, started: float) -> int:
        return max(0, int((self._clock() - started) * 1000))


def _identifier(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:16]


def _integer(value: object) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _text(value: object, limit: int) -> Optional[str]:
    return (
        None
        if value is None or value == ""
        else str(value).replace("\x00", "")[:limit]
    )


def _strings(value: object, count: int, length: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        str(item).replace("\x00", "")[:length]
        for item in value[:count]
        if item is not None and item != ""
    ]


def _timestamp(value: object) -> Optional[str]:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return None
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None
