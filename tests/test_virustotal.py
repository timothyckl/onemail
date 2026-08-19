"""Tests for hash-only VirusTotal enrichment and privacy boundaries."""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from agentic.analysis import Artifact, Format, VirusTotalClient, VirusTotalConfig


DIGEST = "a" * 64


def artifact() -> Artifact:
    return Artifact(
        id="a001",
        name="invoice.exe",
        size=512,
        sha256=DIGEST,
        format=Format(detected="application/x-dosexec", extension="exe"),
    )


def report() -> bytes:
    return json.dumps(
        {
            "data": {
                "id": DIGEST,
                "type": "file",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 4,
                        "suspicious": 2,
                        "undetected": 60,
                        "harmless": 3,
                    },
                    "last_analysis_date": 1700000000,
                    "first_submission_date": 1600000000,
                    "last_submission_date": 1700000001,
                    "reputation": -5,
                    "size": 512,
                    "type_description": "Win32 EXE",
                    "meaningful_name": "invoice.exe",
                    "names": ["invoice.exe", "document.exe"],
                    "tags": ["peexe", "signed"],
                },
            }
        }
    ).encode("utf-8")


class VirusTotalTests(unittest.TestCase):
    def test_is_disabled_without_an_api_key(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            self.assertIsNone(VirusTotalClient.from_env())

    def test_returns_bounded_hash_report_evidence_without_uploading(self) -> None:
        requests = []

        def open_report(request, timeout):
            requests.append((request, timeout))
            return io.BytesIO(report())

        with tempfile.TemporaryDirectory() as directory:
            client = VirusTotalClient(
                VirusTotalConfig(
                    api_key="secret-key",
                    cache_path=Path(directory) / "cache.sqlite3",
                    min_interval=0,
                ),
                opener=open_report,
            )
            result = client.lookup(artifact())

        self.assertFalse(result.gaps)
        self.assertEqual(result.evidence[0].kind, "virustotal")
        value = result.evidence[0].value
        self.assertIsInstance(value, dict)
        assert isinstance(value, dict)
        self.assertEqual(value["sha256"], DIGEST)
        self.assertEqual(value["last_analysis_stats"]["malicious"], 4)
        self.assertFalse(value["file_uploaded_by_onemail"])
        self.assertEqual(value["lookup"], "hash-only")
        request, timeout = requests[0]
        self.assertEqual(request.full_url, f"https://www.virustotal.com/api/v3/files/{DIGEST}")
        self.assertEqual(request.get_header("X-apikey"), "secret-key")
        self.assertEqual(timeout, 15)
        self.assertEqual(request.data, None)
        self.assertNotIn("secret-key", json.dumps(value))

    def test_uses_cached_normalised_reports(self) -> None:
        calls = []

        def open_report(_request, _timeout=None, **_kwargs):
            calls.append(True)
            return io.BytesIO(report())

        with tempfile.TemporaryDirectory() as directory:
            client = VirusTotalClient(
                VirusTotalConfig(
                    api_key="secret-key",
                    cache_path=Path(directory) / "cache.sqlite3",
                    min_interval=0,
                ),
                opener=open_report,
            )
            first = client.lookup(artifact())
            second = client.lookup(artifact())

        self.assertEqual(len(calls), 1)
        self.assertFalse(first.evidence[0].value["cached"])
        self.assertTrue(second.evidence[0].value["cached"])

    def test_not_found_is_a_gap_and_never_uploads(self) -> None:
        def missing(request, timeout):
            raise HTTPError(request.full_url, 404, "Not Found", {}, None)

        with tempfile.TemporaryDirectory() as directory:
            client = VirusTotalClient(
                VirusTotalConfig(
                    api_key="secret-key",
                    cache_path=Path(directory) / "cache.sqlite3",
                    min_interval=0,
                ),
                opener=missing,
            )
            result = client.lookup(artifact())

        self.assertFalse(result.evidence)
        self.assertEqual(result.traces[0].status, "not_found")
        self.assertIn("no existing file report", result.gaps[0].reason)

    def test_rate_limit_is_recorded_as_a_gap(self) -> None:
        def limited(request, timeout):
            raise HTTPError(request.full_url, 429, "Too Many Requests", {}, None)

        with tempfile.TemporaryDirectory() as directory:
            client = VirusTotalClient(
                VirusTotalConfig(
                    api_key="secret-key",
                    cache_path=Path(directory) / "cache.sqlite3",
                    min_interval=0,
                ),
                opener=limited,
            )
            result = client.lookup(artifact())

        self.assertEqual(result.traces[0].status, "rate_limited")
        self.assertIn("rate limit", result.gaps[0].reason)

    def test_rejects_a_report_for_another_digest(self) -> None:
        payload = json.loads(report())
        payload["data"]["id"] = "b" * 64

        with tempfile.TemporaryDirectory() as directory:
            client = VirusTotalClient(
                VirusTotalConfig(
                    api_key="secret-key",
                    cache_path=Path(directory) / "cache.sqlite3",
                    min_interval=0,
                ),
                opener=lambda _request, timeout: io.BytesIO(
                    json.dumps(payload).encode("utf-8")
                ),
            )
            result = client.lookup(artifact())

        self.assertFalse(result.evidence)
        self.assertIn("digest mismatch", result.gaps[0].reason)


if __name__ == "__main__":
    unittest.main()
