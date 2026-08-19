"""Security-focused tests for the local Flask investigation endpoints."""

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from web.app import (
    INVESTIGATION_REQUEST_HEADER,
    INVESTIGATION_REQUEST_VALUE,
    _JOBS,
    _JOBS_LOCK,
    agentic_status,
    app,
    render_markdown_safe,
)


class MarkdownRenderingTests(unittest.TestCase):
    def test_preserves_safe_collapsible_evidence_appendix(self) -> None:
        rendered = render_markdown_safe(
            "<details><summary>Show evidence</summary>"
            "<pre><code>safe evidence</code></pre></details>"
        )

        self.assertIn("<details>", rendered)
        self.assertIn("<summary>Show evidence</summary>", rendered)
        self.assertIn("<pre><code>safe evidence</code></pre>", rendered)


class AgenticStatusTests(unittest.TestCase):
    def test_virustotal_is_optional_and_does_not_control_readiness(self) -> None:
        with (
            patch("web.app._model_status", return_value=(True, "model ready")),
            patch("web.app._docker_status", return_value=(True, "docker ready")),
            patch(
                "agentic.analysis.VirusTotalClient.from_env",
                return_value=object(),
            ),
        ):
            status = agentic_status()

        self.assertTrue(status["ready"])
        self.assertTrue(status["virustotal"]["enabled"])
        self.assertIn("never uploaded", status["virustotal"]["detail"])


class InvestigationRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        app.config.update(TESTING=True)
        self.client = app.test_client()
        with _JOBS_LOCK:
            _JOBS.clear()
        self.headers = {
            INVESTIGATION_REQUEST_HEADER: INVESTIGATION_REQUEST_VALUE,
        }

    def test_sample_investigation_cannot_be_started_with_get(self) -> None:
        response = self.client.get("/api/investigate/sample/sample-1.eml")
        self.assertEqual(response.status_code, 405)

    def test_investigation_rejects_a_post_without_the_custom_header(self) -> None:
        with patch("web.app.investigate_bytes") as investigate:
            response = self.client.post(
                "/api/investigate/sample/sample-1.eml"
            )

        self.assertEqual(response.status_code, 403)
        investigate.assert_not_called()

    def test_same_origin_sample_post_can_start_investigation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample-1.eml"
            sample.write_bytes(b"From: sender@example.com\r\n\r\nHello")
            with (
                patch("web.app.SAMPLE_DIRS", (Path(directory),)),
                patch(
                    "web.app.investigate_bytes",
                    return_value={"ok": True, "flagged": False},
                ) as investigate,
            ):
                response = self.client.post(
                    "/api/investigate/sample/sample-1.eml",
                    headers=self.headers,
                )

        self.assertEqual(response.status_code, 202)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        identifier = payload["job"]["id"]

        deadline = time.monotonic() + 1
        job = payload["job"]
        while job["status"] in {"queued", "running"} and time.monotonic() < deadline:
            status = self.client.get(
                f"/api/investigate/{identifier}",
                headers=self.headers,
            )
            self.assertEqual(status.status_code, 200)
            job = status.get_json()["job"]
            time.sleep(0.01)

        self.assertEqual(job["status"], "completed")
        self.assertGreaterEqual(job["total_elapsed_ms"], 0)
        self.assertTrue(job["events"])
        investigate.assert_called_once()

    def test_progress_endpoint_requires_the_custom_header(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample-1.eml"
            sample.write_bytes(b"From: sender@example.com\r\n\r\nHello")
            with (
                patch("web.app.SAMPLE_DIRS", (Path(directory),)),
                patch(
                    "web.app.investigate_bytes",
                    return_value={"ok": True, "flagged": False},
                ),
            ):
                started = self.client.post(
                    "/api/investigate/sample/sample-1.eml",
                    headers=self.headers,
                ).get_json()

        response = self.client.get(f"/api/investigate/{started['job']['id']}")
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
