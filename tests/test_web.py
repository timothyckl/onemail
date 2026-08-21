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


def _successful_worker(_name, _content, _identifier, _input_path, messages) -> None:
    messages.put(
        {
            "kind": "result",
            "result": {"ok": True, "flagged": False},
        }
    )


def _blocking_worker(_name, _content, _identifier, input_path, _messages) -> None:
    Path(input_path).write_text("worker active", encoding="utf-8")
    while True:
        time.sleep(1)


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


class WebNavigationTests(unittest.TestCase):
    def test_agentic_workflow_has_a_dedicated_navigation_tab(self) -> None:
        app.config.update(TESTING=True)
        response = app.test_client().get("/")
        markup = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn('data-mode="agentic"', markup)
        self.assertIn('data-mode="agentic" role="tab" aria-selected="false" aria-disabled="true" disabled', markup)
        self.assertNotIn('id="agentic-form"', markup)
        self.assertIn('id="agentic-result"', markup)
        script = (Path(__file__).parents[1] / "web" / "static" / "app.js").read_text()
        self.assertIn("Continue investigating", script)
        self.assertIn("startAgenticStage", script)
        self.assertIn("Start investigation", script)
        self.assertIn("Restart investigation", script)
        self.assertIn("Stop investigation", script)
        self.assertIn('class: "btn-preview-report"', script)
        self.assertIn("Download report", script)
        self.assertIn('class: "report-actions preview-download-actions"', script)
        self.assertIn('class: "agentic-progress-out"', script)
        self.assertIn('class: "container-activity-out"', script)
        self.assertIn("function activityRow", script)
        self.assertIn("function activitySummary", script)
        self.assertIn('text: "Raw output"', script)
        self.assertNotIn("activity-actor", script)
        styles = (Path(__file__).parents[1] / "web" / "static" / "style.css").read_text()
        self.assertIn("max-height: clamp(280px, 48vh, 520px)", styles)
        self.assertIn("[hidden] { display: none !important; }", styles)
        self.assertNotIn(".activity-actor", styles)
        self.assertNotIn('text: "Intelligence report JSON"', script)

    def test_agentic_progress_uses_user_facing_phases(self) -> None:
        script = (Path(__file__).parents[1] / "web" / "static" / "app.js").read_text()

        self.assertIn("function investigationPhases", script)
        self.assertIn('action: "Prepare secure environment"', script)
        self.assertIn('action: "Extract and catalogue evidence"', script)
        self.assertIn('action: "Plan targeted analysis"', script)
        self.assertIn('action: "Analyse suspicious artefacts"', script)
        self.assertIn('action: "Correlate findings"', script)
        self.assertIn('action: "Generate investigation report"', script)
        self.assertIn('return "<1 s"', script)
        self.assertNotIn("pipeline.forEach", script)
        self.assertNotIn('running && phase.status !== "failed"', script)


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
            with patch("web.app.SAMPLE_DIRS", (Path(directory),)):
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

    def test_progress_endpoint_requires_the_custom_header(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample-1.eml"
            sample.write_bytes(b"From: sender@example.com\r\n\r\nHello")
            with (
                patch("web.app.SAMPLE_DIRS", (Path(directory),)),
                patch("web.app._investigation_worker", new=_successful_worker),
            ):
                started = self.client.post(
                    "/api/investigate/sample/sample-1.eml",
                    headers=self.headers,
                ).get_json()

        response = self.client.get(f"/api/investigate/{started['job']['id']}")
        self.assertEqual(response.status_code, 403)

    def test_stop_endpoint_cancels_job_and_runs_container_teardown(self) -> None:
        def cleanup(_identifier, input_path):
            input_path.unlink(missing_ok=True)
            return None

        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample-1.eml"
            sample.write_bytes(b"From: sender@example.com\r\n\r\nHello")
            with (
                patch("web.app.SAMPLE_DIRS", (Path(directory),)),
                patch("web.app._investigation_worker", new=_blocking_worker),
                patch("web.app._cleanup_investigation_resources", side_effect=cleanup) as teardown,
            ):
                response = self.client.post(
                    "/api/investigate/sample/sample-1.eml",
                    headers=self.headers,
                )
                identifier = response.get_json()["job"]["id"]
                with _JOBS_LOCK:
                    active_job = _JOBS[identifier]
                deadline = time.monotonic() + 2
                while not active_job.input_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(active_job.input_path.exists())
                stopped = self.client.post(
                    f"/api/investigate/{identifier}/stop",
                    headers=self.headers,
                )

        self.assertEqual(stopped.status_code, 200)
        job = stopped.get_json()["job"]
        self.assertEqual(job["status"], "cancelled")
        self.assertTrue(job["result"]["cancelled"])
        assert active_job._process is not None
        self.assertFalse(active_job._process.is_alive())
        teardown.assert_called_once_with(identifier, active_job.input_path)


if __name__ == "__main__":
    unittest.main()
