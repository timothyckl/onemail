"""Optional integration test for the local Docker analysis image."""

import importlib.util
import os
import sys
import unittest
from email.message import EmailMessage
from pathlib import Path

from agentic import Case
from agentic.analysis import DockerSandbox, Limits, Task
from agentic.progress import ProgressTracker
from detection import DetectionEngine, Email


class DockerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if importlib.util.find_spec("docker") is None:
            raise unittest.SkipTest("Docker SDK is not installed")
        if sys.platform != "win32" and not os.environ.get("DOCKER_HOST"):
            sockets = (
                Path("/var/run/docker.sock"),
                Path.home() / ".docker/run/docker.sock",
                Path.home() / ".orbstack/run/docker.sock",
            )
            if not any(path.exists() for path in sockets):
                raise unittest.SkipTest("Docker daemon socket is unavailable")
        import docker

        client = None
        try:
            client = docker.from_env()
            client.ping()
            client.images.get("onemail-analysis:latest")
        except Exception as error:
            if client is not None:
                client.close()
            raise unittest.SkipTest(
                "Docker daemon or onemail-analysis:latest image is unavailable"
            ) from error
        cls.client = client

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "client"):
            cls.client.close()

    @staticmethod
    def _fixture_case(name: str) -> Case:
        path = Path(__file__).parent / "agentic_test_data" / name
        email = Email(file=name, content=path.read_bytes())
        return Case(email=email, detection=DetectionEngine().detect(email))

    def test_runs_the_static_baseline_and_removes_the_container(self) -> None:
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "recipient@example.net"
        message["Reply-To"] = "reply@evil.example"
        message.set_content("Review the attachment")
        message.add_attachment(
            b"MZ\x00\x00",
            maintype="application",
            subtype="octet-stream",
            filename="sample.exe",
        )
        email = Email(file="docker.eml", content=message.as_bytes())
        detection = DetectionEngine().detect(email)
        case = Case(email=email, detection=detection)

        sandbox = DockerSandbox(case, Limits(), client=self.client)
        with sandbox:
            result = sandbox.baseline()

        self.assertIsNotNone(result.image)
        assert result.image is not None
        self.assertTrue(result.image.startswith("sha256:"))
        self.assertEqual({item.id for item in result.artifacts}, {"email", "a001"})
        self.assertTrue(all(len(item.sha256) == 64 for item in result.artifacts))
        remaining = self.client.containers.list(
            all=True,
            filters={"label": "onemail.component=analysis"},
        )
        self.assertEqual(remaining, [])

    def test_streams_container_progress_and_extracts_archive_children(self) -> None:
        events = []
        sandbox = DockerSandbox(
            self._fixture_case("07_archive_zip.eml"),
            Limits(seconds=120),
            client=self.client,
            progress=ProgressTracker(events.append),
        )
        with sandbox:
            baseline = sandbox.baseline()
            archive = next(item for item in baseline.artifacts if item.id != "email")
            result = sandbox.execute(
                Task(
                    "archive",
                    archive.id,
                    rationale="Inspect the archive for bounded child artefacts.",
                )
            )

        self.assertEqual(len(result.artifacts), 3)
        self.assertTrue(all(item.parent == archive.id for item in result.artifacts))
        self.assertTrue(all(item.similarity_hash for item in result.artifacts))
        self.assertFalse(result.failures)
        self.assertTrue(
            any(event.stage == "container" and event.status == "running" for event in events)
        )
        self.assertTrue(
            any(event.action == "Extract bounded archive members" for event in events)
        )
        self.assertTrue(
            any(
                event.actor == "agent"
                and event.rationale == "Inspect the archive for bounded child artefacts."
                for event in events
            )
        )
        self.assertTrue(any(event.command for event in events))
        self.assertTrue(any(event.output for event in events))

    def test_renders_a_pdf_offline(self) -> None:
        sandbox = DockerSandbox(
            self._fixture_case("09_pdf_openaction.eml"),
            Limits(seconds=120),
            client=self.client,
        )
        with sandbox:
            baseline = sandbox.baseline()
            pdf = next(item for item in baseline.artifacts if item.id != "email")
            result = sandbox.execute(Task("render", pdf.id, {"pages": "1"}))

        self.assertFalse(result.failures)
        value = result.evidence[0].value
        self.assertIsInstance(value, dict)
        assert isinstance(value, dict)
        self.assertFalse(value["external_resources_fetched"])
        self.assertEqual(len(value["screenshot_sha256"]), 64)

    def test_emulates_a_pe_without_native_execution(self) -> None:
        sandbox = DockerSandbox(
            self._fixture_case("10_pe_executable.eml"),
            Limits(seconds=120),
            client=self.client,
        )
        with sandbox:
            baseline = sandbox.baseline()
            executable = next(item for item in baseline.artifacts if item.id != "email")
            result = sandbox.execute(
                Task("emulate_pe", executable.id, {"seconds": "5"})
            )

        self.assertFalse(result.failures)
        value = result.evidence[0].value
        self.assertIsInstance(value, dict)
        assert isinstance(value, dict)
        self.assertFalse(value["native_execution"])
        self.assertEqual(value["mode"], "Speakeasy API emulation")


if __name__ == "__main__":
    unittest.main()
