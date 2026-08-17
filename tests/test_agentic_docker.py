"""Optional integration test for the local Docker analysis image."""

import importlib.util
import os
import sys
import unittest
from email.message import EmailMessage
from pathlib import Path

from agentic import Case
from agentic.analysis import DockerSandbox, Limits
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


if __name__ == "__main__":
    unittest.main()
