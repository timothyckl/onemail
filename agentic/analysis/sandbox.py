"""Sandbox abstraction and hardened local Docker implementation."""

import hashlib
import json
import os
import re
import tempfile
from abc import ABC, abstractmethod
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, Optional

from agentic import Case

from .models import (
    Artifact,
    Batch,
    Evidence,
    Failure,
    Format,
    Gap,
    Limits,
    Match,
    Metrics,
    Observation,
    Preview,
    Task,
    Trace,
)


class Sandbox(ABC):
    """Execute approved static-analysis tasks in an isolated environment."""

    @abstractmethod
    def __enter__(self) -> "Sandbox":
        raise NotImplementedError

    @abstractmethod
    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        raise NotImplementedError

    @abstractmethod
    def baseline(self) -> Batch:
        raise NotImplementedError

    @abstractmethod
    def execute(self, task: Task) -> Batch:
        raise NotImplementedError


class DockerSandbox(Sandbox):
    """Run one case in an ephemeral, offline Ubuntu analysis container."""

    def __init__(
        self,
        case: Case,
        limits: Limits,
        image: str = "onemail-analysis:latest",
        client: Optional[Any] = None,
    ) -> None:
        self._owns_client = client is None
        if client is None:
            try:
                import docker
            except ImportError as error:
                raise RuntimeError("Docker SDK is required for static analysis") from error
            client = docker.from_env()
        self._case = case
        self._limits = limits
        self._image = image
        self._client = client
        self._container: Optional[Any] = None
        self._email_path: Optional[Path] = None
        self._image_id: Optional[str] = None
        self._artifact_ids: set[str] = set()
        self._trace_ids: set[str] = set()
        self._evidence_ids: set[str] = set()
        self._observation_ids: set[str] = set()

    def __enter__(self) -> "DockerSandbox":
        memory = max(self._limits.total_bytes * 2, 256 * 1024 * 1024)
        try:
            handle = tempfile.NamedTemporaryFile(prefix="onemail-", suffix=".eml", delete=False)
            try:
                handle.write(self._case.email.content)
            finally:
                handle.close()
            self._email_path = Path(handle.name)
            os.chmod(self._email_path, 0o444)
            self._image_id = self._client.images.get(self._image).id
            self._container = self._client.containers.run(
                self._image_id,
                command=[
                    "/usr/bin/timeout",
                    f"{self._limits.seconds}s",
                    "/bin/sleep",
                    "infinity",
                ],
                detach=True,
                auto_remove=False,
                network_disabled=True,
                read_only=True,
                user="analyst",
                cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                pids_limit=128,
                mem_limit=memory,
                nano_cpus=1_000_000_000,
                tmpfs={
                    "/work": (
                        "rw,nosuid,nodev,noexec,mode=1777,size="
                        f"{max(self._limits.total_bytes, 128 * 1024 * 1024)}"
                    )
                },
                volumes={
                    str(self._email_path): {
                        "bind": "/work/message.eml",
                        "mode": "ro",
                    }
                },
                labels={"onemail.component": "analysis"},
            )
        except Exception as error:
            cleanup_error = self._cleanup()
            if cleanup_error is not None:
                raise RuntimeError("failed to remove analysis container") from cleanup_error
            raise error
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        error = self._cleanup()
        if error is not None:
            message = "failed to remove analysis container"
            if exc is not None:
                message += f"; analysis also failed: {type(exc).__name__}: {exc}"
            failure = RuntimeError(message)
            raise failure from error

    def _cleanup(self) -> Optional[Exception]:
        if self._container is None:
            input_error = self._remove_input()
            return input_error or self._close_client()
        container = self._container
        self._container = None
        try:
            container.kill()
        except Exception:
            pass
        try:
            container.wait(timeout=10)
        except Exception:
            pass
        removal_error = None
        try:
            container.remove(force=True)
        except Exception as error:
            removal_error = error
        input_error = self._remove_input()
        close_error = self._close_client()
        return removal_error or input_error or close_error

    def _remove_input(self) -> Optional[Exception]:
        if self._email_path is None:
            return None
        path = self._email_path
        self._email_path = None
        try:
            path.unlink(missing_ok=True)
        except Exception as error:
            return error
        return None

    def _close_client(self) -> Optional[Exception]:
        if not self._owns_client:
            return None
        self._owns_client = False
        try:
            self._client.close()
        except Exception as error:
            return error
        return None

    def baseline(self) -> Batch:
        batch = self._run(
            [
                "baseline",
                "/work/message.eml",
                json.dumps(self._limits.__dict__, sort_keys=True),
            ]
        )
        email = next((item for item in batch.artifacts if item.id == "email"), None)
        expected = hashlib.sha256(self._case.email.content).hexdigest()
        if email is None or email.sha256 != expected:
            raise ValueError("sandbox email digest does not match the case")
        return batch

    def execute(self, task: Task) -> Batch:
        return self._run(
            [
                "task",
                task.name,
                task.artifact,
                json.dumps(dict(task.options), sort_keys=True),
                json.dumps(self._limits.__dict__, sort_keys=True),
            ]
        )

    def _run(self, arguments: list[str]) -> Batch:
        if self._container is None:
            raise RuntimeError("sandbox is not running")
        result = self._container.exec_run(
            ["/opt/venv/bin/python", "/opt/onemail/runner.py"] + arguments,
            demux=False,
        )
        output = result.output.decode("utf-8", "replace")
        if result.exit_code != 0:
            raise RuntimeError(output[: self._limits.output_bytes])
        data = json.loads(output)
        if not isinstance(data, dict):
            raise ValueError("sandbox output must be a JSON object")
        batch = replace(_batch(data), image=self._image_id)
        self._validate(batch)
        return batch

    def _validate(self, batch: Batch) -> None:
        artifact_ids = _unique("artifact", [item.id for item in batch.artifacts])
        trace_ids = _unique("trace", [item.id for item in batch.traces])
        evidence_ids = _unique("evidence", [item.id for item in batch.evidence])
        observation_ids = _unique("observation", [item.id for item in batch.observations])
        if artifact_ids & self._artifact_ids:
            raise ValueError("sandbox returned a duplicate artifact id")
        if trace_ids & self._trace_ids:
            raise ValueError("sandbox returned a duplicate trace id")
        if evidence_ids & self._evidence_ids:
            raise ValueError("sandbox returned a duplicate evidence id")
        if observation_ids & self._observation_ids:
            raise ValueError("sandbox returned a duplicate observation id")

        known_artifacts = self._artifact_ids | artifact_ids
        known_traces = self._trace_ids | trace_ids
        known_evidence = self._evidence_ids | evidence_ids
        for artifact in batch.artifacts:
            if re.fullmatch(r"[0-9a-f]{64}", artifact.sha256) is None:
                raise ValueError("sandbox returned an invalid artifact digest")
        for item in batch.evidence:
            if item.origin != "analysis":
                raise ValueError("sandbox evidence must have analysis origin")
            if item.artifact is not None and item.artifact not in known_artifacts:
                raise ValueError("sandbox evidence references an unknown artifact")
            if item.trace is not None and item.trace not in known_traces:
                raise ValueError("sandbox evidence references an unknown trace")
        for item in batch.traces:
            if item.artifact not in known_artifacts:
                raise ValueError("sandbox trace references an unknown artifact")
        for item in batch.observations:
            if not set(item.evidence) <= known_evidence:
                raise ValueError("sandbox observation references unknown evidence")

        self._artifact_ids.update(artifact_ids)
        self._trace_ids.update(trace_ids)
        self._evidence_ids.update(evidence_ids)
        self._observation_ids.update(observation_ids)

def _batch(data: Dict[str, Any]) -> Batch:
    return Batch(
        artifacts=tuple(_artifact(item) for item in data.get("artifacts", [])),
        traces=tuple(Trace(**item) for item in data.get("traces", [])),
        evidence=tuple(Evidence(**item) for item in data.get("evidence", [])),
        observations=tuple(Observation(**item) for item in data.get("observations", [])),
        gaps=tuple(Gap(**item) for item in data.get("gaps", [])),
        failures=tuple(Failure(**item) for item in data.get("failures", [])),
        image=data.get("image"),
    )


def _artifact(data: Dict[str, Any]) -> Artifact:
    return Artifact(
        id=data["id"],
        name=data["name"],
        size=data["size"],
        sha256=data["sha256"],
        format=Format(**data.get("format", {})),
        metrics=Metrics(**data.get("metrics", {})),
        preview=Preview(**data.get("preview", {})),
        matches=tuple(Match(**item) for item in data.get("matches", [])),
    )


def _unique(kind: str, values: list[str]) -> set[str]:
    unique = set(values)
    if len(unique) != len(values):
        raise ValueError(f"sandbox returned duplicate {kind} ids")
    return unique
