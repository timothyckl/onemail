"""Sandbox abstraction and hardened local Docker implementation."""

import hashlib
import json
import os
import re
import tempfile
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from agentic import Case
from agentic.progress import ProgressTracker

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
    """Execute approved investigation tasks in an isolated environment."""

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


class InvestigationCancelled(RuntimeError):
    """Raised when a caller stops an active investigation."""


@dataclass(frozen=True)
class _ActiveContainerEvent:
    stage: str
    action: str
    artifact: Optional[str]
    tool: Optional[str]
    step_id: str
    actor: str
    rationale: str
    command: str


class DockerSandbox(Sandbox):
    """Run one case in an ephemeral, offline Ubuntu analysis container."""

    def __init__(
        self,
        case: Case,
        limits: Limits,
        image: str = "onemail-analysis:latest",
        client: Optional[Any] = None,
        progress: Optional[ProgressTracker] = None,
        cancelled: Optional[Callable[[], bool]] = None,
        investigation_id: Optional[str] = None,
        input_path: Optional[Path] = None,
    ) -> None:
        self._owns_client = client is None
        if client is None:
            try:
                import docker
            except ImportError as error:
                raise RuntimeError("Docker SDK is required for isolated analysis") from error
            client = docker.from_env()
        self._case = case
        self._limits = limits
        self._image = image
        self._client = client
        self._progress = progress or ProgressTracker()
        self._cancelled = cancelled or (lambda: False)
        self._investigation_id = investigation_id
        self._configured_input_path = input_path
        self._container: Optional[Any] = None
        self._email_path: Optional[Path] = None
        self._image_id: Optional[str] = None
        self._artifact_ids: set[str] = set()
        self._trace_ids: set[str] = set()
        self._evidence_ids: set[str] = set()
        self._observation_ids: set[str] = set()
        self._cleanup_lock = threading.Lock()

    def __enter__(self) -> "DockerSandbox":
        self._raise_if_cancelled()
        memory = max(self._limits.total_bytes * 4, 512 * 1024 * 1024)
        step = self._progress.start(
            "sandbox", "Create isolated analysis container", tool="Docker"
        )
        try:
            if self._configured_input_path is None:
                handle = tempfile.NamedTemporaryFile(prefix="onemail-", suffix=".eml", delete=False)
                try:
                    handle.write(self._case.email.content)
                finally:
                    handle.close()
                self._email_path = Path(handle.name)
            else:
                self._email_path = self._configured_input_path
                with self._email_path.open("xb") as handle:
                    handle.write(self._case.email.content)
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
                        f"{max(self._limits.total_bytes * 2, 256 * 1024 * 1024)}"
                    )
                },
                volumes={
                    str(self._email_path): {
                        "bind": "/work/message.eml",
                        "mode": "ro",
                    }
                },
                labels={
                    "onemail.component": "analysis",
                    **(
                        {"onemail.investigation": self._investigation_id}
                        if self._investigation_id
                        else {}
                    ),
                },
            )
            self._raise_if_cancelled()
        except Exception as error:
            cleanup_error = self._cleanup()
            self._progress.finish(
                step,
                "sandbox",
                "Create isolated analysis container",
                status="failed",
                tool="Docker",
                detail=type(error).__name__,
            )
            if cleanup_error is not None:
                raise RuntimeError("failed to remove analysis container") from cleanup_error
            raise error
        self._progress.finish(
            step,
            "sandbox",
            "Create isolated analysis container",
            tool="Docker",
            detail=(self._image_id or self._image)[:120],
        )
        return self

    def stop(self) -> None:
        """Immediately terminate the container and release its resources."""

        error = self._cleanup()
        if error is not None:
            raise RuntimeError("failed to remove analysis container") from error

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        step = self._progress.start(
            "sandbox", "Remove analysis container", tool="Docker"
        )
        error = self._cleanup()
        self._progress.finish(
            step,
            "sandbox",
            "Remove analysis container",
            status="failed" if error is not None else "completed",
            tool="Docker",
            detail=type(error).__name__ if error is not None else "",
        )
        if error is not None:
            message = "failed to remove analysis container"
            if exc is not None:
                message += f"; analysis also failed: {type(exc).__name__}: {exc}"
            failure = RuntimeError(message)
            raise failure from error

    def _cleanup(self) -> Optional[Exception]:
        with self._cleanup_lock:
            container = self._container
            self._container = None
            email_path = self._email_path
            self._email_path = None
            owns_client = self._owns_client
            self._owns_client = False
        if container is None:
            input_error = self._remove_input_path(email_path)
            return input_error or self._close_owned_client(owns_client)
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
        input_error = self._remove_input_path(email_path)
        close_error = self._close_owned_client(owns_client)
        return removal_error or input_error or close_error

    @staticmethod
    def _remove_input_path(path: Optional[Path]) -> Optional[Exception]:
        if path is None:
            return None
        try:
            path.unlink(missing_ok=True)
        except Exception as error:
            return error
        return None

    def _close_owned_client(self, owns_client: bool) -> Optional[Exception]:
        if not owns_client:
            return None
        try:
            self._client.close()
        except Exception as error:
            return error
        return None

    def baseline(self) -> Batch:
        self._raise_if_cancelled()
        batch = self._run(
            [
                "baseline",
                "/work/message.eml",
                json.dumps(self._limits.__dict__, sort_keys=True),
            ],
            actor="system",
            rationale="",
        )
        email = next((item for item in batch.artifacts if item.id == "email"), None)
        expected = hashlib.sha256(self._case.email.content).hexdigest()
        if email is None or email.sha256 != expected:
            raise ValueError("sandbox email digest does not match the case")
        return batch

    def execute(self, task: Task) -> Batch:
        self._raise_if_cancelled()
        return self._run(
            [
                "task",
                task.name,
                task.artifact,
                json.dumps(dict(task.options), sort_keys=True),
                json.dumps(self._limits.__dict__, sort_keys=True),
            ],
            actor="agent",
            rationale=task.rationale,
        )

    def _run(
        self,
        arguments: list[str],
        *,
        actor: str,
        rationale: str,
    ) -> Batch:
        self._raise_if_cancelled()
        if self._container is None:
            raise RuntimeError("sandbox is not running")
        command = ["/opt/venv/bin/python", "/opt/onemail/runner.py"] + arguments
        created = self._client.api.exec_create(
            self._container.id,
            command,
            stdout=True,
            stderr=True,
        )
        execution_id = created["Id"] if isinstance(created, dict) else created
        stream = self._client.api.exec_start(execution_id, stream=True, demux=False)
        buffer = b""
        messages: list[str] = []
        data: Optional[Dict[str, Any]] = None
        active: Dict[str, _ActiveContainerEvent] = {}
        byte_limit = max(self._limits.output_bytes * 128, 8 * 1024 * 1024)

        try:
            try:
                for chunk in stream:
                    self._raise_if_cancelled()
                    buffer += (
                        chunk
                        if isinstance(chunk, bytes)
                        else str(chunk).encode("utf-8", "replace")
                    )
                    if len(buffer) > byte_limit:
                        raise ValueError("sandbox output exceeded its protocol limit")
                    while b"\n" in buffer:
                        raw, buffer = buffer.split(b"\n", 1)
                        data = self._protocol_line(
                            raw,
                            data,
                            active,
                            messages,
                            actor=actor,
                            rationale=rationale,
                        )
                if buffer.strip():
                    data = self._protocol_line(
                        buffer,
                        data,
                        active,
                        messages,
                        actor=actor,
                        rationale=rationale,
                    )
            except Exception as error:
                for item in active.values():
                    self._progress.finish(
                        item.step_id,
                        item.stage,
                        item.action,
                        status="failed",
                        artifact=item.artifact,
                        tool=item.tool,
                        detail=type(error).__name__,
                        actor=item.actor,
                        kind="tool",
                        rationale=item.rationale,
                        command=item.command,
                    )
                active.clear()
                raise
        finally:
            response = getattr(stream, "_response", None)
            if response is not None:
                response.close()

        inspected = self._client.api.exec_inspect(execution_id)
        exit_code = inspected.get("ExitCode") if isinstance(inspected, dict) else None
        if exit_code != 0:
            for item in active.values():
                self._progress.finish(
                    item.step_id,
                    item.stage,
                    item.action,
                    status="failed",
                    artifact=item.artifact,
                    tool=item.tool,
                    detail="Container runner stopped unexpectedly",
                    actor=item.actor,
                    kind="tool",
                    rationale=item.rationale,
                    command=item.command,
                    exit_code=exit_code if isinstance(exit_code, int) else None,
                )
            detail = "\n".join(messages)[: self._limits.output_bytes]
            raise RuntimeError(detail or f"sandbox runner exited with code {exit_code}")
        if data is None:
            raise ValueError("sandbox returned no result")
        for item in active.values():
            self._progress.finish(
                item.step_id,
                item.stage,
                item.action,
                status="failed",
                artifact=item.artifact,
                tool=item.tool,
                detail="Container runner omitted completion event",
                actor=item.actor,
                kind="tool",
                rationale=item.rationale,
                command=item.command,
            )
        batch = replace(_batch(data), image=self._image_id)
        self._validate(batch)
        return batch

    def _raise_if_cancelled(self) -> None:
        if self._cancelled():
            raise InvestigationCancelled("investigation stopped")

    def _protocol_line(
        self,
        raw: bytes,
        current: Optional[Dict[str, Any]],
        active: Dict[
            str,
            _ActiveContainerEvent,
        ],
        messages: list[str],
        *,
        actor: str,
        rationale: str,
    ) -> Optional[Dict[str, Any]]:
        text = raw.decode("utf-8", "replace").strip()
        if not text:
            return current
        try:
            payload = json.loads(text)
        except ValueError:
            messages.append(text[:1000])
            return current
        if not isinstance(payload, dict):
            raise ValueError("sandbox protocol message must be a JSON object")
        message_type = payload.get("type")
        if message_type == "event":
            runner_id = str(payload.get("id", ""))[:120]
            action = str(payload.get("action", "Container activity"))[:120]
            artifact = _optional_text(payload.get("artifact"), 200)
            tool = _optional_text(payload.get("tool"), 80)
            command = str(payload.get("command", ""))[:1000]
            status = payload.get("status")
            if status == "running":
                step_id = self._progress.start(
                    "container",
                    action,
                    artifact=artifact,
                    tool=tool,
                    actor=actor,
                    kind="tool",
                    rationale=rationale,
                    command=command,
                )
                active[runner_id] = _ActiveContainerEvent(
                    stage="container",
                    action=action,
                    artifact=artifact,
                    tool=tool,
                    step_id=step_id,
                    actor=actor,
                    rationale=rationale,
                    command=command,
                )
            elif status in {"completed", "failed", "skipped"}:
                item = active.pop(runner_id, None)
                duration = payload.get("duration_ms")
                duration_ms = duration if isinstance(duration, int) and duration >= 0 else None
                output = str(payload.get("output", ""))[:4000]
                reported_exit_code = payload.get("exit_code")
                event_exit_code = (
                    reported_exit_code if isinstance(reported_exit_code, int) else None
                )
                if item is not None:
                    self._progress.finish(
                        item.step_id,
                        item.stage,
                        item.action,
                        status=status,
                        artifact=item.artifact,
                        tool=item.tool,
                        duration_ms=duration_ms,
                        detail=str(payload.get("detail", ""))[:500],
                        actor=item.actor,
                        kind="tool",
                        rationale=item.rationale,
                        command=item.command or command,
                        output=output,
                        exit_code=event_exit_code,
                    )
                else:
                    self._progress.event(
                        "container",
                        action,
                        status,
                        artifact=artifact,
                        tool=tool,
                        duration_ms=duration_ms,
                        detail=str(payload.get("detail", ""))[:500],
                        actor=actor,
                        kind="tool",
                        rationale=rationale,
                        command=command,
                        output=output,
                        exit_code=event_exit_code,
                    )
            else:
                raise ValueError("sandbox returned an invalid progress status")
            return current
        if message_type == "result":
            result = payload.get("batch")
            if not isinstance(result, dict):
                raise ValueError("sandbox result must contain a batch object")
            return result
        if message_type is None:
            # Backwards compatibility with an image built before progress events.
            return payload
        raise ValueError("sandbox returned an unknown protocol message")

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
            if artifact.parent is not None and artifact.parent not in known_artifacts:
                raise ValueError("sandbox artifact references an unknown parent")
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
        similarity_hash=data.get("similarity_hash"),
        parent=data.get("parent"),
        format=Format(**data.get("format", {})),
        metrics=Metrics(**data.get("metrics", {})),
        preview=Preview(**data.get("preview", {})),
        matches=tuple(Match(**item) for item in data.get("matches", [])),
    )


def _optional_text(value: object, limit: int) -> Optional[str]:
    return None if value is None else str(value).replace("\x00", "")[:limit]


def _unique(kind: str, values: list[str]) -> set[str]:
    unique = set(values)
    if len(unique) != len(values):
        raise ValueError(f"sandbox returned duplicate {kind} ids")
    return unique
