"""Structured, bounded progress events for investigations."""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, Literal, Optional


ProgressStatus = Literal["queued", "running", "completed", "skipped", "failed"]
ProgressSink = Callable[["ProgressEvent"], None]


@dataclass(frozen=True)
class ProgressEvent:
    """One lifecycle update for an investigation step."""

    sequence: int
    step_id: str
    stage: str
    action: str
    status: ProgressStatus
    recorded_at: str
    total_elapsed_ms: int
    duration_ms: Optional[int] = None
    artifact: Optional[str] = None
    tool: Optional[str] = None
    detail: str = ""
    actor: str = "system"
    kind: str = "activity"
    rationale: str = ""
    command: str = ""
    output: str = ""
    exit_code: Optional[int] = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ProgressTracker:
    """Create consistently timed progress events and deliver them to a sink."""

    def __init__(
        self,
        sink: Optional[ProgressSink] = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._sink = sink
        self._clock = clock
        self._started = clock()
        self._sequence = 0
        self._steps = 0
        self._active: Dict[str, float] = {}
        self._lock = threading.Lock()

    @property
    def elapsed_ms(self) -> int:
        return max(0, int((self._clock() - self._started) * 1000))

    def start(
        self,
        stage: str,
        action: str,
        *,
        artifact: Optional[str] = None,
        tool: Optional[str] = None,
        detail: str = "",
        actor: str = "system",
        kind: str = "activity",
        rationale: str = "",
        command: str = "",
    ) -> str:
        with self._lock:
            self._steps += 1
            step_id = f"step-{self._steps:04d}"
            self._active[step_id] = self._clock()
        self._emit(
            step_id,
            stage,
            action,
            "running",
            artifact=artifact,
            tool=tool,
            detail=detail,
            actor=actor,
            kind=kind,
            rationale=rationale,
            command=command,
        )
        return step_id

    def finish(
        self,
        step_id: str,
        stage: str,
        action: str,
        *,
        status: ProgressStatus = "completed",
        artifact: Optional[str] = None,
        tool: Optional[str] = None,
        detail: str = "",
        duration_ms: Optional[int] = None,
        actor: str = "system",
        kind: str = "activity",
        rationale: str = "",
        command: str = "",
        output: str = "",
        exit_code: Optional[int] = None,
    ) -> None:
        with self._lock:
            started = self._active.pop(step_id, None)
        if duration_ms is None and started is not None:
            duration_ms = max(0, int((self._clock() - started) * 1000))
        self._emit(
            step_id,
            stage,
            action,
            status,
            duration_ms=duration_ms,
            artifact=artifact,
            tool=tool,
            detail=detail,
            actor=actor,
            kind=kind,
            rationale=rationale,
            command=command,
            output=output,
            exit_code=exit_code,
        )

    def event(
        self,
        stage: str,
        action: str,
        status: ProgressStatus,
        *,
        artifact: Optional[str] = None,
        tool: Optional[str] = None,
        detail: str = "",
        duration_ms: Optional[int] = None,
        actor: str = "system",
        kind: str = "activity",
        rationale: str = "",
        command: str = "",
        output: str = "",
        exit_code: Optional[int] = None,
    ) -> str:
        with self._lock:
            self._steps += 1
            step_id = f"step-{self._steps:04d}"
        self._emit(
            step_id,
            stage,
            action,
            status,
            duration_ms=duration_ms,
            artifact=artifact,
            tool=tool,
            detail=detail,
            actor=actor,
            kind=kind,
            rationale=rationale,
            command=command,
            output=output,
            exit_code=exit_code,
        )
        return step_id

    def _emit(
        self,
        step_id: str,
        stage: str,
        action: str,
        status: ProgressStatus,
        *,
        duration_ms: Optional[int] = None,
        artifact: Optional[str] = None,
        tool: Optional[str] = None,
        detail: str = "",
        actor: str = "system",
        kind: str = "activity",
        rationale: str = "",
        command: str = "",
        output: str = "",
        exit_code: Optional[int] = None,
    ) -> None:
        with self._lock:
            self._sequence += 1
            sequence = self._sequence
            total_elapsed_ms = self.elapsed_ms
        event = ProgressEvent(
            sequence=sequence,
            step_id=step_id,
            stage=_bounded(stage, 40),
            action=_bounded(action, 120),
            status=status,
            recorded_at=datetime.now(timezone.utc).isoformat(),
            total_elapsed_ms=total_elapsed_ms,
            duration_ms=duration_ms,
            artifact=_optional_bounded(artifact, 200),
            tool=_optional_bounded(tool, 80),
            detail=_bounded(detail, 500),
            actor=_bounded(actor, 20),
            kind=_bounded(kind, 30),
            rationale=_bounded(rationale, 1000),
            command=_bounded(command, 1000),
            output=_bounded(output, 4000),
            exit_code=exit_code if isinstance(exit_code, int) else None,
        )
        if self._sink is not None:
            self._sink(event)


def _bounded(value: str, limit: int) -> str:
    return str(value).replace("\x00", "")[:limit]


def _optional_bounded(value: Optional[str], limit: int) -> Optional[str]:
    return None if value is None else _bounded(value, limit)
