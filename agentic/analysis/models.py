"""Immutable models shared by isolated investigation components."""

import re
from dataclasses import dataclass, field
from typing import Mapping, Optional, Tuple

from detection import Detection


@dataclass(frozen=True)
class Format:
    magic: str = ""
    detected: str = "unknown"
    declared: Optional[str] = None
    extension: Optional[str] = None
    mismatch: bool = False


@dataclass(frozen=True)
class Metrics:
    entropy: float = 0.0
    printable_ratio: float = 0.0

    def __post_init__(self) -> None:
        if not 0.0 <= self.entropy <= 8.0:
            raise ValueError("entropy must be between 0 and 8")
        if not 0.0 <= self.printable_ratio <= 1.0:
            raise ValueError("printable ratio must be between 0 and 1")


@dataclass(frozen=True)
class Preview:
    head: str = ""
    tail: str = ""


@dataclass(frozen=True)
class Match:
    rule: str
    namespace: str = "default"
    tags: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Artifact:
    id: str
    name: str
    size: int
    sha256: str
    similarity_hash: Optional[str] = None
    parent: Optional[str] = None
    format: Format = field(default_factory=Format)
    metrics: Metrics = field(default_factory=Metrics)
    preview: Preview = field(default_factory=Preview)
    matches: Tuple[Match, ...] = ()

    def __post_init__(self) -> None:
        if not self.id or not self.name:
            raise ValueError("artifact requires an id and name")
        if self.size < 0:
            raise ValueError("artifact size cannot be negative")
        if len(self.sha256) != 64:
            raise ValueError("artifact requires a SHA-256 digest")
        if self.similarity_hash is not None and not re.fullmatch(
            r"[0-9a-f]{16}", self.similarity_hash
        ):
            raise ValueError("artifact similarity hash must be 64-bit hexadecimal")


@dataclass(frozen=True)
class Task:
    name: str
    artifact: str
    options: Mapping[str, object] = field(default_factory=dict)
    rationale: str = ""


@dataclass(frozen=True)
class Plan:
    tasks: Tuple[Task, ...] = ()
    gaps: Tuple[str, ...] = ()
    stop: bool = False


@dataclass(frozen=True)
class Trace:
    id: str
    task: str
    artifact: str
    tool: str
    version: str
    status: str
    duration_ms: int
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False


@dataclass(frozen=True)
class Evidence:
    id: str
    origin: str
    kind: str
    value: object
    artifact: Optional[str] = None
    trace: Optional[str] = None

    def __post_init__(self) -> None:
        if self.origin not in {"detection", "analysis"}:
            raise ValueError("evidence origin must be detection or analysis")
        if self.origin == "analysis" and self.trace is None:
            raise ValueError("analysis evidence requires a trace")


@dataclass(frozen=True)
class Observation:
    id: str
    summary: str
    evidence: Tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("observation requires evidence")


@dataclass(frozen=True)
class Gap:
    scope: str
    reason: str


@dataclass(frozen=True)
class Failure:
    scope: str
    error: str


@dataclass(frozen=True)
class Batch:
    artifacts: Tuple[Artifact, ...] = ()
    traces: Tuple[Trace, ...] = ()
    evidence: Tuple[Evidence, ...] = ()
    observations: Tuple[Observation, ...] = ()
    gaps: Tuple[Gap, ...] = ()
    failures: Tuple[Failure, ...] = ()
    image: Optional[str] = None


@dataclass(frozen=True)
class Limits:
    email_bytes: int = 25 * 1024 * 1024
    artifact_bytes: int = 25 * 1024 * 1024
    total_bytes: int = 100 * 1024 * 1024
    artifacts: int = 20
    archive_depth: int = 2
    archive_entries: int = 100
    expanded_bytes: int = 100 * 1024 * 1024
    output_bytes: int = 64 * 1024
    tasks: int = 8
    rounds: int = 2
    seconds: int = 180


@dataclass(frozen=True)
class Analysis:
    detection: Detection
    artifacts: Tuple[Artifact, ...]
    traces: Tuple[Trace, ...]
    evidence: Tuple[Evidence, ...]
    observations: Tuple[Observation, ...]
    gaps: Tuple[Gap, ...]
    failures: Tuple[Failure, ...]
    image: Optional[str]
