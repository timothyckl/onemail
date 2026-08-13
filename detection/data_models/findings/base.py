"""Base class shared by deterministic findings."""

from dataclasses import dataclass
from typing import Generic, TypeVar

from ..enums import DetectorName, Severity


T = TypeVar("T", covariant=True)


@dataclass(frozen=True)
class Finding(Generic[T]):
    """A detector finding carrying typed evidence."""

    clause: str
    evidence: T
    detector: DetectorName
    severity: Severity
    heuristic: bool
