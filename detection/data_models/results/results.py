"""Fired, clear, and skipped detector result states."""

from dataclasses import dataclass, field
from typing import Generic, TypeVar

from ..enums import DetectorName, DetectorStatus
from ..findings import Finding
from .base import DetectorResult


T = TypeVar("T", bound=Finding, covariant=True)


@dataclass(frozen=True)
class FiredResult(DetectorResult, Generic[T]):
    """A detector ran and emitted a typed finding."""

    finding: T
    status: DetectorStatus = field(default=DetectorStatus.FIRED, init=False)

    def __post_init__(self) -> None:
        if self.detector != self.finding.detector:
            raise ValueError("result and finding detectors differ")


@dataclass(frozen=True)
class ClearResult(DetectorResult):
    """A detector ran and did not find its target condition."""

    status: DetectorStatus = field(default=DetectorStatus.CLEAR, init=False)


@dataclass(frozen=True)
class SkippedResult(DetectorResult):
    """A detector could not run because required evidence was unavailable."""

    reason: str
    status: DetectorStatus = field(default=DetectorStatus.SKIPPED, init=False)

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError("skipped result requires a reason")
