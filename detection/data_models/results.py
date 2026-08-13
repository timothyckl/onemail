"""The three valid detector result states."""

from dataclasses import dataclass, field
from typing import Union

from .enums import DetectorName, DetectorStatus
from .findings import Finding


@dataclass(frozen=True)
class FiredResult:
    """A detector ran and emitted a finding."""

    detector: DetectorName
    finding: Finding
    status: DetectorStatus = field(default=DetectorStatus.FIRED, init=False)

    def __post_init__(self) -> None:
        if self.detector != self.finding.detector:
            raise ValueError("result and finding detectors differ")


@dataclass(frozen=True)
class ClearResult:
    """A detector ran and did not find its target condition."""

    detector: DetectorName
    status: DetectorStatus = field(default=DetectorStatus.CLEAR, init=False)


@dataclass(frozen=True)
class SkippedResult:
    """A detector could not run because required evidence was unavailable."""

    detector: DetectorName
    reason: str
    status: DetectorStatus = field(default=DetectorStatus.SKIPPED, init=False)

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError("skipped result requires a reason")


DetectorResult = Union[FiredResult, ClearResult, SkippedResult]
