"""Final model at the end of the deterministic detection stage."""

from dataclasses import dataclass
from typing import FrozenSet, Tuple

from .enums import DetectorName
from .findings import Finding
from .observables import MessageObservables
from .results import DetectorResult, FiredResult, SkippedResult

EXPECTED_DETECTORS: FrozenSet[DetectorName] = frozenset(DetectorName)


@dataclass(frozen=True)
class Detection:
    """Complete deterministic detection outcome for one email.

    Exactly one result is required for every detector. Findings, skipped results,
    and the flagged state are derived to prevent duplicated state from drifting.
    """

    file: str
    sha256: str
    observables: MessageObservables
    detector_results: Tuple[DetectorResult, ...]

    def __post_init__(self) -> None:
        if not self.file:
            raise ValueError("detection requires a file name")
        if len(self.sha256) != 64:
            raise ValueError("detection requires an email SHA-256 digest")

        names = [result.detector for result in self.detector_results]
        if len(names) != len(EXPECTED_DETECTORS) or set(names) != EXPECTED_DETECTORS:
            raise ValueError("exactly one result per detector is required")

    @property
    def findings(self) -> Tuple[Finding, ...]:
        """Return findings from detectors that fired."""

        return tuple(
            result.finding
            for result in self.detector_results
            if isinstance(result, FiredResult)
        )

    @property
    def skipped(self) -> Tuple[SkippedResult, ...]:
        """Return detectors that could not run and their reasons."""

        return tuple(
            result
            for result in self.detector_results
            if isinstance(result, SkippedResult)
        )

    @property
    def flagged(self) -> bool:
        """Return whether at least one deterministic detector fired."""

        return bool(self.findings)
