"""Base class for deterministic detectors."""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar, Union

from data_models import (
    ClearResult,
    DetectorName,
    Finding,
    FiredResult,
    MessageObservables,
    SkippedResult,
)


T = TypeVar("T", bound=Finding, covariant=True)


class Detector(ABC, Generic[T]):
    """A deterministic rule that may emit a typed finding."""

    name: DetectorName

    @abstractmethod
    def detect(
        self,
        observables: MessageObservables,
    ) -> Union[FiredResult[T], ClearResult, SkippedResult]:
        """Evaluate one message and return fired, clear, or skipped."""
