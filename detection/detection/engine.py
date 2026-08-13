"""Orchestrate parsing and deterministic rules for one email."""

from typing import Iterable, Optional, Tuple

from data_models import DetectorResult, EmailInput, MessageDetection

from .detectors import DEFAULT_DETECTORS, Detector
from .parser import EmailParser


class DetectionEngine:
    """Build one complete deterministic detection result from one email."""

    def __init__(
        self,
        parser: Optional[EmailParser] = None,
        detectors: Iterable[Detector] = DEFAULT_DETECTORS,
    ) -> None:
        self._parser = parser or EmailParser()
        self._detectors: Tuple[Detector, ...] = tuple(detectors)

    def detect(self, email_input: EmailInput) -> MessageDetection:
        """Parse once, run every detector once, and return the message outcome."""

        observables = self._parser.parse(email_input)
        results: Tuple[DetectorResult, ...] = tuple(
            detector.detect(observables) for detector in self._detectors
        )
        return MessageDetection(
            file=email_input.file,
            observables=observables,
            detector_results=results,
        )
