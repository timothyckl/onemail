"""Boundary between deterministic detection and agentic investigation."""

import hashlib
from dataclasses import dataclass

from detection import Detection, Email


@dataclass(frozen=True)
class Case:
    """A flagged email and its immutable deterministic detection."""

    email: Email
    detection: Detection

    def __post_init__(self) -> None:
        if self.email.file != self.detection.file:
            raise ValueError("case email and detection file names differ")
        if hashlib.sha256(self.email.content).hexdigest() != self.detection.sha256:
            raise ValueError("case email does not match the detected content")
        if not self.detection.flagged:
            raise ValueError("agentic analysis requires a flagged detection")
