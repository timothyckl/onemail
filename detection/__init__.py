"""Public API for deterministic email detection."""

from .data_models import Detection, Email
from .detection import DetectionEngine, EmailParser

__all__ = ["Detection", "DetectionEngine", "Email", "EmailParser"]
