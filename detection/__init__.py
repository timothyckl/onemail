"""Public API for deterministic email detection."""

from .data_models import Detection, Email
from .engine import DetectionEngine
from .parser import EmailParser

__all__ = ["Detection", "DetectionEngine", "Email", "EmailParser"]
