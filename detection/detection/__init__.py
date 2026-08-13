"""Standalone deterministic email detection."""

from .engine import DetectionEngine
from .parser import EmailParser

__all__ = ["DetectionEngine", "EmailParser"]
