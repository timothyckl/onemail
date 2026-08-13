"""Base and concrete detector result models."""

from .base import DetectorResult
from .results import ClearResult, FiredResult, SkippedResult

__all__ = [
    "ClearResult",
    "DetectorResult",
    "FiredResult",
    "SkippedResult",
]
