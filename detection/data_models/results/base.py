"""Base class shared by all detector result states."""

from dataclasses import dataclass, field

from ..enums import DetectorName, DetectorStatus


@dataclass(frozen=True)
class DetectorResult:
    """The detector identity and status common to every result state."""

    detector: DetectorName
    status: DetectorStatus = field(init=False)
