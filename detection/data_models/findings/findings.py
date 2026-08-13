"""Detector-specific findings emitted by deterministic rules."""

from dataclasses import dataclass, field
from ..enums import DetectorName, Severity
from ..evidence import (
    AuthFailureEvidence,
    BecNoPayloadEvidence,
    CredentialUrlEvidence,
    DisplayNameSpoofEvidence,
    ReplyToDivergenceEvidence,
)
from .base import Finding


@dataclass(frozen=True)
class AuthFailureFinding(Finding[AuthFailureEvidence]):
    """Finding emitted when sender authentication deterministically fails."""

    detector: DetectorName = field(default=DetectorName.AUTH_FAILURE, init=False)
    severity: Severity = field(default=Severity.MEDIUM, init=False)
    heuristic: bool = field(default=False, init=False)


@dataclass(frozen=True)
class ReplyToDivergenceFinding(Finding[ReplyToDivergenceEvidence]):
    """Finding emitted when From and Reply-To domains differ."""

    detector: DetectorName = field(default=DetectorName.REPLY_TO_DIVERGENCE, init=False)
    severity: Severity = field(default=Severity.MEDIUM, init=False)
    heuristic: bool = field(default=False, init=False)


@dataclass(frozen=True)
class CredentialUrlFinding(Finding[CredentialUrlEvidence]):
    """Heuristic finding for a mismatched URL plus credential language."""

    detector: DetectorName = field(default=DetectorName.CREDENTIAL_URL, init=False)
    severity: Severity = field(default=Severity.HIGH, init=False)
    heuristic: bool = field(default=True, init=False)


@dataclass(frozen=True)
class DisplayNameSpoofFinding(Finding[DisplayNameSpoofEvidence]):
    """Finding for a brand display name unrelated to the sender domain."""

    detector: DetectorName = field(default=DetectorName.DISPLAY_NAME_SPOOF, init=False)
    severity: Severity = field(default=Severity.HIGH, init=False)
    heuristic: bool = field(default=False, init=False)


@dataclass(frozen=True)
class BecNoPayloadFinding(Finding[BecNoPayloadEvidence]):
    """Finding for a payload-free message with BEC indicators."""

    heuristic: bool
    detector: DetectorName = field(default=DetectorName.BEC_NO_PAYLOAD, init=False)
    severity: Severity = field(default=Severity.HIGH, init=False)
