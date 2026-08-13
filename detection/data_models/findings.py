"""Findings emitted only when a deterministic detector fires."""

from dataclasses import dataclass, field
from typing import Union

from .enums import DetectorName, Severity
from .evidence import (
    AuthFailureEvidence,
    BecNoPayloadEvidence,
    CredentialUrlEvidence,
    DisplayNameSpoofEvidence,
    ReplyToDivergenceEvidence,
)


@dataclass(frozen=True)
class AuthFailureFinding:
    """Finding emitted when sender authentication deterministically fails."""

    clause: str
    evidence: AuthFailureEvidence
    detector: DetectorName = field(default=DetectorName.AUTH_FAILURE, init=False)
    severity: Severity = field(default=Severity.MEDIUM, init=False)
    heuristic: bool = field(default=False, init=False)


@dataclass(frozen=True)
class ReplyToDivergenceFinding:
    """Finding emitted when From and Reply-To domains differ."""

    clause: str
    evidence: ReplyToDivergenceEvidence
    detector: DetectorName = field(default=DetectorName.REPLY_TO_DIVERGENCE, init=False)
    severity: Severity = field(default=Severity.MEDIUM, init=False)
    heuristic: bool = field(default=False, init=False)


@dataclass(frozen=True)
class CredentialUrlFinding:
    """Heuristic finding for a mismatched URL plus credential language."""

    clause: str
    evidence: CredentialUrlEvidence
    detector: DetectorName = field(default=DetectorName.CREDENTIAL_URL, init=False)
    severity: Severity = field(default=Severity.HIGH, init=False)
    heuristic: bool = field(default=True, init=False)


@dataclass(frozen=True)
class DisplayNameSpoofFinding:
    """Finding for a brand display name unrelated to the sender domain."""

    clause: str
    evidence: DisplayNameSpoofEvidence
    detector: DetectorName = field(default=DetectorName.DISPLAY_NAME_SPOOF, init=False)
    severity: Severity = field(default=Severity.HIGH, init=False)
    heuristic: bool = field(default=False, init=False)


@dataclass(frozen=True)
class BecNoPayloadFinding:
    """Finding for a payload-free message with BEC indicators."""

    clause: str
    evidence: BecNoPayloadEvidence
    heuristic: bool
    detector: DetectorName = field(default=DetectorName.BEC_NO_PAYLOAD, init=False)
    severity: Severity = field(default=Severity.HIGH, init=False)


Finding = Union[
    AuthFailureFinding,
    ReplyToDivergenceFinding,
    CredentialUrlFinding,
    DisplayNameSpoofFinding,
    BecNoPayloadFinding,
]
