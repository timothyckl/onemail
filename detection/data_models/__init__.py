"""Standalone data models for deterministic email detection."""

from .enums import (
    AttachmentClass,
    DetectorName,
    DetectorStatus,
    DmarcResult,
    Severity,
    SpfResult,
)
from .evidence import (
    AuthFailureEvidence,
    BecNoPayloadEvidence,
    CredentialUrlEvidence,
    DetectorEvidence,
    DisplayNameSpoofEvidence,
    ReplyToDivergenceEvidence,
)
from .findings import (
    AuthFailureFinding,
    BecNoPayloadFinding,
    CredentialUrlFinding,
    DisplayNameSpoofFinding,
    Finding,
    ReplyToDivergenceFinding,
)
from .input import EmailInput
from .observables import (
    AttachmentObservable,
    DuplicateHeader,
    MessageObservables,
    NestedSender,
    SenderIp,
)
from .outcome import MessageDetection
from .results import (
    ClearResult,
    DetectorResult,
    FiredResult,
    SkippedResult,
)

__all__ = [
    "AttachmentClass",
    "AttachmentObservable",
    "AuthFailureEvidence",
    "AuthFailureFinding",
    "BecNoPayloadEvidence",
    "BecNoPayloadFinding",
    "ClearResult",
    "CredentialUrlEvidence",
    "CredentialUrlFinding",
    "DetectorEvidence",
    "DetectorName",
    "DetectorResult",
    "DetectorStatus",
    "DisplayNameSpoofEvidence",
    "DisplayNameSpoofFinding",
    "DmarcResult",
    "DuplicateHeader",
    "EmailInput",
    "Finding",
    "FiredResult",
    "MessageDetection",
    "MessageObservables",
    "NestedSender",
    "ReplyToDivergenceEvidence",
    "ReplyToDivergenceFinding",
    "SenderIp",
    "Severity",
    "SkippedResult",
    "SpfResult",
]
