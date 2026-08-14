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
from .email import Email
from .observables import (
    AttachmentObservable,
    DuplicateHeader,
    MessageObservables,
    NestedSender,
    SenderIp,
)
from .detection import Detection
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
    "Email",
    "Finding",
    "FiredResult",
    "Detection",
    "MessageObservables",
    "NestedSender",
    "ReplyToDivergenceEvidence",
    "ReplyToDivergenceFinding",
    "SenderIp",
    "Severity",
    "SkippedResult",
    "SpfResult",
]
