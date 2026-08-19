"""Detector base class and concrete deterministic rules."""

from .base import Detector
from .detectors import (
    DEFAULT_DETECTORS as BUILTIN_DETECTORS,
    AuthFailureDetector,
    BecNoPayloadDetector,
    CredentialUrlDetector,
    DisplayNameSpoofDetector,
    ReplyToDivergenceDetector,
)
from .extra_detectors import (
    EXTRA_DETECTORS,
    AttachmentExtensionSpoofDetector,
    DangerousAttachmentDetector,
    DeepMimeNestingDetector,
    DuplicateHeaderConflictDetector,
    HighAbuseTldDetector,
    ImageOnlyBodyDetector,
    LookalikeDomainDetector,
    NestedSenderMismatchDetector,
    PrivateSenderIpDetector,
    RawIpUrlDetector,
)
from .qr_detectors import QR_DETECTORS, QrUrlDetector
from .brand_detectors import BRAND_DETECTORS, BrandContentMismatchDetector

# The engine imports DEFAULT_DETECTORS from this package, so extending it here
# is all that is needed to activate the additional rules.
DEFAULT_DETECTORS = BUILTIN_DETECTORS + EXTRA_DETECTORS + QR_DETECTORS + BRAND_DETECTORS

__all__ = [
    "AttachmentExtensionSpoofDetector",
    "AuthFailureDetector",
    "BRAND_DETECTORS",
    "BecNoPayloadDetector",
    "BrandContentMismatchDetector",
    "CredentialUrlDetector",
    "DEFAULT_DETECTORS",
    "DangerousAttachmentDetector",
    "DeepMimeNestingDetector",
    "Detector",
    "DisplayNameSpoofDetector",
    "DuplicateHeaderConflictDetector",
    "HighAbuseTldDetector",
    "ImageOnlyBodyDetector",
    "LookalikeDomainDetector",
    "NestedSenderMismatchDetector",
    "PrivateSenderIpDetector",
    "QR_DETECTORS",
    "QrUrlDetector",
    "RawIpUrlDetector",
    "ReplyToDivergenceDetector",
]