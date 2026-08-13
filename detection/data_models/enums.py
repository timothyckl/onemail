"""Closed value sets shared by the detection models."""

from enum import Enum


class DetectorName(str, Enum):
    """Stable identifier for each deterministic detector."""

    AUTH_FAILURE = "auth_failure"
    REPLY_TO_DIVERGENCE = "reply_to_divergence"
    CREDENTIAL_URL = "credential_url"
    DISPLAY_NAME_SPOOF = "display_name_spoof"
    BEC_NO_PAYLOAD = "bec_no_payload"


class DetectorStatus(str, Enum):
    """Outcome of running one detector against one message."""

    FIRED = "fired"
    CLEAR = "clear"
    SKIPPED = "skipped"


class Severity(str, Enum):
    """Fixed severity assigned by finding type."""

    MEDIUM = "medium"
    HIGH = "high"


class AttachmentClass(str, Enum):
    """Coarse attachment category derived during email parsing."""

    EXECUTABLE = "executable"
    SCRIPT = "script"
    OFFICE = "office"
    PDF = "pdf"
    ARCHIVE = "archive"
    HTML = "html"
    IMAGE = "image"
    EMAIL = "email"
    OTHER = "other"


class SpfResult(str, Enum):
    """SPF result values understood by the detection stage."""

    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    PERMERROR = "permerror"
    TEMPERROR = "temperror"


class DmarcResult(str, Enum):
    """DMARC result values understood by the detection stage."""

    PASS = "pass"
    FAIL = "fail"
    BEST_GUESS_PASS = "bestguesspass"
    NONE = "none"
