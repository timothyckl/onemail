"""Closed value sets shared by the detection models."""

from enum import Enum


class DetectorName(str, Enum):
    """Stable identifier for each deterministic detector."""

    AUTH_FAILURE = "auth_failure"
    REPLY_TO_DIVERGENCE = "reply_to_divergence"
    CREDENTIAL_URL = "credential_url"
    DISPLAY_NAME_SPOOF = "display_name_spoof"
    BEC_NO_PAYLOAD = "bec_no_payload"
    # Additional deterministic detectors (all run off already-parsed observables).
    DANGEROUS_ATTACHMENT = "dangerous_attachment"
    ATTACHMENT_EXTENSION_SPOOF = "attachment_extension_spoof"
    DUPLICATE_HEADER_CONFLICT = "duplicate_header_conflict"
    NESTED_SENDER_MISMATCH = "nested_sender_mismatch"
    DEEP_MIME_NESTING = "deep_mime_nesting"
    PRIVATE_SENDER_IP = "private_sender_ip"
    RAW_IP_URL = "raw_ip_url"
    LOOKALIKE_DOMAIN = "lookalike_domain"
    HIGH_ABUSE_TLD = "high_abuse_tld"
    IMAGE_ONLY_BODY = "image_only_body"
    # Recovers URLs hidden inside QR-code images ("quishing").
    QR_URL = "qr_url"
    # Brand claimed in message content while sender and links are unrelated.
    BRAND_CONTENT_MISMATCH = "brand_content_mismatch"
    # Structural lure rules (subject obfuscation, abused hosting, 419, filler).
    SUBJECT_OBFUSCATION = "subject_obfuscation"
    SHARED_HOSTING_URL = "shared_hosting_url"
    ADVANCE_FEE = "advance_fee"
    GIBBERISH_BODY = "gibberish_body"


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