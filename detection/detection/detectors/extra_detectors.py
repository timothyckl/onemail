"""Additional deterministic detectors built on already-parsed observables.

Every rule here consumes fields that ``EmailParser`` already produces, so no
parser changes are required. Each detector follows the existing contract: it
returns exactly one of ``FiredResult`` / ``ClearResult`` / ``SkippedResult`` and
never makes a network call or a stateful decision.

The evidence and finding dataclasses live alongside the detectors to keep this
an additive, drop-in module; they subclass the same ``Finding`` base and use the
same ``DetectorName`` / ``Severity`` enums as the built-in detectors.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Final, Optional, Tuple, Union

from ...data_models import (
    AttachmentClass,
    ClearResult,
    DetectorName,
    Finding,
    FiredResult,
    MessageObservables,
    Severity,
    SkippedResult,
)

from .base import Detector
from .detectors import matching_phrases, message_text, registered_domain

# --------------------------------------------------------------------------- #
# Shared configuration tables
# --------------------------------------------------------------------------- #

# File extensions that should essentially never arrive by email.
DANGEROUS_EXTENSIONS: Final[frozenset] = frozenset(
    {
        "exe", "dll", "scr", "msi", "com", "pif", "cpl",
        "js", "vbs", "wsf", "hta", "ps1", "jse", "vbe", "bat", "cmd", "lnk",
    }
)

# Extensions that look benign and are commonly used as the *first* half of a
# double-extension disguise (e.g. ``invoice.pdf.exe``).
BENIGN_LOOKING_EXTENSIONS: Final[frozenset] = frozenset(
    {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg",
     "png", "gif", "htm", "html", "csv", "rtf"}
)

# Right-to-left override, a classic filename-spoofing character.
RLO_CHAR: Final = "\u202e"

# Brands used for lookalike / typosquat comparison (mirrors parser.BRANDS but
# kept local so this module has no import-time dependency on the parser).
LOOKALIKE_BRANDS: Final[Tuple[str, ...]] = (
    "paypal", "microsoft", "apple", "amazon", "netflix", "docusign",
    "office365", "google", "outlook", "facebook", "instagram", "whatsapp",
    "bradesco", "santander", "itau", "nubank",
)

# TLDs with disproportionately high abuse rates. ``me`` and a couple of ccTLDs
# are borderline (they have legitimate use), which is why this detector also
# requires action language before firing.
HIGH_ABUSE_TLDS: Final[frozenset] = frozenset(
    {
        "zip", "mov", "top", "xyz", "tk", "gq", "ml", "cf", "ga",
        "click", "link", "country", "kim", "work", "party", "review",
        "cam", "rest", "buzz", "icu", "support", "me",
    }
)

# Multilingual action / urgency language (EN + PT + ES). Kept separate from the
# built-in English-only lists so existing detectors are unaffected.
ACTION_LANGUAGE: Final[Tuple[str, ...]] = (
    # English
    "verify", "log in", "login", "sign in", "signin", "password",
    "expire", "expires", "expiring", "urgent", "click here", "update your",
    "confirm your", "suspended", "account is locked", "account will be locked",
    # Portuguese
    "expira", "expirando", "expiram", "resgate", "resgatar", "clique aqui",
    "sua conta", "senha", "atualize", "confirme", "bloqueada", "urgente",
    "agora mesmo",
    # Spanish
    "verifica", "contrase\u00f1a", "iniciar sesi\u00f3n", "tu cuenta",
    "haz clic", "urgente",
)

MIME_DEPTH_THRESHOLD: Final = 5
IMAGE_ONLY_TEXT_THRESHOLD: Final = 40  # stripped-text chars below this = "no real text"


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def _extension(name: str) -> str:
    return name.rsplit(".", 1)[-1].strip().lower() if "." in name else ""


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _is_non_public(address: str) -> bool:
    """True for private, loopback, link-local, reserved, or otherwise non-routable IPs."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _levenshtein(a: str, b: str) -> int:
    """Classic edit distance; small strings only, so the O(n*m) table is fine."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (ca != cb),
                )
            )
        previous = current
    return previous[-1]


def _second_level_label(host: str) -> str:
    """Return the registrable label, e.g. 'paypa1' from 'paypa1.secure.example'."""
    registered = registered_domain(host) or ""
    return registered.split(".")[0] if registered else ""


def _tld(host: str) -> str:
    labels = (host or "").strip(".").split(".")
    return labels[-1].lower() if labels else ""


# --------------------------------------------------------------------------- #
# Evidence payloads
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class DangerousAttachmentEvidence:
    names: Tuple[str, ...]
    classes: Tuple[str, ...]


@dataclass(frozen=True)
class AttachmentExtensionSpoofEvidence:
    names: Tuple[str, ...]
    reasons: Tuple[str, ...]


@dataclass(frozen=True)
class DuplicateHeaderConflictEvidence:
    headers: Tuple[str, ...]


@dataclass(frozen=True)
class NestedSenderMismatchEvidence:
    outer_from_domain: Optional[str]
    inner_senders: Tuple[str, ...]


@dataclass(frozen=True)
class DeepMimeNestingEvidence:
    mime_depth: int
    threshold: int


@dataclass(frozen=True)
class PrivateSenderIpEvidence:
    non_public_ips: Tuple[str, ...]


@dataclass(frozen=True)
class RawIpUrlEvidence:
    ip_hosts: Tuple[str, ...]


@dataclass(frozen=True)
class LookalikeDomainEvidence:
    suspect_hosts: Tuple[str, ...]
    brands: Tuple[str, ...]
    punycode: bool


@dataclass(frozen=True)
class HighAbuseTldEvidence:
    hosts: Tuple[str, ...]
    tlds: Tuple[str, ...]
    matched_language: Tuple[str, ...]


@dataclass(frozen=True)
class ImageOnlyBodyEvidence:
    stripped_text_length: int
    url_count: int


# --------------------------------------------------------------------------- #
# Findings (severity / heuristic fixed per finding type, mirroring the built-ins)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class DangerousAttachmentFinding(Finding[DangerousAttachmentEvidence]):
    detector: DetectorName = field(default=DetectorName.DANGEROUS_ATTACHMENT, init=False)
    severity: Severity = field(default=Severity.HIGH, init=False)
    heuristic: bool = field(default=False, init=False)


@dataclass(frozen=True)
class AttachmentExtensionSpoofFinding(Finding[AttachmentExtensionSpoofEvidence]):
    detector: DetectorName = field(default=DetectorName.ATTACHMENT_EXTENSION_SPOOF, init=False)
    severity: Severity = field(default=Severity.HIGH, init=False)
    heuristic: bool = field(default=False, init=False)


@dataclass(frozen=True)
class DuplicateHeaderConflictFinding(Finding[DuplicateHeaderConflictEvidence]):
    detector: DetectorName = field(default=DetectorName.DUPLICATE_HEADER_CONFLICT, init=False)
    severity: Severity = field(default=Severity.HIGH, init=False)
    heuristic: bool = field(default=False, init=False)


@dataclass(frozen=True)
class NestedSenderMismatchFinding(Finding[NestedSenderMismatchEvidence]):
    detector: DetectorName = field(default=DetectorName.NESTED_SENDER_MISMATCH, init=False)
    severity: Severity = field(default=Severity.MEDIUM, init=False)
    heuristic: bool = field(default=True, init=False)


@dataclass(frozen=True)
class DeepMimeNestingFinding(Finding[DeepMimeNestingEvidence]):
    detector: DetectorName = field(default=DetectorName.DEEP_MIME_NESTING, init=False)
    severity: Severity = field(default=Severity.MEDIUM, init=False)
    heuristic: bool = field(default=True, init=False)


@dataclass(frozen=True)
class PrivateSenderIpFinding(Finding[PrivateSenderIpEvidence]):
    detector: DetectorName = field(default=DetectorName.PRIVATE_SENDER_IP, init=False)
    severity: Severity = field(default=Severity.MEDIUM, init=False)
    heuristic: bool = field(default=True, init=False)


@dataclass(frozen=True)
class RawIpUrlFinding(Finding[RawIpUrlEvidence]):
    detector: DetectorName = field(default=DetectorName.RAW_IP_URL, init=False)
    severity: Severity = field(default=Severity.HIGH, init=False)
    heuristic: bool = field(default=False, init=False)


@dataclass(frozen=True)
class LookalikeDomainFinding(Finding[LookalikeDomainEvidence]):
    # heuristic is variable: punycode homographs are deterministic, edit-distance
    # typosquats are heuristic guesses.
    heuristic: bool
    detector: DetectorName = field(default=DetectorName.LOOKALIKE_DOMAIN, init=False)
    severity: Severity = field(default=Severity.HIGH, init=False)


@dataclass(frozen=True)
class HighAbuseTldFinding(Finding[HighAbuseTldEvidence]):
    detector: DetectorName = field(default=DetectorName.HIGH_ABUSE_TLD, init=False)
    severity: Severity = field(default=Severity.MEDIUM, init=False)
    heuristic: bool = field(default=True, init=False)


@dataclass(frozen=True)
class ImageOnlyBodyFinding(Finding[ImageOnlyBodyEvidence]):
    detector: DetectorName = field(default=DetectorName.IMAGE_ONLY_BODY, init=False)
    severity: Severity = field(default=Severity.MEDIUM, init=False)
    heuristic: bool = field(default=True, init=False)


# --------------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------------- #

class DangerousAttachmentDetector(Detector[DangerousAttachmentFinding]):
    """Fire on executable or script attachment classes."""

    name = DetectorName.DANGEROUS_ATTACHMENT

    def detect(self, observables: MessageObservables):
        if not observables.attachments:
            return SkippedResult(detector=self.name, reason="no attachments present")

        dangerous = tuple(
            a for a in observables.attachments
            if a.attachment_class in (AttachmentClass.EXECUTABLE, AttachmentClass.SCRIPT)
        )
        if not dangerous:
            return ClearResult(detector=self.name)

        finding = DangerousAttachmentFinding(
            clause="attachment with an executable or script file type",
            evidence=DangerousAttachmentEvidence(
                names=tuple(a.name for a in dangerous)[:5],
                classes=tuple(a.attachment_class.value for a in dangerous)[:5],
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


class AttachmentExtensionSpoofDetector(Detector[AttachmentExtensionSpoofFinding]):
    """Fire on double extensions or right-to-left-override filename tricks."""

    name = DetectorName.ATTACHMENT_EXTENSION_SPOOF

    def detect(self, observables: MessageObservables):
        if not observables.attachments:
            return SkippedResult(detector=self.name, reason="no attachments present")

        flagged_names = []
        reasons = set()
        for attachment in observables.attachments:
            name = attachment.name or ""
            lowered = name.lower()
            if RLO_CHAR in name:
                flagged_names.append(name)
                reasons.add("right-to-left override character in filename")
            parts = lowered.rsplit(".", 2)
            if len(parts) == 3:
                middle, last = parts[1], parts[2]
                if middle in BENIGN_LOOKING_EXTENSIONS and last in DANGEROUS_EXTENSIONS:
                    flagged_names.append(name)
                    reasons.add(f"double extension .{middle}.{last}")

        if not flagged_names:
            return ClearResult(detector=self.name)

        finding = AttachmentExtensionSpoofFinding(
            clause="attachment filename disguises its real type",
            evidence=AttachmentExtensionSpoofEvidence(
                names=tuple(dict.fromkeys(flagged_names))[:5],
                reasons=tuple(sorted(reasons))[:5],
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


class DuplicateHeaderConflictDetector(Detector[DuplicateHeaderConflictFinding]):
    """Fire when an identity header appears multiple times with conflicting values."""

    name = DetectorName.DUPLICATE_HEADER_CONFLICT
    _CRITICAL = frozenset({"from", "subject", "date", "sender", "return-path"})

    def detect(self, observables: MessageObservables):
        conflicts = tuple(
            dh.name for dh in observables.duplicate_headers if dh.name in self._CRITICAL
        )
        if not conflicts:
            return ClearResult(detector=self.name)

        finding = DuplicateHeaderConflictFinding(
            clause="conflicting duplicate identity header(s): " + ", ".join(conflicts),
            evidence=DuplicateHeaderConflictEvidence(headers=conflicts),
        )
        return FiredResult(detector=self.name, finding=finding)


class NestedSenderMismatchDetector(Detector[NestedSenderMismatchFinding]):
    """Fire when a forwarded inner message declares a different sender domain."""

    name = DetectorName.NESTED_SENDER_MISMATCH

    def detect(self, observables: MessageObservables):
        if not observables.nested_senders:
            return ClearResult(detector=self.name)

        outer = registered_domain(observables.from_domain)
        mismatched = []
        for nested in observables.nested_senders:
            # nested.sender is a full address string; pull its domain.
            at = nested.sender.rsplit("@", 1)
            inner_domain = registered_domain(at[-1]) if len(at) == 2 else None
            if inner_domain and inner_domain != outer:
                mismatched.append(nested.sender)

        if not mismatched:
            return ClearResult(detector=self.name)

        finding = NestedSenderMismatchFinding(
            clause="forwarded inner message has a sender unrelated to the outer From",
            evidence=NestedSenderMismatchEvidence(
                outer_from_domain=observables.from_domain,
                inner_senders=tuple(mismatched)[:5],
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


class DeepMimeNestingDetector(Detector[DeepMimeNestingFinding]):
    """Fire on unusually deep MIME nesting used to bury payloads."""

    name = DetectorName.DEEP_MIME_NESTING

    def detect(self, observables: MessageObservables):
        if observables.mime_depth < MIME_DEPTH_THRESHOLD:
            return ClearResult(detector=self.name)

        finding = DeepMimeNestingFinding(
            clause=f"MIME nesting depth {observables.mime_depth} exceeds threshold",
            evidence=DeepMimeNestingEvidence(
                mime_depth=observables.mime_depth,
                threshold=MIME_DEPTH_THRESHOLD,
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


class PrivateSenderIpDetector(Detector[PrivateSenderIpFinding]):
    """Fire when the message shows only non-routable origin IPs and no public one.

    A private/reserved IP alongside a public one is normal (internal relays), so
    this fires only when *no* public sender IP is observable at all.
    """

    name = DetectorName.PRIVATE_SENDER_IP

    def detect(self, observables: MessageObservables):
        if not observables.sender_ips:
            return ClearResult(detector=self.name)

        addresses = [ip.address for ip in observables.sender_ips]
        non_public = tuple(a for a in addresses if _is_non_public(a))
        has_public = any(not _is_non_public(a) for a in addresses)

        if not non_public or has_public:
            return ClearResult(detector=self.name)

        finding = PrivateSenderIpFinding(
            clause="message shows only non-routable origin IP(s) and no public sender IP",
            evidence=PrivateSenderIpEvidence(non_public_ips=non_public[:5]),
        )
        return FiredResult(detector=self.name, finding=finding)


class RawIpUrlDetector(Detector[RawIpUrlFinding]):
    """Fire when a link points at a bare IP address instead of a hostname."""

    name = DetectorName.RAW_IP_URL

    def detect(self, observables: MessageObservables):
        if not observables.url_hosts:
            return SkippedResult(detector=self.name, reason="no URLs in message")

        ip_hosts = tuple(h for h in observables.url_hosts if _is_ip_literal(h))
        if not ip_hosts:
            return ClearResult(detector=self.name)

        finding = RawIpUrlFinding(
            clause="link uses a raw IP address as its host",
            evidence=RawIpUrlEvidence(ip_hosts=ip_hosts[:5]),
        )
        return FiredResult(detector=self.name, finding=finding)


class LookalikeDomainDetector(Detector[LookalikeDomainFinding]):
    """Fire on punycode/homograph hosts or near-miss typosquats of known brands."""

    name = DetectorName.LOOKALIKE_DOMAIN

    def detect(self, observables: MessageObservables):
        candidates = list(observables.url_hosts)
        if observables.from_domain:
            candidates.append(observables.from_domain)
        if not candidates:
            return SkippedResult(detector=self.name, reason="no domains to evaluate")

        punycode_hosts = tuple(h for h in candidates if "xn--" in h.lower())

        typo_hits = []
        matched_brands = set()
        for host in candidates:
            label = _second_level_label(host)
            if not label or label in LOOKALIKE_BRANDS:
                continue  # exact brand match is not a lookalike by itself
            for brand in LOOKALIKE_BRANDS:
                if len(brand) < 5:
                    continue
                distance = _levenshtein(label, brand)
                if 0 < distance <= 1:
                    typo_hits.append(host)
                    matched_brands.add(brand)
                    break

        if not punycode_hosts and not typo_hits:
            return ClearResult(detector=self.name)

        suspect_hosts = tuple(dict.fromkeys(list(punycode_hosts) + typo_hits))[:5]
        is_punycode = bool(punycode_hosts)
        clause = (
            "domain uses punycode/homograph encoding"
            if is_punycode
            else "domain closely resembles a known brand (possible typosquat)"
        )
        finding = LookalikeDomainFinding(
            clause=clause,
            evidence=LookalikeDomainEvidence(
                suspect_hosts=suspect_hosts,
                brands=tuple(sorted(matched_brands))[:5],
                punycode=is_punycode,
            ),
            heuristic=not is_punycode,
        )
        return FiredResult(detector=self.name, finding=finding)


class HighAbuseTldDetector(Detector[HighAbuseTldFinding]):
    """Fire on a high-abuse TLD combined with action/urgency language."""

    name = DetectorName.HIGH_ABUSE_TLD

    def detect(self, observables: MessageObservables):
        if not observables.url_hosts:
            return SkippedResult(detector=self.name, reason="no URLs in message")

        abuse_hosts = tuple(h for h in observables.url_hosts if _tld(h) in HIGH_ABUSE_TLDS)
        matched_language = matching_phrases(message_text(observables), ACTION_LANGUAGE)
        if not abuse_hosts or not matched_language:
            return ClearResult(detector=self.name)

        finding = HighAbuseTldFinding(
            clause="link on a high-abuse TLD combined with action/urgency language",
            evidence=HighAbuseTldEvidence(
                hosts=abuse_hosts[:5],
                tlds=tuple(dict.fromkeys(_tld(h) for h in abuse_hosts))[:5],
                matched_language=matched_language[:5],
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


class ImageOnlyBodyDetector(Detector[ImageOnlyBodyFinding]):
    """Fire on an HTML-only body with essentially no text but at least one link."""

    name = DetectorName.IMAGE_ONLY_BODY

    def detect(self, observables: MessageObservables):
        if not observables.has_html or observables.has_plain:
            return ClearResult(detector=self.name)

        stripped_length = len(observables.body_text.strip())
        if stripped_length >= IMAGE_ONLY_TEXT_THRESHOLD or observables.url_count == 0:
            return ClearResult(detector=self.name)

        finding = ImageOnlyBodyFinding(
            clause="HTML-only message with almost no text and at least one link",
            evidence=ImageOnlyBodyEvidence(
                stripped_text_length=stripped_length,
                url_count=observables.url_count,
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


# Order is stable and appended after the built-in detectors.
EXTRA_DETECTORS: Final[Tuple[Detector, ...]] = (
    DangerousAttachmentDetector(),
    AttachmentExtensionSpoofDetector(),
    DuplicateHeaderConflictDetector(),
    NestedSenderMismatchDetector(),
    DeepMimeNestingDetector(),
    PrivateSenderIpDetector(),
    RawIpUrlDetector(),
    LookalikeDomainDetector(),
    HighAbuseTldDetector(),
    ImageOnlyBodyDetector(),
)