"""Structural lure detectors added in Phase 4.

Four deterministic rules over already-parsed observables:

- ``SubjectObfuscationDetector``: homoglyph / combining-mark / math-letter
  obfuscation in the subject line. Legitimate senders do not write
  ``Aܿmܿaܿzܿon``; the rule requires *mixed* script so genuinely non-Latin
  mail (for example fully Cyrillic subjects) stays clear.
- ``SharedHostingUrlDetector``: a link on a free-hosting / shortener platform
  unrelated to the sender, paired with lure language or a brand claim.
- ``AdvanceFeeDetector``: prize / lottery / 419 vocabulary combined with a
  structural oddity (freemail sender, Reply-To divergence, no payload, or a
  link to a host unrelated to the sender).
- ``GibberishBodyDetector``: bodies padded with random consonant strings to
  evade text analysis, combined with an unrelated link.

Every detector is a pure function of ``MessageObservables``; the reporting
validator re-runs them to ground fired findings.
"""

import re
from dataclasses import dataclass, field
from typing import Final, Optional, Tuple, Union

from .. import textnorm
from ..brands import find_content_brand
from ..data_models import (
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
from .lexicon import ADVANCE_FEE_LANGUAGE, CREDENTIAL_LANGUAGE, URGENCY_LANGUAGE


# Combined lure vocabulary for the shared-hosting pairing rule.
LURE_LANGUAGE: Final[Tuple[str, ...]] = tuple(
    dict.fromkeys(CREDENTIAL_LANGUAGE + URGENCY_LANGUAGE + ADVANCE_FEE_LANGUAGE)
)

# Free-hosting, serverless, and shortener platforms routinely abused to host
# phishing pages. Matched with exact or dot-boundary suffix semantics.
SHARED_HOSTING_DOMAINS: Final[Tuple[str, ...]] = (
    "firebaseapp.com",
    "web.app",
    "run.app",
    "cloudfront.net",
    "amazonaws.com",
    "storage.googleapis.com",
    "sites.google.com",
    "herokuapp.com",
    "github.io",
    "pages.dev",
    "workers.dev",
    "netlify.app",
    "vercel.app",
    "glitch.me",
    "repl.co",
    "blogspot.com",
    "weebly.com",
    "weeblysite.com",
    "wixsite.com",
    "000webhostapp.com",
    "godaddysites.com",
    "square.site",
    "canva.site",
    "linktr.ee",
    # Shorteners.
    "bit.ly",
    "tinyurl.com",
    "cutt.ly",
    "rebrand.ly",
    "goo.gl",
    "is.gd",
    "rb.gy",
    "shorturl.at",
    "ow.ly",
    "buff.ly",
    "t.ly",
    "s.id",
)

# Consumer mailbox providers: a legitimate company does not run its prize
# draw or payment desk from a freemail address.
FREEMAIL_DOMAINS: Final[Tuple[str, ...]] = (
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "ymail.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "gmx.de",
    "gmx.net",
    "gmx.com",
    "web.de",
    "t-online.de",
    "mail.ru",
    "yandex.ru",
    "yandex.com",
    "protonmail.com",
    "proton.me",
    "zoho.com",
    "mail.com",
)

# Subject-obfuscation thresholds.
MIN_COMBINING_MARKS: Final = 2
MIN_CONFUSABLES: Final = 2
MIN_LATIN_LETTERS: Final = 4

# Gibberish-body thresholds.
MIN_GIBBERISH_TOKENS: Final = 12
GIBBERISH_RATIO_PERCENT: Final = 35

_TOKEN_PATTERN: Final = re.compile(r"[a-z]{4,}")
_VOWELS: Final = frozenset("aeiou")
_HEX_CHARS: Final = frozenset("abcdef")


# --------------------------------------------------------------------------- #
# Evidence payloads
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class SubjectObfuscationEvidence:
    confusable_count: int
    combining_mark_count: int
    latin_letter_count: int


@dataclass(frozen=True)
class SharedHostingUrlEvidence:
    platform_hosts: Tuple[str, ...]
    matched_language: Tuple[str, ...]
    brand: Optional[str]


@dataclass(frozen=True)
class AdvanceFeeEvidence:
    matched_language: Tuple[str, ...]
    from_domain: Optional[str]
    freemail_sender: bool
    reply_to_differs: bool
    no_payload: bool
    mismatched_hosts: Tuple[str, ...]


@dataclass(frozen=True)
class GibberishBodyEvidence:
    gibberish_token_count: int
    token_count: int
    mismatched_hosts: Tuple[str, ...]


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class SubjectObfuscationFinding(Finding[SubjectObfuscationEvidence]):
    detector: DetectorName = field(default=DetectorName.SUBJECT_OBFUSCATION, init=False)
    severity: Severity = field(default=Severity.HIGH, init=False)
    heuristic: bool = field(default=False, init=False)


@dataclass(frozen=True)
class SharedHostingUrlFinding(Finding[SharedHostingUrlEvidence]):
    detector: DetectorName = field(default=DetectorName.SHARED_HOSTING_URL, init=False)
    severity: Severity = field(default=Severity.MEDIUM, init=False)
    heuristic: bool = field(default=True, init=False)


@dataclass(frozen=True)
class AdvanceFeeFinding(Finding[AdvanceFeeEvidence]):
    detector: DetectorName = field(default=DetectorName.ADVANCE_FEE, init=False)
    severity: Severity = field(default=Severity.HIGH, init=False)
    heuristic: bool = field(default=True, init=False)


@dataclass(frozen=True)
class GibberishBodyFinding(Finding[GibberishBodyEvidence]):
    detector: DetectorName = field(default=DetectorName.GIBBERISH_BODY, init=False)
    severity: Severity = field(default=Severity.MEDIUM, init=False)
    heuristic: bool = field(default=True, init=False)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _on_platform(host: str) -> bool:
    candidate = host.strip().strip(".").lower()
    return any(
        candidate == domain or candidate.endswith("." + domain)
        for domain in SHARED_HOSTING_DOMAINS
    )


def _mismatched_hosts(observables: MessageObservables) -> Tuple[str, ...]:
    sender = registered_domain(observables.from_domain)
    return tuple(
        host
        for host in observables.url_hosts
        if registered_domain(host) != sender
    )


# --------------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------------- #

class SubjectObfuscationDetector(Detector[SubjectObfuscationFinding]):
    """Fire on homoglyph, combining-mark, or math-letter subject obfuscation."""

    name = DetectorName.SUBJECT_OBFUSCATION

    def detect(
        self,
        observables: MessageObservables,
    ) -> Union[FiredResult[SubjectObfuscationFinding], ClearResult, SkippedResult]:
        subject = observables.subject
        if subject is None:
            return SkippedResult(detector=self.name, reason="no Subject header")

        confusables = textnorm.count_confusables(subject)
        combining = textnorm.count_combining_marks(subject)
        latin = sum(1 for c in subject if c.isascii() and c.isalpha())

        # Combining marks in a subject are always synthetic. Homoglyphs only
        # count when the subject is predominantly Latin, so genuinely
        # non-Latin-script mail stays clear.
        mixed_script = (
            confusables >= MIN_CONFUSABLES
            and latin >= MIN_LATIN_LETTERS
            and latin >= 2 * confusables
        )
        if combining < MIN_COMBINING_MARKS and not mixed_script:
            return ClearResult(detector=self.name)

        finding = SubjectObfuscationFinding(
            clause=(
                "subject line uses Unicode obfuscation "
                f"({confusables} homoglyph, {combining} combining-mark characters)"
            ),
            evidence=SubjectObfuscationEvidence(
                confusable_count=confusables,
                combining_mark_count=combining,
                latin_letter_count=latin,
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


class SharedHostingUrlDetector(Detector[SharedHostingUrlFinding]):
    """Fire on an abused-platform link plus lure language or a brand claim."""

    name = DetectorName.SHARED_HOSTING_URL

    def detect(
        self,
        observables: MessageObservables,
    ) -> Union[FiredResult[SharedHostingUrlFinding], ClearResult, SkippedResult]:
        if not observables.url_hosts:
            return SkippedResult(detector=self.name, reason="no URLs in message")

        sender = registered_domain(observables.from_domain)
        platform_hosts = tuple(
            host
            for host in observables.url_hosts
            if _on_platform(host) and registered_domain(host) != sender
        )
        if not platform_hosts:
            return ClearResult(detector=self.name)

        text = message_text(observables)
        matched_language = matching_phrases(text, LURE_LANGUAGE)
        brand = find_content_brand(text)
        if not matched_language and brand is None:
            return ClearResult(detector=self.name)

        finding = SharedHostingUrlFinding(
            clause=(
                "link hosted on a free-hosting or shortener platform unrelated "
                "to the sender, with lure language or a brand claim"
            ),
            evidence=SharedHostingUrlEvidence(
                platform_hosts=platform_hosts[:5],
                matched_language=matched_language[:5],
                brand=brand,
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


class AdvanceFeeDetector(Detector[AdvanceFeeFinding]):
    """Fire on prize/419 vocabulary combined with a structural oddity."""

    name = DetectorName.ADVANCE_FEE

    def detect(
        self,
        observables: MessageObservables,
    ) -> Union[FiredResult[AdvanceFeeFinding], ClearResult, SkippedResult]:
        text = message_text(observables)
        if not text:
            return SkippedResult(detector=self.name, reason="no subject or body text")

        matched_language = matching_phrases(text, ADVANCE_FEE_LANGUAGE)
        if not matched_language:
            return ClearResult(detector=self.name)

        sender = registered_domain(observables.from_domain)
        freemail_sender = sender in FREEMAIL_DOMAINS
        reply_to_differs = observables.reply_to_differs is True
        no_payload = not observables.url_count and not observables.attachment_count
        mismatched = _mismatched_hosts(observables)

        if not (freemail_sender or reply_to_differs or no_payload or mismatched):
            return ClearResult(detector=self.name)

        reasons = []
        if freemail_sender:
            reasons.append("freemail sender")
        if reply_to_differs:
            reasons.append("Reply-To divergence")
        if no_payload:
            reasons.append("no payload")
        if mismatched:
            reasons.append("link to an unrelated host")

        finding = AdvanceFeeFinding(
            clause=(
                "advance-fee / prize lure language with " + " and ".join(reasons)
            ),
            evidence=AdvanceFeeEvidence(
                matched_language=matched_language[:5],
                from_domain=observables.from_domain,
                freemail_sender=freemail_sender,
                reply_to_differs=reply_to_differs,
                no_payload=no_payload,
                mismatched_hosts=mismatched[:5],
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


class GibberishBodyDetector(Detector[GibberishBodyFinding]):
    """Fire on consonant-string filler text plus a link to an unrelated host."""

    name = DetectorName.GIBBERISH_BODY

    def detect(
        self,
        observables: MessageObservables,
    ) -> Union[FiredResult[GibberishBodyFinding], ClearResult, SkippedResult]:
        if not observables.url_hosts:
            return SkippedResult(detector=self.name, reason="no URLs in message")
        if not observables.body_text:
            return SkippedResult(detector=self.name, reason="no body text")

        tokens = [
            token
            for token in _TOKEN_PATTERN.findall(observables.body_text.lower())
            # All-hex tokens are CSS colours ("ffffff"), not language.
            if not set(token) <= _HEX_CHARS
        ]
        gibberish = [token for token in tokens if not set(token) & _VOWELS]
        if (
            len(tokens) < MIN_GIBBERISH_TOKENS
            or 100 * len(gibberish) < GIBBERISH_RATIO_PERCENT * len(tokens)
        ):
            return ClearResult(detector=self.name)

        mismatched = _mismatched_hosts(observables)
        if not mismatched:
            return ClearResult(detector=self.name)

        finding = GibberishBodyFinding(
            clause=(
                "body is padded with vowel-free filler tokens "
                f"({len(gibberish)} of {len(tokens)}) and links to an unrelated host"
            ),
            evidence=GibberishBodyEvidence(
                gibberish_token_count=len(gibberish),
                token_count=len(tokens),
                mismatched_hosts=mismatched[:5],
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


STRUCTURAL_DETECTORS: Final[Tuple[Detector, ...]] = (
    SubjectObfuscationDetector(),
    SharedHostingUrlDetector(),
    AdvanceFeeDetector(),
    GibberishBodyDetector(),
)
