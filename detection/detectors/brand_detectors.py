"""Deterministic rule for brand impersonation in message content.

The display-name spoof rule only sees the ``From`` header, but most brand
phishing in the corpus claims the brand in the *subject or body* ("Binance
Cybersecurity", "Verify Your Trust Wallet") while both the sender domain and
every link point somewhere unrelated. This detector fires on exactly that
combination.

Like every rule here it is a pure function of the parsed observables: the
reporting validator re-runs it to ground the finding, so no state or network
access is permitted.
"""

from dataclasses import dataclass, field
from typing import Final, Optional, Tuple, Union

from ..brands import brand_matches_domain, find_content_brand
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
from .detectors import message_text


@dataclass(frozen=True)
class BrandContentMismatchEvidence:
    brand: str
    from_domain: Optional[str]
    mismatched_hosts: Tuple[str, ...]


@dataclass(frozen=True)
class BrandContentMismatchFinding(Finding[BrandContentMismatchEvidence]):
    # Content mention is weaker evidence than a spoofed display name, so the
    # finding is marked heuristic even though the rule itself is deterministic.
    detector: DetectorName = field(default=DetectorName.BRAND_CONTENT_MISMATCH, init=False)
    severity: Severity = field(default=Severity.HIGH, init=False)
    heuristic: bool = field(default=True, init=False)


class BrandContentMismatchDetector(Detector[BrandContentMismatchFinding]):
    """Fire when message text claims a brand unrelated to sender and links."""

    name = DetectorName.BRAND_CONTENT_MISMATCH

    def detect(
        self,
        observables: MessageObservables,
    ) -> Union[FiredResult[BrandContentMismatchFinding], ClearResult, SkippedResult]:
        if not observables.url_hosts:
            return SkippedResult(detector=self.name, reason="no URLs in message")
        text = message_text(observables)
        if not text:
            return SkippedResult(detector=self.name, reason="no subject or body text")

        brand = find_content_brand(text)
        if brand is None:
            return ClearResult(detector=self.name)

        from_domain = (observables.from_domain or "").lower() or None
        if from_domain is not None and brand_matches_domain(brand, from_domain):
            return ClearResult(detector=self.name)

        mismatched_hosts = tuple(
            host
            for host in observables.url_hosts
            if not brand_matches_domain(brand, host)
        )
        if not mismatched_hosts:
            return ClearResult(detector=self.name)

        finding = BrandContentMismatchFinding(
            clause=(
                f"message content claims '{brand}' but sender ({from_domain}) "
                "and linked hosts are unrelated to the brand"
            ),
            evidence=BrandContentMismatchEvidence(
                brand=brand,
                from_domain=from_domain,
                mismatched_hosts=mismatched_hosts[:5],
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


BRAND_DETECTORS: Final[Tuple[Detector, ...]] = (BrandContentMismatchDetector(),)
