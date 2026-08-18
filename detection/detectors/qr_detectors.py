"""Deterministic rule for URLs hidden inside QR-code images ("quishing").

Quishing evades text- and header-based URL analysis by carrying the
credential-harvesting link inside an image. The parser decodes those QR codes
into ``observables.image_urls`` (and merges them into ``observables.urls`` so the
generic URL detectors also apply). This detector fires on the signal unique to
QR delivery: an image-encoded link pointing at a domain unrelated to the sender.

Like every rule here it is a pure function of the parsed observables, so the
reporting validator can reconstruct and ground its output.
"""

from dataclasses import dataclass, field
from typing import Final, Optional, Tuple, Union
from urllib.parse import urlsplit

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
from .detectors import registered_domain


@dataclass(frozen=True)
class QrUrlEvidence:
    """Sender domain and the off-domain hosts a QR image linked to."""

    from_registered_domain: Optional[str]
    qr_hosts: Tuple[str, ...]
    mismatched_hosts: Tuple[str, ...]
    image_count: int


@dataclass(frozen=True)
class QrUrlFinding(Finding[QrUrlEvidence]):
    """Heuristic finding for a QR-encoded link unrelated to the sender."""

    detector: DetectorName = field(default=DetectorName.QR_URL, init=False)
    severity: Severity = field(default=Severity.HIGH, init=False)
    heuristic: bool = field(default=True, init=False)


CLAUSE: Final[str] = (
    "QR code image encodes a link to a domain unrelated to the sender"
)


class QrUrlDetector(Detector[QrUrlFinding]):
    """Fire when a QR-decoded link points off the sender's registered domain."""

    name = DetectorName.QR_URL

    def detect(
        self,
        observables: MessageObservables,
    ) -> Union[FiredResult[QrUrlFinding], ClearResult, SkippedResult]:
        if not observables.image_urls:
            return SkippedResult(
                detector=self.name,
                reason="no QR-decoded URLs in message",
            )

        from_domain = registered_domain(observables.from_domain)
        qr_hosts = _hosts(observables.image_urls)
        # With no From domain to compare against, alignment cannot be confirmed,
        # so every decoded host is treated as unrelated.
        mismatched_hosts = tuple(
            host
            for host in qr_hosts
            if from_domain is None or registered_domain(host) != from_domain
        )
        if not mismatched_hosts:
            return ClearResult(detector=self.name)

        finding = QrUrlFinding(
            clause=CLAUSE,
            evidence=QrUrlEvidence(
                from_registered_domain=from_domain,
                qr_hosts=qr_hosts[:5],
                mismatched_hosts=mismatched_hosts[:5],
                image_count=observables.qr_image_count,
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


def _hosts(urls: Tuple[str, ...]) -> Tuple[str, ...]:
    """Return the distinct lower-cased hosts of ``urls`` in stable order."""

    hosts = set()
    for url in urls:
        host = urlsplit(url).hostname
        if host:
            hosts.add(host.lower())
    return tuple(sorted(hosts))


QR_DETECTORS: Final[Tuple[Detector, ...]] = (QrUrlDetector(),)
