"""Phase 6: authentication semantics and the freemail-sender rule.

SPF and DMARC only prove that a message came from the mailbox it claims;
attackers pass both on throwaway or freemail accounts they own. The corpus is
dominated by SPF-pass senders, so authentication *failure* fires the existing
``AuthFailureDetector`` while authentication *pass* must never be exculpatory.
No detector in this codebase clears on a pass; a regression test enforces it.

The rule added here covers the complementary signal: an organisation does not
run account security or brand communications from a consumer mailbox. A
freemail sender that claims a brand or uses credential-action language is
fired regardless of its (typically valid) authentication results.
"""

from dataclasses import dataclass, field
from typing import Final, Optional, Tuple, Union

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
from .lexicon import CREDENTIAL_LANGUAGE
from .structural_detectors import FREEMAIL_DOMAINS


@dataclass(frozen=True)
class FreemailSenderEvidence:
    from_domain: Optional[str]
    brand: Optional[str]
    matched_language: Tuple[str, ...]


@dataclass(frozen=True)
class FreemailSenderFinding(Finding[FreemailSenderEvidence]):
    detector: DetectorName = field(default=DetectorName.FREEMAIL_SENDER, init=False)
    severity: Severity = field(default=Severity.MEDIUM, init=False)
    heuristic: bool = field(default=True, init=False)


class FreemailSenderDetector(Detector[FreemailSenderFinding]):
    """Fire on a freemail sender claiming a brand or a credential action."""

    name = DetectorName.FREEMAIL_SENDER

    def detect(
        self,
        observables: MessageObservables,
    ) -> Union[FiredResult[FreemailSenderFinding], ClearResult, SkippedResult]:
        if observables.from_domain is None:
            return SkippedResult(detector=self.name, reason="no From header to evaluate")

        sender = registered_domain(observables.from_domain)
        if sender not in FREEMAIL_DOMAINS:
            return ClearResult(detector=self.name)

        text = message_text(observables)
        brand = find_content_brand(text) if text else None
        matched_language = (
            matching_phrases(text, CREDENTIAL_LANGUAGE) if text else ()
        )
        if brand is None and not matched_language:
            return ClearResult(detector=self.name)

        reasons = []
        if brand is not None:
            reasons.append(f"a claim about '{brand}'")
        if matched_language:
            reasons.append("credential-action language")

        finding = FreemailSenderFinding(
            clause=(
                f"consumer mailbox sender ({sender}) with " + " and ".join(reasons)
            ),
            evidence=FreemailSenderEvidence(
                from_domain=observables.from_domain,
                brand=brand,
                matched_language=matched_language[:5],
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


FREEMAIL_DETECTORS: Final[Tuple[Detector, ...]] = (FreemailSenderDetector(),)
