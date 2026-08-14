"""Stateless deterministic rules over immutable message observables."""

from typing import Final, Optional, Sequence, Tuple, Union

from ..data_models import (
    AuthFailureEvidence,
    AuthFailureFinding,
    BecNoPayloadEvidence,
    BecNoPayloadFinding,
    ClearResult,
    CredentialUrlEvidence,
    CredentialUrlFinding,
    DetectorName,
    DisplayNameSpoofEvidence,
    DisplayNameSpoofFinding,
    DmarcResult,
    Finding,
    FiredResult,
    MessageObservables,
    ReplyToDivergenceEvidence,
    ReplyToDivergenceFinding,
    SkippedResult,
    SpfResult,
)

from .base import Detector


CREDENTIAL_LANGUAGE: Final[Tuple[str, ...]] = (
    "verify your account",
    "verify your details",
    "sign in to continue",
    "signin",
    "log in",
    "login",
    "unlock your account",
    "your password will expire",
    "account is locked",
    "account will be locked",
    "validate your account",
    "unusual activity",
    "unusual sign-in",
    "verify now",
)

URGENCY_LANGUAGE: Final[Tuple[str, ...]] = (
    "wire transfer",
    "gift card",
    "gift cards",
    "urgent",
    "confidential",
    "cannot call",
    "in a meeting",
    "before the bank closes",
    "process a vendor payment",
)


class AuthFailureDetector(Detector[AuthFailureFinding]):
    """Detect explicit SPF or DMARC failure."""

    name = DetectorName.AUTH_FAILURE

    def detect(
        self,
        observables: MessageObservables,
    ) -> Union[FiredResult[AuthFailureFinding], ClearResult, SkippedResult]:
        has_authentication = (
            observables.has_authentication_results
            or observables.has_received_spf
            or observables.spf_result is not None
        )
        if not has_authentication:
            return SkippedResult(
                detector=self.name,
                reason="no Authentication-Results / Received-SPF present",
            )

        failed = []
        spf_result = observables.spf_result
        if spf_result is SpfResult.FAIL or spf_result is SpfResult.SOFTFAIL:
            failed.append(f"spf={spf_result.value}")
        if observables.dmarc_result is DmarcResult.FAIL:
            failed.append("dmarc=fail")
        if not failed:
            return ClearResult(detector=self.name)

        finding = AuthFailureFinding(
            clause="sender authentication failed: " + ", ".join(failed),
            evidence=AuthFailureEvidence(
                spf_result=observables.spf_result,
                dmarc_result=observables.dmarc_result,
                from_domain=observables.from_domain,
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


class ReplyToDivergenceDetector(Detector[ReplyToDivergenceFinding]):
    """Detect a Reply-To domain that differs from the From domain."""

    name = DetectorName.REPLY_TO_DIVERGENCE

    def detect(
        self,
        observables: MessageObservables,
    ) -> Union[FiredResult[ReplyToDivergenceFinding], ClearResult, SkippedResult]:
        if observables.reply_to_differs is None:
            return SkippedResult(detector=self.name, reason="no Reply-To header present")
        if not observables.reply_to_differs:
            return ClearResult(detector=self.name)

        finding = ReplyToDivergenceFinding(
            clause=(
                f"Reply-To domain ({observables.reply_to_domain}) differs from From domain "
                f"({observables.from_domain})"
            ),
            evidence=ReplyToDivergenceEvidence(
                from_domain=observables.from_domain,
                reply_to_domain=observables.reply_to_domain,
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


class CredentialUrlDetector(Detector[CredentialUrlFinding]):
    """Detect an unrelated URL host combined with credential-action language."""

    name = DetectorName.CREDENTIAL_URL

    def detect(
        self,
        observables: MessageObservables,
    ) -> Union[FiredResult[CredentialUrlFinding], ClearResult, SkippedResult]:
        if not observables.url_hosts:
            return SkippedResult(detector=self.name, reason="no URLs in message")

        from_domain = registered_domain(observables.from_domain)
        mismatched_hosts = tuple(
            host
            for host in observables.url_hosts
            if registered_domain(host) != from_domain
        )
        text = message_text(observables)
        matched_language = matching_phrases(text, CREDENTIAL_LANGUAGE)
        if not mismatched_hosts or not matched_language:
            return ClearResult(detector=self.name)

        finding = CredentialUrlFinding(
            clause="link to a domain unrelated to the sender, with credential-action language",
            evidence=CredentialUrlEvidence(
                from_registered_domain=from_domain,
                mismatched_hosts=mismatched_hosts[:5],
                matched_language=matched_language[:5],
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


class DisplayNameSpoofDetector(Detector[DisplayNameSpoofFinding]):
    """Detect a recognised brand display name unrelated to the sender domain."""

    name = DetectorName.DISPLAY_NAME_SPOOF

    def detect(
        self,
        observables: MessageObservables,
    ) -> Union[FiredResult[DisplayNameSpoofFinding], ClearResult, SkippedResult]:
        if observables.from_domain is None and observables.display_name is None:
            return SkippedResult(detector=self.name, reason="no From header to evaluate")
        if not observables.display_name_brand:
            return ClearResult(detector=self.name)

        from_domain = (observables.from_domain or "").lower()
        if observables.display_name_brand in from_domain:
            return ClearResult(detector=self.name)

        finding = DisplayNameSpoofFinding(
            clause=(
                f"display name claims '{observables.display_name_brand}' but sender domain "
                f"({from_domain}) is unrelated"
            ),
            evidence=DisplayNameSpoofEvidence(
                display_name=observables.display_name,
                brand=observables.display_name_brand,
                from_domain=from_domain,
            ),
        )
        return FiredResult(detector=self.name, finding=finding)


class BecNoPayloadDetector(Detector[BecNoPayloadFinding]):
    """Detect payload-free messages with Reply-To or urgency indicators."""

    name = DetectorName.BEC_NO_PAYLOAD

    def detect(
        self,
        observables: MessageObservables,
    ) -> Union[FiredResult[BecNoPayloadFinding], ClearResult, SkippedResult]:
        if observables.url_count or observables.attachment_count:
            return ClearResult(detector=self.name)

        reply_to_differs = observables.reply_to_differs is True
        matched_language = matching_phrases(message_text(observables), URGENCY_LANGUAGE)
        if not reply_to_differs and not matched_language:
            return ClearResult(detector=self.name)

        reasons = []
        if reply_to_differs:
            reasons.append(
                f"Reply-To ({observables.reply_to_domain}) differs from From "
                f"({observables.from_domain})"
            )
        if matched_language:
            reasons.append("urgency / payment-request language")

        finding = BecNoPayloadFinding(
            clause="no-payload message with " + " and ".join(reasons),
            evidence=BecNoPayloadEvidence(
                reply_to_differs=reply_to_differs,
                matched_language=matched_language[:5],
                from_domain=observables.from_domain,
            ),
            heuristic=bool(matched_language) and not reply_to_differs,
        )
        return FiredResult(detector=self.name, finding=finding)


def registered_domain(host: Optional[str]) -> Optional[str]:
    """Return the final two DNS labels used by the existing detector contract.

    This deliberately preserves the current simple comparison. It does not implement the
    public suffix list and therefore does not fully handle domains such as ``example.co.uk``.
    """

    if not host:
        return None
    labels = host.strip().strip(".").lower().split(".")
    return ".".join(labels if len(labels) <= 2 else labels[-2:])


def message_text(observables: MessageObservables) -> str:
    """Return lower-cased subject and decoded body text for language rules."""

    parts = tuple(part for part in (observables.subject, observables.body_text) if part)
    return " ".join(parts).lower()


def matching_phrases(text: str, phrases: Sequence[str]) -> Tuple[str, ...]:
    """Return configured phrases found in ``text`` in stable configuration order."""

    return tuple(phrase for phrase in phrases if phrase in text)


DEFAULT_DETECTORS: Final[Tuple[Detector, ...]] = (
    AuthFailureDetector(),
    ReplyToDivergenceDetector(),
    CredentialUrlDetector(),
    DisplayNameSpoofDetector(),
    BecNoPayloadDetector(),
)
