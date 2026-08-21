"""Deterministic analyst-facing copy for the web console scan result.

This module is deliberately limited to presentation of the deterministic scan.
It performs no detection, model inference, sandbox analysis, or report generation.
Every sentence is selected from fixed copy and interpolated only with observed
finding evidence or message facts.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from detection.data_models import DetectorName


@dataclass(frozen=True)
class DetectorPresentation:
    """Stable, human-readable metadata for one detector."""

    title: str
    check: str


DETECTOR_PRESENTATIONS: Mapping[DetectorName, DetectorPresentation] = {
    DetectorName.AUTH_FAILURE: DetectorPresentation(
        "Sender authentication failed",
        "Checks for an explicit SPF soft-fail/fail or DMARC failure.",
    ),
    DetectorName.REPLY_TO_DIVERGENCE: DetectorPresentation(
        "Replies go to a different domain",
        "Compares the visible From domain with the Reply-To domain.",
    ),
    DetectorName.CREDENTIAL_URL: DetectorPresentation(
        "Credential request links to an unrelated domain",
        "Looks for credential-action language alongside a link unrelated to the sender.",
    ),
    DetectorName.DISPLAY_NAME_SPOOF: DetectorPresentation(
        "Display name may impersonate a recognised brand",
        "Compares a recognised brand in the display name with the actual sender domain.",
    ),
    DetectorName.BEC_NO_PAYLOAD: DetectorPresentation(
        "Message matches a payload-free BEC pattern",
        "Looks for a link-free and attachment-free message with reply redirection or urgency language.",
    ),
    DetectorName.DANGEROUS_ATTACHMENT: DetectorPresentation(
        "Attachment can execute code",
        "Identifies executable or script attachment types.",
    ),
    DetectorName.ATTACHMENT_EXTENSION_SPOOF: DetectorPresentation(
        "Attachment filename disguises its type",
        "Identifies double extensions and right-to-left filename manipulation.",
    ),
    DetectorName.DUPLICATE_HEADER_CONFLICT: DetectorPresentation(
        "Identity headers contain conflicting values",
        "Checks for conflicting duplicate From, Sender, Subject, or Date headers.",
    ),
    DetectorName.NESTED_SENDER_MISMATCH: DetectorPresentation(
        "Forwarded message has a different sender",
        "Compares the outer sender with senders found in attached or forwarded messages.",
    ),
    DetectorName.DEEP_MIME_NESTING: DetectorPresentation(
        "Message structure is unusually deeply nested",
        "Compares MIME nesting depth with the detector threshold.",
    ),
    DetectorName.PRIVATE_SENDER_IP: DetectorPresentation(
        "No public origin IP was visible",
        "Checks whether the observed origin chain contains only non-routable addresses.",
    ),
    DetectorName.RAW_IP_URL: DetectorPresentation(
        "Link uses an IP address instead of a domain",
        "Identifies links whose host is a bare IPv4 or IPv6 address.",
    ),
    DetectorName.LOOKALIKE_DOMAIN: DetectorPresentation(
        "Domain resembles a recognised brand",
        "Checks sender and link domains for brand-like typos or internationalised homographs.",
    ),
    DetectorName.HIGH_ABUSE_TLD: DetectorPresentation(
        "Action-oriented link uses a high-abuse TLD",
        "Combines action or urgency language with a link on a frequently abused TLD.",
    ),
    DetectorName.IMAGE_ONLY_BODY: DetectorPresentation(
        "Message body is almost entirely visual",
        "Identifies HTML-only messages with very little readable text and at least one link.",
    ),
    DetectorName.QR_URL: DetectorPresentation(
        "QR code links to an unrelated domain",
        "Decodes QR-code links and compares their domains with the sender domain.",
    ),
    DetectorName.BRAND_CONTENT_MISMATCH: DetectorPresentation(
        "Brand claim does not match the sender or links",
        "Compares a brand claim in the message with the sender and linked domains.",
    ),
    DetectorName.SUBJECT_OBFUSCATION: DetectorPresentation(
        "Subject uses Unicode obfuscation",
        "Identifies homoglyphs and combining marks used to alter how subject text is represented.",
    ),
    DetectorName.SHARED_HOSTING_URL: DetectorPresentation(
        "Lure links to a shared-hosting platform",
        "Combines lure language or a brand claim with an unrelated shared-hosting or shortened link.",
    ),
    DetectorName.ADVANCE_FEE: DetectorPresentation(
        "Message matches an advance-fee or prize-lure pattern",
        "Combines advance-fee language with a structural sender, reply, payload, or link anomaly.",
    ),
    DetectorName.GIBBERISH_BODY: DetectorPresentation(
        "Message contains probable filler text",
        "Looks for a high proportion of vowel-free filler tokens alongside an unrelated link.",
    ),
    DetectorName.FREEMAIL_SENDER: DetectorPresentation(
        "Consumer mailbox makes an organisational or credential claim",
        "Identifies brand or credential language sent from a consumer mailbox provider.",
    ),
}


EVIDENCE_LABELS: Mapping[str, str] = {
    "spf_result": "SPF result",
    "dmarc_result": "DMARC result",
    "from_domain": "Sender domain",
    "from_registered_domain": "Sender registered domain",
    "reply_to_domain": "Reply-To domain",
    "reply_to_differs": "Reply-To differs",
    "mismatched_hosts": "Unrelated linked hosts",
    "matched_language": "Matched message language",
    "display_name": "Displayed sender name",
    "brand": "Recognised brand",
    "names": "Attachment names",
    "classes": "Attachment types",
    "reasons": "Filename indicators",
    "headers": "Conflicting headers",
    "outer_from_domain": "Outer sender domain",
    "inner_senders": "Nested senders",
    "mime_depth": "Observed MIME depth",
    "threshold": "Detector threshold",
    "non_public_ips": "Non-public origin IPs",
    "ip_hosts": "IP-address link hosts",
    "suspect_hosts": "Lookalike domains",
    "brands": "Resembled brands",
    "punycode": "Internationalised domain",
    "hosts": "Linked hosts",
    "tlds": "Top-level domains",
    "stripped_text_length": "Readable body characters",
    "url_count": "Links found",
    "qr_hosts": "QR-code link hosts",
    "image_count": "QR-code images",
    "confusable_count": "Homoglyph characters",
    "combining_mark_count": "Combining-mark characters",
    "latin_letter_count": "Latin letters",
    "platform_hosts": "Shared-hosting link hosts",
    "freemail_sender": "Consumer mailbox sender",
    "no_payload": "No links or attachments",
    "gibberish_token_count": "Probable filler tokens",
    "token_count": "Body tokens assessed",
}


SEVERITY_COPY: Mapping[str, str] = {
    "medium": "A meaningful anomaly that needs context and corroboration; it is not proof of maliciousness.",
    "high": "A stronger indicator associated with deception or potentially harmful content; it is not proof of maliciousness.",
}

BASIS_COPY: Mapping[bool, tuple[str, str]] = {
    False: (
        "Observed condition",
        "The stated condition was directly present in the parsed message data.",
    ),
    True: (
        "Pattern-based signal",
        "The observed facts matched a suspicious pattern that can also have benign explanations.",
    ),
}


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    return value


def _values(evidence: Mapping[str, Any], key: str) -> list[str]:
    value = evidence.get(key)
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(_plain(item)) for item in value if item not in (None, "")]
    if value == "":
        return []
    return [str(_plain(value))]


def _joined(evidence: Mapping[str, Any], key: str, fallback: str = "not observed") -> str:
    values = _values(evidence, key)
    return ", ".join(values) if values else fallback


def _counted(count: Any, singular: str, plural: str | None = None) -> str:
    try:
        number = int(count)
    except (TypeError, ValueError):
        return f"an unknown number of {plural or singular + 's'}"
    return f"{number} {singular if number == 1 else (plural or singular + 's')}"


def _interpretation(detector: DetectorName, evidence: Mapping[str, Any]) -> str:
    """Build detector-specific prose using only supplied evidence."""

    sender = _joined(evidence, "from_domain")
    sender_registered = _joined(evidence, "from_registered_domain")
    hosts = _joined(evidence, "mismatched_hosts")
    language = _joined(evidence, "matched_language")

    if detector is DetectorName.AUTH_FAILURE:
        spf = _joined(evidence, "spf_result")
        dmarc = _joined(evidence, "dmarc_result")
        failed = []
        if spf in {"fail", "softfail"}:
            qualifier = "did not authorise" if spf == "fail" else "did not clearly authorise"
            failed.append(f"SPF {qualifier} the transmitting source")
        if dmarc == "fail":
            failed.append("DMARC did not establish aligned authentication for the visible From domain")
        detail = " and ".join(failed) or "the recorded sender-authentication result reported a failure"
        return (
            f"For the message claiming the sender domain {sender}, {detail}. "
            "This weakens confidence in the claimed sender identity, although forwarding "
            "or mail-system configuration can also cause authentication failures."
        )
    if detector is DetectorName.REPLY_TO_DIVERGENCE:
        return (
            f"The visible sender uses {sender}, while replies are directed to "
            f"{_joined(evidence, 'reply_to_domain')}. This separates the displayed sender "
            "identity from the response destination; legitimate services can also use separate reply domains."
        )
    if detector is DetectorName.CREDENTIAL_URL:
        return (
            f"The message uses credential-action wording ({language}) and links to {hosts}, "
            f"whose registered domain differs from the sender domain {sender_registered}. "
            "This combination is commonly associated with credential-harvesting messages."
        )
    if detector is DetectorName.DISPLAY_NAME_SPOOF:
        return (
            f"The displayed sender name {_joined(evidence, 'display_name')} references "
            f"{_joined(evidence, 'brand')}, but the domain in the From address is {sender}. "
            "The visible identity and sending domain therefore do not represent the same recognised brand."
        )
    if detector is DetectorName.BEC_NO_PAYLOAD:
        indicators = []
        if evidence.get("reply_to_differs") is True:
            indicators.append("a separate Reply-To domain")
        if _values(evidence, "matched_language"):
            indicators.append(f"urgency or payment language ({language})")
        detail = " and ".join(indicators) or "a business-email-compromise language pattern"
        return (
            f"The message contains no links or attachments and includes {detail}. "
            "This resembles conversational business email compromise, where the message itself carries the lure."
        )
    if detector is DetectorName.DANGEROUS_ATTACHMENT:
        return (
            f"The attachment(s) {_joined(evidence, 'names')} were classified as "
            f"{_joined(evidence, 'classes')}. Executable and script files can run code rather than "
            "only display document content."
        )
    if detector is DetectorName.ATTACHMENT_EXTENSION_SPOOF:
        return (
            f"The filename(s) {_joined(evidence, 'names')} contain {_joined(evidence, 'reasons')}. "
            "The displayed name can therefore make the attachment appear to have a different file type."
        )
    if detector is DetectorName.DUPLICATE_HEADER_CONFLICT:
        return (
            f"The message contains conflicting values for {_joined(evidence, 'headers')}. "
            "Different mail software can select different duplicate header values, making the displayed identity ambiguous."
        )
    if detector is DetectorName.NESTED_SENDER_MISMATCH:
        return (
            f"The outer message is from {sender}, while an attached or forwarded message identifies "
            f"{_joined(evidence, 'inner_senders')} as sender. This difference may be expected in a genuine forward, "
            "but the two sender identities are not related."
        )
    if detector is DetectorName.DEEP_MIME_NESTING:
        return (
            f"The message has a MIME nesting depth of {_joined(evidence, 'mime_depth')}, meeting or exceeding "
            f"the detector threshold of {_joined(evidence, 'threshold')}. Deep nesting can conceal content inside "
            "multiple message or multipart layers."
        )
    if detector is DetectorName.PRIVATE_SENDER_IP:
        return (
            f"The observable origin chain contains only non-public addresses: {_joined(evidence, 'non_public_ips')}. "
            "No internet-routable origin was available from these headers; local relays can also produce this pattern."
        )
    if detector is DetectorName.RAW_IP_URL:
        return (
            f"The message links directly to {_joined(evidence, 'ip_hosts')} instead of using a domain name. "
            "This removes the normal domain-name ownership and brand cues from the destination."
        )
    if detector is DetectorName.LOOKALIKE_DOMAIN:
        kind = "internationalised domain spelling" if evidence.get("punycode") else "near-match spelling"
        return (
            f"The domain(s) {_joined(evidence, 'suspect_hosts')} use {kind} that resembles "
            f"{_joined(evidence, 'brands')}. The observed domain is distinct from the recognised brand domain."
        )
    if detector is DetectorName.HIGH_ABUSE_TLD:
        return (
            f"The link host(s) {_joined(evidence, 'hosts')} use the TLD(s) {_joined(evidence, 'tlds')} and appear "
            f"with action or urgency language ({language}). The TLD alone is not a maliciousness indicator; "
            "the signal comes from this combination."
        )
    if detector is DetectorName.IMAGE_ONLY_BODY:
        return (
            f"The HTML-only body contains {_counted(evidence.get('stripped_text_length'), 'readable character')} "
            f"and {_counted(evidence.get('url_count'), 'link')}. Most of the message meaning may therefore be "
            "carried visually rather than in extractable text."
        )
    if detector is DetectorName.QR_URL:
        return (
            f"The message contains {_counted(evidence.get('image_count'), 'QR-code image')} linking to {hosts}, "
            f"which is unrelated to the sender domain {sender_registered}. The destination is encoded in an image "
            "rather than presented as ordinary message text."
        )
    if detector is DetectorName.BRAND_CONTENT_MISMATCH:
        return (
            f"The message claims {_joined(evidence, 'brand')}, but the sender domain {sender} and linked host(s) "
            f"{hosts} are unrelated to that brand. The claimed identity is therefore not supported by either domain."
        )
    if detector is DetectorName.SUBJECT_OBFUSCATION:
        return (
            f"The subject contains {_counted(evidence.get('confusable_count'), 'homoglyph character')} and "
            f"{_counted(evidence.get('combining_mark_count'), 'combining-mark character')}. These Unicode forms "
            "can preserve a familiar visual appearance while changing the underlying text."
        )
    if detector is DetectorName.SHARED_HOSTING_URL:
        context = []
        if _values(evidence, "matched_language"):
            context.append(f"lure language ({language})")
        if _values(evidence, "brand"):
            context.append(f"a claim about {_joined(evidence, 'brand')}")
        return (
            f"The message links to {_joined(evidence, 'platform_hosts')}, an unrelated shared-hosting or shortening "
            f"platform, alongside {' and '.join(context) or 'lure context'}. These platforms have legitimate uses, "
            "so the signal comes from the combined context."
        )
    if detector is DetectorName.ADVANCE_FEE:
        structures = []
        if evidence.get("freemail_sender") is True:
            structures.append("a consumer-mailbox sender")
        if evidence.get("reply_to_differs") is True:
            structures.append("a separate Reply-To domain")
        if evidence.get("no_payload") is True:
            structures.append("no links or attachments")
        if _values(evidence, "mismatched_hosts"):
            structures.append(f"an unrelated link host ({hosts})")
        return (
            f"The message uses advance-fee or prize language ({language}) together with "
            f"{', '.join(structures) or 'a structural anomaly'}. This combination matches a common advance-fee lure pattern."
        )
    if detector is DetectorName.GIBBERISH_BODY:
        return (
            f"Of {_counted(evidence.get('token_count'), 'body token')}, "
            f"{_counted(evidence.get('gibberish_token_count'), 'token')} appear to be vowel-free filler, and the message "
            f"links to {hosts}. This pattern can indicate text padding intended to alter content-based analysis."
        )
    if detector is DetectorName.FREEMAIL_SENDER:
        claims = []
        if _values(evidence, "brand"):
            claims.append(f"a claim about {_joined(evidence, 'brand')}")
        if _values(evidence, "matched_language"):
            claims.append(f"credential-action wording ({language})")
        return (
            f"The message was sent from the consumer mailbox domain {sender} and contains "
            f"{' and '.join(claims) or 'an organisational claim'}. Consumer mailboxes can be legitimate, but they "
            "do not establish control of the organisation or brand being referenced."
        )
    raise KeyError(f"no interpretation copy for {detector.value}")


def _display_value(key: str, value: Any) -> str:
    value = _plain(value)
    if value is None or value == "":
        return "Not observed"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(_plain(item)) for item in value) if value else "None"
    if key in {"spf_result", "dmarc_result"}:
        return {
            "pass": "Pass",
            "fail": "Fail",
            "softfail": "Soft fail",
            "bestguesspass": "Best-guess pass",
            "permerror": "Permanent error",
            "temperror": "Temporary error",
            "none": "No policy result",
            "neutral": "Neutral",
        }.get(str(value), str(value))
    return str(value)


def present_finding(
    detector: DetectorName,
    severity: str,
    heuristic: bool,
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """Return deterministic display fields for one fired finding."""

    metadata = DETECTOR_PRESENTATIONS[detector]
    basis_label, basis_explanation = BASIS_COPY[heuristic]
    facts = [
        {
            "key": key,
            "label": EVIDENCE_LABELS.get(key, key.replace("_", " ").title()),
            "value": _display_value(key, value),
        }
        for key, value in evidence.items()
        if value not in (None, "", (), [])
    ]
    return {
        "title": metadata.title,
        "check": metadata.check,
        "interpretation": _interpretation(detector, evidence),
        "severity_label": f"{severity.title()} concern",
        "severity_explanation": SEVERITY_COPY[severity],
        "basis_label": basis_label,
        "basis_explanation": basis_explanation,
        "key_facts": facts,
    }


def present_skipped(detector: DetectorName, reason: str) -> dict[str, str]:
    metadata = DETECTOR_PRESENTATIONS[detector]
    return {
        "detector": detector.value,
        "title": metadata.title,
        "check": metadata.check,
        "reason": reason,
    }


def _observable_item(
    label: str,
    value: Any,
    explanation: str,
    tone: str = "neutral",
) -> dict[str, Any]:
    return {
        "label": label,
        "value": "Not observed" if value in (None, "") else value,
        "explanation": explanation,
        "tone": tone,
    }


def _size(value: int) -> str:
    if value < 1024:
        return f"{value} bytes"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KB"
    return f"{value / (1024 * 1024):.1f} MB"


def present_observables(observables: Any, fired: Iterable[DetectorName]) -> list[dict[str, Any]]:
    """Group message facts and explain their significance without inference."""

    fired_names = set(fired)
    identity_warning = bool(
        fired_names
        & {
            DetectorName.REPLY_TO_DIVERGENCE,
            DetectorName.DISPLAY_NAME_SPOOF,
            DetectorName.BRAND_CONTENT_MISMATCH,
            DetectorName.FREEMAIL_SENDER,
        }
    )
    auth_warning = DetectorName.AUTH_FAILURE in fired_names
    url_findings = fired_names & {
        DetectorName.CREDENTIAL_URL,
        DetectorName.RAW_IP_URL,
        DetectorName.LOOKALIKE_DOMAIN,
        DetectorName.HIGH_ABUSE_TLD,
        DetectorName.QR_URL,
        DetectorName.BRAND_CONTENT_MISMATCH,
        DetectorName.SHARED_HOSTING_URL,
        DetectorName.GIBBERISH_BODY,
    }
    attachment_findings = fired_names & {
        DetectorName.DANGEROUS_ATTACHMENT,
        DetectorName.ATTACHMENT_EXTENSION_SPOOF,
    }

    if observables.reply_to_differs is True:
        reply_explanation = "Replies are directed to a different domain from the visible sender."
        reply_tone = "warn"
    elif observables.reply_to_differs is False:
        reply_explanation = "The Reply-To and visible sender domains match."
        reply_tone = "ok"
    else:
        reply_explanation = "No separate Reply-To domain was available for comparison."
        reply_tone = "neutral"

    spf = observables.spf_result.value if observables.spf_result else None
    spf_explanations = {
        "pass": "The transmitting source passed SPF for the authenticated mail identity; this alone does not establish that the message is benign.",
        "fail": "The transmitting source was not authorised by the applicable SPF policy.",
        "softfail": "The SPF policy indicated that the transmitting source was probably not authorised.",
        "neutral": "The SPF policy made no assertion about the transmitting source.",
        "none": "No applicable SPF policy result was available.",
        "permerror": "SPF could not be evaluated because of a permanent policy error.",
        "temperror": "SPF could not be evaluated because of a temporary error.",
    }
    dmarc = observables.dmarc_result.value if observables.dmarc_result else None
    dmarc_explanations = {
        "pass": "The visible From domain passed DMARC alignment; this alone does not establish that the message is benign.",
        "fail": "The visible From domain did not establish aligned SPF or DKIM authentication under DMARC.",
        "bestguesspass": "The receiver inferred DMARC alignment without a published policy result.",
        "none": "No applicable DMARC policy result was available.",
    }

    sender_items = [
        _observable_item(
            "From domain",
            observables.from_domain,
            "Domain in the visible From address.",
            "warn" if identity_warning else "neutral",
        ),
        _observable_item(
            "Reply-To domain",
            observables.reply_to_domain,
            reply_explanation,
            reply_tone,
        ),
        _observable_item(
            "Display name",
            observables.display_name,
            "Sender name displayed by most mail clients.",
            "warn" if DetectorName.DISPLAY_NAME_SPOOF in fired_names else "neutral",
        ),
        _observable_item(
            "Recognised brand",
            observables.display_name_brand,
            "Brand recognised in the displayed sender name, when present.",
            "warn" if DetectorName.DISPLAY_NAME_SPOOF in fired_names else "neutral",
        ),
    ]

    auth_items = [
        _observable_item(
            "SPF",
            _display_value("spf_result", spf),
            spf_explanations.get(spf, "No SPF result was present in the parsed authentication headers."),
            "warn" if spf in {"fail", "softfail"} else ("ok" if spf == "pass" else "neutral"),
        ),
        _observable_item(
            "DMARC",
            _display_value("dmarc_result", dmarc),
            dmarc_explanations.get(dmarc, "No DMARC result was present in the parsed authentication headers."),
            "warn" if dmarc == "fail" else ("ok" if dmarc in {"pass", "bestguesspass"} else "neutral"),
        ),
    ]

    if observables.url_count:
        link_explanation = (
            f"One or more links contributed to {len(url_findings)} fired link-related "
            f"{'check' if len(url_findings) == 1 else 'checks'}."
            if url_findings
            else "No link-specific detector fired; the presence of links alone is not treated as suspicious."
        )
    else:
        link_explanation = "No links were extracted from the message."
    link_items = [
        _observable_item(
            "Links",
            observables.url_count,
            link_explanation,
            "warn" if url_findings else "neutral",
        ),
        _observable_item(
            "Linked hosts",
            ", ".join(observables.url_hosts) if observables.url_hosts else None,
            "Distinct destination hosts extracted from ordinary and QR-code links.",
            "warn" if url_findings else "neutral",
        ),
    ]

    if observables.attachment_count:
        attachment_explanation = (
            f"One or more files contributed to {len(attachment_findings)} fired attachment "
            f"{'check' if len(attachment_findings) == 1 else 'checks'}."
            if attachment_findings
            else "No attachment-specific detector fired; this does not establish that the files are safe."
        )
    else:
        attachment_explanation = "No decoded attachments were present."
    content_items = [
        _observable_item(
            "Attachments",
            observables.attachment_count,
            attachment_explanation,
            "warn" if attachment_findings else "neutral",
        )
    ]
    content_items.extend(
        _observable_item(
            f"Attachment {index}",
            f"{item.name} · {item.attachment_class.value} · {_size(item.size)}",
            f"Declared content type: {item.content_type}.",
            "warn" if attachment_findings else "neutral",
        )
        for index, item in enumerate(observables.attachments, start=1)
    )

    structure_items = [
        _observable_item(
            "Subject",
            observables.subject,
            "Subject text as parsed from the message.",
            "warn" if DetectorName.SUBJECT_OBFUSCATION in fired_names else "neutral",
        ),
        _observable_item(
            "MIME depth",
            observables.mime_depth,
            (
                "The message structure met the unusually deep nesting threshold."
                if DetectorName.DEEP_MIME_NESTING in fired_names
                else "The number of nested MIME layers; no unusual-depth finding fired."
            ),
            "warn" if DetectorName.DEEP_MIME_NESTING in fired_names else "neutral",
        ),
        _observable_item(
            "Received hops",
            observables.received_count,
            "Number of Received headers observed; this is delivery context rather than a risk judgement.",
        ),
    ]

    return [
        {
            "title": "Sender identity",
            "summary": "Visible sender, reply destination, and any recognised display-name brand.",
            "max_columns": 2,
            "items": sender_items,
        },
        {
            "title": "Authentication",
            "summary": (
                "At least one recorded sender-authentication result failed."
                if auth_warning
                else "Recorded SPF and DMARC outcomes, including unavailable or inconclusive states."
            ),
            "items": auth_items,
        },
        {
            "title": "Links",
            "summary": "Link counts are contextualised by whether a link-related detector fired.",
            "items": link_items,
        },
        {
            "title": "Files and attachments",
            "summary": "Attachment presence is separated from attachment-specific risk findings.",
            "items": content_items,
        },
        {
            "title": "Message context",
            "summary": "Additional structural and delivery facts.",
            "items": structure_items,
        },
    ]


def scan_summary(findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Describe the deterministic scan outcome without composing a new verdict."""

    count = len(findings)
    if not count:
        return {
            "count": 0,
            "title": "No deterministic concerns detected",
            "text": "None of the deterministic checks identified a reportable condition in this message.",
        }
    titles = [str(item["presentation"]["title"]) for item in findings]
    if count == 1:
        listed = titles[0]
    elif count == 2:
        listed = " and ".join(titles)
    else:
        listed = ", ".join(titles[:-1]) + ", and " + titles[-1]
    return {
        "count": count,
        "title": f"{count} deterministic {'concern' if count == 1 else 'concerns'} detected",
        "text": f"The detected conditions concern: {listed}. Each finding below explains the observed condition and its security relevance.",
    }


def assert_complete_catalogue() -> None:
    """Fail fast if a detector lacks analyst-facing copy."""

    expected = set(DetectorName)
    actual = set(DETECTOR_PRESENTATIONS)
    if actual != expected:
        missing = ", ".join(sorted(item.value for item in expected - actual))
        extra = ", ".join(sorted(item.value for item in actual - expected))
        raise RuntimeError(f"detector presentation catalogue mismatch; missing={missing}; extra={extra}")


assert_complete_catalogue()
