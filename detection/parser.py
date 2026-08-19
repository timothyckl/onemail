"""Convert raw RFC 822 email bytes into immutable observable facts."""

import hashlib
import re
from dataclasses import dataclass
from email import message_from_bytes, policy
from email.message import Message
from email.utils import parsedate_to_datetime
from typing import Final, Iterable, Optional, Set, Tuple

from . import qr, textnorm
from .brands import BRANDS, find_brand
from .domains import registered_domain
from .data_models import (
    AttachmentClass,
    AttachmentObservable,
    DmarcResult,
    DuplicateHeader,
    Email,
    MessageObservables,
    NestedSender,
    SenderIp,
    SpfResult,
)


URL_PATTERN: Final = re.compile(rb"https?://[^\s\"'<>\)\]}]+", re.IGNORECASE)
HOST_PATTERN: Final = re.compile(r"https?://([^/:?#]+)", re.IGNORECASE)
ADDRESS_DOMAIN_PATTERN: Final = re.compile(r"[\w.+-]+@([A-Za-z0-9.-]+)")
DISPLAY_NAME_PATTERN: Final = re.compile(r'^\s*"?([^"<]+?)"?\s*<')
RECEIVING_GATEWAY_PATTERN: Final = re.compile(r"\bby\s+([A-Za-z0-9.\-]+)")
IP_PATTERN: Final = re.compile(r"[\[\(]?((?:\d{1,3}\.){3}\d{1,3})[\]\)]?")
SPF_PATTERN: Final = re.compile(
    r"spf=(pass|fail|softfail|neutral|none|permerror|temperror)"
)
RECEIVED_SPF_PATTERN: Final = re.compile(r"\s*(pass|fail|softfail|neutral|none)")
DMARC_PATTERN: Final = re.compile(r"dmarc=(pass|fail|bestguesspass|none)")

BODY_LIMIT: Final = 20_000
VALUE_LIMIT: Final = 200
URL_LIMIT: Final = 400
QR_IMAGE_LIMIT: Final = 12  # max images scanned for QR codes per message

# ``BRANDS`` now lives in ``detection.brands`` (imported above) so the parser
# and the brand detectors share one vocabulary and one legitimate-domain map.

ATTACHMENT_CLASSES: Final = {
    "exe": AttachmentClass.EXECUTABLE,
    "dll": AttachmentClass.EXECUTABLE,
    "scr": AttachmentClass.EXECUTABLE,
    "msi": AttachmentClass.EXECUTABLE,
    "com": AttachmentClass.EXECUTABLE,
    "pif": AttachmentClass.EXECUTABLE,
    "cpl": AttachmentClass.EXECUTABLE,
    "js": AttachmentClass.SCRIPT,
    "vbs": AttachmentClass.SCRIPT,
    "wsf": AttachmentClass.SCRIPT,
    "hta": AttachmentClass.SCRIPT,
    "ps1": AttachmentClass.SCRIPT,
    "jse": AttachmentClass.SCRIPT,
    "vbe": AttachmentClass.SCRIPT,
    "bat": AttachmentClass.SCRIPT,
    "cmd": AttachmentClass.SCRIPT,
    "lnk": AttachmentClass.SCRIPT,
    "doc": AttachmentClass.OFFICE,
    "docm": AttachmentClass.OFFICE,
    "docx": AttachmentClass.OFFICE,
    "xls": AttachmentClass.OFFICE,
    "xlsm": AttachmentClass.OFFICE,
    "xlsx": AttachmentClass.OFFICE,
    "xlsb": AttachmentClass.OFFICE,
    "ppt": AttachmentClass.OFFICE,
    "pptx": AttachmentClass.OFFICE,
    "rtf": AttachmentClass.OFFICE,
    "pdf": AttachmentClass.PDF,
    "zip": AttachmentClass.ARCHIVE,
    "rar": AttachmentClass.ARCHIVE,
    "7z": AttachmentClass.ARCHIVE,
    "iso": AttachmentClass.ARCHIVE,
    "img": AttachmentClass.ARCHIVE,
    "gz": AttachmentClass.ARCHIVE,
    "tar": AttachmentClass.ARCHIVE,
    "cab": AttachmentClass.ARCHIVE,
    "z": AttachmentClass.ARCHIVE,
    "ace": AttachmentClass.ARCHIVE,
    "htm": AttachmentClass.HTML,
    "html": AttachmentClass.HTML,
    "shtml": AttachmentClass.HTML,
    "svg": AttachmentClass.HTML,
    "mhtml": AttachmentClass.HTML,
    "png": AttachmentClass.IMAGE,
    "jpg": AttachmentClass.IMAGE,
    "jpeg": AttachmentClass.IMAGE,
    "gif": AttachmentClass.IMAGE,
    "bmp": AttachmentClass.IMAGE,
    "eml": AttachmentClass.EMAIL,
    "msg": AttachmentClass.EMAIL,
}

INLINE_IMAGE_TYPES: Final = frozenset(
    {"image/png", "image/jpeg", "image/gif", "image/bmp", "image/x-icon"}
)


class EmailParser:
    """Extract observable facts from one email without making a judgment."""

    def parse(self, email: Email) -> MessageObservables:
        """Return immutable observables derived solely from ``email.content``."""

        try:
            message = message_from_bytes(
                email.content,
                policy=policy.default,
            )
        except Exception as error:  # hostile input must become data, not a crash
            return MessageObservables(
                path=email.file,
                byte_count=len(email.content),
                parse_error=type(error).__name__,
            )

        try:
            duplicate_headers = self._duplicate_headers(message)
            nested_senders = self._nested_senders(message)
            received = self._received_observables(message)
            authentication = self._authentication_observables(message)
            sender = self._sender_observables(message)
            content = self._content_observables(message, email.content)

            subject = self._header(message, "Subject")

            return MessageObservables(
                path=email.file,
                byte_count=len(email.content),
                subject=subject,
                body_text=content.body_text,
                normalized_subject=(
                    textnorm.normalize(subject) if subject is not None else None
                ),
                normalized_body_text=textnorm.normalize(content.body_text),
                subject_confusable_count=textnorm.count_confusables(subject or ""),
                body_combining_mark_count=textnorm.count_combining_marks(
                    content.body_text
                ),
                has_html=content.has_html,
                has_plain=content.has_plain,
                mime_depth=self._mime_depth(message),
                is_mailing_list=self._is_mailing_list(message),
                from_domain=sender.from_domain,
                reply_to_domain=sender.reply_to_domain,
                reply_to_differs=sender.reply_to_differs,
                display_name=sender.display_name,
                display_name_brand=sender.display_name_brand,
                has_authentication_results=authentication.has_authentication_results,
                has_dkim_signature=authentication.has_dkim_signature,
                has_received_spf=authentication.has_received_spf,
                spf_result=authentication.spf_result,
                dmarc_result=authentication.dmarc_result,
                urls=content.urls,
                url_hosts=content.url_hosts,
                image_urls=content.image_urls,
                qr_image_count=content.qr_image_count,
                attachments=content.attachments,
                inline_image_count=content.inline_image_count,
                duplicate_headers=duplicate_headers,
                nested_senders=nested_senders,
                raw_date=self._header(message, "Date", limit=80),
                date_epoch=self._date_epoch(message),
                received_count=received.count,
                received_epoch=received.epoch,
                received_iso=received.iso,
                receiving_gateway=received.gateway,
                sender_ips=received.sender_ips,
            )
        except Exception as error:  # malformed structured headers may fail lazily
            return MessageObservables(
                path=email.file,
                byte_count=len(email.content),
                parse_error=type(error).__name__,
            )

    @staticmethod
    def _is_mailing_list(message: Message) -> bool:
        """Return True when mailing-list infrastructure headers are present.

        Deliberately excludes ``List-Unsubscribe`` and ``Precedence: bulk``:
        bulk marketing and phishing both add those freely, so they do not
        evidence a real distribution list.
        """

        for name in ("List-Id", "List-Post", "Mailing-List", "X-Mailing-List"):
            if EmailParser._header(message, name) is not None:
                return True
        precedence = EmailParser._header(message, "Precedence") or ""
        return precedence.strip().lower() == "list"

    @staticmethod
    def _header(message: Message, name: str, limit: Optional[int] = None) -> Optional[str]:
        try:
            value = str(message.get(name) or "")
        except Exception:
            return None
        if not value:
            return None
        return value[:limit] if limit is not None else value

    @staticmethod
    def _leaf_parts(message: Message) -> Iterable[Message]:
        if message.is_multipart():
            for part in message.iter_parts():
                yield from EmailParser._leaf_parts(part)
            return
        yield message

    @staticmethod
    def _mime_depth(message: Message, depth: int = 0) -> int:
        if not message.is_multipart():
            return depth
        try:
            return max(
                (EmailParser._mime_depth(part, depth + 1) for part in message.iter_parts()),
                default=depth,
            )
        except Exception:
            return depth

    @staticmethod
    def _duplicate_headers(message: Message) -> Tuple[DuplicateHeader, ...]:
        duplicates = []
        for name in ("from", "to", "subject", "reply-to", "date", "sender", "return-path"):
            values = tuple(str(value).strip() for value in message.get_all(name, []))
            if len(values) <= 1 or len(set(values)) <= 1:
                continue
            duplicates.append(
                DuplicateHeader(
                    name=name,
                    values=values[:4],
                    selected_value=values[0],
                    reason=(
                        f"{name!r} appears {len(values)} times with different values; "
                        "the parser selects the first value"
                    ),
                )
            )
        return tuple(duplicates)

    @staticmethod
    def _nested_senders(message: Message) -> Tuple[NestedSender, ...]:
        nested = []
        try:
            for part in message.walk():
                if part.get_content_type() != "message/rfc822":
                    continue
                for child in part.get_payload():
                    sender = str(child.get("From", "") or "").strip()
                    if sender:
                        nested.append(
                            NestedSender(
                                sender=sender[:VALUE_LIMIT],
                                subject=str(child.get("Subject", "") or "")[:VALUE_LIMIT],
                                reason="sender identity observed in a forwarded message",
                            )
                        )
        except Exception:
            pass
        return tuple(nested)

    @staticmethod
    def _received_observables(message: Message) -> "_ReceivedObservables":
        received = tuple(str(value) for value in message.get_all("Received", []))
        epoch = None
        iso = None
        gateway = None
        sender_ips = []

        if received:
            try:
                parsed = parsedate_to_datetime(received[0].rsplit(";", 1)[-1].strip())
                if parsed is not None:
                    epoch = int(parsed.timestamp())
                    iso = parsed.isoformat()
            except Exception:
                pass
            match = RECEIVING_GATEWAY_PATTERN.search(received[0])
            if match:
                gateway = match.group(1).lower()

        for hop, header in enumerate(received):
            for match in IP_PATTERN.finditer(header):
                address = match.group(1)
                if all(0 <= int(octet) <= 255 for octet in address.split(".")):
                    sender_ips.append(SenderIp(address=address, hop=hop, trusted=hop == 0))

        return _ReceivedObservables(
            count=len(received),
            epoch=epoch,
            iso=iso,
            gateway=gateway,
            sender_ips=tuple(sender_ips),
        )

    @staticmethod
    def _date_epoch(message: Message) -> Optional[int]:
        value = message.get("Date")
        if value is None:
            return None
        try:
            parsed = parsedate_to_datetime(str(value))
            return int(parsed.timestamp()) if parsed is not None else None
        except Exception:
            return None

    @staticmethod
    def _authentication_observables(message: Message) -> "_AuthenticationObservables":
        header_names = {name.lower() for name in message.keys()}
        text = " ".join(
            str(value)
            for name, value in message.items()
            if name.lower() in {"authentication-results", "received-spf"}
        ).lower()

        spf_result = None
        dmarc_result = None
        if text:
            spf_match = SPF_PATTERN.search(text)
            if spf_match:
                spf_result = SpfResult(spf_match.group(1))
            elif "received-spf" in header_names:
                match = RECEIVED_SPF_PATTERN.match(str(message.get("Received-SPF") or "").lower())
                if match:
                    spf_result = SpfResult(match.group(1))
            dmarc_match = DMARC_PATTERN.search(text)
            if dmarc_match:
                dmarc_result = DmarcResult(dmarc_match.group(1))

        return _AuthenticationObservables(
            has_authentication_results="authentication-results" in header_names,
            has_dkim_signature="dkim-signature" in header_names,
            has_received_spf="received-spf" in header_names,
            spf_result=spf_result,
            dmarc_result=dmarc_result,
        )

    @staticmethod
    def _sender_observables(message: Message) -> "_SenderObservables":
        raw_from = message.get("From")
        from_domain = _address_domain(raw_from)
        display_name = None
        display_name_brand = None

        if raw_from is not None:
            match = DISPLAY_NAME_PATTERN.match(str(raw_from))
            if match:
                display_name = match.group(1).strip() or None
                if display_name:
                    # Match against the Unicode-folded name so homoglyph or
                    # combining-mark obfuscation cannot hide the brand.
                    display_name_brand = find_brand(textnorm.normalize(display_name))

        raw_reply_to = message.get("Reply-To")
        reply_to_domain = _address_domain(raw_reply_to)
        # Compare registrable domains: bounce.example.com replying via
        # example.com is the same registrant, not divergence.
        reply_to_differs = (
            None
            if raw_reply_to is None
            else registered_domain(reply_to_domain) != registered_domain(from_domain)
        )
        return _SenderObservables(
            from_domain=from_domain,
            reply_to_domain=reply_to_domain,
            reply_to_differs=reply_to_differs,
            display_name=display_name,
            display_name_brand=display_name_brand,
        )

    @staticmethod
    def _content_observables(message: Message, raw: bytes) -> "_ContentObservables":
        attachments = []
        body_chunks = []
        urls: Set[str] = set()
        image_urls: Set[str] = set()
        has_html = False
        has_plain = False
        inline_image_count = 0
        qr_image_count = 0
        images_scanned = 0

        for part in EmailParser._leaf_parts(message):
            content_type = (part.get_content_type() or "").lower()
            try:
                file_name = part.get_filename()
            except Exception:
                file_name = None
            disposition = (part.get_content_disposition() or "").lower()
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None

            if content_type == "text/html":
                has_html = True
            elif content_type == "text/plain" and disposition != "attachment":
                has_plain = True

            is_attachment = bool(file_name) or disposition == "attachment"
            if is_attachment and not (
                disposition == "inline" and content_type in INLINE_IMAGE_TYPES
            ):
                attachments.append(
                    AttachmentObservable(
                        name=file_name or "",
                        content_type=content_type,
                        attachment_class=_attachment_class(file_name or "", content_type),
                        sha256=hashlib.sha256(payload).hexdigest() if payload else None,
                        size=len(payload) if payload else 0,
                    )
                )
            elif content_type in INLINE_IMAGE_TYPES:
                inline_image_count += 1

            # Recover URLs hidden in QR codes, from both inline images and image
            # attachments. Decoding is bounded, offline, and never raises.
            if (
                payload
                and content_type.startswith("image/")
                and images_scanned < QR_IMAGE_LIMIT
            ):
                images_scanned += 1
                decoded = qr.decode_qr_urls(payload)
                if decoded:
                    qr_image_count += 1
                    image_urls.update(item[:URL_LIMIT] for item in decoded)

            if payload and content_type.startswith("text/") and not is_attachment:
                text = payload.decode("utf-8", "replace")
                if content_type == "text/html":
                    text = re.sub(r"<[^>]+>", " ", text)
                body_chunks.append(text)
                urls.update(
                    item.decode("utf-8", "replace")[:URL_LIMIT]
                    for item in URL_PATTERN.findall(payload)
                )

        if not urls:
            urls.update(
                item.decode("utf-8", "replace")[:URL_LIMIT]
                for item in URL_PATTERN.findall(raw)
            )

        # Merge QR-decoded URLs so the existing URL detectors evaluate them too.
        urls.update(image_urls)

        ordered_urls = tuple(sorted(urls))
        hosts = set()
        for url in ordered_urls:
            match = HOST_PATTERN.match(url)
            if match:
                hosts.add(match.group(1).lower())

        return _ContentObservables(
            body_text=" ".join(body_chunks)[:BODY_LIMIT],
            has_html=has_html,
            has_plain=has_plain,
            urls=ordered_urls,
            url_hosts=tuple(sorted(hosts)),
            image_urls=tuple(sorted(image_urls)),
            qr_image_count=qr_image_count,
            attachments=tuple(attachments),
            inline_image_count=inline_image_count,
        )


def _address_domain(value: object) -> Optional[str]:
    if not value:
        return None
    match = ADDRESS_DOMAIN_PATTERN.search(str(value))
    return match.group(1).lower() if match else None


def _attachment_class(name: str, content_type: str) -> AttachmentClass:
    extension = name.rsplit(".", 1)[-1].strip().lower()[:8] if "." in name else ""
    if extension in ATTACHMENT_CLASSES:
        return ATTACHMENT_CLASSES[extension]
    if content_type.startswith("image/"):
        return AttachmentClass.IMAGE
    if content_type == "application/pdf":
        return AttachmentClass.PDF
    return AttachmentClass.OTHER


@dataclass(frozen=True)
class _AuthenticationObservables:
    """Authentication values assembled before the public model is created."""

    has_authentication_results: bool
    has_dkim_signature: bool
    has_received_spf: bool
    spf_result: Optional[SpfResult]
    dmarc_result: Optional[DmarcResult]


@dataclass(frozen=True)
class _SenderObservables:
    """Sender values assembled before the public model is created."""

    from_domain: Optional[str]
    reply_to_domain: Optional[str]
    reply_to_differs: Optional[bool]
    display_name: Optional[str]
    display_name_brand: Optional[str]


@dataclass(frozen=True)
class _ReceivedObservables:
    """Received-chain values assembled before the public model is created."""

    count: int
    epoch: Optional[int]
    iso: Optional[str]
    gateway: Optional[str]
    sender_ips: Tuple[SenderIp, ...]


@dataclass(frozen=True)
class _ContentObservables:
    """Body and attachment values assembled before the public model is created."""

    body_text: str
    has_html: bool
    has_plain: bool
    urls: Tuple[str, ...]
    url_hosts: Tuple[str, ...]
    image_urls: Tuple[str, ...]
    qr_image_count: int
    attachments: Tuple[AttachmentObservable, ...]
    inline_image_count: int
