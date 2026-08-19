"""Facts extracted from email bytes before detection rules run."""

from dataclasses import dataclass
from typing import Optional, Tuple

from .enums import AttachmentClass, DmarcResult, SpfResult


@dataclass(frozen=True)
class AttachmentObservable:
    """Metadata derived from one decoded email attachment."""

    name: str
    content_type: str
    attachment_class: AttachmentClass
    sha256: Optional[str]
    size: int

    def __post_init__(self) -> None:
        if self.size < 0:
            raise ValueError("attachment size cannot be negative")


@dataclass(frozen=True)
class DuplicateHeader:
    """A header with conflicting values and the value selected by the parser."""

    name: str
    values: Tuple[str, ...]
    selected_value: str
    reason: str


@dataclass(frozen=True)
class NestedSender:
    """Sender identity observed in an attached or forwarded message."""

    sender: str
    subject: str
    reason: str


@dataclass(frozen=True)
class SenderIp:
    """An IP address extracted from a Received hop."""

    address: str
    hop: int
    trusted: bool

    def __post_init__(self) -> None:
        if self.hop < 0:
            raise ValueError("sender IP hop cannot be negative")


@dataclass(frozen=True)
class MessageObservables:
    """Facts extracted from one email without making a detection judgment.

    ``None`` means a value could not be observed. In particular,
    ``reply_to_differs=None`` means there was no Reply-To header, while ``False``
    means the header was present and matched the From domain.
    """

    path: Optional[str] = None
    byte_count: int = 0
    parse_error: Optional[str] = None

    subject: Optional[str] = None
    body_text: str = ""

    # Unicode-folded text (see ``detection.textnorm.normalize``): HTML entities
    # unescaped, homoglyphs / combining marks / math letters folded to plain
    # lower-case Latin. Phrase and brand rules match against these fields so
    # obfuscated text matches what a human reads. ``None`` mirrors ``subject``.
    normalized_subject: Optional[str] = None
    normalized_body_text: str = ""

    # Obfuscation counts observed in the transmitted text. Mixed-script
    # homoglyphs and combining-mark tricks are themselves detection signals.
    subject_confusable_count: int = 0
    body_combining_mark_count: int = 0

    has_html: bool = False
    has_plain: bool = False
    mime_depth: int = 0

    # True when the message carries mailing-list infrastructure headers
    # (List-Id, List-Post, Mailing-List, or Precedence: list/bulk). Lists
    # legitimately rewrite Reply-To, so divergence rules must not judge them.
    is_mailing_list: bool = False

    from_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    reply_to_differs: Optional[bool] = None
    display_name: Optional[str] = None
    display_name_brand: Optional[str] = None

    has_authentication_results: bool = False
    has_dkim_signature: bool = False
    has_received_spf: bool = False
    spf_result: Optional[SpfResult] = None
    dmarc_result: Optional[DmarcResult] = None

    urls: Tuple[str, ...] = ()
    url_hosts: Tuple[str, ...] = ()

    # URLs recovered by decoding QR codes inside inline or attached images. These
    # are also merged into ``urls``/``url_hosts`` so the existing URL detectors
    # evaluate them; ``image_urls`` records the image-derived subset so a finding
    # can cite that a link was hidden in an image rather than written in text.
    image_urls: Tuple[str, ...] = ()
    qr_image_count: int = 0

    attachments: Tuple[AttachmentObservable, ...] = ()
    inline_image_count: int = 0

    duplicate_headers: Tuple[DuplicateHeader, ...] = ()
    nested_senders: Tuple[NestedSender, ...] = ()

    raw_date: Optional[str] = None
    date_epoch: Optional[int] = None
    received_count: int = 0
    received_epoch: Optional[int] = None
    received_iso: Optional[str] = None
    receiving_gateway: Optional[str] = None
    sender_ips: Tuple[SenderIp, ...] = ()

    def __post_init__(self) -> None:
        counts = (
            self.byte_count,
            self.subject_confusable_count,
            self.body_combining_mark_count,
            self.mime_depth,
            self.inline_image_count,
            self.qr_image_count,
            self.received_count,
        )
        if any(value < 0 for value in counts):
            raise ValueError("observable counts cannot be negative")

    @property
    def url_count(self) -> int:
        """Return the number of extracted URLs."""

        return len(self.urls)

    @property
    def attachment_count(self) -> int:
        """Return the number of decoded attachments."""

        return len(self.attachments)

    @property
    def attachment_classes(self) -> Tuple[AttachmentClass, ...]:
        """Return the distinct attachment classes in stable order."""

        classes = {attachment.attachment_class for attachment in self.attachments}
        return tuple(sorted(classes, key=lambda item: item.value))

    @property
    def sender_ip(self) -> Optional[str]:
        """Return the first IP recorded by a trusted Received hop, if any."""

        return next((item.address for item in self.sender_ips if item.trusted), None)
