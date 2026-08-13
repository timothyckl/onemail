"""Detector-specific evidence payloads."""

from dataclasses import dataclass
from typing import Optional, Tuple, Union

from .enums import DmarcResult, SpfResult


@dataclass(frozen=True)
class AuthFailureEvidence:
    """Authentication facts supporting an authentication-failure finding."""

    spf_result: Optional[SpfResult]
    dmarc_result: Optional[DmarcResult]
    from_domain: Optional[str]


@dataclass(frozen=True)
class ReplyToDivergenceEvidence:
    """Domains supporting a Reply-To divergence finding."""

    from_domain: Optional[str]
    reply_to_domain: Optional[str]


@dataclass(frozen=True)
class CredentialUrlEvidence:
    """Mismatched URL hosts and credential language supporting a finding."""

    from_registered_domain: Optional[str]
    mismatched_hosts: Tuple[str, ...]
    matched_language: Tuple[str, ...]


@dataclass(frozen=True)
class DisplayNameSpoofEvidence:
    """Display-name brand claim and the actual sender domain."""

    display_name: Optional[str]
    brand: str
    from_domain: str


@dataclass(frozen=True)
class BecNoPayloadEvidence:
    """Reply-To and language facts supporting a payload-free BEC finding."""

    reply_to_differs: bool
    matched_language: Tuple[str, ...]
    from_domain: Optional[str]


DetectorEvidence = Union[
    AuthFailureEvidence,
    ReplyToDivergenceEvidence,
    CredentialUrlEvidence,
    DisplayNameSpoofEvidence,
    BecNoPayloadEvidence,
]
