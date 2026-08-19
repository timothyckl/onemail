"""Canonical intelligence report models."""

from enum import Enum
from typing import Annotated, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


Reference = Annotated[str, StringConstraints(max_length=80)]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Phase(str, Enum):
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    COMMAND_AND_CONTROL = "Command and Control"
    ACTIONS_ON_OBJECTIVES = "Actions on Objectives"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Claim(Model):
    text: str = Field(max_length=1000)
    confidence: Confidence
    evidence: Tuple[Reference, ...] = Field(max_length=16)


class Indicator(Model):
    type: str = Field(max_length=80)
    value: str = Field(max_length=1000)
    evidence: Tuple[Reference, ...] = Field(max_length=16)


class Facet(Model):
    value: str = Field(max_length=1000)
    confidence: Confidence
    evidence: Tuple[Reference, ...] = Field(max_length=16)


class Diamond(Model):
    adversary: Tuple[Facet, ...] = Field(default=(), max_length=16)
    infrastructure: Tuple[Facet, ...] = Field(default=(), max_length=16)
    capability: Tuple[Facet, ...] = Field(default=(), max_length=16)
    victim: Tuple[Facet, ...] = Field(default=(), max_length=16)


class Mapping(Model):
    id: str = Field(max_length=40)
    name: str = Field(max_length=200)
    rationale: str = Field(max_length=2000)
    confidence: Confidence
    evidence: Tuple[Reference, ...] = Field(max_length=16)


class Attack(Model):
    version: str
    mappings: Tuple[Mapping, ...] = Field(default=(), max_length=32)


class Chain(Model):
    mappings: Tuple[Mapping, ...] = Field(default=(), max_length=7)


class Citation(Model):
    id: str
    origin: str
    kind: str
    value: str


class Item(Model):
    id: str
    name: str
    sha256: str
    detected: str
    parent: Optional[str] = None
    similarity_hash: Optional[str] = None


class Signal(Model):
    detector: str
    severity: str
    heuristic: bool
    clause: str


class Report(Model):
    file: str
    model: str
    summary: str = Field(max_length=4000)
    detection: Tuple[Signal, ...]
    artifacts: Tuple[Item, ...]
    claims: Tuple[Claim, ...]
    indicators: Tuple[Indicator, ...]
    diamond: Diamond
    attack: Attack
    chain: Chain
    gaps: Tuple[str, ...]
    citations: Tuple[Citation, ...]
