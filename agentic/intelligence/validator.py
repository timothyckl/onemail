"""Validate report grounding and framework mappings."""

import json
import ipaddress
import re
from pathlib import Path
from typing import Dict, Iterable, Mapping as ValueMap, Tuple

from agentic.analysis import Analysis, Evidence

from .models import Phase, Report


class Validator:
    """Reject unsupported citations, indicators, and framework mappings."""

    def __init__(self, catalog: Path = Path(__file__).parent / "catalog" / "attack.json") -> None:
        data = json.loads(catalog.read_text(encoding="utf-8"))
        self.version = str(data["version"])
        self._attack: Dict[str, Dict[str, object]] = dict(data["techniques"])

    def attack_name(self, identifier: str) -> str:
        item = self._attack.get(identifier)
        return str(item["name"]) if item is not None else "Unknown technique"

    def validate(self, report: Report, analysis: Analysis) -> Tuple[str, ...]:
        evidence = {item.id: item for item in analysis.evidence}
        identifiers = set(evidence)
        issues = []

        for scope, references in self._references(report):
            unknown = set(references) - identifiers
            if unknown:
                issues.append(f"{scope} cites unknown evidence: {', '.join(sorted(unknown))}")
            if not references:
                issues.append(f"{scope} requires evidence")

        for indicator in report.indicators:
            if not self._indicator(indicator.type, indicator.value, indicator.evidence, evidence):
                issues.append(f"indicator is absent from cited evidence: {indicator.value}")

        for name in ("adversary", "infrastructure", "capability", "victim"):
            for facet in getattr(report.diamond, name):
                if not self._supported(facet.value, facet.evidence, evidence):
                    issues.append(
                        f"Diamond {name} value is absent from cited evidence: {facet.value}"
                    )

        if report.attack.version != self.version:
            issues.append("ATT&CK version does not match the local catalog")
        for mapping in report.attack.mappings:
            technique = self._attack.get(mapping.id)
            if technique is None:
                issues.append(f"unknown ATT&CK technique: {mapping.id}")
                continue
            if technique["name"] != mapping.name:
                issues.append(f"ATT&CK name does not match {mapping.id}")
            cited = [evidence[item] for item in mapping.evidence if item in evidence]
            predicate_values = technique.get("predicates", [])
            predicates = (
                predicate_values if isinstance(predicate_values, list) else []
            )
            if not any(
                self._predicate(str(predicate), item)
                for predicate in predicates
                for item in cited
            ):
                issues.append(f"ATT&CK technique lacks supporting evidence: {mapping.id}")

        phases = {phase.value for phase in Phase}
        chain_support = {
            Phase.WEAPONIZATION.value: {
                "yara_powershell",
                "yara_office_autoopen",
                "positive_antivirus_attachment",
                "dangerous_attachment",
                "obfuscated_attachment",
            },
            Phase.DELIVERY.value: {"detection"},
        }
        for mapping in report.chain.mappings:
            if mapping.id not in phases:
                issues.append(f"unknown Kill Chain phase: {mapping.id}")
            elif mapping.name != mapping.id:
                issues.append(f"Kill Chain name does not match {mapping.id}")
            cited = [evidence[item] for item in mapping.evidence if item in evidence]
            predicates = chain_support.get(mapping.id, set())
            if not any(
                self._predicate(predicate, item)
                for predicate in predicates
                for item in cited
            ):
                issues.append(f"Kill Chain phase lacks supporting evidence: {mapping.id}")

        decision_text = " ".join(
            [report.summary]
            + [item.text for item in report.claims]
        ).lower()
        directives = (
            "should block",
            "should quarantine",
            "should delete",
            "should allow",
            "should dismiss",
            "should escalate",
            "must block",
            "must quarantine",
            "recommend blocking",
            "recommend quarantining",
            "verdict: malicious",
            "verdict: benign",
        )
        if any(item in decision_text for item in directives):
            issues.append("report contains an action directive or verdict")

        citation_ids = {item.id for item in report.citations}
        if citation_ids != identifiers:
            issues.append("report citation appendix does not match analysis evidence")
        return tuple(issues)

    @staticmethod
    def _supported(
        value: str,
        references: Tuple[str, ...],
        evidence: ValueMap[str, Evidence],
    ) -> bool:
        expected = value.strip().lower()
        return any(
            reference in evidence
            and expected in {item.strip().lower() for item in _atoms(evidence[reference].value)}
            for reference in references
        )

    @classmethod
    def _indicator(
        cls,
        kind: str,
        value: str,
        references: Tuple[str, ...],
        evidence: ValueMap[str, Evidence],
    ) -> bool:
        normalized_kind = kind.strip().lower()
        normalized_value = value.strip()
        if normalized_kind == "ipv4":
            try:
                if ipaddress.ip_address(normalized_value).version != 4:
                    return False
            except ValueError:
                return False
        elif normalized_kind == "sha256":
            if re.fullmatch(r"[0-9a-fA-F]{64}", normalized_value) is None:
                return False
        elif normalized_kind == "domain":
            if re.fullmatch(r"[A-Za-z0-9.-]+", normalized_value) is None:
                return False
        elif normalized_kind == "url":
            if not normalized_value.lower().startswith(("http://", "https://")):
                return False
        elif normalized_kind == "email":
            if "@" not in normalized_value:
                return False
        elif normalized_kind != "filename":
            return False
        return cls._supported(normalized_value, references, evidence)

    @staticmethod
    def _predicate(predicate: str, evidence: Evidence) -> bool:
        value = evidence.value
        if predicate == "detection":
            return evidence.origin == "detection"
        if predicate == "url":
            return evidence.kind in {
                "credential_url",
                "raw_ip_url",
                "lookalike_domain",
                "high_abuse_tld",
            }
        if predicate == "attachment":
            return evidence.kind in {
                "dangerous_attachment",
                "attachment_extension_spoof",
            }
        if predicate == "dangerous_attachment":
            return evidence.kind == "dangerous_attachment"
        if predicate == "positive_antivirus_attachment":
            return (
                evidence.kind == "antivirus"
                and evidence.artifact not in {None, "email"}
                and isinstance(value, dict)
                and "FOUND" in str(value.get("result", ""))
            )
        if predicate == "embedded_attachment":
            return (
                evidence.kind == "embedded"
                and evidence.artifact not in {None, "email"}
                and bool(value)
            )
        if predicate == "obfuscated_attachment":
            return (
                evidence.kind == "profile"
                and evidence.artifact not in {None, "email"}
                and isinstance(value, dict)
                and float(value.get("entropy", 0.0)) >= 7.2
            )
        if predicate in {
            "script",
            "encoded_script",
            "powershell",
            "visual_basic",
            "javascript",
        }:
            if (
                evidence.kind != "script"
                or evidence.artifact in {None, "email"}
                or not isinstance(value, dict)
            ):
                return False
            tokens = {str(item).lower() for item in value.get("tokens", [])}
            if predicate == "script":
                return bool(tokens)
            if predicate == "encoded_script":
                return bool(tokens & {"frombase64string", "invoke-expression"})
            expected = {
                "powershell": {"powershell", "invoke-expression", "frombase64string"},
                "visual_basic": {"wscript.shell"},
                "javascript": {"wscript.shell"},
            }[predicate]
            return bool(tokens & expected)
        if predicate in {"yara_powershell", "yara_office_autoopen"}:
            if (
                evidence.kind != "yara"
                or evidence.artifact in {None, "email"}
                or not isinstance(value, dict)
            ):
                return False
            rules = {
                str(item.get("rule", ""))
                for item in value.get("matches", [])
                if isinstance(item, dict)
            }
            expected = {
                "yara_powershell": "Suspicious_PowerShell_Encoded_Command",
                "yara_office_autoopen": "Suspicious_Office_AutoOpen",
            }[predicate]
            return expected in rules
        return False

    @staticmethod
    def _references(report: Report) -> Iterable[Tuple[str, Tuple[str, ...]]]:
        for index, claim in enumerate(report.claims):
            yield f"claim[{index}]", claim.evidence
        for index, indicator in enumerate(report.indicators):
            yield f"indicator[{index}]", indicator.evidence
        for name in ("adversary", "infrastructure", "capability", "victim"):
            for index, facet in enumerate(getattr(report.diamond, name)):
                yield f"diamond.{name}[{index}]", facet.evidence
        for index, mapping in enumerate(report.attack.mappings):
            yield f"attack[{index}]", mapping.evidence
        for index, mapping in enumerate(report.chain.mappings):
            yield f"chain[{index}]", mapping.evidence


def _text(value: object) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, default=str)


def _atoms(value: object) -> Tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, dict):
        return tuple(item for child in value.values() for item in _atoms(child))
    if isinstance(value, (list, tuple)):
        return tuple(item for child in value for item in _atoms(child))
    if value is None:
        return ()
    return (str(value),)
