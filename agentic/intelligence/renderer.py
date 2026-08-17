"""Deterministically render a validated intelligence report as Markdown."""

import html

from .models import Report


class Renderer:
    def render(self, report: Report) -> str:
        lines = [
            f"# Intelligence Report: {_safe(report.file)}",
            "",
            "## Summary",
            "",
            _safe(report.summary),
            "",
            "## Detection Context",
            "",
        ]
        lines.extend(
            _items(
                tuple(_safe(item) for item in report.detection),
                "No deterministic findings recorded.",
            )
        )
        lines.extend(["", "## Artifacts", ""])
        lines.extend(
            f"- {_code(item.name)} ({_code(item.sha256)}): {_safe(item.detected)}"
            for item in report.artifacts
        )
        lines.extend(["", "## Claims", ""])
        lines.extend(
            f"- {_safe(item.text)} ({item.confidence.value}; evidence: "
            f"{', '.join(_safe(value) for value in item.evidence)})"
            for item in report.claims
        )
        lines.extend(["", "## Indicators", ""])
        lines.extend(
            f"- {_safe(item.type)}: {_code(item.value)} (evidence: "
            f"{', '.join(_safe(value) for value in item.evidence)})"
            for item in report.indicators
        )
        lines.extend(["", "## Diamond Model", ""])
        for name in ("adversary", "infrastructure", "capability", "victim"):
            lines.append(f"### {name.title()}")
            lines.append("")
            lines.extend(
                _items(
                    tuple(
                        f"{_safe(item.value)} ({item.confidence.value}; evidence: "
                        f"{', '.join(_safe(value) for value in item.evidence)})"
                        for item in getattr(report.diamond, name)
                    ),
                    "Unknown from available evidence.",
                )
            )
            lines.append("")
        lines.extend(["## MITRE ATT&CK", ""])
        lines.extend(
            _items(
                tuple(
                    f"{_safe(item.id)} {_safe(item.name)}: {_safe(item.rationale)} "
                    f"({item.confidence.value}; evidence: "
                    f"{', '.join(_safe(value) for value in item.evidence)})"
                    for item in report.attack.mappings
                ),
                "No supported mappings.",
            )
        )
        lines.extend(["", "## Cyber Kill Chain", ""])
        lines.extend(
            _items(
                tuple(
                    f"{_safe(item.id)}: {_safe(item.rationale)} "
                    f"({item.confidence.value}; evidence: "
                    f"{', '.join(_safe(value) for value in item.evidence)})"
                    for item in report.chain.mappings
                ),
                "No supported mappings.",
            )
        )
        lines.extend(["", "## Gaps", ""])
        lines.extend(
            _items(
                tuple(_safe(item) for item in report.gaps),
                "No additional gaps recorded.",
            )
        )
        lines.extend(["", "## Evidence", ""])
        lines.extend(
            f"- {_code(item.id)} [{_safe(item.origin)}/{_safe(item.kind)}]: "
            f"{_safe(item.value)}"
            for item in report.citations
        )
        return "\n".join(lines).rstrip() + "\n"


def _items(values: tuple[str, ...], empty: str) -> list[str]:
    return [f"- {item}" for item in values] if values else [f"- {empty}"]


def _safe(value: str) -> str:
    escaped = html.escape(value, quote=False).replace("\n", " ").replace("\r", " ")
    for character in ("\\", "`", "*", "_", "[", "]", "(", ")", "#"):
        escaped = escaped.replace(character, "\\" + character)
    return escaped


def _code(value: str) -> str:
    escaped = html.escape(value, quote=False).replace("\n", " ").replace("\r", " ")
    return f"<code>{escaped}</code>"
