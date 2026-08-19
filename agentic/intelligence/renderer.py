"""Deterministically render a validated intelligence report as readable Markdown."""

import html
import json

from .models import Report


class Renderer:
    def render(self, report: Report) -> str:
        lines = [
            "# OneMail Investigation Report",
            "",
            "> **Scope:** Evidence-grounded isolated investigation. This report does not "
            "assign a malicious/benign verdict or prescribe an action.",
            "",
            "| Report detail | Value |",
            "| --- | --- |",
            f"| Email | {_code(report.file)} |",
            f"| Model | {_code(report.model)} |",
            "| Analysis | Deterministic detection + sandboxed inspection, rendering, and emulation |",
            "",
            "## Investigation Overview",
            "",
            _safe(report.summary),
            "",
            "### At a glance",
            "",
            "| Category | Count |",
            "| --- | ---: |",
            f"| Detection signals | {len(report.detection)} |",
            f"| Analysed files | {len(report.artifacts)} |",
            f"| Grounded observations | {len(report.claims)} |",
            f"| Indicators | {len(report.indicators)} |",
            f"| Evidence records | {len(report.citations)} |",
            f"| Gaps and limitations | {len(report.gaps)} |",
            "",
            "## Key Findings",
            "",
            "### Detection signals",
            "",
        ]
        lines.extend(
            _table(
                ("Severity", "Detector", "Basis", "Finding"),
                tuple(
                    (
                        item.severity.upper(),
                        _code(item.detector),
                        "Heuristic" if item.heuristic else "Deterministic",
                        _safe(item.clause),
                    )
                    for item in report.detection
                ),
                "No deterministic detection signals were recorded.",
            )
        )

        lines.extend(["", "### Grounded analysis observations", ""])
        lines.extend(
            _table(
                ("#", "Confidence", "Observation", "Evidence"),
                tuple(
                    (
                        str(index),
                        item.confidence.value.title(),
                        _safe(item.text),
                        _references(item.evidence),
                    )
                    for index, item in enumerate(report.claims, start=1)
                ),
                "No additional grounded observations were selected.",
            )
        )

        lines.extend(["", "## Analysed Files", ""])
        lines.extend(
            _table(
                ("ID", "File", "Parent", "Detected type", "Similarity", "SHA-256"),
                tuple(
                    (
                        _code(item.id),
                        _code(item.name),
                        _code(item.parent) if item.parent else "—",
                        _safe(item.detected),
                        _code(item.similarity_hash) if item.similarity_hash else "—",
                        _code(item.sha256),
                    )
                    for item in report.artifacts
                ),
                "No files were returned by the analysis sandbox.",
            )
        )

        lines.extend(["", "## Indicators", ""])
        lines.extend(
            _table(
                ("Type", "Value", "Evidence"),
                tuple(
                    (
                        _safe(item.type.title()),
                        _code(item.value),
                        _references(item.evidence),
                    )
                    for item in report.indicators
                ),
                "No independently grounded indicators were retained.",
            )
        )

        lines.extend(["", "## Technical Assessment", "", "### Diamond Model", ""])
        diamond_rows = []
        for category in ("adversary", "infrastructure", "capability", "victim"):
            facets = getattr(report.diamond, category)
            if facets:
                diamond_rows.extend(
                    (
                        category.title(),
                        _safe(item.value),
                        item.confidence.value.title(),
                        _references(item.evidence),
                    )
                    for item in facets
                )
            else:
                diamond_rows.append(
                    (category.title(), "Unknown from available evidence", "—", "—")
                )
        lines.extend(
            _table(
                ("Facet", "Assessment", "Confidence", "Evidence"),
                tuple(diamond_rows),
                "No Diamond Model facets were supported.",
            )
        )

        lines.extend(["", "### MITRE ATT&CK", ""])
        lines.extend(
            _table(
                ("Technique", "Confidence", "Evidence-based rationale", "Evidence"),
                tuple(
                    (
                        f"{_code(item.id)} {_safe(item.name)}",
                        item.confidence.value.title(),
                        _safe(item.rationale),
                        _references(item.evidence),
                    )
                    for item in report.attack.mappings
                ),
                "No ATT&CK mappings were supported by the available evidence.",
            )
        )

        lines.extend(["", "### Cyber Kill Chain", ""])
        lines.extend(
            _table(
                ("Phase", "Confidence", "Evidence-based rationale", "Evidence"),
                tuple(
                    (
                        _safe(item.id),
                        item.confidence.value.title(),
                        _safe(item.rationale),
                        _references(item.evidence),
                    )
                    for item in report.chain.mappings
                ),
                "No Cyber Kill Chain mappings were supported by the available evidence.",
            )
        )

        lines.extend(["", "## Limitations and Gaps", ""])
        lines.extend(
            [f"- {_safe(item)}" for item in report.gaps]
            if report.gaps
            else ["- No additional gaps were recorded."]
        )

        lines.extend(["", "## Technical Evidence Appendix", ""])
        if report.citations:
            lines.extend(
                [
                    "<details>",
                    f"<summary>Show {len(report.citations)} evidence records</summary>",
                    "",
                ]
            )
            for citation in report.citations:
                lines.extend(
                    [
                        f"<h4><code>{_html(citation.id)}</code> — "
                        f"{_html(citation.kind)}</h4>",
                        f"<p><strong>Source:</strong> {_html(citation.origin)}</p>",
                        f"<pre><code>{_html(_pretty(citation.value))}</code></pre>",
                    ]
                )
            lines.extend(["", "</details>"])
        else:
            lines.append("No technical evidence records were retained.")

        return "\n".join(lines).rstrip() + "\n"


def _table(
    headers: tuple[str, ...],
    rows: tuple[tuple[str, ...], ...],
    empty: str,
) -> list[str]:
    if not rows:
        return [empty]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend(
        "| " + " | ".join(_cell(value) for value in row) + " |" for row in rows
    )
    return lines


def _references(values: tuple[str, ...]) -> str:
    return ", ".join(_code(value) for value in values) if values else "—"


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _safe(value: str) -> str:
    escaped = _html(value).replace("\n", " ").replace("\r", " ")
    for character in ("\\", "`", "*", "_", "[", "]", "(", ")", "#"):
        escaped = escaped.replace(character, "\\" + character)
    return escaped


def _code(value: str) -> str:
    return f"<code>{_html(value).replace(chr(10), ' ').replace(chr(13), ' ')}</code>"


def _html(value: str) -> str:
    return html.escape(value, quote=False)


def _pretty(value: str) -> str:
    try:
        return json.dumps(json.loads(value), indent=2, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        return value
