"""Allowlisted, typed investigation tasks available to the analysis agent."""

from dataclasses import dataclass
from typing import Dict, Literal, Tuple


OptionKind = Literal["integer", "choice", "boolean"]
ToolCategory = Literal[
    "static", "rendering", "emulation", "correlation", "enrichment"
]


@dataclass(frozen=True)
class Option:
    """One bounded option accepted by a typed task."""

    name: str
    description: str
    kind: OptionKind
    minimum: int | None = None
    maximum: int | None = None
    choices: Tuple[str, ...] = ()

    def accepts(self, value: object) -> bool:
        text = str(value).strip().lower()
        if self.kind == "boolean":
            return text in {"true", "false"}
        if self.kind == "choice":
            return text in self.choices
        try:
            number = int(text)
        except ValueError:
            return False
        return (self.minimum is None or number >= self.minimum) and (
            self.maximum is None or number <= self.maximum
        )

    def prompt(self) -> dict[str, object]:
        value: dict[str, object] = {
            "name": self.name,
            "description": self.description,
            "type": self.kind,
        }
        if self.minimum is not None:
            value["minimum"] = self.minimum
        if self.maximum is not None:
            value["maximum"] = self.maximum
        if self.choices:
            value["choices"] = self.choices
        return value


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    category: ToolCategory = "static"
    formats: Tuple[str, ...] = ()
    options: Tuple[Option, ...] = ()


TOOLS: Dict[str, Tool] = {
    "archive": Tool(
        name="archive",
        description=(
            "Recursively extract bounded archive members and register them as child "
            "artifacts without executing them."
        ),
        formats=("archive", "zip", "7-zip", "rar", "tar"),
    ),
    "office": Tool(
        name="office",
        description=(
            "Inspect Office metadata, macros, relationships, and external references."
        ),
        formats=("office", "ole", "microsoft", "word", "excel", "powerpoint"),
    ),
    "pdf": Tool(
        name="pdf",
        description=(
            "Inspect PDF pages, actions, JavaScript, links, encryption, and embedded files."
        ),
        formats=("pdf",),
    ),
    "pe": Tool(
        name="pe",
        description=(
            "Inspect Portable Executable headers, sections, imports, exports, resources, "
            "signing data, and packer indicators."
        ),
        formats=("pe32", "portable executable", "dos executable", "x-dosexec", "x-msdownload"),
    ),
    "script": Tool(
        name="script",
        description=(
            "Parse scripts, identify encodings, and perform bounded deobfuscation."
        ),
        formats=("script", "text", "javascript", "powershell", "batch", "html"),
    ),
    "decode": Tool(
        name="decode",
        description=(
            "Recover bounded base64 and hexadecimal payloads as child artifacts."
        ),
    ),
    "embedded": Tool(
        name="embedded",
        description=(
            "Carve bounded embedded file signatures into addressable child artifacts."
        ),
    ),
    "ioc": Tool(
        name="ioc",
        description="Extract bounded URLs, domains, IP addresses, and email addresses.",
    ),
    "metadata": Tool(
        name="metadata",
        description="Extract bounded metadata with ExifTool.",
    ),
    "render": Tool(
        name="render",
        description=(
            "Render HTML, PDF, or Office content offline and return visual-text evidence."
        ),
        category="rendering",
        formats=("html", "pdf", "office", "ole", "microsoft", "word", "excel", "powerpoint"),
        options=(
            Option(
                name="pages",
                description="Maximum number of pages to inspect.",
                kind="integer",
                minimum=1,
                maximum=5,
            ),
        ),
    ),
    "emulate_pe": Tool(
        name="emulate_pe",
        description=(
            "Emulate a PE with an intercepted Windows API model; never execute it natively."
        ),
        category="emulation",
        formats=("pe32", "portable executable", "dos executable", "x-dosexec", "x-msdownload"),
        options=(
            Option(
                name="seconds",
                description="Emulation wall-clock timeout.",
                kind="integer",
                minimum=1,
                maximum=30,
            ),
        ),
    ),
    "emulate_script": Tool(
        name="emulate_script",
        description=(
            "Symbolically emulate common script decoding and command construction without "
            "starting a language runtime or shell."
        ),
        category="emulation",
        formats=("script", "text", "javascript", "powershell", "batch", "html"),
    ),
    "virustotal_hash": Tool(
        name="virustotal_hash",
        description=(
            "Query VirusTotal for an existing report using this artifact's SHA-256. "
            "No file bytes are uploaded, but the hash is disclosed to VirusTotal."
        ),
        category="enrichment",
    ),
}

BASELINE_TASKS: Tuple[str, ...] = (
    "extract",
    "profile",
    "identify",
    "strings",
    "yara",
)
