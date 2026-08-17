"""Allowlisted static-analysis tasks available to the analysis agent."""

from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    formats: Tuple[str, ...] = ()
    options: Tuple[str, ...] = ()


TOOLS: Dict[str, Tool] = {
    "archive": Tool(
        name="archive",
        description="List bounded archive contents without extracting or executing them.",
        formats=("archive", "zip", "7-zip", "rar", "tar"),
    ),
    "office": Tool(
        name="office",
        description="Inspect Office metadata and macros with oletools.",
        formats=("office", "ole", "microsoft", "word", "excel", "powerpoint"),
    ),
    "pdf": Tool(
        name="pdf",
        description="Inspect PDF structure and JavaScript indicators.",
        formats=("pdf",),
    ),
    "pe": Tool(
        name="pe",
        description="Inspect Portable Executable headers, sections, and imports.",
        formats=("pe32", "portable executable", "dos executable", "x-dosexec", "x-msdownload"),
    ),
    "script": Tool(
        name="script",
        description="Inspect script encoding and suspicious command-language tokens.",
        formats=("script", "text", "javascript", "powershell", "batch"),
    ),
    "embedded": Tool(
        name="embedded",
        description="Locate embedded file signatures at non-zero byte offsets.",
    ),
    "metadata": Tool(
        name="metadata",
        description="Extract bounded metadata with ExifTool.",
    ),
}

BASELINE_TASKS: Tuple[str, ...] = (
    "extract",
    "profile",
    "identify",
    "strings",
    "yara",
    "antivirus",
)
