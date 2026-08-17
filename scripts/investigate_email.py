"""Investigate one flagged EML file with Docker and DeepSeek."""

import argparse
import os
from pathlib import Path
from typing import Optional, Sequence

from langchain_deepseek import ChatDeepSeek

from agentic import Case
from agentic.analysis import Analyzer, DockerSandbox, LangChainAgent
from agentic.intelligence import Renderer, Reporter
from detection import DetectionEngine, Email


def investigate(path: Path, output: Path, model_name: str) -> bool:
    """Investigate a flagged email and write validated intelligence reports."""

    email = Email(file=path.as_posix(), content=path.read_bytes())
    detection = DetectionEngine().detect(email)
    if not detection.flagged:
        print("Email was not flagged; agentic investigation was not started.")
        return False

    print(f"Detection flagged the email with {len(detection.findings)} finding(s).")
    model = ChatDeepSeek(
        model=model_name,
        temperature=0,
        timeout=60,
        max_retries=2,
        max_tokens=8192,
    )
    case = Case(email=email, detection=detection)
    analysis = Analyzer(
        sandbox=lambda item, limits: DockerSandbox(item, limits),
        agent=LangChainAgent(model, structured_output_method="json_mode"),
    ).analyze(case)
    report = Reporter(
        model,
        name=model_name,
        structured_output_method="json_mode",
    ).report(analysis)

    output.mkdir(parents=True, exist_ok=True)
    prefix = output / f"{path.stem}-intelligence"
    json_path = Path(f"{prefix}.json")
    markdown_path = Path(f"{prefix}.md")
    json_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(Renderer().render(report), encoding="utf-8")
    print(f"JSON report written to: {json_path}")
    print(f"Markdown report written to: {markdown_path}")
    return True


def main(arguments: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="path to an EML file")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("."),
        help="report output directory (default: current directory)",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("DEEPSEEK_MODEL", "deepseek-chat"),
        help="DeepSeek model name (default: DEEPSEEK_MODEL or deepseek-chat)",
    )
    options = parser.parse_args(arguments)
    investigate(options.file, options.output, options.model)


if __name__ == "__main__":
    main()
