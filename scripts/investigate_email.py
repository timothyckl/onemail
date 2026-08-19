"""Investigate one flagged EML file with Docker and a local LM Studio model."""

import argparse
from pathlib import Path
from typing import Optional, Sequence

from agentic import Case
from agentic.analysis import (
    Analyzer,
    DockerSandbox,
    LangChainAgent,
    Limits,
    SQLiteCorrelator,
    VirusTotalClient,
)
from agentic.intelligence import Renderer, Reporter
from agentic.progress import ProgressEvent, ProgressTracker
from agentic.lmstudio import (
    DEFAULT_API_KEY,
    DEFAULT_BASE_URL,
    DEFAULT_MAX_TOKENS,
    DEFAULT_MODEL,
    DEFAULT_REASONING_EFFORT,
    DEFAULT_TIMEOUT,
    LMStudioConfig,
    analysis_seconds_from_env,
    config_from_env,
    create_chat_model,
    load_dotenv,
    role_config,
)
from detection import DetectionEngine, Email


def _print_progress(event: ProgressEvent) -> None:
    marker = {
        "queued": "○",
        "running": "▶",
        "completed": "✓",
        "skipped": "–",
        "failed": "!",
    }[event.status]
    duration = "" if event.duration_ms is None else f" ({event.duration_ms / 1000:.1f}s)"
    context = " · ".join(item for item in (event.tool, event.artifact) if item)
    suffix = f" [{context}]" if context else ""
    detail = f" — {event.detail}" if event.detail and event.status != "running" else ""
    print(f"{marker} {event.action}{suffix}{duration}{detail}", flush=True)


def investigate(
    path: Path,
    output: Path,
    model_name: str,
    base_url: str = DEFAULT_BASE_URL,
    api_key: str = DEFAULT_API_KEY,
    timeout: int = DEFAULT_TIMEOUT,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    reasoning_effort: str = DEFAULT_REASONING_EFFORT,
) -> bool:
    """Investigate a flagged email and write validated intelligence reports."""

    progress = ProgressTracker(_print_progress)
    detection_step = progress.start("detection", "Run deterministic detection")
    email = Email(file=path.as_posix(), content=path.read_bytes())
    detection = DetectionEngine().detect(email)
    progress.finish(
        detection_step,
        "detection",
        "Run deterministic detection",
        detail=f"{len(detection.findings)} finding(s)",
    )
    if not detection.flagged:
        print("Email was not flagged; agentic investigation was not started.")
        return False

    print(f"Detection flagged the email with {len(detection.findings)} finding(s).")
    config = LMStudioConfig(
        base_url=base_url,
        model=model_name,
        api_key=api_key,
        timeout=timeout,
        max_tokens=max_tokens,
        reasoning_effort=reasoning_effort,
    )
    planner_config = role_config(config, "planner")
    reporter_config = role_config(config, "reporter")
    planner_model = create_chat_model(planner_config)
    reporter_model = create_chat_model(reporter_config)
    case = Case(email=email, detection=detection)
    analysis = Analyzer(
        sandbox=lambda item, limits: DockerSandbox(
            item, limits, progress=progress
        ),
        agent=LangChainAgent(
            planner_model,
            timeout=planner_config.timeout,
            structured_output_method="json_schema",
            progress=progress,
        ),
        limits=Limits(seconds=analysis_seconds_from_env()),
        progress=progress,
        correlator=SQLiteCorrelator.from_env(),
        virustotal=VirusTotalClient.from_env(),
    ).analyze(case)
    report = Reporter(
        reporter_model,
        name=model_name,
        timeout=reporter_config.timeout,
        structured_output_method="json_schema",
        progress=progress,
    ).report(analysis)

    output.mkdir(parents=True, exist_ok=True)
    prefix = output / f"{path.stem}-intelligence"
    json_path = Path(f"{prefix}.json")
    markdown_path = Path(f"{prefix}.md")
    json_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    render_step = progress.start("reporting", "Render intelligence report")
    markdown_path.write_text(Renderer().render(report), encoding="utf-8")
    progress.finish(render_step, "reporting", "Render intelligence report")
    print(f"JSON report written to: {json_path}")
    print(f"Markdown report written to: {markdown_path}")
    print(f"Total investigation time: {progress.elapsed_ms / 1000:.1f}s")
    return True


def main(arguments: Optional[Sequence[str]] = None) -> None:
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    defaults = config_from_env()
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
        default=defaults.model,
        help="LM Studio model ID (default: LMSTUDIO_MODEL)",
    )
    parser.add_argument(
        "--base-url",
        default=defaults.base_url,
        help="LM Studio OpenAI-compatible base URL (default: LMSTUDIO_BASE_URL)",
    )
    options = parser.parse_args(arguments)
    investigate(
        options.file,
        options.output,
        options.model,
        options.base_url,
        defaults.api_key,
        defaults.timeout,
        defaults.max_tokens,
        defaults.reasoning_effort,
    )


if __name__ == "__main__":
    main()
