"""OneMail web console.

A small Flask front end for the OneMail project. It runs deterministic
detection on uploaded ``.eml`` files, starts asynchronous LM Studio + Docker
investigations for flagged messages, and previews Markdown reports.

Drop this file at the OneMail repository root (next to ``detection/``,
``reporting/`` and ``dataset/``) and run::

    python -m pip install -r requirements-web.txt
    python app.py

The deterministic stage remains available without external services. Agentic
investigation additionally requires a configured local LM Studio server and
Docker daemon; readiness failures are reported without disabling detection.
"""

from __future__ import annotations

import re
import multiprocessing
import queue
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, is_dataclass
from email import policy
from email.parser import BytesParser
from enum import Enum
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from flask import Flask, jsonify, render_template, request

# --- Where this app and its assets (templates/static/samples) live.
APP_DIR = Path(__file__).resolve().parent


def _find_repo_root(start: Path) -> Path:
    """Walk up from the app directory to the folder holding the OneMail packages.

    The app may live at the repo root or in a subfolder such as ``web/``. We
    locate the first ancestor (including ``start``) that contains the
    ``detection`` package so imports work regardless of where app.py sits.
    """

    for candidate in (start, *start.parents):
        if (candidate / "detection" / "__init__.py").is_file():
            return candidate
    return start


# --- Make the OneMail packages importable regardless of the launch directory.
REPO_ROOT = _find_repo_root(APP_DIR)
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from detection import DetectionEngine, Email  # noqa: E402
except ModuleNotFoundError as error:  # pragma: no cover - startup guard
    raise SystemExit(
        "Could not import the OneMail 'detection' package.\n"
        f"  app.py is at:      {APP_DIR}\n"
        f"  detected repo root: {REPO_ROOT}\n"
        "Place this app at the OneMail repo root or in a subfolder of it (a "
        "folder that contains 'detection/'), then run it again."
    ) from error
from reporting import DetectionRecord, DetectionReport  # noqa: E402
from web.presentation import (  # noqa: E402
    present_finding,
    present_observables,
    present_skipped,
    scan_summary as build_scan_summary,
)
from agentic.progress import ProgressEvent, ProgressTracker  # noqa: E402
from agentic.lmstudio import (  # noqa: E402
    analysis_seconds_from_env,
    config_from_env,
    create_chat_model,
    load_dotenv,
    model_status,
    role_config,
)

# Markdown rendering is optional. A minimal fallback keeps the preview working
# even before the extra web dependency is installed.
try:
    import markdown as _markdown  # type: ignore

    def _render_markdown(text: str) -> str:
        return _markdown.markdown(
            text, extensions=["fenced_code", "tables", "sane_lists"]
        )

    MARKDOWN_ENGINE = "python-markdown"
except Exception:  # pragma: no cover - exercised only without the dependency
    # No python-markdown available: the built-in _fallback_markdown below is used.
    MARKDOWN_ENGINE = "builtin-fallback"


app = Flask(
    __name__,
    template_folder=str(APP_DIR / "templates"),
    static_folder=str(APP_DIR / "static"),
)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB per upload.

ENGINE = DetectionEngine()

# Where bundled sample emails may live, in priority order. These are the corpus
# directories a local checkout may carry (see the evaluation-corpora layout in
# ARCHITECTURE.md; ``email/`` holds one gitignored folder per corpus).
SAMPLE_DIRS: Tuple[Path, ...] = (
    REPO_ROOT / "email" / "phishing_pot",
    REPO_ROOT / "dataset" / "phishing_pot" / "email",
)
SAMPLE_NAME = re.compile(r"^sample-\d+\.eml$")


def _find_sample_report() -> Optional[Path]:
    """Return a bundled Markdown report to preview, if one ships with the app.

    Prefers ``samples/sample-report.md`` but accepts any ``.md`` in the samples
    folder, so a renamed report (e.g. sample-1-intelligence.md) still loads.
    """

    samples_dir = APP_DIR / "samples"
    preferred = samples_dir / "sample-report.md"
    if preferred.is_file():
        return preferred
    if samples_dir.is_dir():
        markdown_files = sorted(samples_dir.glob("*.md"))
        if markdown_files:
            return markdown_files[0]
    return None


SAMPLE_REPORT = _find_sample_report()

EML_EXTENSIONS = {".eml"}
MARKDOWN_EXTENSIONS = {".md", ".markdown", ".txt"}
INVESTIGATION_REQUEST_HEADER = "X-OneMail-Request"
INVESTIGATION_REQUEST_VALUE = "investigate"


# --------------------------------------------------------------------------- #
# Serialization helpers
# --------------------------------------------------------------------------- #
def _to_jsonable(value: Any) -> Any:
    """Convert detection dataclasses and enums into JSON-friendly values."""

    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {key: _to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(item) for item in value]
    return value


def _observable_summary(observables: Any, content: bytes) -> Dict[str, Any]:
    """Pull the fields worth showing at a glance from parsed observables."""

    hosts = list(observables.url_hosts)
    attachments = [
        {
            "name": item.name,
            "content_type": item.content_type,
            "attachment_class": item.attachment_class.value,
            "size": item.size,
        }
        for item in observables.attachments
    ]
    return {
        "subject": observables.subject,
        "from_domain": observables.from_domain,
        "reply_to_domain": observables.reply_to_domain,
        "reply_to_differs": observables.reply_to_differs,
        "display_name": observables.display_name,
        "display_name_brand": observables.display_name_brand,
        "raw_date": observables.raw_date,
        "body_text": observables.body_text,
        "has_html": observables.has_html,
        "has_plain": observables.has_plain,
        "inline_image_count": observables.inline_image_count,
        "spf_result": observables.spf_result.value if observables.spf_result else None,
        "dmarc_result": (
            observables.dmarc_result.value if observables.dmarc_result else None
        ),
        "has_authentication_results": observables.has_authentication_results,
        "url_count": observables.url_count,
        "url_hosts": hosts[:25],
        "url_hosts_truncated": max(len(hosts) - 25, 0),
        "attachment_count": observables.attachment_count,
        "attachments": attachments,
        "mime_depth": observables.mime_depth,
        "received_count": observables.received_count,
        "parse_error": observables.parse_error,
        **_message_body_presentation(content),
    }


def scan_bytes(name: str, content: bytes) -> Dict[str, Any]:
    """Run deterministic detection over one email and package the result."""

    email = Email(file=name, content=content)
    detection = ENGINE.detect(email)
    report = DetectionReport.build(
        [DetectionRecord.detected("uploaded", detection)]
    )

    findings = []
    for finding in detection.findings:
        evidence = _to_jsonable(finding.evidence)
        findings.append(
            {
                "detector": finding.detector.value,
                "severity": finding.severity.value,
                "heuristic": finding.heuristic,
                "clause": finding.clause,
                "evidence": evidence,
                "presentation": present_finding(
                    finding.detector,
                    finding.severity.value,
                    finding.heuristic,
                    evidence,
                ),
            }
        )
    skipped = [
        present_skipped(result.detector, result.reason)
        for result in detection.skipped
    ]
    clear = [
        result.detector.value
        for result in detection.detector_results
        if result.status.value == "clear"
    ]

    return {
        "ok": True,
        "file": detection.file,
        "sha256": detection.sha256,
        "byte_count": len(content),
        "flagged": detection.flagged,
        "findings": findings,
        "skipped": skipped,
        "clear": clear,
        "detector_total": len(detection.detector_results),
        "scan_summary": build_scan_summary(findings),
        "observables": _observable_summary(detection.observables, content),
        "observable_sections": present_observables(
            detection.observables,
            (finding.detector for finding in detection.findings),
        ),
        "validation_issues": len(report.validation_issues),
        "report": report.to_dict(),
    }


# --------------------------------------------------------------------------- #
# Markdown preview (report output-format test harness)
# --------------------------------------------------------------------------- #
_ALLOWED_TAGS = {
    "h1", "h2", "h3", "h4", "h5", "h6", "p", "ul", "ol", "li", "blockquote",
    "pre", "code", "strong", "em", "b", "i", "u", "del", "a", "hr", "br",
    "table", "thead", "tbody", "tr", "th", "td", "span", "details", "summary",
}
_ALLOWED_ATTRS = {"a": {"href", "title"}, "th": {"align"}, "td": {"align"}}
_SAFE_URL = re.compile(r"^(https?:|mailto:|#)", re.IGNORECASE)
_DROP_CONTENT_TAGS = {"script", "style"}


class _Sanitizer(HTMLParser):
    """Allowlist sanitizer so rendered Markdown cannot inject active content."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: List[str] = []
        self._suppress_depth = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag in _DROP_CONTENT_TAGS:
            self._suppress_depth += 1
            return
        if tag not in _ALLOWED_TAGS or self._suppress_depth:
            return
        allowed = _ALLOWED_ATTRS.get(tag, set())
        kept = []
        for key, value in attrs:
            if key not in allowed or value is None:
                continue
            if key == "href" and not _SAFE_URL.match(value.strip()):
                continue
            kept.append(f'{key}="{self._escape(value)}"')
        rendered = tag + ("" if not kept else " " + " ".join(kept))
        self.out.append(f"<{rendered}>")

    def handle_startendtag(
        self, tag: str, attrs: List[Tuple[str, Optional[str]]]
    ) -> None:
        if tag in _ALLOWED_TAGS and not self._suppress_depth:
            self.out.append(f"<{tag} />")

    def handle_endtag(self, tag: str) -> None:
        if tag in _DROP_CONTENT_TAGS:
            self._suppress_depth = max(self._suppress_depth - 1, 0)
            return
        if tag in _ALLOWED_TAGS and not self._suppress_depth:
            self.out.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if not self._suppress_depth:
            self.out.append(self._escape(data))

    @staticmethod
    def _escape(text: str) -> str:
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    def result(self) -> str:
        return "".join(self.out)


_MESSAGE_BODY_LIMIT = 200_000
_MESSAGE_BODY_TAGS = {
    "h1", "h2", "h3", "h4", "h5", "h6", "p", "ul", "ol", "li",
    "blockquote", "pre", "code", "strong", "em", "b", "i", "u", "del",
    "hr", "br", "table", "thead", "tbody", "tr", "th", "td", "div",
    "section", "article", "header", "footer", "label", "small", "sub", "sup",
}
_MESSAGE_BODY_DROP_CONTENT_TAGS = {
    "script", "style", "head", "title", "template", "noscript", "iframe",
    "object", "embed", "svg", "canvas",
}


class _MessageBodySanitizer(HTMLParser):
    """Preserve inert message formatting without retaining active HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: List[str] = []
        self._suppress_depth = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag in _MESSAGE_BODY_DROP_CONTENT_TAGS:
            self._suppress_depth += 1
            return
        if self._suppress_depth:
            return
        if tag == "a":
            self.out.append('<span class="email-link">')
        elif tag == "form":
            self.out.append('<div class="email-form">')
        elif tag == "input":
            self.out.append('<span class="email-input-placeholder" aria-hidden="true"></span>')
        elif tag == "img":
            self.out.append('<span class="email-image-placeholder">[Image not loaded]</span>')
        elif tag in _MESSAGE_BODY_TAGS:
            self.out.append(f"<{tag}>")

    def handle_startendtag(
        self, tag: str, attrs: List[Tuple[str, Optional[str]]]
    ) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag in _MESSAGE_BODY_DROP_CONTENT_TAGS:
            self._suppress_depth = max(self._suppress_depth - 1, 0)
            return
        if self._suppress_depth:
            return
        if tag == "a":
            self.out.append("</span>")
        elif tag == "form":
            self.out.append("</div>")
        elif tag in _MESSAGE_BODY_TAGS and tag not in {"br", "hr"}:
            self.out.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if not self._suppress_depth:
            self.out.append(_Sanitizer._escape(data))

    def result(self) -> str:
        return "".join(self.out).strip()


def _message_body_presentation(content: bytes) -> Dict[str, Optional[str]]:
    """Extract one preferred MIME body for the analyst-facing message preview."""

    empty = {
        "presentation_body_format": None,
        "presentation_body_text": None,
        "presentation_body_html": None,
    }
    try:
        message = BytesParser(policy=policy.default).parsebytes(content)
        part = message.get_body(preferencelist=("html", "plain"))
        if part is None and message.get_content_maintype() == "text":
            part = message
        if part is None:
            return empty
        try:
            body = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True)
            if payload is None:
                return empty
            body = payload.decode(part.get_content_charset() or "utf-8", "replace")
        if not isinstance(body, str):
            return empty
    except Exception:
        return empty

    body = body[:_MESSAGE_BODY_LIMIT]
    if part.get_content_type().lower() == "text/html":
        sanitizer = _MessageBodySanitizer()
        sanitizer.feed(body)
        sanitizer.close()
        return {
            "presentation_body_format": "html",
            "presentation_body_text": None,
            "presentation_body_html": sanitizer.result(),
        }
    return {
        "presentation_body_format": "plain",
        "presentation_body_text": body,
        "presentation_body_html": None,
    }


def _fallback_markdown(text: str) -> str:
    """Very small Markdown subset used only when python-markdown is absent."""

    import html

    lines = text.splitlines()
    html_parts: List[str] = []
    in_list = False
    in_code = False
    para: List[str] = []

    def flush_para() -> None:
        if para:
            html_parts.append("<p>" + " ".join(para) + "</p>")
            para.clear()

    def inline(fragment: str) -> str:
        fragment = html.escape(fragment)
        fragment = re.sub(r"`([^`]+)`", r"<code>\1</code>", fragment)
        fragment = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", fragment)
        fragment = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", fragment)
        return fragment

    for line in lines:
        if line.strip().startswith("```"):
            flush_para()
            if in_list:
                html_parts.append("</ul>")
                in_list = False
            if not in_code:
                html_parts.append("<pre><code>")
                in_code = True
            else:
                html_parts.append("</code></pre>")
                in_code = False
            continue
        if in_code:
            html_parts.append(html.escape(line))
            continue
        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        if heading:
            flush_para()
            if in_list:
                html_parts.append("</ul>")
                in_list = False
            level = len(heading.group(1))
            html_parts.append(f"<h{level}>{inline(heading.group(2))}</h{level}>")
            continue
        item = re.match(r"^\s*[-*]\s+(.*)$", line)
        if item:
            flush_para()
            if not in_list:
                html_parts.append("<ul>")
                in_list = True
            html_parts.append(f"<li>{inline(item.group(1))}</li>")
            continue
        if not line.strip():
            flush_para()
            if in_list:
                html_parts.append("</ul>")
                in_list = False
            continue
        para.append(inline(line))

    flush_para()
    if in_list:
        html_parts.append("</ul>")
    if in_code:
        html_parts.append("</code></pre>")
    return "\n".join(html_parts)


def render_markdown_safe(text: str) -> str:
    """Render Markdown to sanitized HTML for the preview panel."""

    if MARKDOWN_ENGINE == "python-markdown":
        raw_html = _render_markdown(text)
    else:
        raw_html = _fallback_markdown(text)
    sanitizer = _Sanitizer()
    sanitizer.feed(raw_html)
    return sanitizer.result()


# --------------------------------------------------------------------------- #
# File-handling helpers
# --------------------------------------------------------------------------- #
def _extension(filename: str) -> str:
    return Path(filename or "").suffix.lower()


def _bad_request(message: str, status: int = 400):
    response = jsonify({"ok": False, "error": message})
    response.status_code = status
    return response


def _require_investigation_request():
    """Reject browser form submissions from other origins.

    Browsers cannot attach this custom header cross-origin without a successful
    CORS preflight, and this application does not allow cross-origin requests.
    """

    if (
        request.headers.get(INVESTIGATION_REQUEST_HEADER)
        != INVESTIGATION_REQUEST_VALUE
    ):
        return _bad_request("Investigation request header is missing or invalid.", 403)
    return None


# --------------------------------------------------------------------------- #
# Agentic investigation (LM Studio + Docker sandbox)
#
# This stage is optional and heavy: it needs LM Studio's local server, the
# Docker daemon, and the built ``onemail-analysis:latest`` image. Everything here is
# imported lazily so the deterministic app keeps working when those aren't
# present. When the stage isn't available we return a precise, actionable
# message rather than crashing.
# --------------------------------------------------------------------------- #
import importlib.util  # noqa: E402
import os  # noqa: E402


# Pick up LM Studio connection settings from the repo .env if present.
load_dotenv(REPO_ROOT / ".env")

LMSTUDIO = config_from_env()
ANALYSIS_IMAGE = "onemail-analysis:latest"
MAX_PROGRESS_EVENTS = 512
JOB_RETENTION_SECONDS = 3600


class _InvestigationJob:
    """Thread-safe, memory-only state for one local investigation."""

    def __init__(self, name: str) -> None:
        self.id = uuid.uuid4().hex
        self.name = name
        self.status = "queued"
        self.result: Optional[Dict[str, Any]] = None
        self.created = time.monotonic()
        self.finished: Optional[float] = None
        self.input_path = Path(tempfile.gettempdir()) / f"onemail-{self.id}.eml"
        self._events: List[Dict[str, object]] = []
        self._lock = threading.Lock()
        self._process: Optional[multiprocessing.Process] = None
        self._pipeline_step: Optional[str] = None
        self.progress = ProgressTracker(self._record)
        self.progress.event("pipeline", "Investigation queued", "queued")

    def _record(self, event: ProgressEvent) -> None:
        with self._lock:
            if len(self._events) < MAX_PROGRESS_EVENTS:
                self._events.append(event.to_dict())

    def start(self) -> None:
        with self._lock:
            if self.status == "queued":
                self.status = "running"

    def complete(self, result: Dict[str, Any]) -> None:
        with self._lock:
            if self.status == "cancelled":
                return
            self.result = result
            self.status = "completed" if result.get("ok") else "failed"
            self.finished = time.monotonic()

    def fail(self, error: BaseException) -> None:
        with self._lock:
            if self.status == "cancelled":
                return
            self.result = {
                "ok": False,
                "flagged": True,
                "file": self.name,
                "error": f"Agentic investigation failed: {type(error).__name__}: {error}",
            }
            self.status = "failed"
            self.finished = time.monotonic()

    def attach_process(self, process: multiprocessing.Process) -> None:
        with self._lock:
            self._process = process

    def attach_pipeline_step(self, step_id: str) -> None:
        with self._lock:
            self._pipeline_step = step_id

    def is_cancelled(self) -> bool:
        with self._lock:
            return self.status == "cancelled"

    def record_worker_event(self, event: Dict[str, object]) -> None:
        event = dict(event)
        event["step_id"] = "worker-" + str(event.get("step_id", "event"))
        with self._lock:
            if len(self._events) < MAX_PROGRESS_EVENTS:
                self._events.append(event)

    def cancel(self) -> bool:
        with self._lock:
            if self.status not in {"queued", "running"}:
                return False
            self.status = "cancelled"
            self.result = {
                "ok": False,
                "cancelled": True,
                "flagged": True,
                "file": self.name,
                "note": "Investigation stopped and its analysis container was terminated.",
            }
            self.finished = time.monotonic()
            process = self._process
            pipeline_step = self._pipeline_step
        if process is not None and process.is_alive():
            process.terminate()
            process.join(timeout=5)
            if process.is_alive():
                process.kill()
                process.join(timeout=5)
        if pipeline_step is not None:
            self.progress.finish(
                pipeline_step,
                "pipeline",
                "Run agentic investigation",
                status="failed",
                detail="Stopped by user",
            )
        self.progress.event(
            "pipeline",
            "Investigation stopped",
            "failed",
            detail="Stopped by user",
        )
        cleanup_error = _cleanup_investigation_resources(self.id, self.input_path)
        if cleanup_error is not None:
            with self._lock:
                assert self.result is not None
                self.result["error"] = cleanup_error
        return True

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "file": self.name,
                "status": self.status,
                "total_elapsed_ms": self.progress.elapsed_ms,
                "events": list(self._events),
                "result": self.result,
            }


_JOBS: Dict[str, _InvestigationJob] = {}
_JOBS_LOCK = threading.Lock()
_PROCESS_CONTEXT = multiprocessing.get_context("spawn")


def _investigation_worker(
    name: str,
    content: bytes,
    identifier: str,
    input_path: str,
    messages: Any,
) -> None:
    """Run the whole investigation in a terminable child process."""

    def emit(event: ProgressEvent) -> None:
        messages.put({"kind": "event", "event": event.to_dict()})

    try:
        result = investigate_bytes(
            name,
            content,
            progress=ProgressTracker(emit),
            investigation_id=identifier,
            input_path=Path(input_path),
        )
    except BaseException as error:
        messages.put(
            {
                "kind": "error",
                "error": f"{type(error).__name__}: {error}",
            }
        )
    else:
        messages.put({"kind": "result", "result": result})


def _cleanup_investigation_resources(
    identifier: str,
    input_path: Path,
) -> Optional[str]:
    """Remove resources that survive forced child-process termination."""

    errors: List[str] = []
    client = None
    try:
        if importlib.util.find_spec("docker") is not None:
            import docker

            client = docker.from_env(timeout=5)
            containers = client.containers.list(
                all=True,
                filters={"label": f"onemail.investigation={identifier}"},
            )
            for container in containers:
                try:
                    container.kill()
                except Exception:
                    pass
                try:
                    container.remove(force=True)
                except Exception as error:
                    errors.append(f"container removal failed: {type(error).__name__}: {error}")
    except Exception as error:
        errors.append(f"container cleanup failed: {type(error).__name__}: {error}")
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
    try:
        input_path.unlink(missing_ok=True)
    except Exception as error:
        errors.append(f"input cleanup failed: {type(error).__name__}: {error}")
    if errors:
        return "Investigation stopped, but resource cleanup reported: " + "; ".join(errors)
    return None


def _discard_expired_jobs() -> None:
    now = time.monotonic()
    with _JOBS_LOCK:
        expired = [
            identifier
            for identifier, job in _JOBS.items()
            if job.finished is not None and now - job.finished > JOB_RETENTION_SECONDS
        ]
        for identifier in expired:
            del _JOBS[identifier]


def _start_investigation(name: str, content: bytes) -> _InvestigationJob:
    _discard_expired_jobs()
    job = _InvestigationJob(name)
    with _JOBS_LOCK:
        _JOBS[job.id] = job

    messages = _PROCESS_CONTEXT.Queue()
    process = _PROCESS_CONTEXT.Process(
        target=_investigation_worker,
        args=(name, content, job.id, str(job.input_path), messages),
        daemon=True,
        name=f"onemail-worker-{job.id[:8]}",
    )
    job.attach_process(process)
    job.start()
    step = job.progress.start("pipeline", "Run agentic investigation")
    job.attach_pipeline_step(step)
    try:
        process.start()
    except BaseException as error:
        job.progress.finish(
            step,
            "pipeline",
            "Run agentic investigation",
            status="failed",
            detail=type(error).__name__,
        )
        job.fail(error)
        return job

    def monitor() -> None:
        result_received = False
        while process.is_alive():
            try:
                message = messages.get(timeout=0.1)
            except queue.Empty:
                continue
            result_received = _handle_worker_message(job, step, message) or result_received
        process.join()
        while True:
            try:
                message = messages.get_nowait()
            except queue.Empty:
                break
            result_received = _handle_worker_message(job, step, message) or result_received
        if not result_received:
            job.fail(RuntimeError(f"investigation worker exited with code {process.exitcode}"))
        messages.close()

    threading.Thread(
        target=monitor,
        daemon=True,
        name=f"onemail-monitor-{job.id[:8]}",
    ).start()
    return job


def _handle_worker_message(
    job: _InvestigationJob,
    step: str,
    message: Dict[str, Any],
) -> bool:
    if job.is_cancelled():
        return message.get("kind") in {"result", "error"}
    kind = message.get("kind")
    if kind == "event" and isinstance(message.get("event"), dict):
        job.record_worker_event(message["event"])
        return False
    if kind == "result" and isinstance(message.get("result"), dict):
        result = message["result"]
        job.progress.finish(
            step,
            "pipeline",
            "Run agentic investigation",
            status="completed" if result.get("ok") else "failed",
            detail="Investigation complete" if result.get("ok") else "Investigation failed",
        )
        job.complete(result)
        return True
    if kind == "error":
        error = RuntimeError(str(message.get("error") or "unknown worker failure"))
        job.progress.finish(
            step,
            "pipeline",
            "Run agentic investigation",
            status="failed",
            detail="Worker failed",
        )
        job.fail(error)
        return True
    return False


def _job(identifier: str) -> Optional[_InvestigationJob]:
    _discard_expired_jobs()
    with _JOBS_LOCK:
        return _JOBS.get(identifier)


def _model_status() -> Tuple[bool, str]:
    return model_status(LMSTUDIO)


def _docker_status() -> Tuple[bool, str]:
    if importlib.util.find_spec("docker") is None:
        return False, "The Docker SDK is not installed. Install the project: pip install -e ."
    # Check for a daemon socket first, so a missing daemon fails fast instead of hanging.
    if sys.platform != "win32" and not os.environ.get("DOCKER_HOST"):
        sockets = (
            Path("/var/run/docker.sock"),
            Path.home() / ".docker/run/docker.sock",
            Path.home() / ".orbstack/run/docker.sock",
            Path.home() / ".colima/default/docker.sock",
        )
        if not any(path.exists() for path in sockets):
            return False, "Docker daemon socket not found. Start Docker and retry."
    try:
        import docker

        client = docker.from_env(timeout=6)
        client.ping()
    except Exception as error:  # daemon down / unreachable
        return (
            False,
            f"Docker daemon is not reachable ({type(error).__name__}). Start Docker and retry.",
        )
    try:
        client.images.get(ANALYSIS_IMAGE)
    except Exception:
        client.close()
        return (
            False,
            f"The analysis image '{ANALYSIS_IMAGE}' is not built. Build it: "
            f"docker build -t {ANALYSIS_IMAGE} agentic/analysis/image",
        )
    client.close()
    return True, "Docker daemon and analysis image are ready."


def agentic_status() -> Dict[str, Any]:
    """Report whether the agentic stage can run, and optional enrichments."""

    from agentic.analysis import VirusTotalClient

    model_ok, model_detail = _model_status()
    docker_ok, docker_detail = _docker_status()
    try:
        virustotal_enabled = VirusTotalClient.from_env() is not None
        virustotal_detail = (
            "Hash-only lookups enabled; files are never uploaded."
            if virustotal_enabled
            else "Hash-only lookups disabled because VIRUSTOTAL_API_KEY is unset."
        )
    except ValueError as error:
        virustotal_enabled = False
        virustotal_detail = f"VirusTotal configuration is invalid: {error}"
    return {
        "ready": model_ok and docker_ok,
        "model": {"ok": model_ok, "detail": model_detail},
        "docker": {"ok": docker_ok, "detail": docker_detail},
        "virustotal": {
            "enabled": virustotal_enabled,
            "detail": virustotal_detail,
        },
    }


def investigate_bytes(
    name: str,
    content: bytes,
    progress: Optional[ProgressTracker] = None,
    cancelled: Optional[Callable[[], bool]] = None,
    register_teardown: Optional[Callable[[Callable[[], None]], None]] = None,
    investigation_id: Optional[str] = None,
    input_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run detection, then the LM Studio + Docker investigation if flagged."""

    from agentic.analysis import InvestigationCancelled

    progress = progress or ProgressTracker()
    cancelled = cancelled or (lambda: False)

    def ensure_running() -> None:
        if cancelled():
            raise InvestigationCancelled("investigation stopped")

    ensure_running()
    detection_step = progress.start("detection", "Run deterministic detection")
    email = Email(file=name, content=content)
    detection = ENGINE.detect(email)
    progress.finish(
        detection_step,
        "detection",
        "Run deterministic detection",
        detail=f"{len(detection.findings)} finding(s)",
    )
    ensure_running()

    if not detection.flagged:
        return {
            "ok": True,
            "flagged": False,
            "file": detection.file,
            "note": "This email was not flagged, so agentic investigation does not run. "
            "Only flagged emails form a Case.",
        }

    readiness_step = progress.start("preflight", "Check model and Docker readiness")
    status = agentic_status()
    progress.finish(
        readiness_step,
        "preflight",
        "Check model and Docker readiness",
        status="completed" if status["ready"] else "failed",
    )
    if not status["ready"]:
        problems = [
            part["detail"] for part in (status["model"], status["docker"]) if not part["ok"]
        ]
        return {
            "ok": False,
            "flagged": True,
            "file": detection.file,
            "error": "The agentic stage is not available in this environment.",
            "problems": problems,
            "status": status,
        }

    try:
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
    except Exception as error:
        return {
            "ok": False,
            "flagged": True,
            "file": detection.file,
            "error": f"Could not import the agentic stack: {type(error).__name__}: {error}",
        }

    try:
        ensure_running()
        model_step = progress.start("model", "Initialise LM Studio clients")
        planner_config = role_config(LMSTUDIO, "planner")
        reporter_config = role_config(LMSTUDIO, "reporter")
        planner_model = create_chat_model(planner_config)
        reporter_model = create_chat_model(reporter_config)
        progress.finish(
            model_step,
            "model",
            "Initialise LM Studio clients",
            detail=(
                f"Planner reasoning: {planner_config.reasoning_effort}; "
                f"reporter reasoning: {reporter_config.reasoning_effort}"
            ),
        )
        ensure_running()
        case_step = progress.start("pipeline", "Validate investigation case")
        case = Case(email=email, detection=detection)
        progress.finish(case_step, "pipeline", "Validate investigation case")
        def create_sandbox(item, limits):
            sandbox = DockerSandbox(
                item,
                limits,
                progress=progress,
                cancelled=cancelled,
                investigation_id=investigation_id,
                input_path=input_path,
            )
            if register_teardown is not None:
                register_teardown(sandbox.stop)
            return sandbox

        analysis = Analyzer(
            sandbox=create_sandbox,
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
            cancelled=cancelled,
        ).analyze(case)
        ensure_running()
        report = Reporter(
            reporter_model,
            name=LMSTUDIO.model,
            timeout=reporter_config.timeout,
            structured_output_method="json_schema",
            progress=progress,
        ).report(analysis)
        ensure_running()
        render_step = progress.start("reporting", "Render intelligence report")
        markdown = Renderer().render(report)
        report_json = report.model_dump(mode="json")
        progress.finish(render_step, "reporting", "Render intelligence report")
    except InvestigationCancelled:
        raise
    except Exception as error:
        return {
            "ok": False,
            "flagged": True,
            "file": detection.file,
            "error": f"Agentic investigation failed: {type(error).__name__}: {error}",
        }

    return {
        "ok": True,
        "flagged": True,
        "file": detection.file,
        "model": LMSTUDIO.model,
        "report_markdown": markdown,
        "report_html": render_markdown_safe(markdown),
        "report_json": report_json,
    }


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    return render_template(
        "index.html",
        detector_count=len(ENGINE._detectors),
        markdown_engine=MARKDOWN_ENGINE,
        has_samples=any(directory.is_dir() for directory in SAMPLE_DIRS),
    )


@app.post("/api/scan")
def api_scan():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return _bad_request("Choose an .eml file to scan.")
    if _extension(upload.filename) not in EML_EXTENSIONS:
        return _bad_request("Only .eml files can be scanned.")

    content = upload.read()
    if not content:
        return _bad_request("That file is empty.")

    try:
        return jsonify(scan_bytes(Path(upload.filename).name, content))
    except Exception as error:  # pragma: no cover - defensive guard
        return _bad_request(f"Detection failed: {type(error).__name__}: {error}", 500)


@app.get("/api/sample/<name>")
def api_sample(name: str):
    if not SAMPLE_NAME.match(name):
        return _bad_request("Unknown sample name.", 404)
    for directory in SAMPLE_DIRS:
        candidate = (directory / name).resolve()
        # Guard against path traversal: candidate must stay inside the dir.
        if directory.resolve() in candidate.parents and candidate.is_file():
            return jsonify(scan_bytes(name, candidate.read_bytes()))
    return _bad_request(f"Sample {name} is not present in this checkout.", 404)


@app.get("/api/agentic-status")
def api_agentic_status():
    return jsonify({"ok": True, **agentic_status()})


@app.post("/api/investigate")
def api_investigate():
    rejected = _require_investigation_request()
    if rejected is not None:
        return rejected

    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return _bad_request("Choose an .eml file to investigate.")
    if _extension(upload.filename) not in EML_EXTENSIONS:
        return _bad_request("Only .eml files can be investigated.")
    content = upload.read()
    if not content:
        return _bad_request("That file is empty.")
    job = _start_investigation(Path(upload.filename).name, content)
    return jsonify({"ok": True, "job": job.snapshot()}), 202


@app.post("/api/investigate/sample/<name>")
def api_investigate_sample(name: str):
    rejected = _require_investigation_request()
    if rejected is not None:
        return rejected

    if not SAMPLE_NAME.match(name):
        return _bad_request("Unknown sample name.", 404)
    for directory in SAMPLE_DIRS:
        candidate = (directory / name).resolve()
        if directory.resolve() in candidate.parents and candidate.is_file():
            job = _start_investigation(name, candidate.read_bytes())
            return jsonify({"ok": True, "job": job.snapshot()}), 202
    return _bad_request(f"Sample {name} is not present in this checkout.", 404)


@app.get("/api/investigate/<identifier>")
def api_investigation_status(identifier: str):
    rejected = _require_investigation_request()
    if rejected is not None:
        return rejected
    job = _job(identifier)
    if job is None:
        return _bad_request("Investigation job was not found or has expired.", 404)
    return jsonify({"ok": True, "job": job.snapshot()})


@app.post("/api/investigate/<identifier>/stop")
def api_stop_investigation(identifier: str):
    rejected = _require_investigation_request()
    if rejected is not None:
        return rejected
    job = _job(identifier)
    if job is None:
        return _bad_request("Investigation job was not found or has expired.", 404)
    if not job.cancel():
        return _bad_request("Investigation is no longer running.", 409)
    return jsonify({"ok": True, "job": job.snapshot()})


@app.post("/api/preview")
def api_preview():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return _bad_request("Choose a Markdown file to preview.")
    if _extension(upload.filename) not in MARKDOWN_EXTENSIONS:
        return _bad_request("Only .md, .markdown or .txt files can be previewed.")

    raw = upload.read()
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _bad_request("That file is not valid UTF-8 text.")

    return jsonify(
        {
            "ok": True,
            "file": Path(upload.filename).name,
            "engine": MARKDOWN_ENGINE,
            "html": render_markdown_safe(source),
            "source": source,
        }
    )


@app.get("/api/sample-report")
def api_sample_report():
    if SAMPLE_REPORT is None or not SAMPLE_REPORT.is_file():
        return _bad_request("Bundled sample report is missing.", 404)
    source = SAMPLE_REPORT.read_text(encoding="utf-8")
    return jsonify(
        {
            "ok": True,
            "file": SAMPLE_REPORT.name,
            "engine": MARKDOWN_ENGINE,
            "html": render_markdown_safe(source),
            "source": source,
        }
    )


@app.errorhandler(413)
def too_large(_error):
    return _bad_request("That upload is larger than the 25 MB limit.", 413)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)
