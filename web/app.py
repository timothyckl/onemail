"""OneMail web console.

A small Flask front end for the OneMail project. It runs the deterministic
detection stage on uploaded ``.eml`` files and previews Markdown reports so the
output format can be checked without a model or Docker.

Drop this file at the OneMail repository root (next to ``detection/``,
``reporting/`` and ``dataset/``) and run::

    python -m pip install -r requirements-web.txt
    python app.py

Only the deterministic detection stage runs here. The agentic investigation
stage is intentionally out of scope: it needs a configured LangChain model and
a local Docker daemon, matching the boundary the project itself draws.
"""

from __future__ import annotations

import re
import sys
from dataclasses import asdict, is_dataclass
from enum import Enum
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
# directories the OneMail repo already ships with (found under the repo root).
SAMPLE_DIRS: Tuple[Path, ...] = (
    REPO_ROOT / "email",
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


def _observable_summary(observables: Any) -> Dict[str, Any]:
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
    }


def scan_bytes(name: str, content: bytes) -> Dict[str, Any]:
    """Run deterministic detection over one email and package the result."""

    email = Email(file=name, content=content)
    detection = ENGINE.detect(email)
    report = DetectionReport.build(
        [DetectionRecord.detected("uploaded", detection)]
    )

    findings = [
        {
            "detector": finding.detector.value,
            "severity": finding.severity.value,
            "heuristic": finding.heuristic,
            "clause": finding.clause,
            "evidence": _to_jsonable(finding.evidence),
        }
        for finding in detection.findings
    ]
    skipped = [
        {"detector": result.detector.value, "reason": result.reason}
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
        "observables": _observable_summary(detection.observables),
        "validation_issues": len(report.validation_issues),
        "report": report.to_dict(),
    }


# --------------------------------------------------------------------------- #
# Markdown preview (report output-format test harness)
# --------------------------------------------------------------------------- #
_ALLOWED_TAGS = {
    "h1", "h2", "h3", "h4", "h5", "h6", "p", "ul", "ol", "li", "blockquote",
    "pre", "code", "strong", "em", "b", "i", "u", "del", "a", "hr", "br",
    "table", "thead", "tbody", "tr", "th", "td", "span",
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


# --------------------------------------------------------------------------- #
# Agentic investigation (DeepSeek + Docker sandbox)
#
# This stage is optional and heavy: it needs a DeepSeek API key, the Docker
# daemon, and the built ``onemail-analysis:latest`` image. Everything here is
# imported lazily so the deterministic app keeps working when those aren't
# present. When the stage isn't available we return a precise, actionable
# message rather than crashing.
# --------------------------------------------------------------------------- #
import importlib.util  # noqa: E402
import os  # noqa: E402


def _load_dotenv(path: Path) -> None:
    """Load simple KEY=VALUE lines from a .env, without overriding real env vars."""

    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


# Pick up DEEPSEEK_API_KEY / DEEPSEEK_MODEL from the repo .env if present.
_load_dotenv(REPO_ROOT / ".env")

DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
ANALYSIS_IMAGE = "onemail-analysis:latest"


def _model_status() -> Tuple[bool, str]:
    if importlib.util.find_spec("langchain_deepseek") is None:
        return False, "langchain-deepseek is not installed. Install the project: pip install -e ."
    if not os.environ.get("DEEPSEEK_API_KEY"):
        return (
            False,
            "DEEPSEEK_API_KEY is not set. Add it to your environment or the repo .env, then retry.",
        )
    return True, f"DeepSeek ready (model: {DEEPSEEK_MODEL})."


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
    """Report whether the agentic stage can run, and why not if it can't."""

    model_ok, model_detail = _model_status()
    docker_ok, docker_detail = _docker_status()
    return {
        "ready": model_ok and docker_ok,
        "model": {"ok": model_ok, "detail": model_detail},
        "docker": {"ok": docker_ok, "detail": docker_detail},
    }


def investigate_bytes(name: str, content: bytes) -> Dict[str, Any]:
    """Run detection, then the DeepSeek + Docker agentic investigation if flagged."""

    email = Email(file=name, content=content)
    detection = ENGINE.detect(email)

    if not detection.flagged:
        return {
            "ok": True,
            "flagged": False,
            "file": detection.file,
            "note": "This email was not flagged, so agentic investigation does not run. "
            "Only flagged emails form a Case.",
        }

    status = agentic_status()
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
        from langchain_deepseek import ChatDeepSeek
        from agentic import Case
        from agentic.analysis import Analyzer, DockerSandbox, LangChainAgent
        from agentic.intelligence import Renderer, Reporter
    except Exception as error:
        return {
            "ok": False,
            "flagged": True,
            "file": detection.file,
            "error": f"Could not import the agentic stack: {type(error).__name__}: {error}",
        }

    try:
        model = ChatDeepSeek(
            model=DEEPSEEK_MODEL,
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
            model, name=DEEPSEEK_MODEL, structured_output_method="json_mode"
        ).report(analysis)
        markdown = Renderer().render(report)
        report_json = report.model_dump(mode="json")
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
        "model": DEEPSEEK_MODEL,
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
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return _bad_request("Choose an .eml file to investigate.")
    if _extension(upload.filename) not in EML_EXTENSIONS:
        return _bad_request("Only .eml files can be investigated.")
    content = upload.read()
    if not content:
        return _bad_request("That file is empty.")
    # Always 200: the JSON body carries ok/flagged/problems so the UI can render
    # unavailability and failures without a generic error banner.
    return jsonify(investigate_bytes(Path(upload.filename).name, content))


@app.get("/api/investigate/sample/<name>")
def api_investigate_sample(name: str):
    if not SAMPLE_NAME.match(name):
        return _bad_request("Unknown sample name.", 404)
    for directory in SAMPLE_DIRS:
        candidate = (directory / name).resolve()
        if directory.resolve() in candidate.parents and candidate.is_file():
            return jsonify(investigate_bytes(name, candidate.read_bytes()))
    return _bad_request(f"Sample {name} is not present in this checkout.", 404)


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