---
name: handoff
description: Load the OneMail project architecture, setup, operating commands, and safety boundaries for a new Claude Code session.
disable-model-invocation: true
---

# OneMail project handoff

Use this briefing to orient yourself before working in this repository. Treat the
tracked source and the current contents of `README.md`, `ARCHITECTURE.md`,
`pyproject.toml`, and `.env.example` as authoritative if a later task requires
more detail. Do not modify files merely because this command was invoked.

## Purpose and governing rule

OneMail is an email threat-analysis pipeline with two deliberately separate
stages:

1. Deterministic code parses a raw `.eml` and decides whether it is flagged.
2. Only a flagged email may enter bounded agentic investigation for enrichment.

The model never decides whether an email is malicious, overturns the
deterministic result, or recommends an action. Intelligence output must remain
evidence-grounded decision support without a maliciousness verdict.

## Repository map

- `detection/`: immutable detection models, RFC 822 parsing, text
  normalization, domain and brand utilities, optional QR decoding, and 22
  deterministic detectors. `DetectionEngine` parses once and runs every
  detector once; each returns a typed fired, clear, or skipped result.
- `agentic/case.py`: strict detection-to-investigation boundary. A `Case`
  requires a flagged detection plus matching filename and SHA-256.
- `agentic/analysis/`: deterministic baseline, bounded LangChain planner,
  allowlisted typed tools, policy enforcement, Docker sandbox, progress events,
  optional local correlation, and optional VirusTotal hash lookup.
- `agentic/analysis/image/`: Ubuntu analysis image, runner, and YARA rules.
- `agentic/intelligence/`: structured report drafting, evidence validation,
  MITRE ATT&CK catalogue, Diamond Model and Kill Chain mappings, and
  deterministic Markdown rendering.
- `reporting/`: post-detection batch reports and independent finding grounding.
- `dataset/`: read-only phishing-corpus access, separate from detection.
- `scripts/`: command-line entry points for detection, evaluation, reporting,
  and full investigation.
- `web/`: local Flask console for scanning, asynchronous investigation,
  progress display, cancellation, and sanitized Markdown preview.
- `tests/`: unittest coverage for detection, precision behavior, sandboxing,
  model grounding, enrichment, correlation, web security, and optional corpora.

Do not inspect gitignored corpora, credentials, caches, generated reports, or
other ignored local state unless the user explicitly requests it. Keep
`onemail_pi/` out of scope unless the user explicitly brings it into scope.

## Requirements

- Python 3.10 or newer.
- Core Python dependencies are declared in `pyproject.toml` and mirrored in
  `requirements.txt`: Docker SDK, LangChain Core/OpenAI, and Pydantic.
- The web console additionally uses Flask and Markdown.
- QR recovery is optional and uses OpenCV plus NumPy.
- Full agentic investigation requires:
  - a running local Docker daemon;
  - the `onemail-analysis:latest` image;
  - LM Studio serving an OpenAI-compatible local endpoint with the configured
    model loaded.
- Deterministic detection needs neither Docker nor a model.
- VirusTotal is optional. It performs existing-report lookups by SHA-256 only;
  OneMail has no upload path, though queried hashes are disclosed to
  VirusTotal.

## Setup

Install the project from the repository root:

```bash
python -m pip install -e .
```

Install optional QR support or all development/fixture dependencies when
needed:

```bash
python -m pip install -e ".[qr]"
python -m pip install -e ".[dev]"
```

Prepare local agentic configuration:

```bash
cp .env.example .env
docker build -t onemail-analysis:latest agentic/analysis/image
```

Start LM Studio's local server and load the model named by `LMSTUDIO_MODEL`.
Defaults use `http://127.0.0.1:1234/v1` and
`qwen/qwen3.6-35b-a3b`. `.env` is local and must remain uncommitted.

Important configuration groups in `.env.example`:

- `LMSTUDIO_*`: endpoint, model, placeholder API key, timeout, token budget,
  and reasoning effort.
- `LMSTUDIO_PLANNER_*`: reasoning-enabled investigation planning.
- `LMSTUDIO_REPORTER_*`: schema-constrained report drafting with reasoning off.
- `ONEMAIL_ANALYSIS_TIMEOUT`: total analysis wall-clock budget.
- `ONEMAIL_CORRELATION_DB`: local normalized indicator/hash store.
- `VIRUSTOTAL_*`: optional hash-only enrichment, cache, timeout, and throttle.

## Run the project

Detect one email without Docker or a model:

```bash
python -m scripts.detect_email path/to/message.eml
```

Run the full flagged-email workflow and write JSON plus Markdown intelligence:

```bash
python scripts/investigate_email.py path/to/message.eml --output reports
```

Run the local web console:

```bash
python web/app.py
```

Then open `http://127.0.0.1:5000`. It is a local development tool and must not
be exposed publicly without separate production hardening.

Corpus and reporting entry points, when the corresponding local corpora are
intentionally available, are:

```bash
python -m scripts.read_phishing_pot
python -m scripts.detect_phishing_pot
python -m scripts.report_phishing_pot
python -m scripts.measure_detection
python -m scripts.detect_spamassassin
python -m scripts.detect_nazario
```

## Verify changes

Run the tracked unit suite from the repository root:

```bash
python -m unittest discover -s tests -v
```

The Docker integration test skips unless the Docker SDK, daemon, and analysis
image are available. Corpus gates skip when their local-only datasets are
absent. Precision-sensitive changes must preserve the legitimate fixtures with
zero fired detectors and must not weaken configured corpus recall or
false-positive gates.

## Security and implementation boundaries

- Detection operates on immutable observables and typed evidence; detectors do
  not reparse raw bytes or invoke models.
- Authentication failure is a signal, but SPF/DMARC pass is never
  exculpatory.
- Agentic work starts only after `Case` revalidates the flagged email and hash.
- The Docker sandbox is ephemeral, offline, non-root, read-only, capability
  dropped, resource limited, and receives the email through a read-only mount.
- The model can select only host-allowlisted typed tasks. It has no direct
  shell, host filesystem, Docker, or network access.
- Attachments are inspected, rendered offline, or constrainedly emulated; they
  are never executed natively.
- Analysis records artifacts, traces, evidence, observations, gaps, and
  failures. Unsupported claims or framework mappings are retried, pruned, or
  rejected by the intelligence validator.
- Local correlation stores normalized metadata and hashes, not raw messages or
  attachment bytes.
- Web uploads and jobs are bounded; rendered Markdown is allowlist-sanitized.

## On invocation

Acknowledge that the OneMail handoff is loaded, summarize the deterministic
verdict boundary and the requirements for detection versus full investigation,
and state that you are ready for the next repository task. Do not make changes
until the user supplies that task.
