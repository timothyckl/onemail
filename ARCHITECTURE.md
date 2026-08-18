# OneMail — Architecture & Developer Guide

OneMail is an email threat-analysis pipeline. It runs **deterministic phishing
detection** first, and only escalates flagged messages to a **bounded agentic
investigation** that produces an evidence-grounded analyst report. The design
principle throughout is that *machines decide maliciousness deterministically;
the model only enriches, never verdicts.*

This document describes how the code is organised, how data flows through it,
and where the trust boundaries sit. For task-oriented usage (how to run each
stage) see `README.md`.

---

## 1. Pipeline at a glance

```
raw .eml bytes
      │
      ▼
┌─────────────┐   parse once, run every detector once
│  detection  │   → Detection { flagged, findings, observables, sha256 }
└─────────────┘
      │ flagged only
      ▼
┌─────────────┐   Case: revalidates file name + SHA-256 + flagged
│   agentic   │
│  ┌────────┐ │   analysis  → static baseline + bounded LangChain agent
│  │analysis│ │              runs typed tasks inside a locked-down container
│  └────────┘ │   → Analysis { artifacts, observations, gaps, metrics }
│  ┌────────┐ │
│  │ intel  │ │   intelligence → validates every claim against evidence
│  └────────┘ │               → Report (canonical JSON + deterministic Markdown)
└─────────────┘
```

Two independent side channels sit alongside the pipeline:

- **`reporting/`** turns a batch of detections into a validated coverage report
  (used for corpus evaluation). It runs *after* detection is complete.
- **`web/`** is a local Flask console that exposes the detection stage (and a
  Markdown report preview) in the browser.

---

## 2. Repository layout

```
.
├── README.md              Usage guide (detection, dataset, agentic, web)
├── ARCHITECTURE.md        This document
├── pyproject.toml         Package metadata + runtime dependencies
├── requirements.txt       Same constraints for non-editable installs (+ web deps)
├── .env.example           Template for the agentic stage's DeepSeek credentials
├── .gitignore
│
├── detection/             Stage 1 — deterministic detection
│   ├── engine.py            DetectionEngine: parse once, run all detectors
│   ├── parser.py            EmailParser: raw bytes → MessageObservables
│   ├── detectors/           The deterministic rules
│   │   ├── base.py            Detector ABC (typed, generic over Finding)
│   │   ├── detectors.py       5 core detectors
│   │   └── extra_detectors.py 10 additional detectors
│   └── data_models/         Standalone, dependency-light typed models
│       ├── email.py           Email (file + raw bytes)
│       ├── observables.py     MessageObservables + sub-observables
│       ├── enums.py           Severity, DetectorName/Status, SPF/DMARC results…
│       ├── evidence.py        Typed evidence records per detector
│       ├── findings/          Typed findings (what a fired detector emits)
│       ├── results/           DetectorResult = Fired | Clear | Skipped
│       └── detection.py       Detection (the full per-email outcome)
│
├── agentic/               Stage 2 — investigation of flagged emails
│   ├── case.py              Case: the detection→investigation boundary
│   ├── structured.py        Structured-output helpers for the model
│   ├── timeout.py           Bounded model-call timeouts
│   ├── analysis/            Static analysis in an isolated sandbox
│   │   ├── analyzer.py        Analyzer: deterministic baseline + agent loop
│   │   ├── agent.py           Agent ABC + LangChainAgent
│   │   ├── sandbox.py         Sandbox ABC + DockerSandbox
│   │   ├── policy.py          Policy: what the agent is allowed to request
│   │   ├── tools.py           Typed tasks the agent may select
│   │   ├── models.py          Analysis result types
│   │   └── image/             The analysis container
│   │       ├── Dockerfile       Ubuntu 24.04, non-root, no network
│   │       ├── runner.py        In-container entry point
│   │       ├── rules/base.yar   YARA rules
│   │       └── signatures/      ClamAV signature drop-in (.gitkeep placeholder)
│   └── intelligence/        Evidence-grounded reporting
│       ├── reporter.py        Reporter: Analysis → Report (via the model)
│       ├── validator.py       Validator: grounds every claim in evidence
│       ├── renderer.py        Renderer: Report → deterministic Markdown
│       ├── models.py          Report types (Diamond, ATT&CK, Kill Chain…)
│       └── catalog/attack.json  MITRE ATT&CK reference catalogue
│
├── reporting/             Batch coverage reporting (post-detection)
│   └── detection.py         DetectionReport, DetectionRecord, finding validator
│
├── dataset/               Phishing-corpus access (data, not detection)
│   ├── phishing.py          PhishingPot + PhishingEmail
│   └── phishing_pot/        Corpus location (samples supplied separately)
│       ├── README.md
│       └── email/.gitkeep
│
├── scripts/               Runnable entry points (python -m scripts.*)
│   ├── detect_email.py          Detect one .eml
│   ├── detect_phishing_pot.py   Detect across the corpus
│   ├── read_phishing_pot.py     List corpus samples
│   ├── report_phishing_pot.py   Write a validated coverage report
│   └── investigate_email.py     Full pipeline with Docker + DeepSeek
│
├── tests/                 unittest suite
│   ├── test_detection.py
│   ├── test_phishing_pot.py
│   ├── test_agentic.py            fakes only, never calls a real model
│   └── test_agentic_docker.py     skips unless Docker + image are present
│
└── web/                   Local Flask console for the detection stage
    ├── app.py
    ├── templates/index.html
    ├── static/{app.js,style.css}
    └── samples/sample-1-intelligence.md
```

> **Note on the email corpus.** OneMail is exercised against thousands of real
> honeypot `.eml` files. Those are *data*, not source, and are deliberately kept
> out of the repository (the `email/` and `dataset/phishing_pot/email/` trees are
> gitignored). Drop the samples into `dataset/phishing_pot/email/` before running
> the corpus scripts.

---

## 3. The type system (detection)

Everything in stage 1 is a small, frozen, dependency-light dataclass. This keeps
detection deterministic, cheap to construct in tests, and independent of the
agentic dependencies.

| Type | Role |
| --- | --- |
| `Email` | One email file: a `file` name and unmodified RFC 822 `content` bytes. |
| `MessageObservables` | Everything the parser extracts: subject/body, MIME depth, From/Reply-To domains, SPF/DMARC results, URLs and URL hosts, attachments, duplicate headers, nested senders, sender IPs, received timeline. |
| `AttachmentObservable`, `DuplicateHeader`, `NestedSender`, `SenderIp` | Sub-observables referenced by the message. |
| `Finding` (+ per-detector subclasses) | What a *fired* detector emits, carrying typed `evidence`. |
| `DetectorEvidence` (+ subclasses) | The concrete facts behind a finding, so every claim is traceable. |
| `DetectorResult` = `FiredResult` \| `ClearResult` \| `SkippedResult` | The outcome of running one detector. |
| `Detection` | The complete per-email result: `file`, `sha256`, `observables`, all detector results, and the derived `flagged` flag. |

`Severity`, `DetectorName`, `DetectorStatus`, `SpfResult`, `DmarcResult`, and
`AttachmentClass` are string enums in `enums.py`, giving stable, serialisable
identifiers.

### Detection flow

`DetectionEngine.detect(email)` does exactly three things:

1. Parse the raw bytes **once** into `MessageObservables` (`EmailParser`).
2. Run **every** detector **once** against those observables.
3. Return a `Detection` that also records the email's SHA-256.

Detectors never re-parse and never touch raw bytes — they operate purely on the
already-parsed observables, which is what makes adding a new rule cheap and
side-effect free.

---

## 4. The detector catalogue

Detectors are subclasses of the generic `Detector[T]` ABC. Each declares a
`DetectorName` and implements `detect(observables) -> Fired | Clear | Skipped`.
The engine's default set is assembled in `detectors/__init__.py` as
`DEFAULT_DETECTORS = BUILTIN_DETECTORS + EXTRA_DETECTORS`, so activating a new
rule is a one-line change there.

**Core detectors** (`detectors.py`):

| Name | Signal |
| --- | --- |
| `auth_failure` | SPF/DKIM/DMARC authentication failed or is missing. |
| `reply_to_divergence` | `Reply-To` domain diverges from the `From` domain. |
| `credential_url` | A link points at a credential-harvesting destination. |
| `display_name_spoof` | Display name impersonates a known brand. |
| `bec_no_payload` | Business-email-compromise pattern with no link/attachment. |

**Extra detectors** (`extra_detectors.py`):

| Name | Signal |
| --- | --- |
| `dangerous_attachment` | Executable / high-risk attachment type. |
| `attachment_extension_spoof` | Declared extension disagrees with real type. |
| `duplicate_header_conflict` | Conflicting duplicate headers (e.g. two `From`). |
| `nested_sender_mismatch` | Inner forwarded sender contradicts the outer one. |
| `deep_mime_nesting` | Suspiciously deep MIME structure. |
| `private_sender_ip` | Sender IP is in private/reserved space. |
| `raw_ip_url` | URL uses a raw IP address instead of a hostname. |
| `lookalike_domain` | Homoglyph / typosquat lookalike domain. |
| `high_abuse_tld` | Domain sits in a high-abuse TLD. |
| `image_only_body` | Body is a single image with no real text. |

Each extra detector ships with its own typed evidence and finding classes, so a
fired result always carries structured proof rather than a free-text reason.

---

## 5. The detection→investigation boundary

`agentic.Case` is a deliberately strict gate. Constructing a `Case` revalidates
three invariants and raises `ValueError` otherwise:

1. the email `file` name matches the detection's,
2. the email's SHA-256 matches the detection's recorded hash, and
3. the detection is actually `flagged`.

The original `Email` is retained across the boundary because `Detection` holds
attachment *metadata*, not raw attachment bytes — the sandbox needs the bytes.
This guarantees the investigation can only ever run on an email that
deterministic detection already flagged, on content that has not changed.

---

## 6. Agentic analysis (`agentic/analysis`)

`Analyzer.analyze(case)` always runs a **deterministic static baseline first**,
then hands control to a **bounded** agent that may select additional *typed*
tasks (`tools.py`) subject to `Policy`. The agent is an abstraction (`Agent`);
`LangChainAgent` is the concrete LangChain-backed implementation, and tests
substitute a fake.

All work that touches artifact bytes happens inside `DockerSandbox` (an
implementation of the `Sandbox` ABC). The container defined in `analysis/image/`
is intentionally minimal and locked down:

- Ubuntu 24.04, running as a **non-root** user,
- **no network**, **read-only filesystem**, capped resources,
- **no Docker socket** and no host shell,
- **deleted after every analysis**.

The model therefore never has direct access to Docker, the host filesystem, a
shell, or the network — it can only request typed tasks that the analyzer
executes on its behalf. YARA rules live in `image/rules/`; ClamAV signatures are
expected in `image/signatures/clamav/` (a `.gitkeep` marks the drop-in point).
If signatures are absent, the result records an antivirus **coverage gap** rather
than failing.

The result is an `Analysis` — a structured record of artifacts, matches,
observations, gaps, failures, and metrics (`analysis/models.py`).

---

## 7. Intelligence reporting (`agentic/intelligence`)

The intelligence layer converts a completed `Analysis` into an analyst-facing
`Report` **without ever asserting a maliciousness verdict or an action
decision**. The three collaborators:

- **`Reporter`** — drives the model to draft a structured `Report`.
- **`Validator`** — grounds every claim, indicator, and framework mapping against
  the analysis evidence; unsupported statements are rejected or flagged.
- **`Renderer`** — turns the validated `Report` into **deterministic** Markdown,
  so the same report always renders identically.

Reports are structured around three standard frameworks — the **Diamond Model**,
**MITRE ATT&CK** (backed by `catalog/attack.json`), and the **Cyber Kill Chain**
— plus claims, indicators, citations, and confidence levels (`models.py`). The
output is canonical JSON (`report.model_dump_json`) alongside the rendered
Markdown.

---

## 8. Batch reporting (`reporting/`)

`reporting/` is independent of the agentic stage and is used to evaluate
detection coverage over a corpus. `DetectionReport.build(records)` takes a batch
of `DetectionRecord`s and, as part of building, **automatically validates** that
every finding and its evidence are grounded in the parsed observables — callers
never invoke validation separately. The report exposes counts (discovered,
processed, unreadable, parse-failure, flagged/unflagged), the positive-detection
rate, a `summary()` string, `to_dict()`, and `write_json()`.

Because the honeypot corpus is entirely positively labelled, this measures
**positive-detection coverage only** — not precision or false-positive rate.
Unflagged samples mark coverage gaps for future detectors.

---

## 9. Dataset access (`dataset/`)

`PhishingPot(directory)` provides stable, read-only access to a corpus checkout:
`files()` returns every `*.eml` under the directory in sorted order, and
`read(path)` returns a frozen `PhishingEmail` with the bytes unchanged. The
dataset API is deliberately decoupled from detection — reading the corpus and
detecting on it are separate concerns.

---

## 10. Web console (`web/`)

A small Flask front end for the **detection stage only**. It has two modes:

- **Scan .eml** — upload a raw email; detection runs immediately (no model, no
  Docker) and the page shows the FLAGGED/CLEAR verdict, each fired detector with
  its severity/clause/typed evidence, an observables summary, skipped detectors
  with reasons, and the canonical `DetectionReport` JSON.
- **Preview report .md** — render a Markdown report through an allowlist
  sanitizer, to check output formatting before the agentic stage is wired in.

Uploads are held in memory only (never written to disk), capped at 25 MB, and the
app binds to `127.0.0.1`. It is a local development tool and is **not** hardened
for network exposure. `app.py` adds the repository root to `sys.path`, so it can
run from the `web/` directory.

---

## 11. Configuration & running

- **Python** 3.10+.
- **Install:** `python -m pip install -e .` (or use `requirements.txt`). The web
  console additionally needs Flask and `markdown`, both listed in
  `requirements.txt`.
- **Detection** needs no external services or credentials.
- **Agentic investigation** needs a local Docker daemon, the built image
  (`docker build -t onemail-analysis:latest agentic/analysis/image`), and a
  configured LangChain model. The bundled CLI uses DeepSeek:

  ```bash
  cp .env.example .env      # then set DEEPSEEK_API_KEY
  python scripts/investigate_email.py path/to/email.eml --output reports
  ```

- **Tests:** `python -m unittest discover -s tests -v`. Agentic tests use fakes
  and never call a real model; the Docker integration test skips unless the SDK,
  daemon, and image are present.

---

## 12. Cleanup applied to this snapshot

This tree was tidied from a working copy that had accumulated local cruft. The
following were removed or corrected; **no source behaviour was changed.**

- Deleted editor/OS/build cruft that does not belong in version control:
  `__MACOSX/`, all `.DS_Store` files, all `__pycache__/` directories and `.pyc`
  files, a stray `Archive.zip`, and an empty committed `.env`.
- Removed a junk scratch file (`detection/yourmom.py`) and two empty leftover
  directories (`detection/detection/`, `detection/agentic/`) that only contained
  stale bytecode caches.
- Excluded the 420 MB local `email/` sample dump from the source tree; the
  honeypot corpus belongs under `dataset/phishing_pot/email/`, which is now a
  documented, gitignored placeholder.
- Added `.env.example` (the real `.env` is secret and gitignored) and a
  `dataset/phishing_pot/README.md` explaining the corpus location.
- Tightened `.gitignore` so the same cruft cannot creep back.

### Known documentation gaps (left as-is, not code changes)

- `README.md` refers to `agentic/NOTES.md`, which is not present in this tree.
- The web section of `README.md` describes a root-level layout, whereas the app
  actually lives self-contained under `web/` (its `app.py` adds the repo root to
  `sys.path`, so it still runs). The bundled sample is
  `web/samples/sample-1-intelligence.md`.

These are content mismatches in the prose only and were left for a maintainer to
reconcile, since resolving them touches intent rather than structure.
