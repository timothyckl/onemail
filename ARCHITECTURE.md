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
│  ┌────────┐ │   analysis  → static baseline + reasoning-enabled LangChain planner
│  │analysis│ │              runs typed inspection/render/emulation tasks in Docker
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
├── .env.example           Template for the agentic stage's LM Studio connection
├── .gitignore
│
├── detection/             Stage 1 — deterministic detection
│   ├── engine.py            DetectionEngine: parse once, run all detectors
│   ├── parser.py            EmailParser: raw bytes → MessageObservables
│   ├── textnorm.py          Unicode normalization (homoglyph/entity folding)
│   ├── brands.py            Brand vocabulary + legitimate-domain map
│   ├── domains.py           Suffix-aware registrable-domain derivation
│   ├── qr.py                Optional QR-code decoding (quishing recovery)
│   ├── detectors/           The deterministic rules
│   │   ├── base.py            Detector ABC (typed, generic over Finding)
│   │   ├── detectors.py       5 core detectors
│   │   ├── lexicon.py         Multilingual phrase lexicons (data module)
│   │   ├── extra_detectors.py 10 additional detectors
│   │   ├── qr_detectors.py    QR-URL detector (quishing)
│   │   ├── brand_detectors.py Brand content-mismatch detector
│   │   ├── structural_detectors.py  4 structural lure detectors
│   │   └── freemail_detectors.py    Freemail-sender detector
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
│   ├── lmstudio.py          Role-specific local LM Studio configuration and status
│   ├── progress.py          Timed investigation events shared by CLI and web
│   ├── structured.py        Structured-output helpers for the model
│   ├── timeout.py           Bounded model-call timeouts
│   ├── analysis/            Static analysis in an isolated sandbox
│   │   ├── analyzer.py        Analyzer: deterministic baseline + agent loop
│   │   ├── agent.py           Agent ABC + reasoning-enabled LangChainAgent
│   │   ├── correlation.py     Local exact/fuzzy hash and indicator correlation
│   │   ├── virustotal.py      Optional host-side SHA-256 report broker
│   │   ├── sandbox.py         Sandbox ABC + DockerSandbox
│   │   ├── policy.py          Policy: what the agent is allowed to request
│   │   ├── tools.py           Typed tasks the agent may select
│   │   ├── models.py          Analysis result types
│   │   └── image/             The analysis container
│   │       ├── Dockerfile       Ubuntu 24.04, non-root, no network
│   │       ├── runner.py        In-container entry point
│   │       └── rules/base.yar   YARA rules
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
│   ├── phishing_pot/        Corpus location (email/ links to ../../email/phishing_pot)
│   ├── spamassassin/        Downloaded corpus archives (gitignored cache)
│   └── nazario/             Downloaded source mboxes (gitignored cache)
│
├── email/                 Evaluation corpora, one gitignored folder per corpus
│   └── {phishing_pot,easy_ham,easy_ham_2,hard_ham,spam,spam_2,nazario}/
│
├── scripts/               Runnable entry points (python -m scripts.*)
│   ├── detect_email.py          Detect one .eml
│   ├── detect_phishing_pot.py   Detect across the corpus
│   ├── read_phishing_pot.py     List corpus samples
│   ├── report_phishing_pot.py   Write a validated coverage report
│   ├── measure_detection.py     Per-corpus rates + per-detector fire/solo table
│   ├── detect_spamassassin.py   SpamAssassin ham/spam metrics + confusion matrix
│   ├── detect_nazario.py        Nazario per-source phishing recall
│   └── investigate_email.py     Full pipeline with Docker + LM Studio
│
├── tests/                 unittest suite
│   ├── test_detection.py
│   ├── test_phishing_pot.py       corpus coverage + recall floor
│   ├── test_corpus_gates.py       ham FP ceiling + Nazario floor (skip if absent)
│   ├── test_textnorm.py           Unicode normalization pipeline
│   ├── test_lexicon.py            phrase lexicon contracts + multilingual e2e
│   ├── test_brands.py             brand vocabulary + content mismatch
│   ├── test_structural_detectors.py  structural lure rules
│   ├── test_domains.py            registrable-domain derivation
│   ├── test_freemail.py           freemail rule + auth-pass semantics
│   ├── test_qr.py                 QR/quishing recovery
│   ├── test_ham.py                false-positive guard over tests/ham/
│   ├── ham/                       legitimate .eml fixtures (must stay clean)
│   ├── test_agentic.py            fakes only, never calls a real model
│   └── test_agentic_docker.py     skips unless Docker + image are present
│
└── web/                   Local Flask console for the detection stage
    ├── app.py
    ├── templates/index.html
    ├── static/{app.js,style.css}
    └── samples/sample-1-intelligence.md
```

> **Note on the evaluation corpora.** OneMail is exercised against tens of
> thousands of real `.eml` files. Those are *data*, not source, and are
> deliberately kept out of the repository (the `email/` and
> `dataset/phishing_pot/email/` trees are gitignored). `email/` holds one
> folder per corpus — `phishing_pot/` (honeypot phishing;
> `dataset/phishing_pot/email` is a symlink to it), the SpamAssassin public
> corpus (`easy_ham/`, `easy_ham_2/`, `hard_ham/`, `spam/`, `spam_2/`), and
> `nazario/` (the Nazario mboxes split into one `.eml` per message). The
> labelled ham/spam corpora are what precision is measured and gated on.

---

## 3. The type system (detection)

Everything in stage 1 is a small, frozen, dependency-light dataclass. This keeps
detection deterministic, cheap to construct in tests, and independent of the
agentic dependencies.

| Type | Role |
| --- | --- |
| `Email` | One email file: a `file` name and unmodified RFC 822 `content` bytes. |
| `MessageObservables` | Everything the parser extracts: subject/body, **normalized subject/body** (`normalized_subject`, `normalized_body_text` — Unicode-folded for phrase matching) plus obfuscation counts (`subject_confusable_count`, `body_combining_mark_count`), MIME depth, From/Reply-To domains (divergence compared on registrable domains), a **mailing-list marker** (`is_mailing_list`, from `List-Id`/`List-Post`/`Mailing-List`/`Precedence: list` — `List-Unsubscribe` and `Precedence: bulk` deliberately do not count, as bulk marketing and phishing add both freely), the display-name brand (matched against the folded name), SPF/DMARC results, URLs and URL hosts, **URLs recovered from QR-code images** (`image_urls`, also merged into `urls`), attachments, duplicate headers, nested senders, sender IPs, received timeline. |
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
`DEFAULT_DETECTORS = BUILTIN_DETECTORS + EXTRA_DETECTORS + QR_DETECTORS +
BRAND_DETECTORS + STRUCTURAL_DETECTORS + FREEMAIL_DETECTORS` (22 rules), so
activating a new rule is a one-line change there.

**Core detectors** (`detectors.py`):

| Name | Signal |
| --- | --- |
| `auth_failure` | SPF/DKIM/DMARC authentication failed or is missing. |
| `reply_to_divergence` | `Reply-To` registrable domain diverges from the `From` registrable domain (subdomains are the same registrant). Skips mailing-list traffic, where Reply-To rewriting is expected. |
| `credential_url` | A link to a host unrelated to the sender, paired with credential-action language. A lone generic token (`login`, `signin`, `log in`) never fires alone; a real phrase or two distinct matches is required. |
| `display_name_spoof` | Display name impersonates a known brand (matched on the Unicode-folded name, cleared via the brand's legitimate-domain map). |
| `bec_no_payload` | Business-email-compromise pattern with no link/attachment. |

**Extra detectors** (`extra_detectors.py`):

| Name | Signal |
| --- | --- |
| `dangerous_attachment` | Executable / high-risk attachment type. |
| `attachment_extension_spoof` | Declared extension disagrees with real type. |
| `duplicate_header_conflict` | Conflicting duplicate identity headers (e.g. two `From`). `Return-Path` is exempt: local re-delivery legitimately accumulates one per hop. |
| `nested_sender_mismatch` | Inner forwarded sender contradicts the outer one. |
| `deep_mime_nesting` | Suspiciously deep MIME structure. |
| `private_sender_ip` | The chain shows only private/reserved origin IPs and no public one. Loopback-only chains (fetchmail-style local re-delivery) are unobservable and skip. |
| `raw_ip_url` | URL uses a raw IP address instead of a hostname. |
| `lookalike_domain` | Homoglyph / typosquat lookalike domain. |
| `high_abuse_tld` | Domain sits in a high-abuse TLD. |
| `image_only_body` | Body is a single image with no real text. |

**QR detector** (`qr_detectors.py`):

| Name | Signal |
| --- | --- |
| `qr_url` | A QR code inside an image encodes a link to a domain unrelated to the sender. |

**Brand detector** (`brand_detectors.py`):

| Name | Signal |
| --- | --- |
| `brand_content_mismatch` | Message claims a known brand while the sender domain *and* every linked host are unrelated to it. Requires impersonation context — the brand in the subject or display name, or credential/urgency lure language — so a brand merely mentioned in running body text stays clear, and skips mailing-list traffic, where brands are discussed as news. |

**Structural lure detectors** (`structural_detectors.py`):

| Name | Signal |
| --- | --- |
| `subject_obfuscation` | Combining-mark or mixed-script homoglyph obfuscation in the subject (genuinely non-Latin mail stays clear). |
| `shared_hosting_url` | Link on an abused free-hosting / serverless / shortener platform unrelated to the sender, paired with lure language or a brand claim. |
| `advance_fee` | Prize / lottery / 419 vocabulary combined with a structural oddity (freemail sender, Reply-To divergence, no payload, or an unrelated link host). Skips mailing-list traffic, which quotes scams as news. |
| `gibberish_body` | Body padded with vowel-free filler tokens (CSS hex colours excluded) plus a link to an unrelated host. |

**Freemail detector** (`freemail_detectors.py`):

| Name | Signal |
| --- | --- |
| `freemail_sender` | Consumer-mailbox sender claiming a brand or using credential-action language. Skips mailing-list traffic: people post to lists from consumer mailboxes. |

Each detector ships with its own typed evidence and finding classes, so a fired
result always carries structured proof rather than a free-text reason.

### Text normalization, lexicons, and shared vocabulary

Phrase and brand rules never match raw text. `detection/textnorm.py` folds
HTML entities, NFKC/NFKD compatibility forms, combining marks, and a
conservative Cyrillic/Greek homoglyph map into plain lower-case Latin, so
`[Wallеt Suspеnded]`, `Aܿmܿaܿzܿon`, and mathematical-italic lures match their
plain spellings. The parser stores the folded text on the observables
(`normalized_subject`, `normalized_body_text`) together with obfuscation
counts, which the `subject_obfuscation` rule consumes.

Three static data modules back the rules:

- **`detectors/lexicon.py`** — `CREDENTIAL_LANGUAGE` (~120 phrases),
  `URGENCY_LANGUAGE` (~28), and `ADVANCE_FEE_LANGUAGE` (~36) across English,
  Portuguese, Spanish, French, German, Dutch, and Italian. Every entry is a
  fixed point of `textnorm.normalize` (unit-tested), so no phrase can be
  silently dead.
- **`brands.py`** — 60 brand names (crypto exchanges/wallets, Brazilian
  banking/retail/loyalty, card networks, tech, telecom, logistics) with
  left-token-bounded matching and a brand → legitimate-registered-domains map
  used to keep real brand mail clear.
- **`domains.py`** — `registered_domain()` with a vendored static suffix list:
  multi-label public suffixes (`co.uk`, `com.br`, …) plus shared-hosting
  platform suffixes (`firebaseapp.com`, `s3.amazonaws.com`, …) whose
  subdomains are separate tenants. Unlisted suffixes keep the original
  two-label rule. Every sender/link comparison in the detector set uses this
  one implementation, as does the reporting validator.

### Authentication semantics

SPF/DMARC **failure** fires `auth_failure`; a **pass is never exculpatory** —
attackers pass both on mailboxes they own, and most of the corpus passes SPF.
No detector consults authentication results to suppress a finding, and a
regression test (`test_freemail.py`) asserts that identical content produces
identical fired detectors with and without passing `Authentication-Results`.

### Precision against legitimate mail

Every precision rule above was landed against measurement, not intuition: the
engine is run over labelled corpora (SpamAssassin ham/spam, Nazario phishing,
Phishing Pot) and each false positive is attributed to the single detector
whose removal would un-flag the message (the *solo-cause* table printed by
`scripts/measure_detection.py`). A change ships only when the measured ham
gain clearly outweighs the measured phishing cost — e.g. requiring two
advance-fee phrases was evaluated and **rejected** (it cost 276 phishing
catches to save 18 ham messages), while skipping mailing-list traffic and
comparing registrable domains were accepted. The result on the SpamAssassin
ham corpus is a 44.99% → 2.19% false-positive reduction, traded against
roughly six points of corpus recall (single-signal catches: lone credential
tokens, contextless brand mentions, list Reply-To divergence).

Three gates keep both sides of that trade from regressing silently:
`tests/test_phishing_pot.py` (recall floor 0.72), `tests/test_corpus_gates.py`
(3% ham false-positive ceiling, 0.65 Nazario recall floor; both skip when the
local-only corpora are absent), and `tests/test_ham.py` (zero findings on the
fixture corpus, which includes the measured false-positive archetypes:
rewritten list Reply-To, loopback delivery chains, brand discussion, and an
advisory containing the word "login").

### QR / quishing recovery

"Quishing" hides the credential-harvesting URL inside an image so it never
appears in the text or headers that URL extraction reads. OneMail closes this
blind spot at **parse time**: `detection/qr.py` decodes QR codes from inline and
attached images and the parser records the recovered links in
`observables.image_urls`, **also merging them into `observables.urls`**. Two
things follow from that placement:

- The dedicated `qr_url` detector fires on the signal unique to QR delivery — an
  image-encoded link pointing off the sender's domain.
- Because the decoded URL is merged into `urls`, the **existing** URL rules
  (`credential_url`, `raw_ip_url`, `lookalike_domain`, `high_abuse_tld`) evaluate
  it for free, so a QR pointing at a punycode lookalike or a bare IP lights those
  up too.

Parse time is the correct boundary because the agentic sandbox only runs on
*already-flagged* emails; if a QR code were the only signal, a decode that lived
in the sandbox would never run. The image backend
(`opencv-python-headless`, the `qr` extra) is **optional** — with it absent,
decoding returns nothing and never raises, so core detection stays dependency
light. Decoding is bounded (image size and count caps) and purely passive:
images are decoded, never rendered, executed, or fetched.

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
then hands control to a **bounded** reasoning-enabled agent that may select
additional *typed* tasks (`tools.py`) subject to `Policy`. Task definitions
include a category, applicable formats, and strictly validated option ranges.
The agent is an abstraction (`Agent`); `LangChainAgent` is the concrete
LangChain-backed implementation, and tests substitute a fake.

All work that touches artifact bytes happens inside `DockerSandbox` (an
implementation of the `Sandbox` ABC). The container defined in `analysis/image/`
is intentionally minimal and locked down:

- Ubuntu 24.04, running as a **non-root** user,
- **no network**, **read-only filesystem**, capped resources,
- **no Docker socket** and no host shell,
- **deleted after every analysis**.

The model therefore never has direct access to Docker, the host filesystem, a
shell, or the network — it can only request typed tasks that the analyzer
executes on its behalf. YARA rules live in `image/rules/`. Available tasks cover
bounded recursive archive extraction, embedded carving, base64/hex decoding,
IOC extraction, Office/PDF/PE/script inspection, offline HTML/PDF/Office
rendering with OCR, symbolic script analysis, and Speakeasy CPU/API emulation.
Attachments are never executed natively.

The container runner emits a validated JSON-Lines progress protocol. Each tool
reports start, completion/failure, artifact, tool, and duration while it runs.
The same `ProgressTracker` also instruments planning, policy validation,
reporting, and cleanup.

After the container is removed, `SQLiteCorrelator` compares normalised
indicators, exact SHA-256 values, and bounded 64-bit similarity hashes with prior
local cases. Only normalised metadata is retained; raw email and attachment
bytes are not stored.

When `VIRUSTOTAL_API_KEY` is configured, the planner is additionally offered the
`virustotal_hash` tool. `VirusTotalClient` runs on the host rather than granting
the container network access. It performs API v3 `GET /files/{sha256}` lookups,
normalises and caches bounded responses, and enforces a minimum request interval.
It has no upload implementation. The queried hash is disclosed to VirusTotal;
missing reports and provider failures become explicit gaps.

The result is an `Analysis` — a structured record of parent/child artifacts,
matches, observations, gaps, failures, metrics, and correlation evidence
(`analysis/models.py`).

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
never invoke validation separately. Core-detector findings are reconstructed
field by field; findings from every other detector are grounded by
**re-running the pure detector** on the same observables and requiring an
identical finding, so tampered evidence is always reported. The report exposes
counts (discovered, processed, unreadable, parse-failure, flagged/unflagged),
the positive-detection rate, a `summary()` string, `to_dict()`, and
`write_json()`.

Because the honeypot corpus is entirely positively labelled, this measures
**positive-detection coverage only** — not precision or false-positive rate.
The corpus test enforces a recall floor (currently 0.72; the stage flags about
72%), while precision is measured on the SpamAssassin ham corpus (2.19%
false positives, gated at 3% by `tests/test_corpus_gates.py`) and guarded by
the `tests/ham/` fixture corpus on which no detector may fire. Unflagged samples mark coverage gaps for future detectors.

---

## 9. Dataset access (`dataset/`)

`PhishingPot(directory)` provides stable, read-only access to a corpus checkout:
`files()` returns every `*.eml` under the directory in sorted order, and
`read(path)` returns a frozen `PhishingEmail` with the bytes unchanged. The
dataset API is deliberately decoupled from detection — reading the corpus and
detecting on it are separate concerns.

---

## 10. Web console (`web/`)

A small Flask front end with two modes:

- **Scan .eml** — detection runs immediately and shows the FLAGGED/CLEAR verdict,
  findings, observables, skipped detectors, and canonical `DetectionReport`.
  Flagged messages can start an asynchronous LM Studio + Docker investigation.
- **Preview report .md** — render a Markdown report through an allowlist
  sanitizer independently of the investigation pipeline.

Investigations run as bounded, memory-only background jobs. The browser polls a
same-origin protected status endpoint and displays the current stage, total
elapsed time, each step's duration, and nested live container activity. Completed
jobs retain their timeline alongside the final report and expire from memory
after one hour.

Uploads are held in memory only (apart from the sandbox's short-lived read-only
input file), capped at 25 MB, and the app binds to `127.0.0.1`. It is a local
development tool and is **not** hardened for network exposure. `app.py` adds the
repository root to `sys.path`, so it can run from the `web/` directory.

---

## 11. Configuration & running

- **Python** 3.10+.
- **Install:** `python -m pip install -e .` (or use `requirements.txt`). The web
  console additionally needs Flask and `markdown`, both listed in
  `requirements.txt`.
- **Detection** needs no external services or credentials. QR/quishing recovery
  is an optional extra: `python -m pip install "onemail[qr]"`.
- **Agentic investigation** needs a local Docker daemon, the built image
  (`docker build -t onemail-analysis:latest agentic/analysis/image`), and a
  LM Studio's local OpenAI-compatible server and configured model. Planning
  uses medium reasoning by default while report drafting keeps reasoning off:

  ```bash
  cp .env.example .env
  python scripts/investigate_email.py path/to/email.eml --output reports
  ```

- **Tests:** `python -m unittest discover -s tests -v`. The corpus suite
  enforces the detection recall floor, and `test_ham.py` enforces zero
  false positives on the legitimate fixtures in `tests/ham/` — any new
  detector or lexicon entry must keep both green. Agentic tests use fakes
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

A later pass reorganised the evaluation data and reconciled the remaining
prose gaps:

- `email/` became the single home for all evaluation corpora (one gitignored
  folder per corpus), with `dataset/phishing_pot/email` a symlink into it;
  generated corpus reports and downloaded archives are gitignored.
- The web console section of `README.md` now describes the actual `web/`
  layout, and the stale `agentic/NOTES.md` reference was removed.
- Corpus measurement moved from ad-hoc runs into `scripts/measure_detection.py`
  plus the regression gates in `tests/test_corpus_gates.py`.
