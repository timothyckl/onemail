# OneMail

OneMail performs deterministic email threat detection followed by deeper agentic investigation.

## Architecture

- `detection/data_models/` defines detection data models.
- `detection/` parses emails and applies deterministic rules.
- `agentic/analysis/` performs bounded inspection, rendering, and emulation of flagged emails in an isolated container.
- `agentic/intelligence/` drafts evidence-grounded analyst reports.
- `tests/` contains the project test suite.

Initial detection is always deterministic. Agentic analysis does not decide whether an email is malicious.

## Detection

1. Receive raw email bytes as `Email`.
2. Parse headers, body, URLs, authentication results, and attachment metadata.
   Subject and body text are additionally **Unicode-normalized** (HTML entities,
   homoglyphs, combining marks, and mathematical letters folded to plain
   lower-case Latin) so obfuscated text matches what a human reads.
3. Run each deterministic detector against the parsed observables.
4. Collect fired, clear, and skipped detector results.
5. Return a `Detection` indicating whether the email was flagged.

The default detector set contains 22 rules across six groups: core header and
URL rules, structural MIME/attachment rules, QR ("quishing") recovery, brand
impersonation (a 60-brand vocabulary with a legitimate-domain map, applied to
display names and message content), structural lures (subject obfuscation,
abused free-hosting and shortener platforms, advance-fee/prize language,
gibberish body padding), and a freemail-sender rule. Phrase matching uses
multilingual lexicons (English, Portuguese, Spanish, French, German, Dutch,
Italian), and sender/link comparisons use a suffix-aware registrable-domain
derivation (`example.com.br` and `tenant.firebaseapp.com` are handled
correctly). SPF/DMARC *failure* is a signal; a *pass* is never exculpatory.

```python
from detection import DetectionEngine, Email

email = Email(file="message.eml", content=raw_email_bytes)
result = DetectionEngine().detect(email)

print(result.flagged)
print(result.findings)
```

Runnable example:

```bash
python -m scripts.detect_email dataset/phishing_pot/email/sample-2.eml
```

## Phishing Pot Dataset

`dataset/phishing_pot/` contains real phishing `.eml` samples from honeypots. OneMail reads samples from `dataset/phishing_pot/email/` without modifying their bytes.

All samples are labelled `"phishing"`, so the corpus measures positive detection coverage only, not precision or false-positive rate.

The deterministic stage currently flags about 79% of the corpus, and
`tests/test_phishing_pot.py` enforces a recall floor (currently 0.75) so
coverage cannot silently regress. Precision is guarded separately by a small
legitimate-mail fixture corpus in `tests/ham/`, on which no detector may fire.
Remaining unflagged samples represent coverage gaps for future detector
improvements.

The dataset API is independent of detection:

```python
from dataset import PhishingPot

phishing_pot = PhishingPot("dataset/phishing_pot/email")
for file in phishing_pot.files():
    email = phishing_pot.read(file)
    print(email.file, email.label)
```

Runnable example:

```bash
python -m scripts.read_phishing_pot
```

Run the simple dataset-to-detection example from the repository root:

```bash
python -m scripts.detect_phishing_pot
```

Reporting runs only after detection is complete. `DetectionReport.build()`
automatically checks that every finding and its evidence are grounded in the parsed email observables. Validation issues are included in summaries and JSON
reports; callers do not need to invoke validation separately.

```python
from reporting import DetectionReport

report = DetectionReport.build(records)
print(report.summary())
report.write_json("phishing-pot-report.json")
```

Runnable example:

```bash
python -m scripts.report_phishing_pot
```

## Agentic Investigation

Only flagged detections can form a `Case`. The original email is retained at
this boundary because `Detection` contains attachment metadata rather than raw
attachment bytes.

```python
from agentic import Case

case = Case(email=email, detection=result)
```

`Analyzer` always performs a deterministic static baseline, then lets a bounded
LangChain agent select additional typed tasks for deep inspection, offline
rendering, decoding, carving, IOC extraction, or emulation. The model cannot
access Docker, the host filesystem, a shell, or the network directly.

```python
from agentic.analysis import Analyzer, DockerSandbox, LangChainAgent

model = ...  # Caller-supplied LangChain chat model.
agent = LangChainAgent(model)
analyzer = Analyzer(
    sandbox=lambda case, limits: DockerSandbox(case, limits),
    agent=agent,
)
analysis = analyzer.analyze(case)
```

### Docker

Build the isolated investigation image:

```bash
docker build -t onemail-analysis:latest agentic/analysis/image
```

The Ubuntu 24.04 container runs as a non-root user with no network, a read-only
filesystem, limited resources, and no Docker socket. Containers are deleted
after each analysis. Typed tools support bounded recursive archive extraction,
file carving and decoding, Office/PDF/PE/script inspection, offline document
rendering with OCR, and Speakeasy PE emulation. Samples are never executed
natively. The runner streams structured progress events for every container
action, including its status and duration.

After sandbox analysis, a local SQLite correlation store compares normalised
indicators, exact hashes, and 64-bit similarity hashes with prior investigations.
It never stores raw email or attachment bytes. Configure its location with
`ONEMAIL_CORRELATION_DB`.

Optionally set `VIRUSTOTAL_API_KEY` to offer the planner a typed
`virustotal_hash` enrichment task. This host-side broker queries existing
VirusTotal file reports by SHA-256, caches bounded normalised results, and
throttles requests. It never uploads email or attachment bytes. The queried hash
is disclosed to VirusTotal; missing reports, timeouts, and rate limits are
recorded as investigation gaps.

The intelligence layer consumes structured `Analysis`, validates every claim
and framework mapping against evidence, and emits canonical JSON plus
deterministically rendered Markdown.

```python
from agentic.intelligence import Renderer, Reporter

report = Reporter(model, name="configured-model").report(analysis)
json_report = report.model_dump_json(indent=2)
markdown_report = Renderer().render(report)
```

The report uses the Diamond Model, MITRE ATT&CK, and the Cyber Kill Chain. It
contains no maliciousness verdict or action decision. Deferred capabilities and
provider placeholders are recorded in `agentic/NOTES.md`.

### End-to-End Example

The caller supplies a configured LangChain chat model. Only emails flagged by
the deterministic detection stage proceed to sandboxed analysis.

```python
from pathlib import Path

from langchain_core.language_models import BaseChatModel

from agentic import Case
from agentic.analysis import Analyzer, DockerSandbox, LangChainAgent
from agentic.intelligence import Renderer, Reporter
from detection import DetectionEngine, Email


def investigate(path: Path, model: BaseChatModel) -> None:
    email = Email(file=path.name, content=path.read_bytes())
    detection = DetectionEngine().detect(email)

    if not detection.flagged:
        print("Email was not flagged; agentic investigation was not started.")
        return

    case = Case(email=email, detection=detection)
    analyzer = Analyzer(
        sandbox=lambda item, limits: DockerSandbox(item, limits),
        agent=LangChainAgent(model),
    )
    analysis = analyzer.analyze(case)

    report = Reporter(model, name="configured-model").report(analysis)
    Path("email-intelligence.json").write_text(
        report.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    Path("email-intelligence.md").write_text(
        Renderer().render(report),
        encoding="utf-8",
    )
```

Before calling `investigate()`, build `onemail-analysis:latest`, start the local
Docker daemon, and instantiate `model` with the approved LangChain provider.

### LM Studio

The included web and command-line workflows use LM Studio's local
OpenAI-compatible API for both planning and reporting. Start LM Studio's local
server, load the configured model, then copy the example configuration:

```bash
cp .env.example .env
python scripts/investigate_email.py path/to/email.eml --output reports
```

The default endpoint is `http://127.0.0.1:1234/v1` and the default model is
`qwen/qwen3.6-35b-a3b`. Set `LMSTUDIO_BASE_URL` and `LMSTUDIO_MODEL`, or pass
`--base-url` and `--model`, to override them. No external API key is required;
`LMSTUDIO_API_KEY=lm-studio` is a local placeholder required by the OpenAI
client. Investigation planning defaults to medium reasoning, a 300-second model
timeout, and 16,384 tokens. Report drafting keeps reasoning disabled with an
8,192-token budget so schema-constrained output completes predictably. Configure
these independently with the `LMSTUDIO_PLANNER_*` and `LMSTUDIO_REPORTER_*`
variables in `.env.example`. `ONEMAIL_ANALYSIS_TIMEOUT` controls the overall
analysis deadline. Planning and reporting both use LM Studio's native
JSON-schema response format.

Install the Python dependencies with:

```bash
python -m pip install -e .
```

OneMail requires Python 3.10 or newer. `requirements.txt` contains the same
runtime dependency constraints for environments that do not use editable
installs.

## Tests

The corpus tests use the checked-out Phishing Pot samples directly and enforce
the detection recall floor. `tests/ham/` holds legitimate fixtures written to be
adversarial for the detection rules (brand password resets with credential
language, CDN-backed newsletters, freemail personal mail); `tests/test_ham.py`
asserts that zero detectors fire on them. Unit suites cover the normalization
pipeline (`test_textnorm.py`), phrase lexicons (`test_lexicon.py`), brand rules
(`test_brands.py`), structural lure detectors (`test_structural_detectors.py`),
registrable-domain derivation (`test_domains.py`), and the freemail rule plus
auth-pass semantics (`test_freemail.py`). Agentic unit
tests use safe in-memory messages plus fake models and sandboxes; they never call
a real model. Run from the repository root:

```bash
python -m unittest discover -s tests -v
```

The Docker integration test skips unless the Docker SDK, daemon, and
`onemail-analysis:latest` image are available. Build the image first to exercise
the real sandbox path.

Install the optional fixture-generation dependencies with:

```bash
python -m pip install -e ".[dev]"
```

The agentic fixture generator stages the complete set before publishing it:

```bash
python tests/agentic_test_data/make_agentic_samples.py OUTPUT_DIR
```

# OneMail web console

A small Flask front end for OneMail. Upload a raw `.eml` file and the
deterministic detection stage runs automatically, showing the verdict, grounded
findings, an observables summary, and the canonical `DetectionReport` JSON.
Flagged messages can then start the LM Studio and Docker investigation. The web
console shows the current pipeline stage, total elapsed time, per-step duration,
and live container activity before presenting the final report. A second mode
renders uploaded Markdown reports independently of the pipeline.

## Layout

These files belong at the OneMail repository root, next to `detection/`,
`reporting/`, and `dataset/`:

```
app.py                 # the Flask application
requirements-web.txt   # Flask + markdown
templates/index.html   # page
static/style.css       # styling
static/app.js          # upload / drag-drop / rendering
samples/sample-report.md   # bundled report for the .md preview test
```

## Run it

From the repository root:

```bash
python -m pip install -e .                 # OneMail's own dependencies
python -m pip install -r requirements-web.txt
python app.py
```

Then open <http://127.0.0.1:5000>.

`app.py` adds the repository root to `sys.path`, so it can be launched from
anywhere, but keeping it at the root is simplest.

## Two modes

**Scan .eml** — drop or choose a raw email. Detection runs immediately (no
model, no Docker). You get:

- a FLAGGED / CLEAR verdict with file name and SHA-256,
- each fired detector with its severity, whether it is heuristic, its clause,
  and the typed evidence behind it,
- an observables summary (From / Reply-To domains, SPF, DMARC, URL and
  attachment counts, MIME depth, URL hosts),
- skipped detectors and their reasons,
- the canonical `DetectionReport` JSON.

If the repo's own corpus is present (`email/` or
`dataset/phishing_pot/email/`), one-click chips scan bundled samples such as
`sample-2.eml`.

**Preview report .md** — drop or choose a Markdown file, or load the bundled
`samples/sample-report.md`. It renders the report the way the console will
display analyst output. Use it to sanity-check formatting independent of the
detection pipeline. The bundled sample mirrors the analyst-focused section structure emitted by
`agentic.intelligence.Renderer`, including key findings, analysed files,
framework mappings, limitations, and a collapsible evidence appendix.

## Notes

- Uploads are read in memory and never written to disk. Max upload size is
  25 MB (`app.config["MAX_CONTENT_LENGTH"]`).
- Rendered Markdown is passed through an allowlist sanitizer, so an uploaded
  report cannot inject scripts or `javascript:` links into the page.
- `markdown` is the preferred renderer; if it is not installed the app falls
  back to a small built-in Markdown subset so the preview still works.
- This is a local development tool bound to `127.0.0.1`. It is not hardened for
  public deployment — do not expose it to a network without adding
  authentication and running behind a production WSGI server.