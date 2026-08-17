# OneMail

OneMail performs deterministic email threat detection followed by deeper agentic investigation.

## Architecture

- `detection/data_models/` defines detection data models.
- `detection/` parses emails and applies deterministic rules.
- `agentic/analysis/` performs static analysis of flagged emails in an isolated container.
- `agentic/intelligence/` drafts evidence-grounded analyst reports.
- `tests/` contains the project test suite.

Initial detection is always deterministic. Agentic analysis does not decide whether an email is malicious.

## Detection

1. Receive raw email bytes as `Email`.
2. Parse headers, body, URLs, authentication results, and attachment metadata.
3. Run each deterministic detector against the parsed observables.
4. Collect fired, clear, and skipped detector results.
5. Return a `Detection` indicating whether the email was flagged.

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

Current deterministic detectors cover a narrow set of phishing signals.
Unflagged samples represent coverage gaps for future detector improvements.

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
LangChain agent select additional typed tasks. The model cannot access Docker,
the host filesystem, a shell, or the network directly.

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

Build the static-analysis image:

```bash
docker build -t onemail-analysis:latest agentic/analysis/image
```

The Ubuntu 24.04 container runs as a non-root user with no network, a read-only
filesystem, limited resources, and no Docker socket. Containers are deleted
after each analysis.

ClamAV requires signatures in `agentic/analysis/image/signatures/clamav/`.
Without them, the report records an antivirus coverage gap.

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

### DeepSeek

The included command-line workflow uses `ChatDeepSeek` with JSON output for both
planning and reporting:

```bash
export DEEPSEEK_API_KEY="your-key"
python scripts/investigate_email.py path/to/email.eml --output reports
```

Set `DEEPSEEK_MODEL` or pass `--model` to override the default `deepseek-chat`.
The prompts include the expected JSON schema and a minimal valid example because
DeepSeek requires explicit JSON instructions. Empty or malformed JSON is retried
once within the original model-call timeout. OneMail does not use DeepSeek's
strict function-calling beta because its accepted schema subset excludes the
`maxLength` and `maxItems` constraints used to bound OneMail output.

Install the Python dependencies with:

```bash
python -m pip install -e .
```

OneMail requires Python 3.10 or newer. `requirements.txt` contains the same
runtime dependency constraints for environments that do not use editable
installs.

## Tests

The corpus tests use the checked-out Phishing Pot samples directly. Agentic unit
tests use safe in-memory messages plus fake models and sandboxes; they never call
a real model. Run from the repository root:

```bash
python -m unittest discover -s tests -v
```

The Docker integration test skips unless the Docker SDK, daemon, and
`onemail-analysis:latest` image are available. Build the image first to exercise
the real sandbox path.
