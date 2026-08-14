# OneMail

OneMail performs deterministic email threat detection followed by deeper agentic investigation.

## Architecture

- `detection/data_models/` defines detection data models.
- `detection/detection/` parses emails and applies deterministic rules.
- `agentic/` investigates emails already classified as malicious.
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

## Tests

The tests use the checked-out Phishing Pot corpus directly; they do not generate a synthetic dataset. Run from the repository root:

```bash
python -m unittest discover -s tests -v
```
