# OneMail

OneMail performs deterministic email threat detection followed by deeper agentic investigation.

## Architecture

- `detection/data_models/` defines detection data models.
- `detection/detection/` parses emails and applies deterministic rules.
- `agentic/` investigates emails already classified as malicious.
- `tests/` contains the project test suite.

Initial detection is always deterministic. Agentic analysis does not decide whether an email is malicious.

## Detection

1. Receive raw email bytes as `EmailInput`.
2. Parse headers, body, URLs, authentication results, and attachment metadata.
3. Run each deterministic detector against the parsed observables.
4. Collect fired, clear, and skipped detector results.
5. Return a `MessageDetection` indicating whether the email was flagged.

```python
from data_models import EmailInput
from detection import DetectionEngine

email = EmailInput(file="message.eml", content=raw_email_bytes)
result = DetectionEngine().detect(email)

print(result.flagged)
print(result.findings)
```

## Tests

Run from the repository root:

```bash
PYTHONPATH=detection python3 -m unittest discover -s tests -v
```
