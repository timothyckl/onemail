# Data Models

Standalone, stdlib-only dataclasses for deterministic email detection.

## Model Flow

```text
EmailInput
  -> MessageObservables
  -> DetectorResult per detector
  -> MessageDetection
```

The package defines data models only. It does not parse email, run detectors, or create reports.

## Modules

- `enums.py`: detector, status, severity, authentication, and attachment values
- `input.py`: raw email input
- `observables.py`: facts extracted from email bytes
- `evidence.py`: detector-specific evidence
- `findings.py`: detector-specific findings
- `results.py`: fired, clear, and skipped outcomes
- `outcome.py`: final per-message detection result

## Invariants

- Models are immutable.
- A fired result requires a matching finding.
- A skipped result requires a reason.
- `MessageDetection` requires one result per detector.
- `findings`, `skipped`, and `flagged` are derived values.
- `None` means a value was not observed; it is not a false or zero result.

## Example

```python
from data_models import (
    ClearResult,
    DetectorName,
    MessageDetection,
    MessageObservables,
)

observables = MessageObservables(from_domain="sender.example")
results = tuple(ClearResult(detector=name) for name in DetectorName)

detection = MessageDetection(
    file="message.eml",
    observables=observables,
    detector_results=results,
)

assert detection.flagged is False
```
