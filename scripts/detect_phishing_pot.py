"""Demonstrate deterministic detection over the Phishing Pot dataset."""

from pathlib import Path
from typing import Tuple

from dataset import PhishingPot
from detection import DetectionEngine, Email
from reporting import DetectionRecord, DetectionReport


def detect(
    phishing_pot: PhishingPot,
    engine: DetectionEngine,
) -> Tuple[DetectionRecord, ...]:
    """Run only the deterministic detection stage over the dataset."""

    records = []
    for file in phishing_pot.files():
        try:
            email = phishing_pot.read(file)
        except OSError as error:
            records.append(
                DetectionRecord.unreadable(
                    file=file.as_posix(),
                    label=phishing_pot.label,
                    error=error,
                )
            )
            continue

        detection = engine.detect(
            Email(file=email.file, content=email.content)
        )
        records.append(DetectionRecord.detected(email.label, detection))
    return tuple(records)


def main() -> None:
    phishing_pot = PhishingPot(Path("dataset/phishing_pot/email"))
    records = detect(phishing_pot, DetectionEngine())

    # Reporting is post-detection and cannot affect deterministic outcomes.
    report = DetectionReport.build(records)
    print(report.summary())


if __name__ == "__main__":
    main()
