"""Write a validated JSON report for Phishing Pot detections."""

from pathlib import Path

from dataset import PhishingPot
from detection import DetectionEngine
from reporting import DetectionReport
from scripts.detect_phishing_pot import detect


def build_report() -> DetectionReport:
    """Complete detection before building the separate report."""

    phishing_pot = PhishingPot(Path("dataset/phishing_pot/email"))
    records = detect(phishing_pot, DetectionEngine())
    return DetectionReport.build(records)


def main() -> None:
    output = Path("phishing-pot-report.json")
    report = build_report()
    report.write_json(output)
    print(report.summary())
    print(f"Report written to: {output}")


if __name__ == "__main__":
    main()
