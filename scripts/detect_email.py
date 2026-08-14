"""Run deterministic detection over one EML file."""

import argparse
from pathlib import Path
from typing import Optional, Sequence

from detection import Detection, DetectionEngine, Email


def detect_email(file: Path) -> Detection:
    """Read and detect one email without changing its bytes."""

    email = Email(file=file.as_posix(), content=file.read_bytes())
    return DetectionEngine().detect(email)


def main(arguments: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="path to an EML file")
    options = parser.parse_args(arguments)

    result = detect_email(options.file)
    print(f"Flagged: {result.flagged}")
    for finding in result.findings:
        print(f"{finding.detector.value}: {finding.clause}")


if __name__ == "__main__":
    main()
