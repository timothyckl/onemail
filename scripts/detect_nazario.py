"""Evaluate the deterministic detection engine on the Nazario phishing corpus."""

import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

from detection import DetectionEngine, Email
from detection.data_models import FiredResult


def source_of(file: Path) -> str:
    """Return the originating mbox name for one extracted message."""

    return file.stem.rsplit("-", 1)[0]


def main() -> None:
    root = Path("email/nazario")
    engine = DetectionEngine()

    per_source: Dict[str, Counter] = {}
    detector_fires: Counter = Counter()
    findings_per_flagged: List[int] = []
    errors: List[Tuple[str, str]] = []

    files = tuple(sorted(path for path in root.iterdir() if path.suffix == ".eml"))
    started = time.perf_counter()
    for file in files:
        stats = per_source.setdefault(source_of(file), Counter())
        stats["total"] += 1
        try:
            detection = engine.detect(
                Email(file=file.as_posix(), content=file.read_bytes())
            )
        except Exception as error:  # noqa: BLE001 - survey run
            stats["error"] += 1
            errors.append((file.as_posix(), repr(error)))
            continue
        if detection.flagged:
            stats["flagged"] += 1
            findings_per_flagged.append(len(detection.findings))
            for result in detection.detector_results:
                if isinstance(result, FiredResult):
                    detector_fires[result.detector.value] += 1
    elapsed = time.perf_counter() - started

    print("Per-source results (all messages are labelled phishing)")
    print(f"  {'source':<22} {'total':>6} {'flagged':>8} {'recall':>8} {'errors':>7}")
    totals = Counter()
    for source in sorted(per_source):
        stats = per_source[source]
        totals += stats
        scored = stats["total"] - stats["error"]
        recall = stats["flagged"] / scored if scored else 0.0
        print(
            f"  {source:<22} {stats['total']:>6} {stats['flagged']:>8}"
            f" {recall:>7.2%} {stats['error']:>7}"
        )

    scored = totals["total"] - totals["error"]
    recall = totals["flagged"] / scored if scored else 0.0
    print("\nOverall")
    print(f"  messages           {totals['total']}")
    print(f"  flagged            {totals['flagged']}")
    print(f"  missed             {scored - totals['flagged']}")
    print(f"  recall             {recall:.4f}")

    print("\nDetector fires on flagged messages")
    for detector, count in detector_fires.most_common():
        print(f"  {detector:<40} {count:>6}")

    if findings_per_flagged:
        print(
            f"\nFindings per flagged message: "
            f"mean={sum(findings_per_flagged) / len(findings_per_flagged):.2f}"
            f" max={max(findings_per_flagged)}"
        )

    if errors:
        print(f"\nUnprocessable messages: {len(errors)}")
        for file, error in errors[:10]:
            print(f"  {file}: {error}")

    print(
        f"\nProcessed {totals['total']} messages in {elapsed:.1f}s"
        f" ({totals['total'] / elapsed:.0f} msg/s)"
    )


if __name__ == "__main__":
    main()
