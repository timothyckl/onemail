"""Measure deterministic precision and recall across every local corpus.

Runs the engine over the labelled corpora under ``email/`` and prints the
numbers that gate precision work: per-corpus flag rates, per-detector fire
counts by label, and the solo-cause table (messages whose flag would vanish
if one detector were removed - the direct false-positive or recall driver).
"""

import time
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, Tuple

from detection import DetectionEngine, Email
from detection.data_models import FiredResult

CORPORA: Tuple[Tuple[str, str], ...] = (
    ("easy_ham", "ham"),
    ("easy_ham_2", "ham"),
    ("hard_ham", "ham"),
    ("spam", "spam"),
    ("spam_2", "spam"),
    ("phishing_pot", "phish"),
    ("nazario", "phish"),
)


def corpus_files(directory: Path) -> Iterable[Path]:
    """Yield message files in stable order, excluding corpus artefacts."""

    for path in sorted(directory.iterdir()):
        if path.is_file() and path.name != "cmds" and path.suffix != ".csv":
            yield path


def main() -> None:
    root = Path("email")
    engine = DetectionEngine()

    per_corpus: Dict[str, Counter] = {}
    fires: Dict[str, Counter] = {}
    solo: Dict[str, Counter] = {}

    started = time.perf_counter()
    for name, label in CORPORA:
        directory = root / name
        if not directory.is_dir():
            print(f"  (skipping {name}: not downloaded)")
            continue
        stats = Counter()
        for file in corpus_files(directory):
            stats["total"] += 1
            detection = engine.detect(
                Email(file=file.as_posix(), content=file.read_bytes())
            )
            if not detection.flagged:
                continue
            stats["flagged"] += 1
            fired = [
                result.detector.value
                for result in detection.detector_results
                if isinstance(result, FiredResult)
            ]
            for detector in fired:
                fires.setdefault(label, Counter())[detector] += 1
            if len(fired) == 1:
                solo.setdefault(label, Counter())[fired[0]] += 1
        per_corpus[name] = stats
    elapsed = time.perf_counter() - started

    print("Per-corpus results")
    print(f"  {'corpus':<14} {'label':<6} {'total':>6} {'flagged':>8} {'rate':>8}")
    totals: Dict[str, Counter] = {}
    for name, label in CORPORA:
        if name not in per_corpus:
            continue
        stats = per_corpus[name]
        totals.setdefault(label, Counter()).update(stats)
        rate = stats["flagged"] / stats["total"] if stats["total"] else 0.0
        print(
            f"  {name:<14} {label:<6} {stats['total']:>6}"
            f" {stats['flagged']:>8} {rate:>7.2%}"
        )
    print("\nBy label")
    for label, stats in totals.items():
        rate = stats["flagged"] / stats["total"] if stats["total"] else 0.0
        kind = "false-positive rate" if label == "ham" else "recall"
        print(f"  {label:<6} {stats['flagged']:>6}/{stats['total']:<6} {rate:>7.2%}  ({kind})")

    detectors = sorted(
        set().union(*(counter.keys() for counter in fires.values()))
        if fires
        else ()
    )
    print("\nPer-detector fires (solo-cause in parentheses)")
    print(f"  {'detector':<28} " + " ".join(f"{label:>16}" for label in fires))
    for detector in detectors:
        cells = " ".join(
            f"{fires[label].get(detector, 0):>10}"
            f" ({solo.get(label, Counter()).get(detector, 0):>3})"
            for label in fires
        )
        print(f"  {detector:<28} {cells}")

    total = sum(stats["total"] for stats in per_corpus.values())
    print(f"\nProcessed {total} messages in {elapsed:.1f}s ({total / elapsed:.0f} msg/s)")


if __name__ == "__main__":
    main()
