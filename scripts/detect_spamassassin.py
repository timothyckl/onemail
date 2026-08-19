"""Evaluate the deterministic detection engine on the SpamAssassin public corpus."""

import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

from detection import DetectionEngine, Email
from detection.data_models import FiredResult

CORPORA: Tuple[Tuple[str, str], ...] = (
    ("easy_ham", "ham"),
    ("easy_ham_2", "ham"),
    ("hard_ham", "ham"),
    ("spam", "spam"),
    ("spam_2", "spam"),
)


def corpus_files(directory: Path) -> Tuple[Path, ...]:
    """Return message files in stable order, excluding the 'cmds' artefact."""

    return tuple(
        sorted(
            path
            for path in directory.iterdir()
            if path.is_file() and path.name != "cmds"
        )
    )


def main() -> None:
    root = Path("email")
    engine = DetectionEngine()

    per_corpus: Dict[str, Counter] = {}
    detector_fires: Dict[str, Counter] = {"ham": Counter(), "spam": Counter()}
    findings_per_flagged: Dict[str, List[int]] = {"ham": [], "spam": []}
    errors: List[Tuple[str, str]] = []

    started = time.perf_counter()
    for name, label in CORPORA:
        stats = Counter()
        for file in corpus_files(root / name):
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
                findings_per_flagged[label].append(len(detection.findings))
                for result in detection.detector_results:
                    if isinstance(result, FiredResult):
                        detector_fires[label][result.detector.value] += 1
        per_corpus[name] = stats
    elapsed = time.perf_counter() - started

    print("Per-corpus results")
    print(f"  {'corpus':<12} {'label':<5} {'total':>6} {'flagged':>8} {'rate':>8} {'errors':>7}")
    totals = {"ham": Counter(), "spam": Counter()}
    for name, label in CORPORA:
        stats = per_corpus[name]
        totals[label] += stats
        rate = stats["flagged"] / stats["total"] if stats["total"] else 0.0
        print(
            f"  {name:<12} {label:<5} {stats['total']:>6} {stats['flagged']:>8}"
            f" {rate:>7.2%} {stats['error']:>7}"
        )

    ham, spam = totals["ham"], totals["spam"]
    tp = spam["flagged"]
    fn = spam["total"] - spam["flagged"] - spam["error"]
    fp = ham["flagged"]
    tn = ham["total"] - ham["flagged"] - ham["error"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if tp + tn + fp + fn else 0.0

    print("\nConfusion matrix (spam = positive class)")
    print(f"  TP={tp}  FN={fn}  FP={fp}  TN={tn}")
    print("\nOverall metrics")
    print(f"  precision          {precision:.4f}")
    print(f"  recall             {recall:.4f}")
    print(f"  f1                 {f1:.4f}")
    print(f"  accuracy           {accuracy:.4f}")
    print(f"  ham flag rate      {fp / ham['total']:.4%}")
    print(f"  spam flag rate     {tp / spam['total']:.4%}")

    print("\nDetector fires on flagged spam")
    for detector, count in detector_fires["spam"].most_common():
        print(f"  {detector:<40} {count:>6}")
    print("\nDetector fires on flagged ham (false-positive drivers)")
    for detector, count in detector_fires["ham"].most_common():
        print(f"  {detector:<40} {count:>6}")

    for label in ("spam", "ham"):
        values = findings_per_flagged[label]
        if values:
            print(
                f"\nFindings per flagged {label}: "
                f"mean={sum(values) / len(values):.2f} max={max(values)}"
            )

    if errors:
        print(f"\nUnprocessable messages: {len(errors)}")
        for file, error in errors[:10]:
            print(f"  {file}: {error}")

    total = ham["total"] + spam["total"]
    print(f"\nProcessed {total} messages in {elapsed:.1f}s ({total / elapsed:.0f} msg/s)")


if __name__ == "__main__":
    main()
