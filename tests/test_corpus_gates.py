"""Precision-phase regression gates over the local evaluation corpora.

The Phishing Pot floor (``test_phishing_pot.py``) guards recall on the
primary corpus. These gates guard the other side of the trade: the
SpamAssassin ham false-positive rate and the Nazario recall floor. Both
corpora are local-only downloads (see ``scripts/detect_spamassassin.py``
and ``scripts/detect_nazario.py``), so the gates skip cleanly - like the
Docker-dependent tests - when a corpus is absent.

History: before the precision phase the ham false-positive rate measured
44.99% and Nazario recall 72.72%. The precision fixes traded single-signal
catches for a 20x false-positive cut: ham 2.19%, Nazario 66.41%. Ratchet
the ham ceiling down and the recall floor up as further work lands.
"""

import unittest
from pathlib import Path

from detection import DetectionEngine, Email

HAM_DIRS = (
    Path("email/easy_ham"),
    Path("email/easy_ham_2"),
    Path("email/hard_ham"),
)
NAZARIO_DIR = Path("email/nazario")


def _flag_rate(directories) -> float:
    engine = DetectionEngine()
    total = flagged = 0
    for directory in directories:
        for path in sorted(directory.iterdir()):
            if not path.is_file() or path.name == "cmds" or path.suffix == ".csv":
                continue
            total += 1
            detection = engine.detect(
                Email(file=path.as_posix(), content=path.read_bytes())
            )
            flagged += 1 if detection.flagged else 0
    return flagged / total


@unittest.skipUnless(
    all(directory.is_dir() for directory in HAM_DIRS),
    "SpamAssassin ham corpus is not downloaded",
)
class SpamAssassinHamGateTests(unittest.TestCase):
    def test_ham_false_positive_rate_stays_low(self) -> None:
        self.assertLessEqual(_flag_rate(HAM_DIRS), 0.03)


@unittest.skipUnless(NAZARIO_DIR.is_dir(), "Nazario corpus is not downloaded")
class NazarioRecallGateTests(unittest.TestCase):
    def test_meets_the_minimum_recall_floor(self) -> None:
        self.assertGreaterEqual(_flag_rate((NAZARIO_DIR,)), 0.65)


if __name__ == "__main__":
    unittest.main()
