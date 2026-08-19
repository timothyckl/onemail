"""Phase 7 false-positive guard: legitimate mail must not fire any detector.

The phishing-pot corpus is all-positive, so recall improvements could
silently trade away precision. These fixtures are deliberately adversarial
for the rules added in Phases 1-6:

- a password-reset and a receipt from real brand domains, containing
  credential-action language (pairing rules must respect same-registrant
  links and the brand domain map);
- a newsletter serving images from CloudFront (shared-hosting rule must
  require lure language before firing on platform links);
- personal mail from a freemail address (freemail rule must require a brand
  or credential claim);
- accented German text (subject-obfuscation rule must not count legitimate
  non-ASCII).

Every new detector or lexicon entry must keep this corpus at zero findings.
"""

import unittest
from pathlib import Path

from detection import DetectionEngine
from detection.data_models import Email, FiredResult
from reporting import DetectionRecord, DetectionReport

HAM_DIR = Path("tests/ham")


class HamCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.files = tuple(sorted(HAM_DIR.glob("*.eml")))
        engine = DetectionEngine()
        cls.detections = tuple(
            engine.detect(Email(file=path.as_posix(), content=path.read_bytes()))
            for path in cls.files
        )

    def test_fixture_corpus_is_present(self) -> None:
        self.assertGreaterEqual(len(self.files), 10)

    def test_every_fixture_parses(self) -> None:
        for detection in self.detections:
            self.assertIsNone(
                detection.observables.parse_error,
                f"{detection.file} failed to parse",
            )

    def test_no_detector_fires_on_legitimate_mail(self) -> None:
        for detection in self.detections:
            fired = [
                result.detector.value
                for result in detection.detector_results
                if isinstance(result, FiredResult)
            ]
            self.assertEqual(
                fired,
                [],
                f"{detection.file} produced false positives: {fired}",
            )

    def test_ham_report_validates_cleanly(self) -> None:
        report = DetectionReport.build(
            tuple(
                DetectionRecord.detected("ham", detection)
                for detection in self.detections
            )
        )
        self.assertTrue(report.validation_passed)
        self.assertEqual(report.flagged_count, 0)


if __name__ == "__main__":
    unittest.main()
