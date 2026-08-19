"""Corpus tests for Phishing Pot loading, detection, and reporting."""

import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from detection.data_models import (
    AuthFailureEvidence,
    AuthFailureFinding,
    DetectorName,
    Email,
    FiredResult,
)
from dataset import PhishingPot
from detection import DetectionEngine
from reporting import DetectionRecord, DetectionReport
from scripts.detect_phishing_pot import detect


PHISHING_POT_EMAILS = Path("dataset/phishing_pot/email")


class PhishingPotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.phishing_pot = PhishingPot(PHISHING_POT_EMAILS)
        cls.files = cls.phishing_pot.files()
        cls.records = detect(cls.phishing_pot, DetectionEngine())
        cls.report = DetectionReport.build(cls.records)

    def test_discovers_real_emails_in_stable_order(self) -> None:
        self.assertTrue(self.files)
        self.assertEqual(
            self.files,
            tuple(sorted(self.files, key=lambda path: path.as_posix())),
        )
        self.assertTrue(all(path.suffix.lower() == ".eml" for path in self.files))

    def test_reads_unmodified_bytes_with_a_phishing_label(self) -> None:
        file = self.files[0]
        email = self.phishing_pot.read(file)

        self.assertEqual(email.file, file.as_posix())
        self.assertEqual(email.content, (PHISHING_POT_EMAILS / file).read_bytes())
        self.assertEqual(email.label, "phishing")

    def test_accounts_for_the_complete_positive_corpus(self) -> None:
        self.assertEqual(len(self.records), len(self.files))
        self.assertTrue(all(record.label == "phishing" for record in self.records))
        self.assertEqual(
            self.report.discovered_count,
            self.report.processed_count + self.report.unreadable_count,
        )
        self.assertEqual(
            self.report.processed_count,
            self.report.flagged_count + self.report.unflagged_count,
        )

    def test_every_detection_has_a_complete_detector_result(self) -> None:
        expected = set(DetectorName)
        for record in self.records:
            if record.detection is None:
                continue
            self.assertEqual(
                {result.detector for result in record.detection.detector_results},
                expected,
            )

    def test_reports_parse_failures_without_stopping_the_run(self) -> None:
        expected_parse_failures = sum(
            record.detection is not None
            and record.detection.observables.parse_error is not None
            for record in self.records
        )

        self.assertEqual(self.report.unreadable_count, 0)
        self.assertEqual(self.report.parse_failure_count, expected_parse_failures)
        self.assertEqual(self.report.processed_count, len(self.files))

    def test_meets_the_minimum_recall_floor(self) -> None:
        # Every corpus email is phishing, so flagged/processed is recall.
        # Ratchet this floor upward as detection phases land; it exists to
        # stop silent recall regressions. History: 0.48 baseline, 0.59 after
        # lexicons, 0.73 after brand rules, 0.78 after structural rules,
        # 0.73 after the precision phase (SpamAssassin-ham false positives
        # cut 44.99% -> 3.64% by trading away single-signal catches: lone
        # generic credential tokens, contextless brand mentions, and
        # mailing-list Reply-To divergence).
        recall = self.report.flagged_count / self.report.processed_count
        self.assertGreaterEqual(recall, 0.72)

    def test_automatically_validates_all_corpus_findings(self) -> None:
        self.assertTrue(self.report.validation_passed)
        self.assertEqual(self.report.validation_issues, ())

    def test_report_counts_and_json_data_are_consistent(self) -> None:
        data = self.report.to_dict()
        summary = data["summary"]

        self.assertEqual(summary["discovered"], len(data["emails"]))
        self.assertEqual(summary["processed"], self.report.processed_count)
        self.assertEqual(summary["flagged_phishing"], self.report.flagged_count)
        self.assertEqual(summary["validation_issues"], 0)

    def test_detects_a_real_email_deterministically(self) -> None:
        email = self.phishing_pot.read(self.files[0])
        engine = DetectionEngine()

        detection_email = Email(file=email.file, content=email.content)
        first = engine.detect(detection_email)
        second = engine.detect(detection_email)

        self.assertEqual(first, second)

    def test_reports_tampered_evidence_from_a_real_detection(self) -> None:
        record, result = self._auth_failure_result()
        evidence = replace(result.finding.evidence, from_domain="not-observed.example")
        finding = replace(result.finding, evidence=evidence)
        altered_result = replace(result, finding=finding)
        detection = record.detection
        assert detection is not None
        altered_results = tuple(
            altered_result if item is result else item
            for item in detection.detector_results
        )
        altered_detection = replace(detection, detector_results=altered_results)

        report = DetectionReport.build(
            (DetectionRecord.detected(record.label, altered_detection),)
        )

        self.assertFalse(report.validation_passed)
        self.assertTrue(
            any(
                issue.message == "evidence does not match observables"
                for issue in report.validation_issues
            )
        )

    def test_continues_after_a_read_failure_for_a_real_path(self) -> None:
        files = self.files[:2]
        second_email = self.phishing_pot.read(files[1])
        with patch.object(self.phishing_pot, "files", return_value=files), patch.object(
            self.phishing_pot,
            "read",
            side_effect=(OSError("unreadable"), second_email),
        ):
            records = detect(self.phishing_pot, DetectionEngine())

        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].read_error, "OSError")
        self.assertIsNotNone(records[1].detection)

    def _auth_failure_result(self):
        for record in self.records:
            if record.detection is None:
                continue
            for result in record.detection.detector_results:
                if isinstance(result, FiredResult) and isinstance(
                    result.finding,
                    AuthFailureFinding,
                ):
                    self.assertIsInstance(result.finding.evidence, AuthFailureEvidence)
                    return record, result
        self.fail("Phishing Pot did not produce an authentication-failure finding")


if __name__ == "__main__":
    unittest.main()
