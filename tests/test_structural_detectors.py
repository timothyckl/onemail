"""Phase 4 tests: structural lure detectors."""

import unittest

from detection import DetectionEngine
from detection.data_models import DetectorName, Email, FiredResult, SkippedResult
from detection.detectors.structural_detectors import (
    AdvanceFeeFinding,
    GibberishBodyFinding,
    SharedHostingUrlFinding,
    SubjectObfuscationFinding,
    LURE_LANGUAGE,
)
from reporting import DetectionRecord, DetectionReport


def _email(from_header: str, subject: str, body: str, reply_to: str = "") -> Email:
    headers = [f"From: {from_header}", f"Subject: {subject}"]
    if reply_to:
        headers.append(f"Reply-To: {reply_to}")
    headers += ["MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8"]
    content = ("\r\n".join(headers) + "\r\n\r\n" + body + "\r\n").encode("utf-8")
    return Email(file="test.eml", content=content)


class StructuralDetectorTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = DetectionEngine()

    def _result(self, detection, name: DetectorName):
        return {r.detector: r for r in detection.detector_results}[name]

    def _fired_with(self, detection, finding_type) -> bool:
        return any(
            isinstance(r, FiredResult) and isinstance(r.finding, finding_type)
            for r in detection.detector_results
        )


class SubjectObfuscationTests(StructuralDetectorTestCase):
    def test_fires_on_combining_mark_subject(self) -> None:
        detection = self.engine.detect(
            _email(
                "x@sender.test",
                "Your A\u073fm\u073fa\u073fz\u073fon account",
                "plain body",
            )
        )
        self.assertTrue(self._fired_with(detection, SubjectObfuscationFinding))

    def test_fires_on_mixed_script_homoglyphs(self) -> None:
        # Latin subject with two Cyrillic "е" characters.
        detection = self.engine.detect(
            _email("x@sender.test", "Wall\u0435t Susp\u0435nded", "plain body")
        )
        self.assertTrue(self._fired_with(detection, SubjectObfuscationFinding))

    def test_clear_on_fully_cyrillic_subject(self) -> None:
        detection = self.engine.detect(
            _email("x@sender.test", "\u041f\u0440\u0438\u0432\u0435\u0442 \u043c\u0438\u0440", "plain body")
        )
        self.assertFalse(self._fired_with(detection, SubjectObfuscationFinding))

    def test_clear_on_accented_european_subject(self) -> None:
        detection = self.engine.detect(
            _email("x@sender.test", "Cr\u00e9dito aprovado at\u00e9 s\u00e1bado", "ol\u00e1")
        )
        self.assertFalse(self._fired_with(detection, SubjectObfuscationFinding))

    def test_skips_without_subject(self) -> None:
        content = b"From: x@sender.test\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
        detection = self.engine.detect(Email(file="t.eml", content=content))
        result = self._result(detection, DetectorName.SUBJECT_OBFUSCATION)
        self.assertIsInstance(result, SkippedResult)


class SharedHostingUrlTests(StructuralDetectorTestCase):
    def test_fires_on_platform_link_with_lure_language(self) -> None:
        detection = self.engine.detect(
            _email(
                "x@random-sender.test",
                "Action required",
                "Verify now: https://secure-check.web.app/login",
            )
        )
        self.assertTrue(self._fired_with(detection, SharedHostingUrlFinding))

    def test_fires_on_shortener_with_brand_claim(self) -> None:
        detection = self.engine.detect(
            _email(
                "x@random-sender.test",
                "Netflix payment notice",
                "See details https://bit.ly/3abcdef",
            )
        )
        self.assertTrue(self._fired_with(detection, SharedHostingUrlFinding))

    def test_clear_on_platform_link_without_lure(self) -> None:
        detection = self.engine.detect(
            _email(
                "x@random-sender.test",
                "Team offsite photos",
                "Album: https://myalbum.web.app/2024",
            )
        )
        self.assertFalse(self._fired_with(detection, SharedHostingUrlFinding))

    def test_lure_language_has_no_duplicates(self) -> None:
        self.assertEqual(len(LURE_LANGUAGE), len(set(LURE_LANGUAGE)))


class AdvanceFeeTests(StructuralDetectorTestCase):
    def test_fires_on_prize_lure_from_freemail(self) -> None:
        detection = self.engine.detect(
            _email(
                "Winner Desk <prizes@gmail.com>",
                "Congratulations you have won",
                "You have won the international lottery. No links here.",
            )
        )
        self.assertTrue(self._fired_with(detection, AdvanceFeeFinding))

    def test_fires_on_german_voucher_lure_with_unrelated_link(self) -> None:
        detection = self.engine.detect(
            _email(
                "x@spammy-sender.test",
                "Einkaufsgutschein im Wert von 500\u20ac",
                "Sichern Sie sich jetzt: https://gewinn.click-host.test/go",
            )
        )
        self.assertTrue(self._fired_with(detection, AdvanceFeeFinding))

    def test_clear_on_lure_language_without_structural_oddity(self) -> None:
        # Corporate sender linking only to itself.
        detection = self.engine.detect(
            _email(
                "casino@example-casino.test",
                "Your welcome bonus",
                "Claim at https://www.example-casino.test/bonus",
            )
        )
        self.assertFalse(self._fired_with(detection, AdvanceFeeFinding))

    def test_clear_without_advance_fee_language(self) -> None:
        detection = self.engine.detect(
            _email("a@gmail.com", "Lunch tomorrow?", "Sushi place at noon?")
        )
        self.assertFalse(self._fired_with(detection, AdvanceFeeFinding))


class GibberishBodyTests(StructuralDetectorTestCase):
    def test_fires_on_consonant_filler_with_unrelated_link(self) -> None:
        filler = " ".join(
            ["gllvhrrdcwgtc", "snwjq", "zcziprclvgmqk", "wjwifdhrnbgw",
             "xktrqhb", "cdpclfkvxwp", "lybhvwzfbjdhrn", "whzbvkqnbfpth",
             "gnkhylfttsvslbtd", "mtwbdhp", "qxnpnsmtdxs", "xwpjjzbxmwzsr"]
        )
        detection = self.engine.detect(
            _email(
                "x@uorak.test",
                "Binance Cybersecurity",
                f"https://axobox.test/track {filler}",
            )
        )
        self.assertTrue(self._fired_with(detection, GibberishBodyFinding))

    def test_clear_on_normal_prose(self) -> None:
        detection = self.engine.detect(
            _email(
                "x@sender.test",
                "Notes",
                "Here are the meeting notes from Thursday with the vendor "
                "team about the quarterly roadmap review and hiring plans. "
                "See https://docs.internal-notes.test/minutes for details.",
            )
        )
        self.assertFalse(self._fired_with(detection, GibberishBodyFinding))

    def test_hex_colour_tokens_are_not_gibberish(self) -> None:
        css = " ".join(["ffffff", "eeeeee", "dddddd", "cccccc", "fafafa",
                        "efefef", "dedede", "cdcdcd", "fcfcfc", "dadada",
                        "beefed", "decade"])
        detection = self.engine.detect(
            _email(
                "x@sender.test",
                "Newsletter",
                f"{css} read more at https://cdn.newsletter-host.test/x",
            )
        )
        self.assertFalse(self._fired_with(detection, GibberishBodyFinding))


class ValidationTests(StructuralDetectorTestCase):
    def test_structural_findings_pass_reporting_validation(self) -> None:
        detection = self.engine.detect(
            _email(
                "Winner Desk <prizes@gmail.com>",
                "Wall\u0435t Susp\u0435nded - you have won",
                "Claim your prize: https://lucky.web.app/claim",
            )
        )
        fired = [r for r in detection.detector_results if isinstance(r, FiredResult)]
        self.assertTrue(fired)
        report = DetectionReport.build(
            (DetectionRecord.detected("phishing", detection),)
        )
        self.assertTrue(report.validation_passed)
        self.assertEqual(report.validation_issues, ())


if __name__ == "__main__":
    unittest.main()
