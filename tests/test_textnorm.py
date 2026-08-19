"""Phase 1 acceptance tests: Unicode normalization defeats text obfuscation."""

import unittest

from detection import DetectionEngine, textnorm
from detection.data_models import Email


class NormalizeTests(unittest.TestCase):
    def test_folds_cyrillic_homoglyphs(self) -> None:
        # "Wallеt Suspеnded" with Cyrillic U+0435 in place of Latin "e".
        self.assertEqual(
            textnorm.normalize("[Wall\u0435t Susp\u0435nded] You May los\u0435 all"),
            "[wallet suspended] you may lose all",
        )

    def test_strips_combining_mark_obfuscation(self) -> None:
        # "Amazon" with Syriac combining marks after each letter.
        obfuscated = "A\u073fm\u073fa\u073fz\u073fon account has been locked"
        self.assertEqual(
            textnorm.normalize(obfuscated),
            "amazon account has been locked",
        )

    def test_folds_mathematical_alphanumeric_letters(self) -> None:
        # "Verify" written in Mathematical Sans-Serif Italic letters.
        obfuscated = "\U0001d61d\U0001d626\U0001d633\U0001d62a\U0001d627\U0001d63a"
        self.assertEqual(textnorm.normalize(obfuscated + " now"), "verify now")

    def test_folds_greek_homoglyphs(self) -> None:
        # "Grοupe" with Greek omicron U+03BF.
        self.assertEqual(textnorm.normalize("Gr\u03bfupe INDIGO"), "groupe indigo")

    def test_unescapes_html_entities_before_matching(self) -> None:
        self.assertEqual(
            textnorm.normalize("&#118;erify your &amp; account"),
            "verify your & account",
        )

    def test_folds_accents_for_multilingual_lexicons(self) -> None:
        self.assertEqual(
            textnorm.normalize("Cr\u00e9dito IR Liberado"),
            "credito ir liberado",
        )

    def test_collapses_whitespace_and_casefolds(self) -> None:
        self.assertEqual(textnorm.normalize("  VERIFY\t\nNow  "), "verify now")

    def test_is_total_on_empty_input(self) -> None:
        self.assertEqual(textnorm.normalize(""), "")

    def test_plain_ascii_is_a_fixed_point_apart_from_case(self) -> None:
        self.assertEqual(
            textnorm.normalize("Verify your account now"),
            "verify your account now",
        )


class ObfuscationCountTests(unittest.TestCase):
    def test_counts_homoglyph_and_math_characters(self) -> None:
        self.assertEqual(textnorm.count_confusables("Wall\u0435t"), 1)
        self.assertEqual(textnorm.count_confusables("\U0001d58c\U0001d58a ok"), 2)
        self.assertEqual(textnorm.count_confusables("plain ascii"), 0)

    def test_counts_combining_marks_but_not_precomposed_accents(self) -> None:
        self.assertEqual(textnorm.count_combining_marks("A\u073fm\u073fazon"), 2)
        self.assertEqual(textnorm.count_combining_marks("Cr\u00e9dito"), 0)

    def test_counts_are_zero_for_empty_input(self) -> None:
        self.assertEqual(textnorm.count_confusables(""), 0)
        self.assertEqual(textnorm.count_combining_marks(""), 0)


def _email(subject: str, body: str) -> Email:
    content = (
        "From: Sender <sender@example.test>\r\n"
        f"Subject: {subject}\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        f"{body}\r\n"
    ).encode("utf-8")
    return Email(file="test.eml", content=content)


class ParserNormalizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = DetectionEngine()

    def test_parser_emits_normalized_fields(self) -> None:
        detection = self.engine.detect(
            _email("[Wall\u0435t Susp\u0435nded]", "Verify your wallet now")
        )
        observables = detection.observables
        self.assertEqual(observables.normalized_subject, "[wallet suspended]")
        self.assertEqual(observables.normalized_body_text, "verify your wallet now")

    def test_parser_counts_obfuscated_characters(self) -> None:
        detection = self.engine.detect(
            _email("Wall\u0435t Susp\u0435nded", "A\u073fm\u073fa\u073fz\u073fon")
        )
        observables = detection.observables
        self.assertEqual(observables.subject_confusable_count, 2)
        self.assertEqual(observables.body_combining_mark_count, 4)

    def test_parser_leaves_raw_fields_untouched(self) -> None:
        subject = "Wall\u0435t"
        detection = self.engine.detect(_email(subject, "body text"))
        self.assertEqual(detection.observables.subject, subject)

    def test_missing_subject_yields_none_normalized_subject(self) -> None:
        content = (
            b"From: sender@example.test\r\n"
            b"Content-Type: text/plain\r\n\r\nhello\r\n"
        )
        detection = self.engine.detect(Email(file="t.eml", content=content))
        self.assertIsNone(detection.observables.normalized_subject)

    def test_credential_detector_matches_through_homoglyphs(self) -> None:
        # Cyrillic "е" inside "Verify now" plus an unrelated URL host: the
        # phrase must match after folding, so the credential detector fires.
        from detection.data_models import CredentialUrlFinding, FiredResult

        detection = self.engine.detect(
            _email(
                "V\u0435rify now",
                "Please act: https://evil.example-hosting.test/login",
            )
        )
        fired = [
            result
            for result in detection.detector_results
            if isinstance(result, FiredResult)
            and isinstance(result.finding, CredentialUrlFinding)
        ]
        self.assertEqual(len(fired), 1)


if __name__ == "__main__":
    unittest.main()
