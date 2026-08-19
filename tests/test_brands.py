"""Phase 3 tests: expanded brand vocabulary and content-mismatch detection."""

import unittest

from detection import DetectionEngine, textnorm
from detection.brands import (
    BRAND_DOMAINS,
    BRANDS,
    CONTENT_BRANDS,
    brand_matches_domain,
    find_brand,
    find_content_brand,
)
from detection.data_models import (
    DetectorName,
    DisplayNameSpoofFinding,
    Email,
    FiredResult,
)
from detection.detectors.brand_detectors import (
    BrandContentMismatchDetector,
    BrandContentMismatchFinding,
)
from reporting import DetectionRecord, DetectionReport


class BrandVocabularyTests(unittest.TestCase):
    def test_brands_are_normalized_fixed_points(self) -> None:
        for brand in BRANDS:
            self.assertEqual(
                textnorm.normalize(brand), brand,
                f"brand {brand!r} is not in normalized form",
            )

    def test_original_brands_are_preserved_in_order(self) -> None:
        self.assertEqual(
            BRANDS[:4], ("paypal", "microsoft", "apple", "amazon")
        )

    def test_generic_brands_are_excluded_from_content_matching(self) -> None:
        self.assertIn("bank", BRANDS)
        self.assertNotIn("bank", CONTENT_BRANDS)

    def test_brand_domain_map_only_references_known_brands(self) -> None:
        self.assertTrue(set(BRAND_DOMAINS).issubset(set(BRANDS)))


class BrandMatchingTests(unittest.TestCase):
    def test_left_token_boundary_blocks_embedded_words(self) -> None:
        self.assertIsNone(find_content_brand("fresh pineapple juice"))
        self.assertEqual(find_brand("apple support team"), "apple")
        self.assertEqual(find_brand("paypal24 billing"), "paypal")

    def test_finds_multiword_and_symbol_brands(self) -> None:
        self.assertEqual(find_content_brand("your trust wallet is locked"), "trust wallet")
        self.assertEqual(find_content_brand("important information from at&t!"), "at&t")

    def test_matches_domains_via_token_or_known_domain(self) -> None:
        self.assertTrue(brand_matches_domain("amazon", "amazon.com.br"))
        self.assertTrue(brand_matches_domain("banco do brasil", "mail.bb.com.br"))
        self.assertTrue(brand_matches_domain("outlook", "microsoft.com"))
        self.assertFalse(brand_matches_domain("binance", "libreriacies.es"))
        self.assertFalse(brand_matches_domain("ledger", ""))


def _email(from_header: str, subject: str, body: str) -> Email:
    content = (
        f"From: {from_header}\r\n"
        f"Subject: {subject}\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        f"{body}\r\n"
    ).encode("utf-8")
    return Email(file="test.eml", content=content)


class BrandContentMismatchDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = DetectionEngine()

    def _fired(self, detection) -> bool:
        return any(
            isinstance(result, FiredResult)
            and isinstance(result.finding, BrandContentMismatchFinding)
            for result in detection.detector_results
        )

    def test_fires_on_brand_claim_with_unrelated_sender_and_links(self) -> None:
        detection = self.engine.detect(
            _email(
                "News <info@libreriacies.es>",
                "Binance Cybersecurity",
                "Act here: https://axobox.com/vt/track",
            )
        )
        self.assertTrue(self._fired(detection))

    def test_fires_through_homoglyph_obfuscated_brand(self) -> None:
        # "Amazon" with Cyrillic "а" and combining marks.
        detection = self.engine.detect(
            _email(
                "Support <help@randomsender.test>",
                "Your A\u073fm\u073fa\u073fz\u073fon order",
                "Fix it: https://parcel-fix.test/track",
            )
        )
        self.assertTrue(self._fired(detection))

    def test_clear_on_body_mention_without_impersonation_context(self) -> None:
        # Brand named only in running body text, no credential or urgency
        # language: that is discussion, not impersonation.
        detection = self.engine.detect(
            _email(
                "Colleague <pal@randomsender.test>",
                "Interesting article",
                "Binance had an outage yesterday: https://news-site.test/story",
            )
        )
        self.assertFalse(self._fired(detection))

    def test_fires_on_body_mention_with_lure_language(self) -> None:
        detection = self.engine.detect(
            _email(
                "Support <help@randomsender.test>",
                "Action needed",
                "Binance flagged unusual activity. "
                "Please verify your account: https://axobox.com/vt/track",
            )
        )
        self.assertTrue(self._fired(detection))

    def test_skips_on_mailing_list_traffic(self) -> None:
        content = (
            "From: Member <member@randomsender.test>\r\n"
            "Subject: Binance Cybersecurity\r\n"
            "List-Id: <discuss.example.org>\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Read this: https://axobox.com/vt/track\r\n"
        ).encode("utf-8")
        detection = self.engine.detect(Email(file="list.eml", content=content))
        self.assertFalse(self._fired(detection))

    def test_clear_when_sender_belongs_to_brand(self) -> None:
        detection = self.engine.detect(
            _email(
                "Amazon <no-reply@amazon.com>",
                "Your Amazon order has shipped",
                "Track: https://tracker.example-cdn.test/x",
            )
        )
        self.assertFalse(self._fired(detection))

    def test_clear_when_links_go_to_the_brand(self) -> None:
        detection = self.engine.detect(
            _email(
                "Fan newsletter <fan@fansite.test>",
                "New spotify playlists this week",
                "Listen: https://open.spotify.com/playlist/abc",
            )
        )
        self.assertFalse(self._fired(detection))

    def test_skips_without_urls(self) -> None:
        detector = BrandContentMismatchDetector()
        detection = self.engine.detect(
            _email("a@b.test", "Binance notice", "no links here")
        )
        results = {r.detector: r for r in detection.detector_results}
        result = results[DetectorName.BRAND_CONTENT_MISMATCH]
        self.assertFalse(isinstance(result, FiredResult))

    def test_display_name_spoof_matches_through_obfuscation(self) -> None:
        # Homoglyph "PayPal" in the display name, unrelated sender domain.
        detection = self.engine.detect(
            _email(
                '"P\u0430yP\u0430l Support" <alert@randomsender.test>',
                "hello",
                "hi",
            )
        )
        fired = any(
            isinstance(result, FiredResult)
            and isinstance(result.finding, DisplayNameSpoofFinding)
            for result in detection.detector_results
        )
        self.assertTrue(fired)

    def test_findings_pass_reporting_validation(self) -> None:
        detection = self.engine.detect(
            _email(
                "News <info@libreriacies.es>",
                "Binance Cybersecurity",
                "Act here: https://axobox.com/vt/track",
            )
        )
        report = DetectionReport.build(
            (DetectionRecord.detected("phishing", detection),)
        )
        self.assertTrue(report.validation_passed)


if __name__ == "__main__":
    unittest.main()
