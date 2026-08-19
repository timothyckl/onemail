"""Phase 5 tests: suffix-aware registrable-domain derivation."""

import unittest

from detection import DetectionEngine
from detection.data_models import CredentialUrlFinding, Email, FiredResult
from detection.detectors.detectors import registered_domain
from detection.domains import registered_domain as domains_registered_domain


class RegisteredDomainTests(unittest.TestCase):
    def test_multi_label_public_suffixes(self) -> None:
        self.assertEqual(registered_domain("mail.example.co.uk"), "example.co.uk")
        self.assertEqual(registered_domain("a.b.example.com.br"), "example.com.br")
        self.assertEqual(registered_domain("www.shop.com.au"), "shop.com.au")

    def test_distinct_registrants_no_longer_collapse(self) -> None:
        # The naive rule reduced both to "com.br" and called them related.
        self.assertNotEqual(
            registered_domain("sender.com.br"),
            registered_domain("attacker.com.br"),
        )

    def test_private_platform_suffixes_split_tenants(self) -> None:
        self.assertEqual(
            registered_domain("keithprojct.firebaseapp.com"),
            "keithprojct.firebaseapp.com",
        )
        self.assertNotEqual(
            registered_domain("tenant-a.firebaseapp.com"),
            registered_domain("tenant-b.firebaseapp.com"),
        )

    def test_longest_suffix_wins(self) -> None:
        self.assertEqual(
            registered_domain("bucket.s3.amazonaws.com"),
            "bucket.s3.amazonaws.com",
        )
        self.assertEqual(
            registered_domain("x.eu-west-1.amazonaws.com"),
            "eu-west-1.amazonaws.com",
        )

    def test_host_that_is_a_suffix_returns_itself(self) -> None:
        self.assertEqual(registered_domain("co.uk"), "co.uk")
        self.assertEqual(registered_domain("firebaseapp.com"), "firebaseapp.com")

    def test_unlisted_suffixes_keep_two_label_behaviour(self) -> None:
        self.assertEqual(registered_domain("www.example.com"), "example.com")
        self.assertEqual(registered_domain("deep.sub.example.org"), "example.org")
        self.assertEqual(registered_domain("localhost"), "localhost")

    def test_normalisation_and_edge_cases(self) -> None:
        self.assertEqual(registered_domain("WWW.Example.CO.UK."), "example.co.uk")
        self.assertIsNone(registered_domain(None))
        self.assertIsNone(registered_domain(""))

    def test_detector_function_is_the_shared_implementation(self) -> None:
        self.assertEqual(
            registered_domain("mail.example.co.uk"),
            domains_registered_domain("mail.example.co.uk"),
        )


class EndToEndSuffixTests(unittest.TestCase):
    def test_credential_detector_fires_across_com_br_domains(self) -> None:
        # Sender and link host share only the public suffix "com.br"; the
        # naive rule considered them the same registrant and stayed clear.
        content = (
            "From: Banco <alerta@aviso-seguro.com.br>\r\n"
            "Subject: Confirme seus dados\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Atualize seus dados: https://portal.outro-site.com.br/entrar\r\n"
        ).encode("utf-8")
        detection = DetectionEngine().detect(Email(file="t.eml", content=content))
        fired = any(
            isinstance(result, FiredResult)
            and isinstance(result.finding, CredentialUrlFinding)
            for result in detection.detector_results
        )
        self.assertTrue(fired)


if __name__ == "__main__":
    unittest.main()
