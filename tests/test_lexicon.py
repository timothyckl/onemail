"""Phase 2 tests: expanded multilingual lexicons and their matching contract."""

import unittest

from detection import DetectionEngine, textnorm
from detection.data_models import CredentialUrlFinding, Email, FiredResult
from detection.detectors.lexicon import (
    ADVANCE_FEE_LANGUAGE,
    CREDENTIAL_LANGUAGE,
    URGENCY_LANGUAGE,
)

ALL_LEXICONS = {
    "CREDENTIAL_LANGUAGE": CREDENTIAL_LANGUAGE,
    "URGENCY_LANGUAGE": URGENCY_LANGUAGE,
    "ADVANCE_FEE_LANGUAGE": ADVANCE_FEE_LANGUAGE,
}


class LexiconContractTests(unittest.TestCase):
    def test_every_entry_is_a_normalize_fixed_point(self) -> None:
        # An entry that is not its own normalization can never match the
        # normalized message text, so it would be silently dead.
        for name, lexicon in ALL_LEXICONS.items():
            for phrase in lexicon:
                self.assertEqual(
                    textnorm.normalize(phrase),
                    phrase,
                    f"{name} entry {phrase!r} is not in normalized form",
                )

    def test_entries_are_unique_and_non_empty(self) -> None:
        for name, lexicon in ALL_LEXICONS.items():
            self.assertEqual(
                len(lexicon), len(set(lexicon)), f"{name} has duplicates"
            )
            self.assertTrue(all(lexicon), f"{name} has an empty entry")

    def test_original_entries_are_preserved_in_order(self) -> None:
        # Evidence ordering follows configuration order; keep the original
        # entries first so historical findings remain stable.
        self.assertEqual(
            CREDENTIAL_LANGUAGE[:3],
            ("verify your account", "verify your details", "sign in to continue"),
        )
        self.assertEqual(URGENCY_LANGUAGE[:2], ("wire transfer", "gift card"))


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


class MultilingualDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = DetectionEngine()

    def _credential_fired(self, subject: str, body: str) -> bool:
        detection = self.engine.detect(_email(subject, body))
        return any(
            isinstance(result, FiredResult)
            and isinstance(result.finding, CredentialUrlFinding)
            for result in detection.detector_results
        )

    def test_portuguese_customs_fee_scam_fires(self) -> None:
        self.assertTrue(
            self._credential_fired(
                "AVISO: Seu pedido foi bloqueado pela fiscaliza\u00e7\u00e3o",
                "Pague a taxa: https://rastreio.example-taxa.test/pagar",
            )
        )

    def test_german_account_confirmation_fires(self) -> None:
        self.assertTrue(
            self._credential_fired(
                "Best\u00e4tigen Sie Ihr Konto",
                "Jetzt hier: https://konto.example-sicher.test/check",
            )
        )

    def test_english_wallet_suspension_fires(self) -> None:
        self.assertTrue(
            self._credential_fired(
                "Notice: Your Wallet is currently Suspended!",
                "Restore access: https://restore.example-wallet.test/x",
            )
        )

    def test_french_account_confirmation_fires(self) -> None:
        self.assertTrue(
            self._credential_fired(
                "Confirmation requise pour votre compte",
                "Cliquez: https://compte.example-fr.test/verifier",
            )
        )

    def test_benign_text_with_link_stays_clear(self) -> None:
        self.assertFalse(
            self._credential_fired(
                "Weekly team notes",
                "Slides from the offsite: https://slides.example-cdn.test/deck",
            )
        )


if __name__ == "__main__":
    unittest.main()
