"""Tests for QR-code ("quishing") URL recovery and detection.

Detector-logic tests build observables directly and always run. The parse and
engine integration tests need both an image QR backend and the ``qrcode`` helper
to synthesise fixtures, so they skip cleanly when either is unavailable.
"""

import io
import unittest
from email.message import EmailMessage
from typing import Optional

from detection import DetectionEngine, Email, EmailParser, qr
from detection.data_models import (
    ClearResult,
    FiredResult,
    MessageObservables,
    SkippedResult,
)
from detection.detectors.qr_detectors import QrUrlDetector, QrUrlEvidence, QrUrlFinding
from reporting import DetectionRecord, DetectionReport

try:  # fixture generator is a test-only convenience, not a runtime dependency
    import qrcode as _qrcode
except Exception:  # pragma: no cover - exercised only where qrcode is absent
    _qrcode = None

_CAN_BUILD_FIXTURES = _qrcode is not None and qr.available()
_FIXTURE_REASON = "requires the qr backend and the qrcode fixture generator"


def _qr_png(url: str) -> bytes:
    buf = io.BytesIO()
    _qrcode.make(url).save(buf, format="PNG")
    return buf.getvalue()


def _quishing_email(
    *,
    sender: str = '"IT Helpdesk" <helpdesk@corp.example>',
    qr_url: str = "https://corp-verify.attacker.example/login",
    body: str = "Please scan the QR code to continue.",
    inline: bool = True,
    filename: Optional[str] = "qr.png",
) -> Email:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = "victim@corp.example"
    message["Subject"] = "Action required"
    message.set_content(body)
    if inline:
        message.add_related(_qr_png(qr_url), maintype="image", subtype="png", cid="qr1")
    else:
        message.add_attachment(
            _qr_png(qr_url), maintype="image", subtype="png", filename=filename
        )
    return Email(file="quish.eml", content=message.as_bytes())


class QrUrlDetectorTests(unittest.TestCase):
    """Detector logic, exercised directly against observables."""

    def test_fires_when_qr_host_is_off_domain(self) -> None:
        result = QrUrlDetector().detect(
            MessageObservables(
                from_domain="corp.example",
                image_urls=("https://corp-verify.attacker.example/login",),
                url_hosts=("corp-verify.attacker.example",),
                qr_image_count=1,
            )
        )
        self.assertIsInstance(result, FiredResult)
        assert isinstance(result, FiredResult)
        self.assertIsInstance(result.finding, QrUrlFinding)
        self.assertEqual(result.finding.severity.value, "high")
        self.assertTrue(result.finding.heuristic)
        evidence = result.finding.evidence
        assert isinstance(evidence, QrUrlEvidence)
        self.assertEqual(evidence.from_registered_domain, "corp.example")
        self.assertEqual(evidence.mismatched_hosts, ("corp-verify.attacker.example",))
        self.assertEqual(evidence.image_count, 1)

    def test_fires_when_sender_domain_is_unknown(self) -> None:
        result = QrUrlDetector().detect(
            MessageObservables(
                from_domain=None,
                image_urls=("https://anywhere.example/login",),
                qr_image_count=1,
            )
        )
        self.assertIsInstance(result, FiredResult)

    def test_clears_when_qr_host_matches_sender(self) -> None:
        result = QrUrlDetector().detect(
            MessageObservables(
                from_domain="corp.example",
                image_urls=("https://corp.example/payslip",),
                url_hosts=("corp.example",),
                qr_image_count=1,
            )
        )
        self.assertIsInstance(result, ClearResult)

    def test_skips_when_no_qr_url_present(self) -> None:
        result = QrUrlDetector().detect(MessageObservables(from_domain="corp.example"))
        self.assertIsInstance(result, SkippedResult)


@unittest.skipUnless(_CAN_BUILD_FIXTURES, _FIXTURE_REASON)
class QrParsingTests(unittest.TestCase):
    """Parser and engine integration with a real decoded QR image."""

    def test_parser_recovers_and_merges_qr_url(self) -> None:
        observables = EmailParser().parse(_quishing_email())
        self.assertEqual(
            observables.image_urls,
            ("https://corp-verify.attacker.example/login",),
        )
        self.assertEqual(observables.qr_image_count, 1)
        # The decoded URL is merged so the generic URL detectors see it too.
        self.assertIn(
            "https://corp-verify.attacker.example/login", observables.urls
        )
        self.assertIn("corp-verify.attacker.example", observables.url_hosts)

    def test_parser_reads_qr_from_image_attachment(self) -> None:
        observables = EmailParser().parse(_quishing_email(inline=False))
        self.assertEqual(observables.qr_image_count, 1)
        self.assertTrue(observables.image_urls)

    def test_engine_flags_quishing_email_and_report_validates(self) -> None:
        email = _quishing_email()
        detection = DetectionEngine().detect(email)
        self.assertTrue(detection.flagged)
        fired = {
            result.detector.value
            for result in detection.detector_results
            if isinstance(result, FiredResult)
        }
        self.assertIn("qr_url", fired)

        report = DetectionReport.build(
            [DetectionRecord.detected("phishing", detection)]
        )
        self.assertTrue(report.validation_passed)
        self.assertEqual(report.flagged_count, 1)

    def test_non_qr_image_does_not_fire(self) -> None:
        message = EmailMessage()
        message["From"] = "helpdesk@corp.example"
        message["Subject"] = "Newsletter"
        message.set_content("No QR here.")
        # A 1x1 PNG with no QR code.
        pixel = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00"
            b"\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        message.add_related(pixel, maintype="image", subtype="png", cid="p")
        observables = EmailParser().parse(
            Email(file="plain.eml", content=message.as_bytes())
        )
        self.assertEqual(observables.image_urls, ())
        self.assertIsInstance(
            QrUrlDetector().detect(observables), SkippedResult
        )


class QrBackendDegradationTests(unittest.TestCase):
    """Decoding must degrade to 'no result', never crash, without a backend."""

    def test_decode_returns_empty_without_backend(self) -> None:
        original_opencv, original_pyzbar = qr._opencv, qr._pyzbar
        qr._opencv = lambda: None
        qr._pyzbar = lambda: None
        try:
            self.assertFalse(qr.available())
            self.assertEqual(qr.decode_qr_urls(b"\x89PNG not-a-real-image"), ())
        finally:
            qr._opencv, qr._pyzbar = original_opencv, original_pyzbar

    def test_decode_rejects_empty_and_oversized_input(self) -> None:
        self.assertEqual(qr.decode_qr_urls(b""), ())
        self.assertEqual(
            qr.decode_qr_urls(b"x" * (qr.MAX_IMAGE_BYTES + 1)), ()
        )


if __name__ == "__main__":
    unittest.main()
