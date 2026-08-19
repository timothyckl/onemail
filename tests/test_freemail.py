"""Phase 6 tests: freemail-sender rule and authentication semantics."""

import unittest

from detection import DetectionEngine
from detection.data_models import DetectorName, Email, FiredResult, SkippedResult
from detection.detectors.freemail_detectors import FreemailSenderFinding
from reporting import DetectionRecord, DetectionReport


def _email(
    from_header: str,
    subject: str,
    body: str,
    auth_results: str = "",
) -> Email:
    headers = [f"From: {from_header}"]
    if auth_results:
        headers.append(f"Authentication-Results: {auth_results}")
    headers += [
        f"Subject: {subject}",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
    ]
    content = ("\r\n".join(headers) + "\r\n\r\n" + body + "\r\n").encode("utf-8")
    return Email(file="test.eml", content=content)


class FreemailSenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = DetectionEngine()

    def _fired(self, detection) -> bool:
        return any(
            isinstance(r, FiredResult) and isinstance(r.finding, FreemailSenderFinding)
            for r in detection.detector_results
        )

    def test_fires_on_freemail_with_credential_language(self) -> None:
        detection = self.engine.detect(
            _email(
                "Security <acct-team@gmail.com>",
                "Your account has been suspended",
                "Please verify your identity to restore access.",
            )
        )
        self.assertTrue(self._fired(detection))

    def test_fires_on_freemail_with_brand_claim_and_no_urls(self) -> None:
        # BrandContentMismatch skips without URLs; this rule still covers it.
        detection = self.engine.detect(
            _email(
                "Support <helpdesk9481@hotmail.com>",
                "Netflix billing problem",
                "Reply with your details to keep your membership active.",
            )
        )
        self.assertTrue(self._fired(detection))

    def test_fires_despite_passing_authentication(self) -> None:
        # SPF pass on a mailbox the attacker owns is not exculpatory.
        detection = self.engine.detect(
            _email(
                "Security <acct-team@gmail.com>",
                "Verify your wallet",
                "Confirm your identity now.",
                auth_results="mx.test; spf=pass; dmarc=pass",
            )
        )
        self.assertTrue(self._fired(detection))
        auth = {r.detector: r for r in detection.detector_results}[
            DetectorName.AUTH_FAILURE
        ]
        self.assertFalse(isinstance(auth, FiredResult))

    def test_clear_on_corporate_sender_with_credential_language(self) -> None:
        detection = self.engine.detect(
            _email(
                "IT <it@corp-example.test>",
                "Password expiry",
                "Please verify your account on the intranet.",
            )
        )
        self.assertFalse(self._fired(detection))

    def test_clear_on_freemail_small_talk(self) -> None:
        detection = self.engine.detect(
            _email(
                "Alex <alex.friend@gmail.com>",
                "Dinner on Friday?",
                "Shall we try the new ramen place at seven?",
            )
        )
        self.assertFalse(self._fired(detection))

    def test_skips_without_from_header(self) -> None:
        content = b"Subject: hello\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
        detection = self.engine.detect(Email(file="t.eml", content=content))
        result = {r.detector: r for r in detection.detector_results}[
            DetectorName.FREEMAIL_SENDER
        ]
        self.assertIsInstance(result, SkippedResult)

    def test_findings_pass_reporting_validation(self) -> None:
        detection = self.engine.detect(
            _email(
                "Security <acct-team@gmail.com>",
                "Verify your wallet",
                "Confirm your identity now.",
            )
        )
        report = DetectionReport.build(
            (DetectionRecord.detected("phishing", detection),)
        )
        self.assertTrue(report.validation_passed)


class AuthPassNotExculpatoryTests(unittest.TestCase):
    def test_auth_pass_does_not_suppress_other_detectors(self) -> None:
        # Identical phishing content with and without passing authentication
        # must produce the same set of fired detectors (auth aside).
        engine = DetectionEngine()
        kwargs = dict(
            from_header="News <info@libreriacies.es>",
            subject="Binance: verify your account",
            body="Act now: https://axobox.test/login",
        )
        without_auth = engine.detect(_email(**kwargs))
        with_auth = engine.detect(
            _email(**kwargs, auth_results="mx.test; spf=pass; dmarc=pass")
        )

        def fired_names(detection):
            return {
                r.detector
                for r in detection.detector_results
                if isinstance(r, FiredResult) and r.detector is not DetectorName.AUTH_FAILURE
            }

        self.assertTrue(fired_names(without_auth))
        self.assertEqual(fired_names(with_auth), fired_names(without_auth))


if __name__ == "__main__":
    unittest.main()
