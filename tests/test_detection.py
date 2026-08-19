"""Behavioural tests for parsing, rules, and message-level orchestration."""

import unittest
from email.message import EmailMessage
from typing import Optional

from detection import DetectionEngine, EmailParser
from detection.detectors import (
    AuthFailureDetector,
    BecNoPayloadDetector,
    CredentialUrlDetector,
    DisplayNameSpoofDetector,
    Detector,
    ReplyToDivergenceDetector,
)
from detection.data_models import (
    AttachmentClass,
    AuthFailureEvidence,
    AuthFailureFinding,
    BecNoPayloadFinding,
    ClearResult,
    CredentialUrlFinding,
    DetectorName,
    DisplayNameSpoofFinding,
    Email,
    Finding,
    FiredResult,
    MessageObservables,
    ReplyToDivergenceFinding,
    DetectorResult,
    SkippedResult,
    SpfResult,
)


def email_bytes(
    *,
    sender: str = "sender@example.com",
    reply_to: Optional[str] = None,
    subject: str = "Hello",
    body: str = "Ordinary message",
    authentication: Optional[str] = None,
) -> bytes:
    """Build a minimal email fixture using the standard-library writer."""

    message = EmailMessage()
    message["From"] = sender
    message["To"] = "recipient@example.net"
    message["Subject"] = subject
    if reply_to is not None:
        message["Reply-To"] = reply_to
    if authentication is not None:
        message["Authentication-Results"] = authentication
    message.set_content(body)
    return message.as_bytes()


class EmailParserTests(unittest.TestCase):
    def test_parser_builds_typed_observables(self) -> None:
        raw = email_bytes(
            sender='"PayPal Service" <notice@evil.example>',
            reply_to="collect@other.example",
            body="Verify your account at https://login.evil.example/start",
            authentication="mx.example; spf=fail; dmarc=fail",
        )

        observables = EmailParser().parse(Email(file="message.eml", content=raw))

        self.assertEqual(observables.path, "message.eml")
        self.assertEqual(observables.from_domain, "evil.example")
        self.assertEqual(observables.reply_to_domain, "other.example")
        self.assertTrue(observables.reply_to_differs)
        self.assertEqual(observables.display_name_brand, "paypal")
        self.assertEqual(observables.spf_result, SpfResult.FAIL)
        self.assertEqual(observables.url_hosts, ("login.evil.example",))

    def test_parser_extracts_attachment_metadata(self) -> None:
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "recipient@example.net"
        message.set_content("See attachment")
        message.add_attachment(
            b"MZ\x00\x00",
            maintype="application",
            subtype="octet-stream",
            filename="payload.exe",
        )

        observables = EmailParser().parse(
            Email(file="attachment.eml", content=message.as_bytes())
        )

        self.assertEqual(observables.attachment_count, 1)
        self.assertEqual(
            observables.attachments[0].attachment_class,
            AttachmentClass.EXECUTABLE,
        )
        self.assertEqual(observables.attachments[0].size, 4)
        self.assertIsNotNone(observables.attachments[0].sha256)

    def test_parser_preserves_missing_and_conflicting_header_states(self) -> None:
        raw = (
            b"From: first@example.com\r\n"
            b"From: second@example.net\r\n"
            b"To: recipient@example.org\r\n"
            b"Subject: Duplicate sender\r\n"
            b"\r\n"
            b"Body\r\n"
        )

        observables = EmailParser().parse(Email(file="duplicate.eml", content=raw))

        self.assertEqual(observables.from_domain, "example.com")
        self.assertIsNone(observables.reply_to_differs)
        self.assertEqual(observables.duplicate_headers[0].name, "from")
        self.assertEqual(observables.duplicate_headers[0].selected_value, "first@example.com")


class DetectorTests(unittest.TestCase):
    def test_polymorphic_types_share_bases(self) -> None:
        finding = AuthFailureFinding(
            clause="sender authentication failed: spf=fail",
            evidence=AuthFailureEvidence(
                spf_result=SpfResult.FAIL,
                dmarc_result=None,
                from_domain="sender.example",
            ),
        )
        result = FiredResult(detector=DetectorName.AUTH_FAILURE, finding=finding)

        self.assertIsInstance(finding, Finding)
        self.assertIsInstance(result, DetectorResult)
        self.assertIsInstance(AuthFailureDetector(), Detector)

    def test_auth_failure_fires_clears_and_skips(self) -> None:
        detector = AuthFailureDetector()
        fired = detector.detect(
            MessageObservables(
                has_authentication_results=True,
                spf_result=SpfResult.FAIL,
            )
        )
        clear = detector.detect(
            MessageObservables(
                has_authentication_results=True,
                spf_result=SpfResult.PASS,
            )
        )
        skipped = detector.detect(MessageObservables())

        self.assertIsInstance(fired, FiredResult)
        assert isinstance(fired, FiredResult)
        self.assertIsInstance(fired.finding, AuthFailureFinding)
        self.assertIsInstance(clear, ClearResult)
        self.assertIsInstance(skipped, SkippedResult)

    def test_reply_to_divergence_fires(self) -> None:
        detector = ReplyToDivergenceDetector()
        fired = detector.detect(
            MessageObservables(
                from_domain="sender.example",
                reply_to_domain="evil.example",
                reply_to_differs=True,
            )
        )
        clear = detector.detect(MessageObservables(reply_to_differs=False))
        skipped = detector.detect(MessageObservables())

        self.assertIsInstance(fired, FiredResult)
        assert isinstance(fired, FiredResult)
        self.assertIsInstance(fired.finding, ReplyToDivergenceFinding)
        self.assertIsInstance(clear, ClearResult)
        self.assertIsInstance(skipped, SkippedResult)

    def test_reply_to_divergence_skips_on_mailing_list(self) -> None:
        skipped = ReplyToDivergenceDetector().detect(
            MessageObservables(
                from_domain="sender.example",
                reply_to_domain="list.example",
                reply_to_differs=True,
                is_mailing_list=True,
            )
        )
        self.assertIsInstance(skipped, SkippedResult)

    def test_credential_url_requires_mismatch_and_language(self) -> None:
        detector = CredentialUrlDetector()
        fired = detector.detect(
            MessageObservables(
                from_domain="sender.example",
                body_text="Please verify your account",
                urls=("https://evil.example/login",),
                url_hosts=("evil.example",),
            )
        )
        clear = detector.detect(
            MessageObservables(
                from_domain="sender.example",
                body_text="Read the latest news",
                urls=("https://evil.example/news",),
                url_hosts=("evil.example",),
            )
        )
        skipped = detector.detect(MessageObservables())

        self.assertIsInstance(fired, FiredResult)
        assert isinstance(fired, FiredResult)
        self.assertIsInstance(fired.finding, CredentialUrlFinding)
        self.assertIsInstance(clear, ClearResult)
        self.assertIsInstance(skipped, SkippedResult)

    def test_credential_url_ignores_a_lone_generic_token(self) -> None:
        detector = CredentialUrlDetector()
        lone_token = detector.detect(
            MessageObservables(
                from_domain="sender.example",
                body_text="Use your login details on the wiki",
                urls=("https://wiki.example/page",),
                url_hosts=("wiki.example",),
            )
        )
        two_tokens = detector.detect(
            MessageObservables(
                from_domain="sender.example",
                body_text="signin here or log in now",
                urls=("https://evil.example/x",),
                url_hosts=("evil.example",),
            )
        )
        self.assertIsInstance(lone_token, ClearResult)
        self.assertIsInstance(two_tokens, FiredResult)

    def test_display_name_spoof_fires(self) -> None:
        detector = DisplayNameSpoofDetector()
        fired = detector.detect(
            MessageObservables(
                from_domain="unrelated.example",
                display_name="PayPal Service",
                display_name_brand="paypal",
            )
        )
        clear = detector.detect(MessageObservables(from_domain="sender.example"))
        skipped = detector.detect(MessageObservables())

        self.assertIsInstance(fired, FiredResult)
        assert isinstance(fired, FiredResult)
        self.assertIsInstance(fired.finding, DisplayNameSpoofFinding)
        self.assertIsInstance(clear, ClearResult)
        self.assertIsInstance(skipped, SkippedResult)

    def test_payload_free_bec_does_not_fire_on_absence_alone(self) -> None:
        detector = BecNoPayloadDetector()
        fired = detector.detect(MessageObservables(body_text="Urgent wire transfer"))
        clear = detector.detect(MessageObservables(body_text="Confirm the meeting"))

        self.assertIsInstance(fired, FiredResult)
        assert isinstance(fired, FiredResult)
        self.assertIsInstance(fired.finding, BecNoPayloadFinding)
        self.assertIsInstance(clear, ClearResult)


class ExtraDetectorTests(unittest.TestCase):
    def test_dangerous_attachment_fires_on_executable(self) -> None:
        from detection.detectors import DangerousAttachmentDetector
        from detection.data_models import AttachmentObservable

        exe = AttachmentObservable(
            name="invoice.exe",
            content_type="application/octet-stream",
            attachment_class=AttachmentClass.EXECUTABLE,
            sha256="0" * 64,
            size=10,
        )
        fired = DangerousAttachmentDetector().detect(
            MessageObservables(attachments=(exe,))
        )
        skipped = DangerousAttachmentDetector().detect(MessageObservables())
        self.assertIsInstance(fired, FiredResult)
        self.assertIsInstance(skipped, SkippedResult)

    def test_extension_spoof_fires_on_double_extension(self) -> None:
        from detection.detectors import AttachmentExtensionSpoofDetector
        from detection.data_models import AttachmentObservable

        spoof = AttachmentObservable(
            name="statement.pdf.exe",
            content_type="application/octet-stream",
            attachment_class=AttachmentClass.EXECUTABLE,
            sha256="0" * 64,
            size=10,
        )
        fired = AttachmentExtensionSpoofDetector().detect(
            MessageObservables(attachments=(spoof,))
        )
        self.assertIsInstance(fired, FiredResult)

    def test_raw_ip_url_fires(self) -> None:
        from detection.detectors import RawIpUrlDetector

        fired = RawIpUrlDetector().detect(
            MessageObservables(
                urls=("http://203.0.113.9/login",), url_hosts=("203.0.113.9",)
            )
        )
        clear = RawIpUrlDetector().detect(
            MessageObservables(urls=("http://safe.example/",), url_hosts=("safe.example",))
        )
        skipped = RawIpUrlDetector().detect(MessageObservables())
        self.assertIsInstance(fired, FiredResult)
        self.assertIsInstance(clear, ClearResult)
        self.assertIsInstance(skipped, SkippedResult)

    def test_lookalike_domain_requires_brand_similarity(self) -> None:
        from detection.detectors import LookalikeDomainDetector

        typo = LookalikeDomainDetector().detect(
            MessageObservables(url_hosts=("paypa1.com",))
        )
        homograph = LookalikeDomainDetector().detect(
            MessageObservables(url_hosts=("xn--pypal-4ve.com",))
        )
        legitimate_idn = LookalikeDomainDetector().detect(
            MessageObservables(url_hosts=("xn--bcher-kva.de",))
        )

        self.assertIsInstance(typo, FiredResult)
        assert isinstance(typo, FiredResult)
        self.assertTrue(typo.finding.heuristic)
        self.assertIsInstance(homograph, FiredResult)
        assert isinstance(homograph, FiredResult)
        self.assertFalse(homograph.finding.heuristic)
        self.assertEqual(homograph.finding.evidence.brands, ("paypal",))
        self.assertIsInstance(legitimate_idn, ClearResult)

    def test_nested_sender_mismatch_requires_an_outer_sender(self) -> None:
        from detection.data_models import NestedSender
        from detection.detectors import NestedSenderMismatchDetector

        nested = NestedSender(
            sender="forwarder@other.example",
            subject="Forwarded message",
            reason="sender identity observed in a forwarded message",
        )
        skipped = NestedSenderMismatchDetector().detect(
            MessageObservables(nested_senders=(nested,))
        )
        matching = NestedSenderMismatchDetector().detect(
            MessageObservables(
                from_domain="mail.other.example", nested_senders=(nested,)
            )
        )
        mismatching = NestedSenderMismatchDetector().detect(
            MessageObservables(
                from_domain="corp.example", nested_senders=(nested,)
            )
        )

        self.assertIsInstance(skipped, SkippedResult)
        self.assertIsInstance(matching, ClearResult)
        self.assertIsInstance(mismatching, FiredResult)

    def test_high_abuse_tld_requires_language(self) -> None:
        from detection.detectors import HighAbuseTldDetector

        fired = HighAbuseTldDetector().detect(
            MessageObservables(
                subject="Your account expires today",
                url_hosts=("secure-login.top",),
                urls=("https://secure-login.top/",),
            )
        )
        clear = HighAbuseTldDetector().detect(
            MessageObservables(
                subject="Weekly newsletter",
                url_hosts=("secure-login.top",),
                urls=("https://secure-login.top/",),
            )
        )
        self.assertIsInstance(fired, FiredResult)
        self.assertIsInstance(clear, ClearResult)

    def test_private_sender_ip_only_when_no_public_ip(self) -> None:
        from detection.detectors import PrivateSenderIpDetector
        from detection.data_models import SenderIp

        only_private = PrivateSenderIpDetector().detect(
            MessageObservables(sender_ips=(SenderIp(address="10.0.0.5", hop=1, trusted=False),))
        )
        mixed = PrivateSenderIpDetector().detect(
            MessageObservables(
                sender_ips=(
                    SenderIp(address="10.0.0.5", hop=1, trusted=False),
                    SenderIp(address="137.184.34.4", hop=2, trusted=False),
                )
            )
        )
        self.assertIsInstance(only_private, FiredResult)
        self.assertIsInstance(mixed, ClearResult)

    def test_private_sender_ip_skips_on_loopback_only_chain(self) -> None:
        from detection.detectors import PrivateSenderIpDetector
        from detection.data_models import SenderIp

        loopback_only = PrivateSenderIpDetector().detect(
            MessageObservables(
                sender_ips=(
                    SenderIp(address="127.0.0.1", hop=1, trusted=False),
                    SenderIp(address="127.0.0.1", hop=2, trusted=False),
                )
            )
        )
        self.assertIsInstance(loopback_only, SkippedResult)

    def test_duplicate_header_conflict_ignores_return_path(self) -> None:
        from detection.detectors import DuplicateHeaderConflictDetector
        from detection.data_models import DuplicateHeader

        result = DuplicateHeaderConflictDetector().detect(
            MessageObservables(
                duplicate_headers=(
                    DuplicateHeader(
                        name="return-path",
                        values=("<a@x.example>", "<b@y.example>"),
                        selected_value="<a@x.example>",
                        reason="'return-path' appears 2 times with different values",
                    ),
                )
            )
        )
        self.assertIsInstance(result, ClearResult)

    def test_parser_compares_reply_to_by_registrable_domain(self) -> None:
        same_registrant = EmailParser().parse(
            Email(
                file="sub.eml",
                content=email_bytes(
                    sender="news@lockergnome.com",
                    reply_to="news@sprocket.lockergnome.com",
                ),
            )
        )
        different_registrant = EmailParser().parse(
            Email(
                file="diff.eml",
                content=email_bytes(
                    sender="news@sender.example",
                    reply_to="other@evil.example",
                ),
            )
        )
        self.assertFalse(same_registrant.reply_to_differs)
        self.assertTrue(different_registrant.reply_to_differs)

    def test_advance_fee_skips_on_mailing_list(self) -> None:
        from detection.detectors import AdvanceFeeDetector

        skipped = AdvanceFeeDetector().detect(
            MessageObservables(
                from_domain="member.example",
                body_text="they claimed the inheritance was cursed",
                reply_to_differs=True,
                is_mailing_list=True,
            )
        )
        self.assertIsInstance(skipped, SkippedResult)

    def test_freemail_sender_skips_on_mailing_list(self) -> None:
        from detection.detectors import FreemailSenderDetector

        skipped = FreemailSenderDetector().detect(
            MessageObservables(
                from_domain="hotmail.com",
                body_text="microsoft just bought another company",
                is_mailing_list=True,
            )
        )
        self.assertIsInstance(skipped, SkippedResult)

    def test_parser_marks_mailing_list_messages(self) -> None:
        message = EmailMessage()
        message["From"] = "member@example.org"
        message["Subject"] = "list traffic"
        message["List-Id"] = "<discuss.example.org>"
        message.set_content("hello")
        observables = EmailParser().parse(
            Email(file="list.eml", content=message.as_bytes())
        )
        self.assertTrue(observables.is_mailing_list)

        bulk = EmailMessage()
        bulk["From"] = "blast@example.org"
        bulk["Subject"] = "promo"
        bulk["Precedence"] = "bulk"
        bulk.set_content("hello")
        observables = EmailParser().parse(
            Email(file="bulk.eml", content=bulk.as_bytes())
        )
        self.assertFalse(observables.is_mailing_list)

    def test_image_only_body_fires(self) -> None:
        from detection.detectors import ImageOnlyBodyDetector

        fired = ImageOnlyBodyDetector().detect(
            MessageObservables(
                has_html=True, has_plain=False, body_text="  ",
                urls=("https://x.example/",),
            )
        )
        clear = ImageOnlyBodyDetector().detect(
            MessageObservables(
                has_html=True, has_plain=False,
                body_text="A perfectly ordinary amount of readable body text here.",
                urls=("https://x.example/",),
            )
        )
        self.assertIsInstance(fired, FiredResult)
        self.assertIsInstance(clear, ClearResult)


class DetectionEngineTests(unittest.TestCase):
    def test_engine_returns_complete_flagged_detection(self) -> None:
        raw = email_bytes(
            reply_to="collect@evil.example",
            body="Quick request",
            authentication="mx.example; spf=pass; dmarc=pass",
        )

        detection = DetectionEngine().detect(
            Email(file="message.eml", content=raw)
        )

        self.assertEqual(
            {result.detector for result in detection.detector_results},
            set(DetectorName),
        )
        self.assertTrue(detection.flagged)
        self.assertEqual(
            {finding.detector for finding in detection.findings},
            {DetectorName.REPLY_TO_DIVERGENCE, DetectorName.BEC_NO_PAYLOAD},
        )

    def test_engine_is_deterministic(self) -> None:
        email = Email(
            file="message.eml",
            content=email_bytes(authentication="mx.example; spf=pass; dmarc=pass"),
        )
        engine = DetectionEngine()

        first = engine.detect(email)
        second = engine.detect(email)

        self.assertEqual(first, second)
        self.assertFalse(first.flagged)
        self.assertEqual(first.findings, ())
        # On a bare email, the Reply-To and credential-URL rules skip; additional
        # detectors that need attachments or URLs also skip. Assert the intended
        # pair is present rather than an exact set, so adding detectors that skip
        # on an empty message doesn't make this brittle.
        skipped_detectors = {result.detector for result in first.skipped}
        self.assertLessEqual(
            {DetectorName.REPLY_TO_DIVERGENCE, DetectorName.CREDENTIAL_URL},
            skipped_detectors,
        )


if __name__ == "__main__":
    unittest.main()
