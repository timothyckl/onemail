"""Tests for deterministic analyst-facing scan presentation."""

import unittest
from pathlib import Path

from detection.data_models import (
    AttachmentClass,
    AttachmentObservable,
    DetectorName,
    MessageObservables,
)
from web.app import scan_bytes
from web.presentation import (
    DETECTOR_PRESENTATIONS,
    present_finding,
    present_observables,
)


class DetectorPresentationTests(unittest.TestCase):
    def test_every_detector_has_analyst_facing_copy(self) -> None:
        self.assertEqual(set(DETECTOR_PRESENTATIONS), set(DetectorName))

    def test_authentication_failure_is_interpreted_from_typed_evidence(self) -> None:
        presented = present_finding(
            DetectorName.AUTH_FAILURE,
            "medium",
            False,
            {
                "spf_result": "fail",
                "dmarc_result": "fail",
                "from_domain": "sender.example",
            },
        )

        self.assertEqual(presented["title"], "Sender authentication failed")
        self.assertEqual(presented["severity_label"], "Medium concern")
        self.assertIn("SPF did not authorise", presented["interpretation"])
        self.assertIn("DMARC did not establish aligned authentication", presented["interpretation"])
        self.assertIn("sender.example", presented["interpretation"])
        facts = {item["label"]: item["value"] for item in presented["key_facts"]}
        self.assertEqual(facts["SPF result"], "Fail")
        self.assertEqual(facts["DMARC result"], "Fail")

    def test_scan_payload_keeps_raw_evidence_and_adds_interpretation(self) -> None:
        raw = (
            b'From: "Microsoft Support" <alerts@attacker.example>\r\n'
            b"To: analyst@example.org\r\n"
            b"Subject: Verify your account\r\n"
            b"Authentication-Results: mx.example.org; spf=fail; dmarc=fail\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"Verify your account at https://secure-login.example.net/login\r\n"
        )

        payload = scan_bytes("suspicious.eml", raw)
        finding = next(
            item for item in payload["findings"] if item["detector"] == "auth_failure"
        )

        self.assertEqual(finding["evidence"]["spf_result"], "fail")
        self.assertIn("interpretation", finding["presentation"])
        self.assertIn("observable_sections", payload)
        self.assertNotIn("presentation", str(payload["report"]))

    def test_scan_payload_includes_safe_message_presentation_fields(self) -> None:
        raw = (
            b'From: "Accounts Team" <alerts@example.org>\r\n'
            b"To: analyst@example.net\r\n"
            b"Date: Thu, 20 Aug 2026 17:00:00 +0800\r\n"
            b"Subject: Account review\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Review the account details in this message.\r\n"
        )

        payload = scan_bytes("message.eml", raw)
        observables = payload["observables"]

        self.assertEqual(observables["display_name"], "Accounts Team")
        self.assertEqual(observables["raw_date"], "Thu, 20 Aug 2026 17:00:00 +0800")
        self.assertIn("Review the account details", observables["body_text"])
        self.assertTrue(observables["has_plain"])
        self.assertFalse(observables["has_html"])
        self.assertEqual(observables["inline_image_count"], 0)
        self.assertEqual(observables["presentation_body_format"], "plain")
        self.assertIn("Review the account details", observables["presentation_body_text"])
        self.assertIsNone(observables["presentation_body_html"])

    def test_html_alternative_is_selected_once_and_sanitised_for_presentation(self) -> None:
        raw = (
            b'From: "Accounts Team" <alerts@example.org>\r\n'
            b"To: analyst@example.net\r\n"
            b"Subject: Account review\r\n"
            b"MIME-Version: 1.0\r\n"
            b'Content-Type: multipart/alternative; boundary="choice"\r\n\r\n'
            b"--choice\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Plain fallback only.\r\n"
            b"--choice\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
            b"<html><body><h1>Formatted body</h1>"
            b"<form action='https://example.org/submit'><label>Password "
            b"<input type='password'></label></form>"
            b"<script>alert('no')</script></body></html>\r\n"
            b"--choice--\r\n"
        )

        observables = scan_bytes("alternative.eml", raw)["observables"]
        rendered = observables["presentation_body_html"]

        self.assertEqual(observables["presentation_body_format"], "html")
        self.assertIsNone(observables["presentation_body_text"])
        self.assertIn("<h1>Formatted body</h1>", rendered)
        self.assertIn("email-input-placeholder", rendered)
        self.assertNotIn("Plain fallback only", rendered)
        self.assertNotIn("<form", rendered)
        self.assertNotIn("action=", rendered)
        self.assertNotIn("<script", rendered)
        self.assertNotIn("alert", rendered)

    def test_every_agentic_fixture_has_one_preferred_renderable_body(self) -> None:
        fixtures = Path(__file__).parent / "agentic_test_data"

        for path in sorted(fixtures.glob("*.eml")):
            with self.subTest(path=path.name):
                observables = scan_bytes(path.name, path.read_bytes())["observables"]
                body_format = observables["presentation_body_format"]
                self.assertIn(body_format, {"plain", "html"})
                selected = observables[
                    "presentation_body_html"
                    if body_format == "html"
                    else "presentation_body_text"
                ]
                self.assertTrue(selected.strip())


class ObservablePresentationTests(unittest.TestCase):
    def test_links_and_attachments_are_not_warnings_by_presence_alone(self) -> None:
        observables = MessageObservables(
            from_domain="sender.example",
            urls=("https://sender.example/news",),
            url_hosts=("sender.example",),
            attachments=(
                AttachmentObservable(
                    name="agenda.pdf",
                    content_type="application/pdf",
                    attachment_class=AttachmentClass.PDF,
                    sha256="a" * 64,
                    size=2048,
                ),
            ),
        )

        sections = present_observables(observables, ())
        items = {
            item["label"]: item
            for section in sections
            for item in section["items"]
        }

        self.assertEqual(items["Links"]["tone"], "neutral")
        self.assertIn("presence of links alone", items["Links"]["explanation"])
        self.assertEqual(items["Attachments"]["tone"], "neutral")
        self.assertIn("does not establish", items["Attachments"]["explanation"])

    def test_failed_authentication_is_explained_and_highlighted(self) -> None:
        from detection.data_models import DmarcResult, SpfResult

        observables = MessageObservables(
            has_authentication_results=True,
            spf_result=SpfResult.FAIL,
            dmarc_result=DmarcResult.FAIL,
        )

        sections = present_observables(observables, (DetectorName.AUTH_FAILURE,))
        items = {
            item["label"]: item
            for section in sections
            for item in section["items"]
        }

        self.assertEqual(items["SPF"]["value"], "Fail")
        self.assertEqual(items["SPF"]["tone"], "warn")
        self.assertIn("not authorised", items["SPF"]["explanation"])
        self.assertEqual(items["DMARC"]["tone"], "warn")
        self.assertIn("aligned SPF or DKIM", items["DMARC"]["explanation"])

    def test_sender_identity_is_limited_to_two_columns(self) -> None:
        sections = present_observables(MessageObservables(), ())
        sender = next(section for section in sections if section["title"] == "Sender identity")

        self.assertEqual(sender["max_columns"], 2)


if __name__ == "__main__":
    unittest.main()
