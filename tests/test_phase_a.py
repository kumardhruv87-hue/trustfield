"""Phase A: branded PDF, signed links, payment webhooks, orders, index, email."""
from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

from shipproof import config, emailer, indexstore, orders, payments, pdf, report, score, sign, store
from shipproof.findings import finding


def make_record(scan_id: str = "phasea1234", unlocked: bool = False, count: int = 6) -> dict:
    findings = [
        finding(
            id=f"test.rule_{i}",
            title=f"Finding number {i}",
            severity=["critical", "high", "medium", "low"][i % 4],
            category="Category",
            why="why it matters",
            fix="do this instead",
            evidence=f"https://example.com/evidence-{i}",
        )
        for i in range(count)
    ]
    assessment = score.assess(findings)
    return {
        "id": scan_id,
        "kind": "url",
        "target": "https://example.com",
        "created_at": config.now_iso(),
        "unlocked": unlocked,
        "email": "buyer@example.com",
        "has_ai": False,
        "status": "ok",
        "error": "",
        "findings": [f.to_dict() for f in findings],
        "checks": [{"id": "c1", "name": "Check one", "ok": True, "detail": ""}],
        "meta": {"platform": "Lovable", "stack": ["Next.js", "Supabase"]},
        "score": assessment,
        "kit_payloads": [],
        "kit_results": [],
        "expires_at": "2026-12-01",
    }


class SignTests(unittest.TestCase):
    def test_roundtrip(self):
        token = sign.sign("abc12345", "pdf")
        self.assertEqual(sign.verify(token, "pdf"), "abc12345")

    def test_wrong_purpose(self):
        token = sign.sign("abc12345", "pdf")
        self.assertIsNone(sign.verify(token, "admin"))

    def test_tampered(self):
        token = sign.sign("abc12345", "pdf")
        self.assertIsNone(sign.verify(token[:-2] + "aa", "pdf"))

    def test_expired(self):
        token = sign.sign("abc12345", "pdf", ttl_days=-1)
        self.assertIsNone(sign.verify(token, "pdf"))


class PdfTests(unittest.TestCase):
    def test_pdf_is_valid_and_branded(self):
        data = pdf.build_report_pdf(make_record())
        self.assertTrue(data.startswith(b"%PDF-1.4"))
        self.assertTrue(data.rstrip().endswith(b"%%EOF"))
        self.assertGreater(len(data), 5000)
        self.assertGreater(data.count(b"/Type /Page"), 2)
        self.assertIn(b"Trustfield", data)
        self.assertIn(b"Summary", data)

    def test_pdf_without_findings(self):
        record = make_record(count=0)
        data = pdf.build_report_pdf(record)
        self.assertTrue(data.startswith(b"%PDF-1.4"))
        self.assertIn(b"%%EOF", data[-20:])

    def test_pdf_handles_unicode_and_long_text(self):
        record = make_record()
        record["target"] = "https://example.com/â‚¹-long-" + "x" * 120
        record["findings"][0]["why"] = "à¤°à¤µà¤¿ and emoji ðŸš€ and a very long sentence " * 4
        data = pdf.build_report_pdf(record)
        self.assertTrue(data.startswith(b"%PDF-1.4"))


class PaymentSignatureTests(unittest.TestCase):
    def test_razorpay_signature(self):
        body = b'{"event":"payment.captured"}'
        signature = hmac.new(b"secret", body, hashlib.sha256).hexdigest()
        self.assertTrue(payments.razorpay_verify(body, signature, "secret"))
        self.assertFalse(payments.razorpay_verify(body, signature, "other"))
        self.assertFalse(payments.razorpay_verify(body, "", "secret"))

    def test_stripe_signature(self):
        import time

        body = b'{"type":"checkout.session.completed"}'
        timestamp = str(int(time.time()))
        signature = hmac.new(b"whsec", f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
        header = f"t={timestamp},v1={signature}"
        self.assertTrue(payments.stripe_verify(body, header, "whsec"))
        self.assertFalse(payments.stripe_verify(body, header, "wrong"))
        old = str(int(time.time()) - 10_000)
        old_sig = hmac.new(b"whsec", f"{old}.".encode() + body, hashlib.sha256).hexdigest()
        self.assertFalse(payments.stripe_verify(body, f"t={old},v1={old_sig}", "whsec"))

    def test_razorpay_event_extraction(self):
        payload = {
            "event": "payment.captured",
            "payload": {
                "payment": {
                    "entity": {
                        "id": "pay_123",
                        "email": "Buyer@Example.com ",
                        "amount": 49900,
                        "currency": "INR",
                        "notes": {"report_id": "abc12345", "product": "report"},
                    }
                }
            },
        }
        event = payments.razorpay_event(payload)
        self.assertEqual(event["report_id"], "abc12345")
        self.assertEqual(event["email"], "buyer@example.com")
        self.assertEqual(event["amount_minor"], 49900)

    def test_stripe_event_extraction(self):
        payload = {
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_1",
                    "client_reference_id": "abc12345",
                    "customer_details": {"email": "buyer@example.com"},
                    "amount_total": 900,
                    "currency": "usd",
                    "metadata": {"product": "report"},
                }
            },
        }
        event = payments.stripe_event(payload)
        self.assertEqual(event["report_id"], "abc12345")
        self.assertEqual(event["product"], "report")

    def test_unknown_event_is_ignored(self):
        self.assertIsNone(payments.razorpay_event({"event": "refund.created"}))
        self.assertIsNone(payments.stripe_event({"type": "invoice.paid"}))


class IndexTests(unittest.TestCase):
    def setUp(self):
        config.INDEX_FILE.unlink(missing_ok=True)

    def test_aggregate_rates(self):
        indexstore.record(
            {
                "created_at": "2026-01-01T00:00:00+00:00",
                "kind": "url",
                "meta": {"platform": "Lovable", "stack": ["Supabase"]},
                "checks": [{"id": "a", "ok": True}, {"id": "b", "ok": False}],
                "findings": [{"id": "repo.rls_missing", "severity": "critical"}],
            }
        )
        indexstore.record(
            {
                "created_at": "2026-01-02T00:00:00+00:00",
                "kind": "url",
                "meta": {"platform": "Lovable", "stack": ["Supabase"]},
                "checks": [{"id": "a", "ok": True}],
                "findings": [],
            }
        )
        data = indexstore.aggregate()
        self.assertEqual(data["scans"], 2)
        self.assertEqual(data["top_issues"][0]["id"], "repo.rls_missing")
        self.assertEqual(data["top_issues"][0]["rate"], 50.0)
        self.assertEqual(data["platforms"][0]["name"], "Lovable")

    def test_no_pii_stored(self):
        indexstore.record(
            {
                "created_at": "x",
                "kind": "url",
                "target": "https://secret-customer.example",
                "email": "someone@example.com",
                "meta": {},
                "checks": [],
                "findings": [],
            }
        )
        raw = config.INDEX_FILE.read_text(encoding="utf-8")
        self.assertNotIn("secret-customer", raw)
        self.assertNotIn("someone@example.com", raw)


class OrderTests(unittest.TestCase):
    def setUp(self):
        config.ORDERS_FILE.unlink(missing_ok=True)

    def test_append_exists_summary(self):
        orders.append({"provider_id": "pay_1", "status": "paid", "amount_minor": 49900})
        self.assertTrue(orders.exists("pay_1"))
        self.assertFalse(orders.exists("pay_2"))
        summary = orders.summary()
        self.assertEqual(summary["orders"], 1)
        self.assertEqual(summary["revenue_inr"], 499.0)


class EmailTests(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(config.EMAIL_OUTBOX, ignore_errors=True)

    def test_outbox_fallback_when_no_key(self):
        with mock.patch.object(config, "RESEND_API_KEY", ""):
            result = emailer.send("buyer@example.com", "Test subject", "<p>hello</p>")
        self.assertTrue(result["ok"])
        self.assertEqual(result["mode"], "outbox")
        files = list(config.EMAIL_OUTBOX.glob("*.html"))
        self.assertEqual(len(files), 1)
        self.assertIn("buyer@example.com", files[0].read_text(encoding="utf-8"))

    def test_report_email_contains_pdf_link(self):
        subject, html = emailer.report_email_html(make_record())
        self.assertIn("report", subject.lower())
        self.assertIn("/pdf/phasea1234?token=", html)


class WebhookIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from shipproof import server

        config.ensure_dirs()
        cls.record = make_record("phasea1234", unlocked=False)
        store.save_scan(cls.record)
        cls.httpd = server.make_server("127.0.0.1", 0)
        host, port = cls.httpd.server_address[:2]
        cls.base = f"http://{host}:{port}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _post(self, path: str, body: bytes, headers: dict) -> tuple[int, dict]:
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            exc.close()
            try:
                return exc.code, json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return exc.code, {}

    def test_01_bad_signature_rejected(self):
        body = json.dumps({"event": "payment.captured"}).encode()
        status, _ = self._post("/webhooks/razorpay", body, {"X-Razorpay-Signature": "nope", "Content-Type": "application/json"})
        self.assertEqual(status, 400)

    def test_02_valid_webhook_unlocks_report(self):
        orders_file = config.ORDERS_FILE
        orders_file.unlink(missing_ok=True)
        payload = {
            "event": "payment.captured",
            "payload": {
                "payment": {
                    "entity": {
                        "id": "pay_phasea_1",
                        "email": "buyer@example.com",
                        "amount": 49900,
                        "currency": "INR",
                        "notes": {"report_id": "phasea1234", "product": "report"},
                    }
                }
            },
        }
        body = json.dumps(payload).encode()
        with mock.patch.object(config, "RAZORPAY_WEBHOOK_SECRET", "test-whsec"):
            signature = hmac.new(b"test-whsec", body, hashlib.sha256).hexdigest()
            status, data = self._post(
                "/webhooks/razorpay",
                body,
                {"X-Razorpay-Signature": signature, "Content-Type": "application/json"},
            )
        self.assertEqual(status, 200, data)
        self.assertEqual(data.get("id"), "phasea1234")
        record = store.load_scan("phasea1234")
        self.assertTrue(record["unlocked"])
        summary = orders.summary()
        self.assertGreaterEqual(summary["orders"] + summary["test_orders"], 1)

    def test_03_duplicate_webhook_is_idempotent(self):
        payload = {
            "event": "payment.captured",
            "payload": {"payment": {"entity": {"id": "pay_phasea_1", "notes": {"report_id": "phasea1234"}}}},
        }
        body = json.dumps(payload).encode()
        with mock.patch.object(config, "RAZORPAY_WEBHOOK_SECRET", "test-whsec"):
            signature = hmac.new(b"test-whsec", body, hashlib.sha256).hexdigest()
            status, data = self._post(
                "/webhooks/razorpay",
                body,
                {"X-Razorpay-Signature": signature, "Content-Type": "application/json"},
            )
        self.assertEqual(status, 200)
        self.assertTrue(data.get("duplicate"))

    def test_04_pdf_requires_token(self):
        try:
            urllib.request.urlopen(self.base + "/pdf/phasea1234", timeout=15)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
        self.assertEqual(status, 403)

    def test_05_pdf_download_with_signed_token(self):
        token = sign.sign("phasea1234", "pdf")
        request = urllib.request.Request(self.base + f"/pdf/phasea1234?token={token}")
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            self.assertEqual(response.status, 200)
            self.assertIn("application/pdf", response.headers.get("Content-Type", ""))
        self.assertTrue(body.startswith(b"%PDF-1.4"))

    def test_06_index_page_renders(self):
        with urllib.request.urlopen(self.base + "/index", timeout=15) as response:
            text = response.read().decode("utf-8")
        self.assertEqual(response.status, 200)
        self.assertIn("Vulnerability Index", text)

    def test_07_admin_dashboard_requires_token(self):
        try:
            urllib.request.urlopen(self.base + "/admin", timeout=15)
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 403)
            exc.close()


if __name__ == "__main__":
    unittest.main()

