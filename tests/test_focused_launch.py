"""Regression coverage for the paid customer journey and cost controls."""
from __future__ import annotations

import concurrent.futures
import datetime as dt
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from shipproof import aicopilot, config, orders, payments, report, server, storage, store, usage, watch
from .test_report_modes import make_record


class FocusedLaunchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.patches = [patch.object(config, "DATA_DIR", root),
                        patch.object(config, "SCANS_DIR", root / "scans"),
                        patch.object(config, "ORDERS_FILE", root / "orders.jsonl"),
                        patch.object(config, "LEADS_FILE", root / "leads.jsonl"),
                        patch.object(storage, "enabled", return_value=False)]
        for p in self.patches:
            p.start()
        config.ensure_dirs()
        self.handler = object.__new__(server.Handler)
        self.handler.headers = {}
        self.handler._json = MagicMock()
        self.handler._redirect = MagicMock()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.temp.cleanup()

    def event(self, product="report", amount=49900, **extra):
        return {"provider": "razorpay", "provider_id": "pay_unique", "product": product,
                "report_id": "reportid12", "currency": "INR", "amount_minor": amount,
                "email": "buyer@example.com", **extra}

    def test_real_payment_link_shape_has_canonical_payment_id(self):
        event = payments.razorpay_event({"event": "payment_link.paid", "payload": {
            "payment": {"entity": {"id": "pay_actual"}},
            "payment_link": {"entity": {"id": "plink_actual", "amount_paid": 49900,
                "currency": "INR", "reference_id": "reportid12", "notes": {},
                "customer": {"email": "buyer@example.com"}}}}})
        self.assertEqual(event["provider_id"], "pay_actual")
        self.assertEqual(event["report_id"], "reportid12")

    def test_agency_without_report_id_fulfills_once(self):
        event = self.event("agency", 399900, report_id="")
        with patch.object(server.emailer, "send_agency_welcome"):
            self.handler._apply_payment(event)
            self.handler._apply_payment(event)
        self.assertEqual(sum(r["credits"] for r in server.agency.load()), 10)
        self.assertTrue(self.handler._json.call_args.args[1]["duplicate"])
        self.assertEqual(len(orders.all_orders()), 1)

    def test_wrong_currency_and_zero_amount_do_not_unlock(self):
        store.save_scan(make_record())
        self.handler._apply_payment(self.event(amount=0))
        self.handler._apply_payment(self.event(currency="EUR"))
        self.assertFalse(store.load_scan("reportid12")["unlocked"])
        self.assertEqual(orders.all_orders(), [])

    def test_payment_unlocks_email_pdf_and_repeated_delivery_is_safe(self):
        store.save_scan(make_record())
        with patch.object(server.emailer, "send_report", return_value={"ok": True, "mode": "resend"}) as mail, patch.object(server.notify, "send"):
            self.handler._apply_payment(self.event())
            self.handler._apply_payment(self.event())
        record = store.load_scan("reportid12")
        self.assertTrue(record["unlocked"])
        self.assertEqual(record["email"], "buyer@example.com")
        self.assertEqual(mail.call_count, 1)
        self.assertEqual(len(orders.all_orders()), 1)
        self.assertIn("/pdf/", report.report_page(record))

    def test_paid_recheck_remains_unlocked_and_reuses_one_credit(self):
        old = make_record(); old.update(unlocked=True, kind="repo", target="owner/repo", created_at=config.now_iso())
        store.save_scan(old)
        new = make_record(0); new["id"] = "newreport12"; store.save_scan(new)
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({"id": "newreport12", "teaser": []}).encode()
        with patch.object(server.urllib.request, "urlopen", return_value=response) as fetch:
            self.handler._verify_rescan(old["id"])
            self.handler._verify_rescan(old["id"])
            self.assertEqual(fetch.call_count, 1)
            request = fetch.call_args.args[0]
            self.assertEqual(json.loads(request.data)["kind"], "repo")
        self.assertTrue(store.load_scan("newreport12")["unlocked"])
        self.assertEqual(store.load_scan(old["id"])["verification_scan_id"], "newreport12")

    def test_cancel_is_accessible_in_focus_mode_and_failure_does_not_lie(self):
        self.handler.path = "/watch/cancel"
        payload = b"token=valid"
        self.handler.headers = {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(payload))}
        self.handler.rfile = io.BytesIO(payload)
        self.handler._client_ip = lambda: "127.0.0.1"
        with patch.object(config, "FOCUS_MODE", True), patch.object(watch, "by_cancel_token", return_value={"id": "w_test", "subscription_id": "sub_test"}), patch.object(payments, "cancel_subscription", return_value=False), patch.object(watch, "disable_auto_renew") as disabled:
            with self.assertRaises(server.HTTPProblem) as error:
                self.handler._route("POST")
            self.assertEqual(error.exception.status, 502)
            disabled.assert_not_called()

    def test_concurrent_ai_requests_cannot_exceed_daily_allowance(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"choices":[{"message":{"content":"A fix"}}]}'
        with patch.object(config, "DEEPSEEK_API_KEY", "test"), patch.object(config, "AI_DAILY_LIMIT", 2), patch.object(aicopilot.urllib.request, "urlopen", return_value=response) as upstream:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                answers = list(pool.map(lambda _: aicopilot.ask({}, "Explain"), range(8)))
        self.assertEqual(sum(answer["ok"] for answer in answers), 2)
        self.assertEqual(upstream.call_count, 2)
        self.assertEqual(usage.today("ai_attempts"), 2)

    def test_ai_allowance_restores_after_local_state_is_lost(self):
        previous = {"ai_attempts": {usage._today(): 2}}
        with patch.object(storage, "enabled", return_value=True), patch.object(storage, "get_json", return_value=previous), patch.object(storage, "put_json", return_value=True):
            self.assertFalse(usage.reserve("ai_attempts", 2))

    def test_newly_restored_old_scan_is_deleted_by_creation_date(self):
        record = make_record()
        record["created_at"] = (config.now() - dt.timedelta(days=40)).isoformat()
        store.save_scan(record)
        store.purge_old(30)
        self.assertIsNone(store.load_scan(record["id"]))

    def test_remote_deletion_batches_all_objects(self):
        with patch.object(storage, "enabled", return_value=True), patch.object(storage, "_request", return_value=(200, b"{}")) as request:
            self.assertTrue(storage.delete_many([f"scans/{i}.json" for i in range(205)]))
        self.assertEqual([len(json.loads(call.args[2])["prefixes"]) for call in request.call_args_list], [100, 100, 5])

    def test_no_issues_page_has_no_checkout_pressure(self):
        page = report.report_page(make_record(0))
        self.assertIn("No fixes to buy", page)
        self.assertNotIn("/pay/", page)
        self.assertNotIn("agency-unlock", page)
        self.assertNotIn("Guided chatbot checks", page)

    def test_funnel_does_not_accept_unbounded_source_names(self):
        usage.funnel("scan_complete", "private@example.com")
        self.assertEqual(usage.month("funnel_scan_complete_other"), 1)
        self.assertNotIn("private@example.com", usage._path().read_text())


if __name__ == "__main__":
    unittest.main()
