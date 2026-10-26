from __future__ import annotations

import datetime as dt
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from shipproof import admin_panel, config, orders, payments, report, server, sign, storage, store


class AdminDataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.patches = [patch.object(config, "DATA_DIR", root), patch.object(config, "SCANS_DIR", root / "scans"),
                        patch.object(config, "ORDERS_FILE", root / "orders.jsonl"), patch.object(storage, "enabled", return_value=False)]
        for p in self.patches: p.start()
        config.ensure_dirs()

    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()

    def order(self, pid, **extra):
        return {"provider": "razorpay", "provider_id": pid, "status": "paid", "amount_minor": 49900, "currency": "INR", **extra}

    def test_legacy_test_manual_and_other_currency_are_not_confirmed_inr_sales(self):
        records = [self.order("pay_legacy"), self.order("pay_test_1"),
                   self.order("", provider="manual"), self.order("pay_zero", amount_minor=0),
                   self.order("pay_usd", currency="USD", amount_minor=900, verification="signed_webhook", payment_mode="live"),
                   self.order("pay_real", verification="signed_webhook", payment_mode="live")]
        with patch.object(orders, "all_orders", return_value=records):
            summary = orders.summary()
        self.assertEqual(summary["confirmed_orders"], 1)
        self.assertEqual(summary["confirmed_inr"], 499)
        self.assertEqual(summary["test_orders"], 1)
        self.assertEqual(summary["manual_grants"], 1)
        self.assertEqual(summary["review_count"], 2)

    def test_gateway_check_updates_evidence_without_rewriting_original_order(self):
        raw = self.order("pay_real", amount_minor=0)
        orders.append(raw)
        original = config.ORDERS_FILE.read_bytes()
        orders.record_check("pay_real", {"verified": True, "amount_minor": 49900, "currency": "INR", "payment_mode": "live"})
        self.assertEqual(orders.summary()["confirmed_inr"], 499)
        self.assertEqual(config.ORDERS_FILE.read_bytes(), original)

    def test_duplicate_payment_reference_is_not_double_counted(self):
        row = self.order("pay_real", verification="signed_webhook", payment_mode="live")
        with patch.object(orders, "all_orders", return_value=[row, row]):
            self.assertEqual(orders.summary()["confirmed_orders"], 1)

    def test_email_outbox_is_not_customer_delivery(self):
        self.assertIn("not sent", admin_panel.email_status({"unlocked": True, "email_result": {"ok": True, "mode": "outbox"}}))
        self.assertEqual(admin_panel.email_status({"email_result": {"ok": True, "mode": "resend"}}), "Accepted by email provider")

    def test_recent_scans_sort_by_scan_timestamp_not_cache_mtime(self):
        store.save_scan({"id": "newerscan1", "created_at": config.now_iso()})
        store.save_scan({"id": "olderscan1", "created_at": (config.now() - dt.timedelta(days=1)).isoformat()})
        self.assertEqual(server._recent_scans(1)[0]["id"], "newerscan1")

    def test_expired_and_paused_watch_records_are_not_active(self):
        self.assertFalse(admin_panel.watch_current({"active": False, "paid_until": (config.now() + dt.timedelta(days=1)).isoformat()}))
        self.assertFalse(admin_panel.watch_current({"active": True, "paid_until": (config.now() - dt.timedelta(minutes=1)).isoformat()}))

    def test_gateway_lookup_uses_get_and_does_not_create_money_actions(self):
        with patch.object(config, "RAZORPAY_KEY_ID", "rzp_live_example"), patch.object(config, "RAZORPAY_KEY_SECRET", "local-example"), patch.object(payments, "_rzp", return_value={"id": "pay_real", "status": "captured", "amount": 49900, "currency": "INR"}) as gateway:
            self.assertTrue(payments.lookup_receipt("pay_real")["verified"])
            self.assertEqual(gateway.call_args.args, ("GET", "/v1/payments/pay_real"))

    def test_admin_mutations_require_csrf_even_with_admin_session(self):
        h = object.__new__(server.Handler)
        h._admin_ok = lambda: True
        h._read_form = lambda: {"action": ["reconcile"], "csrf": ["invalid"]}
        with patch.object(payments, "lookup_receipt") as gateway:
            with self.assertRaises(server.HTTPProblem) as exc: h._admin_operation()
            self.assertEqual(exc.exception.status, 403)
            gateway.assert_not_called()

    def test_dashboard_has_no_fake_cost_or_blank_tokens(self):
        page = report.admin_page([], {"confirmed_inr": 0}, {}, "", [], [], False, [])
        self.assertNotIn("?token=", page)
        self.assertNotIn("0.0236", page)
        self.assertNotIn("Est. net payout", page)
        self.assertIn("Legacy records", page)
        self.assertIn('action="/admin/actions"', page)

    def operation(self, action, **fields):
        h = object.__new__(server.Handler)
        h._admin_ok = lambda: True
        h._redirect = MagicMock()
        h._read_form = lambda: {"action": [action], "csrf": [sign.sign("admin", "admin_action")],
                                **{k: [v] for k, v in fields.items()}}
        return h

    def test_access_grant_is_not_a_sale_or_an_automatic_email(self):
        store.save_scan({"id": "adminscan1", "unlocked": False})
        h = self.operation("grant", scan_id="adminscan1", confirmed="1")
        with patch.object(server.emailer, "send_report") as email:
            h._admin_operation()
            email.assert_not_called()
        self.assertTrue(store.load_scan("adminscan1")["unlocked"])
        self.assertEqual(orders.summary()["confirmed_orders"], 0)
        self.assertEqual(orders.summary()["manual_grants"], 1)

    def test_outbox_result_does_not_display_email_success(self):
        store.save_scan({"id": "adminscan1", "unlocked": True, "email": "buyer@example.com"})
        h = self.operation("email", scan_id="adminscan1")
        with patch.object(server.emailer, "send_report", return_value={"ok": True, "mode": "outbox"}):
            h._admin_operation()
        self.assertEqual(h._redirect.call_args.args[0], "/admin?notice=email-failed")
        self.assertIn("not sent", admin_panel.email_status(store.load_scan("adminscan1")))

    def test_admin_reconciliation_persists_provider_evidence(self):
        orders.append(self.order("pay_real"))
        h = self.operation("reconcile")
        with patch.object(payments, "lookup_receipt", return_value={"verified": True, "amount_minor": 49900,
                                                                  "currency": "INR", "payment_mode": "live"}):
            h._admin_operation()
        self.assertEqual(orders.summary()["confirmed_inr"], 499)


    def fulfill(self, **extra):
        return server._fulfill("paidscan01", provider="razorpay", provider_id="pay_realbuyer",
                               amount_minor=49900, verification="signed_webhook", **extra)

    def test_payment_after_complimentary_access_is_recorded_once_without_automatic_ai(self):
        store.save_scan({"id": "paidscan01", "unlocked": True, "email": "buyer@example.com"})
        with patch.object(config, "RAZORPAY_KEY_ID", "rzp_live_example"), \
             patch.object(server.notify, "send"), patch.object(server.usage, "funnel") as funnel, \
             patch.object(server.aicopilot, "ask") as ai, \
             patch.object(server.emailer, "send_report", return_value={"ok": True, "mode": "resend"}) as email:
            self.fulfill()
            self.fulfill()
        self.assertEqual(orders.summary()["confirmed_inr"], 499)
        self.assertEqual(len(orders.all_orders()), 1)
        self.assertEqual(email.call_count, 1)
        self.assertEqual(funnel.call_count, 1)
        ai.assert_not_called()

    def test_distinct_receipts_are_retained_even_for_an_unlocked_report(self):
        store.save_scan({"id": "paidscan01", "unlocked": True})
        with patch.object(server.notify, "send"), patch.object(server.usage, "funnel"):
            self.fulfill()
            server._fulfill("paidscan01", provider="razorpay", provider_id="pay_secondbuyer", amount_minor=49900)
        self.assertEqual(len(orders.all_orders()), 2)

    def test_ledger_write_failure_does_not_grant_access(self):
        store.save_scan({"id": "paidscan01", "unlocked": False})
        with patch.object(orders, "append", side_effect=OSError("disk unavailable")):
            with self.assertRaises(OSError): self.fulfill()
        self.assertFalse(store.load_scan("paidscan01")["unlocked"])

    def test_webhook_retry_finishes_unlock_after_receipt_was_saved(self):
        store.save_scan({"id": "paidscan01", "unlocked": False, "email": "buyer@example.com"})
        h = object.__new__(server.Handler)
        h._json = MagicMock()
        event = {"provider": "razorpay", "provider_id": "pay_realbuyer", "report_id": "paidscan01",
                 "amount_minor": 49900, "currency": "INR", "product": "report"}
        with patch.object(store, "unlock", side_effect=OSError("temporary failure")):
            with self.assertRaises(OSError): h._apply_payment(event)
        self.assertEqual(len(orders.all_orders()), 1)
        self.assertFalse(store.load_scan("paidscan01")["unlocked"])
        with patch.object(server.emailer, "send_report", return_value={"ok": True, "mode": "resend"}) as email:
            h._apply_payment(event)
        self.assertTrue(store.load_scan("paidscan01")["unlocked"])
        self.assertEqual(len(orders.all_orders()), 1)
        email.assert_called_once()

    def test_duplicate_payment_retries_failed_delivery(self):
        store.save_scan({"id": "paidscan01", "unlocked": False, "email": "buyer@example.com"})
        with patch.object(server.notify, "send"), patch.object(server.usage, "funnel"), \
             patch.object(server.emailer, "send_report", side_effect=[{"ok": False, "mode": "resend"}, {"ok": True, "mode": "resend"}]) as email:
            self.fulfill()
            self.fulfill()
        self.assertEqual(email.call_count, 2)
        self.assertEqual(len(orders.all_orders()), 1)
        self.assertTrue(store.load_scan("paidscan01")["email_result"]["ok"])

    def test_solo_dashboard_separates_paid_delivery_from_free_grants(self):
        scans = [{"id": "paidscan01", "unlocked": True, "email": "buyer@example.com"},
                 {"id": "manualscan1", "unlocked": True}]
        revenue = {"records": [{"classification": "Provider confirmed", "scan_id": "paidscan01"}]}
        ctx = admin_panel.context(scans, revenue, {}, [], [], False, [])
        self.assertEqual(ctx["DELIVERY_COUNT"], 1)
        self.assertIn("paidscan01", ctx["PAID_REPORT_ROWS"])
        self.assertNotIn("manualscan1", ctx["PAID_REPORT_ROWS"])
        self.assertIn("manualscan1", ctx["REPORT_ROWS"])
        self.assertEqual(ctx["LEGACY_BLOCK"], "")

    def test_public_pages_do_not_render_operator_personal_name(self):
        with patch.object(config, "LEGAL_NAME", "Dhruv Kumar"):
            for name in ("about", "terms", "trust_center", "customers"):
                page = report.legal_page(name)
                self.assertNotIn("Dhruv Kumar", page)
        self.assertNotIn("Dhruv Kumar", report.index_page())


if __name__ == "__main__": unittest.main()
