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


if __name__ == "__main__": unittest.main()
