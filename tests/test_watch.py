"""Watch subscriptions: create, activate, due, cancel."""
from __future__ import annotations

import unittest

from shipproof import config, watch


class WatchTests(unittest.TestCase):
    def setUp(self):
        self.path = config.DATA_DIR / "watch.json"
        if self.path.exists():
            self.path.unlink()

    def tearDown(self):
        if self.path.exists():
            self.path.unlink()

    def test_create_is_pending_until_paid(self):
        row = watch.create("abc12345", "a@example.com", "https://example.com")
        self.assertFalse(row["active"])
        self.assertTrue(row["checkout_pending"])
        self.assertEqual(watch.count_active(), 0)

    def test_activate_then_due(self):
        row = watch.create("abc12345", "a@example.com", "https://example.com")
        watch.activate(row["id"], 30)
        self.assertEqual(watch.count_active(), 1)
        self.assertEqual(len(watch.due(5)), 1)

    def test_mark_checked_moves_next_check(self):
        row = watch.create("abc12345", "a@example.com", "https://example.com")
        watch.activate(row["id"], 30)
        watch.mark_checked(row["id"], "newscan123", ["f1", "f2"], hours=24)
        self.assertEqual(watch.by_id(row["id"])["last_findings"], ["f1", "f2"])
        self.assertEqual(watch.due(5), [])

    def test_cancel_by_token(self):
        row = watch.create("abc12345", "a@example.com", "https://example.com")
        watch.activate(row["id"], 30)
        self.assertIsNotNone(watch.by_cancel_token(row["cancel_token"]))
        self.assertTrue(watch.cancel(row["id"]))
        self.assertEqual(watch.count_active(), 0)


if __name__ == "__main__":
    unittest.main()
