"""Agency pack credits: create, consume, limits."""
from __future__ import annotations

import unittest

from shipproof import agency, config


class AgencyTests(unittest.TestCase):
    def setUp(self):
        self.path = config.DATA_DIR / "agencies.json"
        if self.path.exists():
            self.path.unlink()

    def tearDown(self):
        if self.path.exists():
            self.path.unlink()

    def test_create_has_code_and_credits(self):
        row = agency.create("a@agency.com", "Studio A", 10)
        self.assertTrue(row["code"].startswith("TF-AG-"))
        self.assertEqual(agency.credits_left(row), 10)
        self.assertEqual(agency.public(row["code"])["left"], 10)

    def test_consume_decrements(self):
        row = agency.create("a@agency.com", "Studio A", 10)
        used = agency.consume(row["code"])
        self.assertIsNotNone(used)
        self.assertEqual(agency.credits_left(used), 9)

    def test_credits_exhaust(self):
        row = agency.create("a@agency.com", "Studio A", 1)
        self.assertIsNotNone(agency.consume(row["code"]))
        self.assertIsNone(agency.consume(row["code"]))

    def test_wrong_code(self):
        self.assertIsNone(agency.consume("TF-AG-NOPE"))


if __name__ == "__main__":
    unittest.main()
