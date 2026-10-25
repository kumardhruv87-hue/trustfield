from __future__ import annotations

import unittest
from unittest import mock

from shipproof import config, report, score
from shipproof.findings import finding

SEVERITIES = ["critical", "high", "medium", "low"]


def make_record(count: int = 6) -> dict:
    findings = [
        finding(
            id=f"test.rule_{i}",
            title=f"Finding number {i}",
            severity=SEVERITIES[i % len(SEVERITIES)],
            category="Category " + str(i % 2),
            why="why it matters",
            fix="do this instead",
            evidence=f"evidence-{i}",
        )
        for i in range(count)
    ]
    assessment = score.assess(findings)
    return {
        "id": "reportid12",
        "kind": "url",
        "target": "https://example.com",
        "created_at": "2026-01-01T00:00:00+00:00",
        "unlocked": False,
        "email": "",
        "has_ai": False,
        "status": "ok",
        "error": "",
        "findings": [f.to_dict() for f in findings],
        "checks": [{"id": "c1", "name": "Check one", "ok": True, "detail": ""}],
        "meta": {},
        "score": assessment,
        "kit_payloads": [],
        "kit_results": [],
        "expires_at": "2026-01-15",
    }


class FreeReportTests(unittest.TestCase):
    def test_free_mode_shows_everything(self):
        record = make_record()
        with mock.patch.object(config, "FREE_REPORTS", True):
            page = report.report_page(record)
        self.assertIn("Watch this app", page)
        self.assertNotIn("Unlock the fixes", page)
        self.assertIn("Copy fix prompt", page)
        self.assertIn("checks run", page)
        self.assertIn("What this scan could not check", page)
        self.assertIn("Where the problems are", page)
        self.assertIn("/pdf/", page)  # paid report exposes the branded PDF

    def test_free_mode_still_shows_counts(self):
        record = make_record()
        with mock.patch.object(config, "FREE_REPORTS", True):
            page = report.report_page(record)
        self.assertIn("All findings", page)
        self.assertIn("Finding number 0", page)

    def test_paywall_when_free_off(self):
        record = make_record()
        with mock.patch.object(config, "FREE_REPORTS", False):
            page = report.report_page(record)
        self.assertIn("Unlock the fixes", page)
        self.assertIn("evidence + fix locked", page)
        self.assertNotIn("Watch this app", page)
        self.assertNotIn("/pdf/", page)

    def test_upsell_hidden_when_paywall(self):
        record = make_record()
        with mock.patch.object(config, "FREE_REPORTS", False):
            page = report.report_page(record)
        self.assertNotIn("Start Watch", page)


class CategorySummaryTests(unittest.TestCase):
    def test_category_rows(self):
        record = make_record()
        rows = report.category_summary(record["findings"])
        self.assertIn("Category 0", rows)
        self.assertIn("Category 1", rows)
        self.assertEqual(rows.count("<tr>"), 3)  # header + 2 categories

    def test_empty(self):
        self.assertEqual(report.category_summary([]), "")


if __name__ == "__main__":
    unittest.main()
