from __future__ import annotations

import unittest

from shipproof import score
from shipproof.findings import finding


def make(fid: str, severity: str, title: str = "") -> object:
    return finding(id=fid, title=title or fid, severity=severity, category="Test", why="why", fix="fix")


class ScoringTests(unittest.TestCase):
    def test_clean_app_scores_high(self):
        result = score.assess([])
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["grade"], "A+")
        self.assertFalse(result["has_critical"])

    def test_one_critical_caps_the_score(self):
        result = score.assess([make("repo.rls_missing", "critical")])
        self.assertLessEqual(result["score"], 45)
        self.assertTrue(result["verdict"].lower().startswith("do not launch"))

    def test_three_criticals_cap_harder(self):
        findings = [make(f"crit.{i}", "critical") for i in range(3)]
        result = score.assess(findings)
        self.assertLessEqual(result["score"], 30)

    def test_repeated_rule_is_capped(self):
        findings = [make("secret.openai_key", "critical") for _ in range(6)]
        result = score.assess(findings)
        # 3 deductions x 25 = 75 -> 25, then critical cap 45 does not raise it
        self.assertEqual(result["score"], 25)

    def test_info_does_not_deduct(self):
        result = score.assess([make("x", "info"), make("y", "info")])
        self.assertEqual(result["score"], 100)

    def test_grade_bands(self):
        self.assertEqual(score.grade_for(100), "A+")
        self.assertEqual(score.grade_for(88), "A")
        self.assertEqual(score.grade_for(78), "B+")
        self.assertEqual(score.grade_for(66), "B")
        self.assertEqual(score.grade_for(51), "C")
        self.assertEqual(score.grade_for(36), "D")
        self.assertEqual(score.grade_for(10), "F")

    def test_cost_risk_critical_when_key_and_no_limit(self):
        findings = [make("live.client_side_ai_call", "critical"), make("repo.no_rate_limit", "high")]
        risk = score.cost_risk(findings, {})
        self.assertEqual(risk["level"], "critical")
        self.assertIn("Example maths", risk["math"])

    def test_cost_risk_high_with_key_only(self):
        risk = score.cost_risk([make("live.exposed_env", "critical")], {})
        self.assertEqual(risk["level"], "high")

    def test_cost_risk_low_when_clean(self):
        self.assertEqual(score.cost_risk([], {})["level"], "low")

    def test_breach_risk_from_rls(self):
        risk = score.breach_risk([make("repo.rls_missing", "critical")])
        self.assertEqual(risk["level"], "critical")

    def test_top_actions_skips_info(self):
        findings = [make("a", "info"), make("b", "high"), make("c", "critical"), make("d", "medium")]
        actions = score.top_actions(findings, limit=2)
        self.assertEqual(len(actions), 2)
        self.assertEqual(actions[0]["severity"], "critical")

    def test_summary_is_hinglish_and_mentions_score(self):
        result = score.assess([make("repo.rls_missing", "critical", "RLS missing")])
        self.assertIn("Score", result["summary_hi"])
        self.assertIn("RLS missing", result["summary_hi"])

    def test_counts_shape(self):
        result = score.assess([make("a", "critical"), make("b", "low")])
        self.assertEqual(result["counts"]["critical"], 1)
        self.assertEqual(result["counts"]["low"], 1)
        self.assertEqual(result["counts"]["high"], 0)


if __name__ == "__main__":
    unittest.main()
