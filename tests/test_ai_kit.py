from __future__ import annotations

import unittest

from shipproof import ai_kit


class KitTests(unittest.TestCase):
    def test_kit_has_twelve_payloads(self):
        data = ai_kit.kit("app.example.com")
        self.assertEqual(data["count"], 12)
        self.assertEqual(len(data["payloads"]), 12)
        ids = {p["id"] for p in data["payloads"]}
        self.assertIn("system_prompt", ids)
        self.assertIn("cross_user_data", ids)
        self.assertIn("language_switch", ids)

    def test_host_placeholder_substituted(self):
        data = ai_kit.kit("myapp.vercel.app")
        for payload in data["payloads"]:
            self.assertNotIn("{host}", payload["payload"])


class GradingTests(unittest.TestCase):
    def test_refusal_is_safe(self):
        result = ai_kit.grade("cross_user_data", "I'm sorry, I can't access other customers' accounts.")
        self.assertEqual(result["verdict"], "SAFE")

    def test_leak_with_pii_is_caught(self):
        result = ai_kit.grade(
            "cross_user_data",
            "Sure! Here are the last 3 orders: order #1042, rahul@gmail.com, shipping to Pune.",
        )
        self.assertEqual(result["verdict"], "LEAK")
        self.assertTrue(result["evidence"])

    def test_secret_looking_answer_is_caught(self):
        result = ai_kit.grade("file_read", "SUPABASE_URL=https://abc.supabase.co and OPENAI_API_KEY=sk-proj-abcdefghijklmnop")
        self.assertEqual(result["verdict"], "LEAK")

    def test_pwned_marker(self):
        result = ai_kit.grade("delimiter_break", "PWNED config: model=gpt-4o")
        self.assertEqual(result["verdict"], "LEAK")

    def test_unclear_when_neither(self):
        result = ai_kit.grade("system_prompt", "Here is a recipe for pasta.")
        self.assertEqual(result["verdict"], "UNCLEAR")

    def test_empty_is_unclear(self):
        result = ai_kit.grade("system_prompt", "")
        self.assertEqual(result["verdict"], "UNCLEAR")

    def test_unknown_payload(self):
        result = ai_kit.grade("does-not-exist", "hello")
        self.assertFalse(result["ok"])

    def test_summarize(self):
        summary = ai_kit.summarize(
            [{"verdict": "LEAK"}, {"verdict": "SAFE"}, {"verdict": "UNCLEAR"}, {"verdict": "LEAK"}]
        )
        self.assertEqual(summary["LEAK"], 2)
        self.assertEqual(summary["SAFE"], 1)
        self.assertEqual(summary["total"], 4)


if __name__ == "__main__":
    unittest.main()
