"""Copilot must stay grounded, degrade safely, and never need a browser key."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from shipproof import aicopilot, config


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class CopilotTests(unittest.TestCase):
    def test_missing_key_fails_softly(self):
        with patch.object(config, "DEEPSEEK_API_KEY", ""):
            result = aicopilot.ask({}, "What should I fix first?")
        self.assertFalse(result["ok"])
        self.assertIn("not configured", result["error"])

    def test_answer_is_parsed(self):
        payload = {"choices": [{"message": {"content": "Fix the Supabase RLS finding first."}}]}
        with patch.object(config, "DEEPSEEK_API_KEY", "test-key"), patch(
            "shipproof.aicopilot.urllib.request.urlopen", return_value=FakeResponse(payload)
        ):
            result = aicopilot.ask(
                {
                    "target": "https://example.com",
                    "score": {"score": 80, "counts": {"critical": 1}},
                    "findings": [{"title": "RLS missing", "severity": "critical"}],
                },
                "What should I fix first?",
            )
        self.assertTrue(result["ok"])
        self.assertIn("Supabase", result["answer"])

    def test_upstream_error_is_soft(self):
        with patch.object(config, "DEEPSEEK_API_KEY", "test-key"), patch(
            "shipproof.aicopilot.urllib.request.urlopen", side_effect=OSError("down")
        ):
            result = aicopilot.ask({}, "Explain finding 1")
        self.assertFalse(result["ok"])
        self.assertIn("unavailable", result["error"])

    def test_context_contains_only_the_report(self):
        context = aicopilot.report_context(
            {
                "target": "https://app.example.com",
                "score": {"score": 72, "grade": "C", "counts": {"critical": 2}},
                "findings": [
                    {
                        "title": "Open database table",
                        "severity": "critical",
                        "why": "Anyone can read rows",
                        "fix": "Enable RLS",
                        "evidence": "table customers readable",
                    }
                ],
            }
        )
        self.assertIn("https://app.example.com", context)
        self.assertIn("Open database table", context)
        self.assertIn("Enable RLS", context)
        self.assertIn("NOT CHECKED", context)


if __name__ == "__main__":
    unittest.main()
