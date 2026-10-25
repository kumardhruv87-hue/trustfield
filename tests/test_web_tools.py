"""Headers grader: deterministic scoring, no network in tests."""
from __future__ import annotations

import unittest

from shipproof import web_tools

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


class HeaderGradeTests(unittest.TestCase):
    def test_all_headers_is_a(self):
        result = web_tools.grade(GOOD_HEADERS, https=True)
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["grade"], "A")

    def test_missing_headers_lose_points(self):
        result = web_tools.grade({}, https=True)
        self.assertLess(result["score"], 50)
        self.assertIn(result["grade"], ("D", "F"))

    def test_http_penalty(self):
        https_result = web_tools.grade(GOOD_HEADERS, https=True)
        http_result = web_tools.grade(GOOD_HEADERS, https=False)
        self.assertLess(http_result["score"], https_result["score"])

    def test_server_banner_penalty(self):
        plain = web_tools.grade(GOOD_HEADERS, https=True)
        banner = web_tools.grade({**GOOD_HEADERS, "Server": "nginx/1.18"}, https=True)
        self.assertLess(banner["score"], plain["score"])

    def test_deterministic(self):
        first = web_tools.grade(GOOD_HEADERS, https=True)
        second = web_tools.grade(GOOD_HEADERS, https=True)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
