from __future__ import annotations

import unittest
from unittest import mock

from shipproof import live, net, score

from . import site_fixture


class LiveScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base = site_fixture.start_site()
        cls.result = live.scan_live(cls.base + "/", has_ai=True, budget_seconds=30)
        cls.ids = {f.id for f in cls.result.findings}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_scan_completes(self):
        self.assertEqual(self.result.error, "")
        self.assertGreaterEqual(self.result.status, 200)

    def test_https_problem_detected(self):
        self.assertIn("live.no_https", self.ids)

    def test_missing_headers(self):
        for finding_id in (
            "live.no_hsts",
            "live.no_csp",
            "live.no_nosniff",
            "live.no_referrer_policy",
            "live.no_frame_protection",
        ):
            self.assertIn(finding_id, self.ids)

    def test_exposed_env(self):
        self.assertIn("live.exposed_env", self.ids)

    def test_exposed_source_map(self):
        self.assertIn("live.sourcemap_exposed", self.ids)

    def test_client_side_ai_call(self):
        self.assertIn("live.client_side_ai_call", self.ids)
        self.assertTrue(self.result.meta["client_side_ai"])

    def test_service_role_in_bundle(self):
        self.assertIn("live.supabase_service_role_in_client", self.ids)

    def test_secret_in_bundle(self):
        self.assertIn("secret.openai_key", self.ids)

    def test_weak_cookie(self):
        self.assertIn("live.weak_cookie_flags", self.ids)

    def test_compliance_pages(self):
        names = {c["name"]: c["ok"] for c in self.result.checks}
        self.assertTrue(names["Privacy policy page"])
        self.assertFalse(names["Terms of service page"])
        self.assertIn("live.no_terms_page", self.ids)

    def test_security_txt_counts_as_passed(self):
        self.assertIn("security.txt published", self.result.passed)

    def test_meta_shape(self):
        self.assertIn("host", self.result.meta)
        self.assertIn("scan_seconds", self.result.meta)
        self.assertGreaterEqual(self.result.meta["bundles_scanned"], 1)

    def test_score_is_low(self):
        assessment = score.assess(self.result.findings, self.result.meta)
        self.assertLess(assessment["score"], 45)
        self.assertEqual(assessment["cost_risk"]["level"], "critical")


class TargetValidationTests(unittest.TestCase):
    def test_bad_scheme_returns_error(self):
        result = live.scan_live("ftp://example.com", budget_seconds=5)
        self.assertTrue(result.error)

    def test_unresolvable_domain_returns_error(self):
        result = live.scan_live("https://this-domain-should-not-exist-4242.invalid", budget_seconds=5)
        self.assertTrue(result.error)


class _FakeHead:
    def __init__(self, status: int, content_range: str) -> None:
        self.status = status
        self._content_range = content_range

    def header(self, name: str, default: str = "") -> str:
        return self._content_range if name.lower() == "content-range" else default


class SupabaseSurfaceTests(unittest.TestCase):
    BLOB = (
        "VITE_SUPABASE_URL:`https://abcdefghijklmnopq.supabase.co`,"
        "VITE_SUPABASE_PUBLISHABLE_KEY:`sb_publishable_lV90EFHEJnN6oDUuxMFnhg_FV3_6yYU`,"
        'supabase.from("visits")'
    )

    def _run(self, content_range: str) -> tuple[live.Collector, dict]:
        collector = live.Collector()
        info: dict = {}
        with mock.patch.object(live.net, "safe_fetch", return_value=_FakeHead(200, content_range)):
            live._supabase_surface("abcdefghijklmnopq", self.BLOB, net.Budget(10), collector, info)
        return collector, info

    def test_zero_visible_rows_is_not_critical(self):
        collector, _ = self._run("*/0")
        ids = {f.id for f in collector.findings}
        self.assertIn("live.supabase_public_key", ids)
        self.assertNotIn("live.supabase_table_publicly_readable", ids)
        self.assertTrue(any(c["id"] == "supabase.rls" and c["ok"] for c in collector.checks))

    def test_visible_rows_is_critical(self):
        collector, info = self._run("*/37")
        ids = {f.id for f in collector.findings}
        self.assertIn("live.supabase_table_publicly_readable", ids)
        self.assertEqual(info["supabase_readable_tables"], ["visits"])

    def test_falls_back_to_common_table_names(self):
        blob = (
            "VITE_SUPABASE_URL:`https://abcdefghijklmnopq.supabase.co`,"
            "VITE_SUPABASE_PUBLISHABLE_KEY:`sb_publishable_lV90EFHEJnN6oDUuxMFnhg_FV3_6yYU`,"
            "const serverFn = '/_serverFn/checkIn';"
        )
        collector = live.Collector()
        info: dict = {}
        with mock.patch.object(live.net, "safe_fetch", return_value=_FakeHead(200, "*/0")):
            live._supabase_surface("abcdefghijklmnopq", blob, net.Budget(10), collector, info)
        self.assertEqual(info["supabase_tables_source"], "fallback probes")
        self.assertTrue(any(c["id"] == "supabase.rls" and c["ok"] for c in collector.checks))


class ChunkFollowTests(unittest.TestCase):
    def test_lazy_chunk_is_followed(self):
        def fake(url: str, **kwargs) -> net.FetchResult:
            result = net.FetchResult(url=url, status=200)
            if url.endswith("/app.js"):
                result.body = b'const chunk = import("./Dashboard-abc12345.js");'
            elif "Dashboard" in url:
                result.body = b'const key = "sk-live-secret-here";'
            else:
                result.body = b""
            return result

        with mock.patch.object(live.net, "safe_fetch", side_effect=fake):
            out = live._fetch_scripts(
                '<script src="/app.js"></script>', "https://example.com/", net.Budget(10)
            )
        self.assertEqual(len(out), 2)
        self.assertTrue(any("Dashboard" in url for url, _ in out))


if __name__ == "__main__":
    unittest.main()
