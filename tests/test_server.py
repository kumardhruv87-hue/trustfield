from __future__ import annotations

import json
import shutil
import threading
import unittest
import urllib.error
import urllib.request

from shipproof import config, report, score, server

from . import site_fixture


def post(base: str, path: str, payload: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        base + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        exc.close()
        try:
            return exc.code, json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return exc.code, {}


def get(base: str, path: str) -> tuple[int, bytes, str]:
    try:
        with urllib.request.urlopen(base + path, timeout=90) as response:
            return response.status, response.read(), response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        body = exc.read()
        exc.close()
        return exc.code, body, exc.headers.get("Content-Type", "")


class HttpAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not str(config.DATA_DIR).endswith("test"):
            raise RuntimeError("refusing to wipe a non-test data directory")
        shutil.rmtree(config.DATA_DIR, ignore_errors=True)
        config.ensure_dirs()
        cls.site, cls.site_base = site_fixture.start_site()
        cls.httpd = server.make_server("127.0.0.1", 0)
        host, port = cls.httpd.server_address[:2]
        cls.base = f"http://{host}:{port}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

        status, data = post(
            cls.base,
            "/api/scan",
            {"kind": "url", "target": cls.site_base, "has_ai": True, "consent": True},
        )
        cls.scan_status = status
        cls.scan = data

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.site.shutdown()
        cls.site.server_close()

    # ---- pages -----------------------------------------------------------
    def test_landing_page(self):
        status, body, ctype = get(self.base, "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", ctype)
        self.assertIn(b"Check my app", body)
        self.assertIn(b"Sample report", body)

    def test_healthz(self):
        status, body, _ = get(self.base, "/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])

    def test_privacy_and_terms(self):
        for page in ("/privacy", "/terms"):
            status, body, _ = get(self.base, page)
            self.assertEqual(status, 200, page)
            self.assertIn(config.BRAND.encode(), body)

    def test_static_css(self):
        status, body, ctype = get(self.base, "/static/style.css")
        self.assertEqual(status, 200)
        self.assertIn("text/css", ctype)

    def test_static_traversal_blocked(self):
        status, _, _ = get(self.base, "/static/..%2Fserver.py")
        self.assertEqual(status, 404)

    def test_unknown_page(self):
        status, body, _ = get(self.base, "/nope")
        self.assertEqual(status, 404)
        self.assertIn(b"not found", body.lower())

    def test_robots_and_sitemap(self):
        self.assertEqual(get(self.base, "/robots.txt")[0], 200)
        self.assertEqual(get(self.base, "/sitemap.xml")[0], 200)
        self.assertEqual(get(self.base, "/favicon.ico")[0], 200)

    # ---- scan ------------------------------------------------------------
    def test_scan_succeeded(self):
        self.assertEqual(self.scan_status, 200, self.scan)
        self.assertTrue(self.scan.get("ok"))
        self.assertEqual(len(self.scan.get("id", "")), 10)
        self.assertLess(self.scan["score"], 45)
        self.assertTrue(self.scan["locked"])
        self.assertLessEqual(len(self.scan["preview_findings"]), 3)
        self.assertIn("report_url", self.scan)

    def test_scan_counts_and_risks(self):
        self.assertGreaterEqual(self.scan["counts"]["critical"], 1)
        self.assertEqual(self.scan["cost_risk"]["level"], "critical")
        self.assertTrue(self.scan["summary_hi"])

    def test_scan_without_consent_is_refused(self):
        status, data = post(self.base, "/api/scan", {"kind": "url", "target": self.site_base})
        self.assertEqual(status, 403)
        self.assertIn("permission", data["error"].lower())

    def test_scan_rejects_bad_scheme(self):
        status, data = post(self.base, "/api/scan", {"kind": "url", "target": "ftp://example.com", "consent": True})
        self.assertEqual(status, 400)

    def test_scan_rejects_bad_repo(self):
        status, _ = post(self.base, "/api/scan", {"kind": "repo", "target": "not a repo", "consent": True})
        self.assertEqual(status, 400)

    def test_report_page_locked(self):
        status, body, _ = get(self.base, self.scan["report_url"])
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn("All findings", text)
        self.assertIn("Unlock the fixes", text)
        self.assertIn("In plain English", text)

    def test_report_page_escapes_html(self):
        record = {
            "id": "abcdef1234",
            "kind": "url",
            "target": '<script>alert("xss")</script>',
            "created_at": "2026-01-01T00:00:00+00:00",
            "unlocked": True,
            "email": "",
            "has_ai": False,
            "status": "ok",
            "error": "",
            "findings": [],
            "checks": [],
            "meta": {},
            "score": score.assess([]),
            "kit_payloads": [],
            "kit_results": [],
            "expires_at": "2026-01-15",
        }
        page = report.report_page(record)
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;", page)

    def test_small_report_is_free(self):
        record = {
            "id": "small12345",
            "kind": "url",
            "target": "https://tiny.example.com",
            "created_at": "2026-01-01T00:00:00+00:00",
            "unlocked": False,
            "email": "",
            "has_ai": False,
            "status": "ok",
            "error": "",
            "findings": [
                {
                    "id": "live.no_referrer_policy",
                    "title": "Referrer-Policy is missing",
                    "severity": "low",
                    "category": "Transport security",
                    "why": "why",
                    "fix": "fix",
                    "evidence": "header",
                    "effort": "5 min",
                    "ref": "",
                    "confidence": "high",
                }
            ],
            "checks": [],
            "meta": {},
            "score": score.assess([]),
            "kit_payloads": [],
            "kit_results": [],
            "expires_at": "2026-01-15",
        }
        page = report.report_page(record)
        self.assertIn("Unlock the fixes", page)
        self.assertIn("All findings", page)

    def test_trust_page(self):
        status, body, _ = get(self.base, self.scan["trust_url"])
        self.assertEqual(status, 200)
        self.assertIn(b"not verified", body)

    def test_badge_svg(self):
        status, body, ctype = get(self.base, f"/badge/{self.scan['id']}.svg")
        self.assertEqual(status, 200)
        self.assertIn("svg", ctype)
        self.assertIn(b"/100", body)

    # ---- kit -------------------------------------------------------------
    def test_kit_endpoint(self):
        status, body, _ = get(self.base, "/api/kit?host=app.example.com")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["count"], 12)
        self.assertEqual(len(data["payloads"]), 12)

    def test_grade_safe(self):
        status, data = post(
            self.base,
            "/api/grade",
            {"payload_id": "cross_user_data", "response": "I'm sorry, I can't access other customers' data."},
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["verdict"], "SAFE")

    def test_grade_leak(self):
        status, data = post(
            self.base,
            "/api/grade",
            {"payload_id": "cross_user_data", "response": "order #1042 belongs to rahul@gmail.com, shipping to Pune"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["verdict"], "LEAK")

    def test_grade_rejects_unknown_payload(self):
        status, _ = post(self.base, "/api/grade", {"payload_id": "nope", "response": "hello"})
        self.assertEqual(status, 400)

    def test_save_kit_results(self):
        status, data = post(
            self.base,
            f"/api/scan/{self.scan['id']}/kit",
            {"results": [{"payload_id": "system_prompt", "response": "I can't share my instructions."}], "token": "test-token"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["saved"], 1)
        self.assertEqual(data["summary"]["SAFE"], 1)

    # ---- leads -----------------------------------------------------------
    def test_lead_validation(self):
        self.assertEqual(post(self.base, "/api/lead", {"email": "not-an-email"})[0], 400)
        self.assertEqual(post(self.base, "/api/lead", {"email": "a@b.co"})[0], 200)

    # ---- paid unlock -----------------------------------------------------
    def test_zz_admin_unlock_flow(self):
        status, body, _ = get(
            self.base,
            f"/admin/unlock?id={self.scan['id']}&token=test-token",
        )
        self.assertEqual(status, 200)
        self.assertIn(b"Guided chatbot checks", body)

        status, body, _ = get(self.base, f"/api/scan/{self.scan['id']}")
        data = json.loads(body)
        self.assertFalse(data["locked"])
        self.assertGreaterEqual(len(data.get("findings", [])), 1)

    def test_admin_unlock_requires_token(self):
        status, _, _ = get(self.base, f"/admin/unlock?id={self.scan['id']}&token=wrong")
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
