from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from shipproof import config, handover, live, repo, report, server, sign
from shipproof.findings import finding
from .test_report_modes import make_record


class HandoverTests(unittest.TestCase):
    def test_pack_is_evidence_based_prioritized_and_requires_real_tests(self):
        record = make_record()
        pack = handover.fix_pack(record)
        self.assertIn(record["target"], pack)
        self.assertLess(pack.index("[CRITICAL]"), pack.index("[LOW]"))
        self.assertIn("evidence-0", pack)
        self.assertIn("NOT RUN", pack)
        self.assertIn("untrusted observations", pack)
        self.assertIn("revoke/rotate", pack)
        self.assertIn("NEEDS OWNER ACTION", pack)

    def test_pack_is_not_exposed_to_unpaid_reports(self):
        record = make_record()
        page = report.report_page(record)
        self.assertNotIn("fix-pack-text", page)
        self.assertNotIn("/fix-pack/", page)
        record["unlocked"] = True
        self.assertIn("/fix-pack/", report.report_page(record))

    def test_download_checks_paid_status(self):
        handler = object.__new__(server.Handler)
        handler.path = "/fix-pack/reportid12.md"; handler.headers = {}
        handler._client_ip = lambda: "test"
        handler._send = MagicMock()
        with patch.object(server.store, "load_scan", return_value=make_record()):
            with self.assertRaises(server.HTTPProblem) as exc:
                handler._route("GET")
            self.assertEqual(exc.exception.status, 402)
        record = make_record(); record["unlocked"] = True
        with patch.object(server.store, "load_scan", return_value=record):
            handler._route("GET")
        self.assertEqual(handler._send.call_args.args[0], 200)
        self.assertIn("attachment", handler._send.call_args.args[3]["Content-Disposition"])

    def test_absent_finding_needs_a_passing_mapped_check(self):
        before = {"findings": [{"id": "f", "title": "Header missing"}],
                  "checks": [{"id": "header", "finding_id": "f", "ok": False}]}
        for after_checks, state in [([], "not_confirmed"),
                                    ([{"id": "header", "ok": False}], "not_confirmed"),
                                    ([{"id": "header", "ok": True}], "check_passed")]:
            self.assertEqual(handover.compare(before, {"findings": [], "checks": after_checks})[0]["state"], state)

    def test_legacy_findings_are_not_falsely_verified(self):
        before = {"findings": [{"id": "f", "title": "Issue"}], "checks": []}
        self.assertEqual(handover.compare(before, {"findings": []})[0]["state"], "not_confirmed")

    def test_remaining_and_new_findings_are_distinguished(self):
        before = {"findings": [{"id": "old", "title": "Old issue"}]}
        after = {"findings": [{"id": "old", "title": "Old issue"}, {"id": "new", "title": "New issue"}]}
        self.assertEqual([r["state"] for r in handover.compare(before, after)], ["still_detected", "new"])

    def test_collectors_record_check_to_finding_mapping(self):
        f = finding("f", "Issue", "high", "Security", "why", "fix")
        for cls in (live.Collector, repo.Collector):
            collector = cls(); collector.fail("check", "Check", f)
            self.assertEqual(collector.checks[0]["finding_id"], "f")

    def test_login_issues_a_session_and_password_only_config_works(self):
        handler = object.__new__(server.Handler)
        handler._client_ip = lambda: "local-login-test"
        handler._read_form = lambda: {"password": ["local-example-password"]}
        handler._redirect = MagicMock()
        with patch.object(config, "ADMIN_PASSWORD", "local-example-password"), patch.object(config, "ADMIN_TOKEN", ""):
            handler._admin_login()
            cookie = handler._redirect.call_args.args[1]
            self.assertIn("HttpOnly; Secure", cookie)
            handler.headers = {"Cookie": cookie.split(";", 1)[0]}
            self.assertTrue(handler._admin_ok())
            handler.headers = {"Cookie": "tf_admin=invalid"}
            self.assertFalse(handler._admin_ok())


if __name__ == "__main__":
    unittest.main()
