"""Client sharing must preserve honest comparisons and never leak paid access."""
from __future__ import annotations

import copy
import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from shipproof import clientproof, config, report, server, sign, storage, store


class ClientHandoverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.patches = [patch.object(config, "DATA_DIR", root),
                        patch.object(config, "SCANS_DIR", root / "scans"),
                        patch.object(storage, "enabled", return_value=False)]
        for p in self.patches:
            p.start()
        config.ensure_dirs()
        findings = [{"id": r, "title": "PRIVATE TITLE " + r, "severity": "high",
                     "evidence": "PRIVATE API SECRET", "fix": "PRIVATE SOURCE PATH"} for r in ("mapped", "missing", "remains")]
        self.before = {"id": "privateold01", "target": "https://user:password@app.example.com/private?api_key=SECRET",
                       "kind": "url", "created_at": config.now_iso(), "unlocked": True,
                       "email": "private@example.com", "findings": findings,
                       "checks": [{"id": "header_check", "finding_id": "mapped", "ok": False}],
                       "score": {"score": 42}}
        self.after = {**copy.deepcopy(self.before), "id": "privatenew01", "verified_against": self.before["id"],
                      "findings": [findings[2], {"id": "new", "title": "PRIVATE NEW TITLE", "severity": "medium"}],
                      "checks": [{"id": "header_check", "ok": True}], "score": {"score": 77}}
        store.save_scan(self.before)
        store.save_scan(self.after)

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.temp.cleanup()

    def handler(self, body):
        h = object.__new__(server.Handler)
        h._read_json = lambda: body
        h._json = MagicMock()
        return h

    def body(self, **extra):
        return {"action": "publish", "confirmed": True,
                "token": sign.sign(self.after["id"], "handover_manage"), **extra}

    def test_comparison_does_not_turn_disappearance_into_a_fix(self):
        summary = clientproof.snapshot(self.before, self.after)
        self.assertEqual(summary["comparison"], {"check_passed": 1, "still_detected": 1, "not_confirmed": 1, "new": 1})

    def test_counts_group_duplicate_alerts_by_finding_type(self):
        before = {**self.before, "findings": self.before["findings"] + [self.before["findings"][0]]}
        summary = clientproof.snapshot(before, self.after)
        self.assertEqual(summary["original_findings"], 3)
        self.assertEqual(summary["comparison"]["check_passed"], 1)

    def test_export_and_html_do_not_disclose_private_data_or_paid_report_ids(self):
        token, summary = clientproof.publish(self.before, self.after)
        public = json.dumps(clientproof.load(token)) + report.client_handover_page(summary, token)
        for value in ("PRIVATE", self.before["id"], self.after["id"], "private@example.com",
                      "app.example.com", "api_key", "password", "/r/", "handover_manage"):
            self.assertNotIn(value, public)
        self.assertNotIn("{{", public)
        self.assertEqual(summary["target"], "Target hidden by owner")

    def test_explicit_target_sharing_excludes_credentials_paths_and_queries(self):
        summary = clientproof.snapshot(self.before, self.after, True)
        self.assertEqual(summary["target"], "app.example.com")
        self.assertNotIn("password", json.dumps(summary))
        self.assertNotIn("api_key", json.dumps(summary))

    def test_repo_target_uses_validated_public_name_only(self):
        before = {**self.before, "kind": "repo", "target": "owner/app"}
        after = {**self.after, "kind": "repo", "target": "owner/app"}
        self.assertEqual(clientproof.snapshot(before, after, True)["target"], "owner/app")

    def test_unsigned_cross_report_and_wrong_purpose_requests_are_blocked(self):
        for token in ("", sign.sign("different01", "handover_manage"), sign.sign(self.after["id"], "pdf")):
            with patch.object(clientproof, "publish") as publish:
                with self.assertRaises(server.HTTPProblem) as exc:
                    self.handler(self.body(token=token))._client_handover(self.after["id"])
                self.assertEqual(exc.exception.status, 403)
                publish.assert_not_called()

    def test_publishing_requires_explicit_consent(self):
        for confirmed in (False, "true", 1, None):
            with self.assertRaises(server.HTTPProblem) as exc:
                self.handler(self.body(confirmed=confirmed))._client_handover(self.after["id"])
            self.assertEqual(exc.exception.status, 403)
        self.assertNotIn("handover_token", store.load_scan(self.after["id"]))

    def test_publish_is_repeat_safe_and_revoke_disables_the_public_link(self):
        token, summary = clientproof.publish(self.before, self.after)
        again, _ = clientproof.publish(self.before, self.after, True)
        self.assertEqual(token, again)
        self.assertEqual(clientproof.load(token)["target"], "Target hidden by owner")
        h = self.handler(self.body(action="revoke", confirmed=False))
        h._client_handover(self.after["id"])
        self.assertTrue(h._json.call_args.args[1]["disabled"])
        self.assertIsNone(clientproof.load(token))
        new_token, _ = clientproof.publish(self.before, self.after, True)
        self.assertNotEqual(new_token, token)
        self.assertIsNone(clientproof.load(token))
        self.assertEqual(clientproof.load(new_token)["target"], "app.example.com")

    def test_links_expire_with_original_report_not_30_days_after_late_publication(self):
        self.before["created_at"] = (config.now() - dt.timedelta(days=29)).isoformat()
        token, summary = clientproof.publish(self.before, self.after)
        expiry = dt.datetime.fromisoformat(summary["expires_at"])
        self.assertLess(expiry - config.now(), dt.timedelta(days=2))
        with patch.object(config, "now", return_value=expiry + dt.timedelta(seconds=1)):
            self.assertIsNone(clientproof.load(token))
            with self.assertRaises(ValueError): clientproof.snapshot(self.before, self.after)

    def test_mismatched_unpaid_or_incomplete_rechecks_cannot_be_published(self):
        for changes in ({"target": "https://other.example.com"}, {"kind": "repo"},
                        {"verified_against": "wrongold01"}, {"unlocked": False}, {"error": "partial scan"}):
            with self.assertRaises(ValueError):
                clientproof.snapshot(self.before, {**self.after, **changes})

    def test_cloud_read_failure_never_serves_a_stale_local_public_copy(self):
        token, _ = clientproof.publish(self.before, self.after)
        with patch.object(storage, "enabled", return_value=True), patch.object(storage, "get_json", return_value=None):
            self.assertIsNone(clientproof.load(token))

    def test_storage_write_failure_is_reported_not_published_as_success(self):
        with patch.object(storage, "enabled", return_value=True), patch.object(storage, "put_json", return_value=False):
            with self.assertRaises(OSError): clientproof._write("A" * 32, {"active": True})
        self.assertFalse(clientproof._path("A" * 32).exists())

    def test_failed_cloud_status_read_cannot_orphan_an_existing_share(self):
        token, _ = clientproof.publish(self.before, self.after)
        current = store.load_scan(self.after["id"])
        with patch.object(storage, "enabled", return_value=True), patch.object(storage, "get_json", return_value=None), \
             patch.object(store, "load_scan", return_value=current), patch.object(storage, "put_json") as write:
            with self.assertRaises(OSError): clientproof.publish(self.before, self.after)
            write.assert_not_called()
        self.assertEqual(store.load_scan(self.after["id"])["handover_token"], token)
        self.assertIsNotNone(clientproof.load(token))

    def test_failed_owner_controls_revoke_the_new_object_before_reporting_failure(self):
        with patch.object(store, "update_scan", return_value=None):
            with self.assertRaises(OSError): clientproof.publish(self.before, self.after)
        files = list((config.DATA_DIR / "handover_links").glob("*.json"))
        self.assertEqual(len(files), 1)
        self.assertIsNone(clientproof.load(files[0].stem))

    def test_expired_cleanup_does_not_touch_live_links_or_reports(self):
        token, _ = clientproof.publish(self.before, self.after)
        clientproof._write("A" * 32, {"active": False})
        clientproof.purge_expired()
        self.assertTrue(clientproof._path(token).exists())
        self.assertFalse(clientproof._path("A" * 32).exists())
        self.assertIsNotNone(store.load_scan(self.after["id"]))

    def test_failed_cloud_read_during_cleanup_cannot_delete_an_active_link(self):
        token, _ = clientproof.publish(self.before, self.after)
        with patch.object(storage, "enabled", return_value=True), patch.object(storage, "get_json", return_value=None), \
             patch.object(storage, "list_prefix", return_value=[]), patch.object(storage, "delete_many") as delete:
            clientproof.purge_expired()
            delete.assert_not_called()
        self.assertTrue(clientproof._path(token).exists())

    def test_sample_is_clearly_fictional_and_has_no_management_controls(self):
        page = report.client_handover_page(clientproof.sample())
        self.assertIn("FICTIONAL SAMPLE", page)
        self.assertNotIn("handover_manage", page)
        self.assertNotIn("{{", page)

    def test_public_routes_serve_only_the_summary_and_stop_after_revocation(self):
        token, _ = clientproof.publish(self.before, self.after)
        h = object.__new__(server.Handler)
        h._client_ip = lambda: "127.0.0.1"
        h._send = MagicMock()
        h.path = "/handover/" + token + ".json"
        with patch.object(server, "_rate_ok", return_value=True):
            h._route("GET")
            args = h._send.call_args.args
            self.assertEqual(args[0], 200)
            self.assertEqual(args[3]["X-Robots-Tag"], "noindex, nofollow, noarchive")
            self.assertNotIn(self.after["id"], args[1].decode())
            clientproof.revoke(self.after)
            with self.assertRaises(server.HTTPProblem) as exc: h._route("GET")
            self.assertEqual(exc.exception.status, 404)


if __name__ == "__main__":
    unittest.main()
