from __future__ import annotations

import io
import unittest
import zipfile
from pathlib import Path

from shipproof import repo, score
from tools import make_fixtures

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "vulnerable-app"


def ensure_fixture() -> None:
    """The fixture's .env is intentionally git-ignored, so regenerate on demand."""
    if not (FIXTURE / ".env").exists():
        make_fixtures.build()


def zip_fixture() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in FIXTURE.rglob("*"):
            if path.is_file():
                archive.write(path, "vulnerable-app/" + path.relative_to(FIXTURE).as_posix())
    return buffer.getvalue()


class RepoScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_fixture()
        if not FIXTURE.exists():
            raise unittest.SkipTest("run python tools/make_fixtures.py first")
        cls.result = repo.scan_repo("owner/vulnerable-app", zip_bytes=zip_fixture())
        cls.ids = {f.id for f in cls.result.findings}

    def test_scan_completes(self):
        self.assertEqual(self.result.error, "")
        self.assertGreaterEqual(self.result.meta["files_scanned"], 8)

    def test_committed_env(self):
        self.assertIn("repo.env_committed", self.ids)

    def test_gitignore_gap(self):
        self.assertIn("repo.gitignore_env", self.ids)

    def test_secrets_from_fixture(self):
        self.assertIn("secret.openai_key", self.ids)
        self.assertIn("secret.stripe_live", self.ids)
        self.assertIn("secret.database_url", self.ids)
        self.assertIn("secret.supabase_service_role_jwt", self.ids)

    def test_service_role_in_client_component(self):
        self.assertIn("repo.server_secret_in_client", self.ids)

    def test_rls_missing(self):
        self.assertIn("repo.rls_missing", self.ids)
        title = next(f.title for f in self.result.findings if f.id == "repo.rls_missing")
        self.assertIn("1", title)

    def test_rls_without_policy(self):
        self.assertIn("repo.rls_no_policy", self.ids)

    def test_no_rate_limit(self):
        self.assertIn("repo.no_rate_limit", self.ids)

    def test_ai_route_without_auth(self):
        self.assertIn("repo.ai_route_no_auth", self.ids)

    def test_webhook_signature(self):
        self.assertIn("repo.webhook_unsigned", self.ids)

    def test_sql_injection_pattern(self):
        self.assertIn("repo.pattern_sql_concat", self.ids)

    def test_no_tests(self):
        self.assertIn("repo.no_tests", self.ids)

    def test_stack_detected(self):
        self.assertIn("Next.js", self.result.meta["stack"])
        self.assertIn("Supabase", self.result.meta["stack"])

    def test_checks_record_both_results(self):
        names = {c["name"]: c["ok"] for c in self.result.checks}
        self.assertFalse(names["No .env files committed"])
        self.assertTrue(names["Row Level Security in migrations"] is False)

    def test_score_is_red(self):
        assessment = score.assess(self.result.findings, self.result.meta)
        self.assertLess(assessment["score"], 45)
        self.assertEqual(assessment["cost_risk"]["level"], "critical")

    def test_no_duplicate_findings(self):
        pairs = [(f.id, f.evidence) for f in self.result.findings]
        self.assertEqual(len(pairs), len(set(pairs)))


class GithubParsingTests(unittest.TestCase):
    def test_full_url(self):
        self.assertEqual(repo.parse_github("https://github.com/acme/app"), ("acme", "app"))

    def test_url_with_git_suffix_and_path(self):
        self.assertEqual(repo.parse_github("https://github.com/acme/app.git/tree/main"), ("acme", "app"))

    def test_short_form(self):
        self.assertEqual(repo.parse_github("acme/app"), ("acme", "app"))

    def test_rejects_other_hosts(self):
        self.assertIsNone(repo.parse_github("https://gitlab.com/acme/app"))


class SafetyTests(unittest.TestCase):
    def test_skips_node_modules(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("repo/node_modules/big.js", "x" * 10)
            archive.writestr("repo/app.js", "console.log('hi')")
        files, stats = repo._iter_text_files(buffer.getvalue())
        self.assertIn("app.js", files)
        self.assertNotIn("node_modules/big.js", files)

    def test_skips_binary(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("repo/logo.png", b"\x00\x01\x02\x00")
        files, _ = repo._iter_text_files(buffer.getvalue())
        self.assertEqual(files, {})

    def test_corrupt_archive_reports_error(self):
        result = repo.scan_repo("owner/broken", zip_bytes=b"not a zip")
        self.assertTrue(result.error)


if __name__ == "__main__":
    unittest.main()
