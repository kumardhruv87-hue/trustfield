from __future__ import annotations

import unittest

from shipproof import repo, repoextra


def new_collector() -> repo.Collector:
    return repo.Collector()


def ids(collector: repo.Collector) -> set[str]:
    return {finding.id for finding in collector.findings}


DIRTY = {
    "server/index.js": """
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const app = express();
app.use(cors());
const agent = new https.Agent({ rejectUnauthorized: false });
app.post('/fetch', (req, res) => { fetch(req.query.url); });
app.get('/go', (req, res) => { res.redirect(req.query.next); });
const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('file'), handler);
const token = jwt.verify(req.headers.authorization);
const messages = [{ role: 'system', content: 'You are a bot ' + req.body.name }];
const stripeTest = "sk_test_51H8xYzABC123DEF456GHI789";
""",
    "api/routes/users.ts": "export async function GET() { return db.from('users').select(); }",
    "api/routes/orders.ts": "export async function GET() { return db.from('orders').select(); }",
    "api/routes/items.ts": "export async function GET() { return db.from('items').select(); }",
    "supabase/migrations/001_init.sql": "create table users (id uuid);\ndrop table users;",
    ".env.example": "OPENAI_API_KEY=sk-proj-aB3dE9fG2hJ5kL8mN1pQ4rS7tU0vW3xY6zA9\nSTRIPE_KEY=sk_test_51H8xYzABC123DEF456GHI789\n",
    "server/notes.txt": "nothing here",
}

CLEAN = {
    "server/index.js": """
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const app = express();
app.use(helmet());
app.use(cors({ origin: ['https://app.example.com'] }));
jwt.verify(token, secret, { algorithms: ['HS256'] });
""",
    "api/routes/users.ts": "import { z } from 'zod'; const schema = z.object({ id: z.string().uuid() });",
    "api/routes/orders.ts": "import { z } from 'zod';",
    "api/routes/items.ts": "import { z } from 'zod';",
    ".env.example": "OPENAI_API_KEY=sk-your-key-here\n",
}


class DirtyRepoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.collector = new_collector()
        cls.info: dict = {}
        repoextra.check_all(DIRTY, cls.collector, cls.info)
        cls.ids = ids(cls.collector)

    def test_insecure_tls(self):
        self.assertIn("repo.insecure_tls", self.ids)

    def test_cors_default(self):
        self.assertIn("repo.cors_default", self.ids)

    def test_ssrf(self):
        self.assertIn("repo.ssrf", self.ids)

    def test_jwt_without_algorithm(self):
        self.assertIn("repo.jwt_no_algorithm_pin", self.ids)

    def test_open_redirect(self):
        self.assertIn("repo.open_redirect", self.ids)

    def test_helmet_missing(self):
        self.assertIn("repo.no_helmet", self.ids)

    def test_upload_validation(self):
        self.assertIn("repo.upload_unvalidated", self.ids)

    def test_prompt_injection(self):
        self.assertIn("repo.prompt_injection", self.ids)

    def test_destructive_migration(self):
        self.assertIn("repo.destructive_migration", self.ids)

    def test_env_example_real_values(self):
        self.assertIn("repo.env_example_real_values", self.ids)

    def test_stripe_test_key(self):
        self.assertIn("repo.stripe_test_key", self.ids)

    def test_input_validation_missing(self):
        self.assertIn("repo.no_input_validation", self.ids)

    def test_checks_are_recorded(self):
        self.assertTrue(self.collector.checks)


class CleanRepoTests(unittest.TestCase):
    def test_clean_repo_has_no_findings(self):
        collector = new_collector()
        repoextra.check_all(CLEAN, collector, {})
        self.assertEqual(ids(collector), set())


class SkipTests(unittest.TestCase):
    def test_test_files_are_ignored(self):
        files = {"src/__tests__/x.test.js": "rejectUnauthorized: false"}
        collector = new_collector()
        repoextra.check_all(files, collector, {})
        self.assertNotIn("repo.insecure_tls", ids(collector))


if __name__ == "__main__":
    unittest.main()
