"""API keys are hashed and revocable; alerts are opt-in."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from shipproof import apikeys, config, notify


class ApiKeyTests(unittest.TestCase):
    def setUp(self):
        self.path = config.DATA_DIR / "apikeys.json"
        if self.path.exists():
            self.path.unlink()

    def tearDown(self):
        if self.path.exists():
            self.path.unlink()

    def test_create_returns_once_and_validates(self):
        raw = apikeys.create("ci")
        self.assertTrue(raw.startswith("tf_"))
        self.assertIsNotNone(apikeys.find(raw))
        self.assertIsNone(apikeys.find("tf_wrong"))
        self.assertGreaterEqual(len(apikeys.public_list()), 1)

    def test_key_is_hashed_at_rest(self):
        raw = apikeys.create("ci")
        stored = self.path.read_text(encoding="utf-8")
        self.assertNotIn(raw, stored)

    def test_revoke(self):
        raw = apikeys.create("ci")
        prefix = raw[:11]
        self.assertTrue(apikeys.revoke(prefix))
        self.assertIsNone(apikeys.find(raw))


class NotifyTests(unittest.TestCase):
    def test_not_configured_by_default(self):
        with patch.object(config, "SLACK_WEBHOOK_URL", ""), patch.object(config, "DISCORD_WEBHOOK_URL", ""), \
             patch("shipproof.emailer.send_alert", return_value={"ok": False}):
            self.assertFalse(notify.configured())
            self.assertFalse(notify.send("t", "m"))

    def test_payload_shape(self):
        captured = {}

        def fake_post(url, payload):
            captured["url"] = url
            captured["payload"] = payload
            return True

        with patch.object(config, "SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"), \
             patch.object(notify, "_post", side_effect=fake_post):
            self.assertTrue(notify.send("Title", "Message", "https://x"))
        self.assertIn("text", captured["payload"])
        self.assertIn("Title", captured["payload"]["text"])


if __name__ == "__main__":
    unittest.main()
