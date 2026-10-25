from __future__ import annotations

import unittest

from shipproof import config, net

from . import site_fixture


class UrlTests(unittest.TestCase):
    def test_adds_https(self):
        self.assertEqual(net.normalize_url("example.com/path"), "https://example.com/path")

    def test_keeps_https(self):
        self.assertEqual(net.normalize_url("https://a.co/x?y=1"), "https://a.co/x?y=1")

    def test_strips_fragment_and_userinfo(self):
        self.assertEqual(net.normalize_url("https://user:pass@example.com/a#frag"), "https://example.com/a")

    def test_rejects_ftp(self):
        with self.assertRaises(net.BlockedTarget):
            net.normalize_url("ftp://example.com/file")

    def test_rejects_empty(self):
        with self.assertRaises(net.BlockedTarget):
            net.normalize_url("   ")

    def test_localhost_normalises_but_is_blocked_by_public_check(self):
        normalised = net.normalize_url("http://localhost:8000/")
        self.assertEqual(normalised, "http://localhost:8000/")
        old = config.ALLOW_PRIVATE
        config.ALLOW_PRIVATE = False
        try:
            with self.assertRaises(net.BlockedTarget):
                net.check_public_host("localhost")
        finally:
            config.ALLOW_PRIVATE = old


class SsrfTests(unittest.TestCase):
    def setUp(self):
        self._old = config.ALLOW_PRIVATE
        config.ALLOW_PRIVATE = False

    def tearDown(self):
        config.ALLOW_PRIVATE = self._old

    def test_loopback_blocked(self):
        with self.assertRaises(net.BlockedTarget):
            net.check_public_host("127.0.0.1")

    def test_private_range_blocked(self):
        with self.assertRaises(net.BlockedTarget):
            net.check_public_host("10.0.0.1")

    def test_metadata_ip_blocked(self):
        with self.assertRaises(net.BlockedTarget):
            net.check_public_host("169.254.169.254")

    def test_fetch_returns_error_instead_of_raising(self):
        result = net.safe_fetch("http://127.0.0.1:9/")
        self.assertTrue(result.error)
        self.assertEqual(result.status, 0)

    def test_public_host_resolution_still_allowed(self):
        # example.com is a stable public name; resolution only, no request.
        try:
            net.check_public_host("example.com")
        except net.BlockedTarget:
            self.skipTest("no DNS in this environment")


class FetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base = site_fixture.start_site()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_fetch_ok(self):
        result = net.safe_fetch(self.base + "/")
        self.assertEqual(result.status, 200)
        self.assertIn(b"Fixture app", result.body)
        self.assertEqual(result.header("content-type"), "text/html; charset=utf-8")

    def test_fetch_404_returns_status(self):
        result = net.safe_fetch(self.base + "/nope")
        self.assertEqual(result.status, 404)
        self.assertFalse(result.error)

    def test_join_and_origin(self):
        self.assertEqual(net.origin(self.base + "/x"), self.base)
        self.assertEqual(net.join(self.base, "/static/app.js"), self.base + "/static/app.js")
        self.assertTrue(net.same_origin(self.base + "/a", self.base + "/b"))

    def test_max_bytes_respected(self):
        result = net.safe_fetch(self.base + "/static/app.js", max_bytes=10)
        self.assertLessEqual(len(result.body), 10)


if __name__ == "__main__":
    unittest.main()
