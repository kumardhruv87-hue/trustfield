from __future__ import annotations

import unittest
from unittest import mock

from shipproof import live, net, webdeep


def new_collector() -> live.Collector:
    return live.Collector()


def ids(collector: live.Collector) -> set[str]:
    return {finding.id for finding in collector.findings}


RICH_HTML = """<!doctype html>
<html>
<head>
  <title>Fixture page</title>
  <script src="https://cdn.example.com/lib.js"></script>
  <!-- password: hunter2 -->
</head>
<body>
  <form action="http://insecure.example.com/login" method="post">
    <input type="password" name="password">
  </form>
  <a target="_blank" href="https://example.com">x</a>
  <iframe src="https://example.com/embed"></iframe>
  <img src="/logo.png">
  <script src="https://www.googletagmanager.com/gtag/js"></script>
</body>
</html>"""

SAFE_HTML = """<!doctype html>
<html lang="en">
<head><title>Safe</title></head>
<body><img src="/a.png" alt="A logo"><a target="_blank" rel="noopener noreferrer" href="https://x.test">x</a></body>
</html>"""


class HelpersTests(unittest.TestCase):
    def test_platform_host_detection(self):
        self.assertTrue(webdeep._is_platform_host("abc.lovable.app"))
        self.assertTrue(webdeep._is_platform_host("app.vercel.app"))
        self.assertFalse(webdeep._is_platform_host("example.com"))
        self.assertFalse(webdeep._is_platform_host("notlovable.app.example.com"))

    def test_ip_detection(self):
        self.assertTrue(webdeep._is_ip("127.0.0.1"))
        self.assertTrue(webdeep._is_ip("::1"))
        self.assertFalse(webdeep._is_ip("example.com"))

    def test_extra_signatures(self):
        package = net.FetchResult(status=200, body=b'{"name":"x","dependencies":{}}', headers={"content-type": "application/json"})
        self.assertTrue(webdeep._extra_signature("/package.json", package))
        compose = net.FetchResult(status=200, body=b"services:\n  web:\n    image: nginx", headers={"content-type": "text/plain"})
        self.assertTrue(webdeep._extra_signature("/docker-compose.yml", compose))
        html = net.FetchResult(status=200, body=b"<html>hello</html>", headers={"content-type": "text/html"})
        self.assertEqual(webdeep._extra_signature("/package.json", html), "")


class HtmlChecksTests(unittest.TestCase):
    def test_rich_page_findings(self):
        collector = new_collector()
        info: dict = {}
        webdeep.check_html("https://app.example.com/", RICH_HTML, collector, info)
        found = ids(collector)
        self.assertIn("deep.form_over_http", found)
        self.assertIn("deep.secret_in_html_comment", found)
        self.assertIn("deep.missing_sri", found)
        self.assertIn("deep.target_blank", found)
        self.assertIn("deep.iframe_sandbox", found)
        self.assertIn("deep.accessibility_basics", found)
        self.assertIn("deep.trackers_no_consent", found)

    def test_clean_page_passes(self):
        collector = new_collector()
        webdeep.check_html("https://app.example.com/", SAFE_HTML, collector, {})
        found = ids(collector)
        self.assertEqual(found, set())
        passed = {check["name"] for check in collector.checks if check["ok"]}
        self.assertIn("Forms submit over HTTPS", passed)
        self.assertIn("Accessibility basics", passed)

    def test_password_on_http_only_fires_on_http(self):
        collector = new_collector()
        webdeep.check_html("http://app.example.com/", RICH_HTML, collector, {})
        self.assertIn("deep.password_over_http", ids(collector))

        collector2 = new_collector()
        webdeep.check_html("https://app.example.com/", RICH_HTML, collector2, {})
        self.assertNotIn("deep.password_over_http", ids(collector2))


class JsChecksTests(unittest.TestCase):
    def test_token_localstorage_eval_message_listener(self):
        blob = (
            'localStorage.setItem("token", data.access_token);'
            "eval(userInput);"
            'window.addEventListener("message", function (event) { handle(event.data); });'
        )
        collector = new_collector()
        webdeep.check_js("https://app.example.com/", blob, net.Budget(10), collector, {})
        found = ids(collector)
        self.assertIn("deep.token_in_localstorage", found)
        self.assertIn("deep.eval_in_bundle", found)
        self.assertIn("deep.postmessage_no_origin", found)

    def test_clean_bundle_passes(self):
        collector = new_collector()
        webdeep.check_js("https://app.example.com/", "const x = 1;", net.Budget(10), collector, {})
        self.assertEqual(ids(collector), set())

    def test_open_firebase_rules_is_critical(self):
        blob = '"projectId": "demo-project", firebase app initialized'
        response = net.FetchResult(url="https://firestore.googleapis.com/", status=200, body=b'{"documents": []}')
        collector = new_collector()
        with mock.patch.object(webdeep.net, "safe_fetch", return_value=response):
            webdeep.check_js("https://app.example.com/", blob, net.Budget(20), collector, {})
        self.assertIn("deep.firebase_open_rules", ids(collector))

    def test_graphql_introspection(self):
        response = net.FetchResult(status=200, body=b'{"data":{"__schema":{"queryType":{"name":"Query"}}}}')
        collector = new_collector()
        with mock.patch.object(webdeep.net, "safe_fetch", return_value=response):
            webdeep.check_graphql("https://app.example.com/", "graphql endpoint", net.Budget(10), collector)
        self.assertIn("deep.graphql_introspection", ids(collector))


class SkipTests(unittest.TestCase):
    def test_dns_skipped_for_platform_subdomain(self):
        collector = new_collector()
        with mock.patch.object(webdeep.config, "ALLOW_PRIVATE", False):
            webdeep.check_dns("abc.lovable.app", net.Budget(5), collector, {})
        self.assertIn("Email authentication (platform subdomain)", {c["name"] for c in collector.checks})
        self.assertEqual(collector.findings, [])

    def test_tls_skipped_for_http(self):
        collector = new_collector()
        webdeep.check_tls("example.com", "http", collector, {})
        self.assertEqual(collector.checks, [])

    def test_tls_skipped_for_private(self):
        collector = new_collector()
        webdeep.check_tls("127.0.0.1", "https", collector, {})
        self.assertEqual(collector.checks, [])


if __name__ == "__main__":
    unittest.main()
