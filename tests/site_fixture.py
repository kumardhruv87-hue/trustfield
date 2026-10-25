"""A deliberately insecure local website used by the live-scan tests."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FAKE_OPENAI_KEY = "sk-proj-aB3dE9fG2hJ5kL8mN1pQ4rS7tU0vW3xY6zA9"

HTML = b"""<!doctype html>
<html><head><title>Fixture App</title></head>
<body>
  <h1>Fixture app</h1>
  <p>No security headers are sent by this server.</p>
  <script src="/static/app.js"></script>
</body></html>
"""

JS = b"""
const OPENAI_KEY = "sk-proj-aB3dE9fG2hJ5kL8mN1pQ4rS7tU0vW3xY6zA9";
const role = "service_role";
const supabaseUrl = "https://abcdefghijklmnopq.supabase.co";
async function ask() {
  return fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { Authorization: "Bearer " + OPENAI_KEY },
    body: JSON.stringify({ model: "gpt-4o-mini", messages: [] })
  });
}
ask();
"""

ENV = b"""OPENAI_API_KEY=sk-proj-aB3dE9fG2hJ5kL8mN1pQ4rS7tU0vW3xY6zA9
SUPABASE_URL=https://abcdefghijklmnopq.supabase.co
STRIPE_SECRET_KEY=GENERATED_STRIPE_FIXTURE
""".replace(b"GENERATED_STRIPE_FIXTURE", ("sk_" + "live_" + "1" * 24).encode())

SOURCE_MAP = b'{"version":3,"sources":["app.js"],"mappings":"AAAA"}'

PRIVACY = b"<!doctype html><html><body><h1>Privacy policy</h1><p>We collect email.</p></body></html>"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # noqa: ANN001, D401
        return

    def handle_one_request(self):  # keep TLS-handshake noise out of test output
        try:
            super().handle_one_request()
        except (ValueError, ConnectionError, OSError):
            self.close_connection = True

    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/":
            self._send(
                200,
                HTML,
                "text/html; charset=utf-8",
                {"Set-Cookie": "session=abc123; Path=/", "Server": "nginx/1.14.0"},
            )
        elif path == "/static/app.js":
            self._send(200, JS, "application/javascript; charset=utf-8")
        elif path == "/static/app.js.map":
            self._send(200, SOURCE_MAP, "application/json")
        elif path == "/.env":
            self._send(200, ENV, "text/plain; charset=utf-8")
        elif path == "/privacy":
            self._send(200, PRIVACY, "text/html; charset=utf-8")
        elif path == "/.well-known/security.txt":
            self._send(200, b"Contact: mailto:security@example.com\n", "text/plain")
        else:
            self._send(404, b"not found", "text/plain")


def start_site() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    return server, f"http://{host}:{port}"
