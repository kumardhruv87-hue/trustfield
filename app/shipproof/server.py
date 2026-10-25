"""HTTP server (stdlib only). No framework, no dependencies, no surprises."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import ssl
import threading
import time
import urllib.request
import traceback
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from . import agency, ai_kit, aicopilot, apikeys, config, guides, questionnaire, vs, usage, emailer, indexstore, live, net, notify, orders, payments, pdf, repo, report, score, sign, store, supabase_tool, watch, web_tools
from . import storage
from . import handover
from .findings import Finding, sort_findings

STATIC_FILES = {
    "style.css": "text/css; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
    "logo.svg": "image/svg+xml",
    "logo-mark.svg": "image/svg+xml",
    "og.png": "image/png",
    "apple-touch-icon.png": "image/png",
    "landing.css": "text/css; charset=utf-8",
    "inter-latin.woff2": "font/woff2",
    "sample-report.html": "text/html; charset=utf-8",
}

RATE_LIMITS = {"scan_hour": (10, 3600), "post_min": (20, 60), "get_min": (120, 60)}
_RATE_DISABLED = os.environ.get("SHIPPROOF_RATE_LIMIT", "").lower() in ("0", "off", "false")

_hits: dict[str, list[float]] = {}
_hits_lock = threading.Lock()
_scan_slots = threading.BoundedSemaphore(config.MAX_CONCURRENT_SCANS)
_payment_lock = threading.RLock()
_verification_lock = threading.Lock()


class HTTPProblem(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _safe_eq(left: str, right: str) -> bool:
    import hmac as _hmac
    return _hmac.compare_digest(str(left), str(right))


def _now_ts() -> float:
    import time

    return time.time()


def _rate_ok(bucket: str, ip: str) -> bool:
    if _RATE_DISABLED:
        return True
    limit, window = RATE_LIMITS[bucket]
    key = f"{bucket}:{ip}"
    now = _now_ts()
    with _hits_lock:
        entries = [t for t in _hits.get(key, []) if now - t < window]
        if len(entries) >= limit:
            _hits[key] = entries
            return False
        entries.append(now)
        _hits[key] = entries
        if len(_hits) > 20_000:  # keep memory bounded
            for stale in [k for k, v in _hits.items() if not v or now - v[-1] > window]:
                _hits.pop(stale, None)
    return True


def _is_paid(record: dict) -> bool:
    findings = record.get("findings") or []
    return bool(
        record.get("unlocked")
        or config.UNLOCK_ALL
        or config.FREE_REPORTS
    )


def _recent_scans(limit: int = 60) -> list[dict]:
    files = list(config.SCANS_DIR.glob("*.json")) if config.SCANS_DIR.exists() else []
    if not files:
        try:
            store.hydrate_from_cloud(limit)
        except Exception:
            pass
        if config.SCANS_DIR.exists():
            files = list(config.SCANS_DIR.glob("*.json"))
    out: list[dict] = []
    for path in files:
        try:
            out.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    def created(record: dict) -> float:
        try:
            stamp = datetime.fromisoformat(str(record.get("created_at")))
            return stamp.replace(tzinfo=stamp.tzinfo or timezone.utc).timestamp()
        except (TypeError, ValueError):
            return 0
    return sorted(out, key=created, reverse=True)[:limit]


def _fulfill(
    scan_id: str,
    *,
    provider: str,
    provider_id: str = "",
    email: str = "",
    amount_minor: int = 0,
    currency: str = "INR",
    product: str = "report",
    verification: str = "",
) -> dict | None:
    """Mark a report paid, record the order, email the buyer. Idempotent per scan."""
    record = store.load_scan(scan_id)
    if record is None:
        return None
    if record.get("unlocked") and provider != "manual":
        return record
    if email and not record.get("email"):
        record = store.update_scan(scan_id, email=email) or record
    record = store.unlock(scan_id) or record
    if provider != "manual":
        usage.funnel("purchase", record.get("source", "direct"))
    if provider_id:
        orders.append(
            {
                "provider": provider,
                "provider_id": provider_id,
                "product": product,
                "amount_minor": int(amount_minor),
                "currency": currency,
                "status": "paid",
                "scan_id": scan_id,
                "email": email or record.get("email", ""),
                "paid_at": config.now_iso(),
                "verification": verification,
                "payment_mode": payments.mode(provider),
            }
        )
    if provider == "manual":
        orders.append(
            {
                "provider": "manual",
                "provider_id": "",
                "product": product,
                "amount_minor": int(amount_minor),
                "currency": currency,
                "status": "paid",
                "scan_id": scan_id,
                "email": email or record.get("email", ""),
                "paid_at": config.now_iso(),
            }
        )
    try:
        notify.send("New paid report", f"{record.get('target', '')} - {record.get('email', '')}",
                    config.BASE_URL + "/r/" + scan_id)
    except Exception:
        pass
    target_email = email or record.get("email", "")
    if target_email:
        try:
            store.save_lead(target_email, scan_id, source="payment")
        except ValueError:
            pass
        result = emailer.send_report({**record, "email": target_email})
        record = store.update_scan(
            scan_id,
            emailed_at=config.now_iso(),
            email_result={k: v for k, v in result.items() if k != "path"},
        ) or record
    return record


def _fire_scan_webhook(row: dict, payload: dict) -> None:
    """POST the finished scan to the key owner's webhook, signed with their key hash."""
    url = str(row.get("webhook_url") or "")
    if not url.startswith("https://"):
        return
    from urllib.parse import urlsplit
    try:
        net.check_public_host(urlsplit(url).hostname or "")
    except Exception:
        apikeys.set_webhook_result(row.get("prefix", ""), "blocked: private or invalid host")
        return
    body = json.dumps({"event": "scan.completed", "sent_at": config.now_iso(), "data": payload}).encode()
    signature = hmac.new(str(row.get("hash", "")).encode(), body, hashlib.sha256).hexdigest()

    def worker() -> None:
        try:
            request = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/json", "X-Trustfield-Event": "scan.completed",
                         "X-Trustfield-Signature": signature, "User-Agent": "Trustfield-Webhook/1.0"},
            )
            with urllib.request.urlopen(request, timeout=10, context=ssl.create_default_context()) as response:
                apikeys.set_webhook_result(row.get("prefix", ""), f"HTTP {response.status}")
        except Exception as exc:
            apikeys.set_webhook_result(row.get("prefix", ""), "error: " + str(exc)[:80])

    threading.Thread(target=worker, daemon=True).start()


def _watch_expiry_check() -> int:
    sent = 0
    for row in watch.expiring(3):
        try:
            emailer.send_watch_expiring(row)
            watch.mark_expiry_reminded(row["id"])
            sent += 1
        except Exception:
            continue
    return sent


def _run_due_watches(limit: int = 3) -> int:
    """Re-scan due Watch targets through our own public API and email new findings."""
    checked = 0
    for row in watch.due(limit):
        try:
            payload = json.dumps({"kind": "url", "target": row.get("target"), "consent": True}).encode()
            request = urllib.request.Request(
                config.BASE_URL.rstrip("/") + "/api/scan", data=payload, method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "Trustfield-Watch/1.0"},
            )
            with urllib.request.urlopen(request, timeout=240, context=ssl.create_default_context()) as response:
                data = json.loads(response.read() or b"{}")
            teaser = data.get("teaser") or []
            ids = [str(item.get("id") or "") for item in teaser]
            old = set(row.get("last_findings") or [])
            new = [item for item in teaser if str(item.get("id") or "") not in old]
            watch.mark_checked(row["id"], str(data.get("id") or ""), ids)
            if new:
                try:
                    emailer.send_watch_alert(row, new, data)
                except Exception:
                    pass
                try:
                    notify.send("Watch: new findings", f"{row.get('target', '')} - {len(new)} new finding(s)",
                                config.BASE_URL + "/r/" + str(data.get("id") or ""))
                except Exception:
                    pass
            checked += 1
        except Exception:
            continue
    return checked


def _record_preview(record: dict) -> dict:
    findings = [f for f in (record.get("findings") or [])]
    ordered = sort_findings([Finding(**f) for f in findings]) if findings else []
    teaser = [
        {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "category": finding.category,
        }
        for finding in ordered
    ]
    score_data = record.get("score") or {}
    locked = not _is_paid(record)
    return {
        "ok": True,
        "id": record.get("id"),
        "kind": record.get("kind"),
        "target": record.get("target"),
        "created_at": record.get("created_at"),
        "locked": locked,
        "paid": not locked,
        "price_inr": config.PRICE_INR,
        "price_usd": config.PRICE_USD,
        "score": score_data.get("score"),
        "grade": score_data.get("grade"),
        "headline": score_data.get("headline"),
        "verdict": score_data.get("verdict"),
        "summary_hi": score_data.get("summary_hi"),
        "summary_en": score_data.get("summary_en"),
        "counts": score_data.get("counts"),
        "total": score_data.get("total"),
        "cost_risk": score_data.get("cost_risk"),
        "breach_risk": score_data.get("breach_risk"),
        "top_actions": [
            {k: v for k, v in action.items() if k != "fix"}
            for action in (score_data.get("top_actions") or [])
        ] if locked else score_data.get("top_actions"),
        "teaser": teaser,
        "preview_findings": teaser[:3],
        "report_url": f"/r/{record.get('id')}",
        "trust_url": f"/t/{record.get('id')}",
        "meta": {
            "stack": (record.get("meta") or {}).get("stack"),
            "platform": (record.get("meta") or {}).get("platform"),
            "files_scanned": (record.get("meta") or {}).get("files_scanned"),
        },
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "Trustfield/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------ plumbing --
    def log_message(self, fmt: str, *args) -> None:  # noqa: ANN002
        line = fmt % args
        if "token=" in line:
            line = line.split("token=")[0] + "token=***"
        print(f"[{self.log_date_time_string()}] {self.address_string()} {line}", flush=True)

    ADMIN_COOKIE = "tf_admin"

    def _admin_ok(self, query: dict | None = None) -> bool:
        if not (config.ADMIN_TOKEN or config.ADMIN_PASSWORD):
            return False
        supplied = (query or {}).get("token", [""])[0]
        if supplied and _safe_eq(supplied, config.ADMIN_TOKEN):
            return True
        cookie = self.headers.get("Cookie") or ""
        for part in cookie.split(";"):
            name, _, value = part.strip().partition("=")
            if name == self.ADMIN_COOKIE and value and sign.verify(value.strip(), "admin_session") == "admin":
                return True
        return False

    def _redirect(self, location: str, cookie: str = "") -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": (
                "default-src 'self'; font-src 'self'; img-src 'self' data: https://*.ahrefs.com; style-src 'self' 'unsafe-inline'; "
                "script-src 'self' https://analytics.ahrefs.com; connect-src 'self' https://analytics.ahrefs.com https://*.ahrefs.com; "
                "base-uri 'none'; form-action 'self'"
            ),
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Cache-Control": "no-store",
        }
        headers.update(extra_headers or {})
        if config.BASE_URL.startswith("https"):
            headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if getattr(self, "_head_only", False):
            return
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, status: int, obj: dict) -> None:
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _html(self, status: int, text: str) -> None:
        self._send(status, text.encode("utf-8"), "text/html; charset=utf-8")

    def _error_page(self, status: int, title: str, message: str) -> None:
        self._html(
            status,
            f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{report.esc(title)} · {report.esc(config.BRAND)}</title>
<link rel="stylesheet" href="/static/style.css"></head>
<body><main class="wrap narrow"><h1>{report.esc(title)}</h1>
<p class="muted">{report.esc(message)}</p>
<p><a class="btn" href="/">â† Back to {report.esc(config.BRAND)}</a></p></main></body></html>""",
        )

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            raise HTTPProblem(400, "Invalid Content-Length")
        if length < 0 or length > config.MAX_BODY_BYTES:
            raise HTTPProblem(413, "Request body too large")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HTTPProblem(400, "Body must be valid JSON")
        if not isinstance(data, dict):
            raise HTTPProblem(400, "Body must be a JSON object")
        return data

    def _read_raw(self, limit: int = 256 * 1024) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            raise HTTPProblem(400, "Invalid Content-Length")
        if length < 0 or length > limit:
            raise HTTPProblem(413, "Request body too large")
        return self.rfile.read(length) if length else b""

    def _client_ip(self) -> str:
        forwarded = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        return forwarded or self.client_address[0]

    # --------------------------------------------------------------- verbs --
    LOGIN_FAILS: dict[str, int] = {}
    LOGIN_BLOCKED: dict[str, float] = {}

    def _read_form(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            raise HTTPProblem(400, "Invalid Content-Length")
        if length <= 0 or length > 10_000:
            return {}
        raw = self.rfile.read(length)
        from urllib.parse import parse_qs as _parse_qs
        return _parse_qs(raw.decode("utf-8", "replace"))

    def _login_page(self, error: str = "") -> None:
        self._send(200, report.admin_login_page(error).encode("utf-8"), "text/html; charset=utf-8", {"Cache-Control": "no-store"})

    def _admin_login(self) -> None:
        ip = self._client_ip()
        if time.time() < self.LOGIN_BLOCKED.get(ip, 0):
            raise HTTPProblem(429, "Too many attempts. Try again in 15 minutes.")
        form = self._read_form()
        password = str((form.get("password") or [""])[0])
        expected = config.ADMIN_PASSWORD
        if expected and _safe_eq(password, expected):
            self.LOGIN_FAILS.pop(ip, None)
            self.LOGIN_BLOCKED.pop(ip, None)
            session = sign.sign("admin", "admin_session", ttl_days=7)
            cookie = (f"{self.ADMIN_COOKIE}={session}; Path=/admin; HttpOnly; Secure; "
                      f"SameSite=Strict; Max-Age=604800")
            return self._redirect("/admin", cookie)
        fails = self.LOGIN_FAILS.get(ip, 0) + 1
        self.LOGIN_FAILS[ip] = fails
        if fails >= 5:
            self.LOGIN_BLOCKED[ip] = time.time() + 900
            self.LOGIN_FAILS[ip] = 0
        self._login_page("Wrong password. Try again.")

    def do_HEAD(self) -> None:  # noqa: N802
        self._head_only = True
        try:
            self.do_GET()
        finally:
            self._head_only = False

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        try:
            self._route(method)
        except HTTPProblem as exc:
            self._json(exc.status, {"ok": False, "error": exc.message})
        except Exception:  # pragma: no cover - last resort
            traceback.print_exc()
            try:
                err = traceback.format_exc()
                try:
                    (config.DATA_DIR / "last_error.txt").write_text(err[-4000:], encoding="utf-8")
                except OSError:
                    pass
                storage.put_json("last_error.json", {
                    "at": config.now_iso(),
                    "path": (self.path or "")[:200],
                    "error": err[-1600:],
                })
            except Exception:
                pass
            self._json(500, {"ok": False, "error": "internal error — please try again"})

    # --------------------------------------------------------------- routes --
    def _route(self, method: str) -> None:
        split = urlsplit(self.path)
        path = unquote(split.path or "/")
        query = parse_qs(split.query)
        path = path.rstrip("/") or "/"
        if config.FOCUS_MODE and (
            path.startswith("/watch/start/") or path == "/agency/start"
            or (path == "/agency" and not query.get("code"))
        ):
            return self._html(410, report.focus_coming_soon())

        if method == "GET":
            if not _rate_ok("get_min", self._client_ip()):
                raise HTTPProblem(429, "Too many requests — slow down a little.")
            if path in ("/", "/pricing", "/scan"):
                return self._html(200, report.index_page())
            if path.startswith("/pay/"):
                scan_id = path[len("/pay/"):].strip("/")
                record = store.load_scan(scan_id)
                if not record:
                    raise HTTPProblem(404, "That report does not exist.")
                if _is_paid(record):
                    return self._redirect("/r/" + scan_id)
                if not record.get("email"):
                    return self._html(200, report.checkout_page(record))
                link = record.get("payment_link") or ""
                if not link:
                    link = payments.create_payment_link(scan_id, config.PRICE_INR)
                    if link:
                        record["payment_link"] = link
                        store.save_scan(record)
                        usage.funnel("checkout", record.get("source", "direct"))
                if not link:
                    raise HTTPProblem(503, "Payment link could not be created. Email " + config.CONTACT_EMAIL)
                self.send_response(302)
                self.send_header("Location", link)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/delete-account":
                body = (
                    "<!doctype html><html><head><meta charset='utf-8'><title>Delete your data</title>"
                    "<link rel='stylesheet' href='/static/style.css'></head><body><main class='wrap narrow legal'>"
                    "<h1>Delete your data</h1><p>Email us and we will delete your report, scan and email within 7 days.</p>"
                    f"<p><a href='mailto:{config.CONTACT_EMAIL}?subject=Delete%20my%20data'>{config.CONTACT_EMAIL}</a></p>"
                    "<p class='fine'>Reports are auto-deleted 30 days after the scan. Paid invoices are kept for tax law.</p>"
                    "</main></body></html>"
                )
                return self._html(200, body)
            if path == "/privacy":
                return self._html(200, report.legal_page("privacy"))
            if path == "/terms":
                return self._html(200, report.legal_page("terms"))
            if path == "/about":
                return self._html(200, report.legal_page("about"))
            if path == "/security":
                return self._html(200, report.legal_page("security"))
            if path == "/subprocessors":
                return self._html(200, report.legal_page("subprocessors"))
            if path == "/refund":
                return self._html(200, report.legal_page("refund"))
            if path == "/changelog":
                return self._html(200, report.legal_page("changelog"))
            if path == "/status":
                return self._html(200, report.legal_page("status"))
            if path == "/methodology":
                return self._html(200, report.legal_page("methodology"))
            if path == "/tools/speed":
                from . import speedtool
                target = (query.get("url") or [""])[0].strip()[:300]
                if target and not target.startswith(("http://", "https://")):
                    target = "https://" + target
                data = speedtool.fetch(target) if target else None
                return self._html(200, speedtool.page_html(data, target))
            if path == "/tools/rls":
                return self._html(200, report.rls_tool_page("", ""))
            if path == "/tools/headers":
                url_value = (query.get("url") or [""])[0][:300]
                result_html = ""
                if url_value:
                    result_html = web_tools.result_html(web_tools.headers_report(url_value))
                return self._html(200, report.headers_tool_page(url_value, result_html))
            if path == "/agency":
                code = (query.get("code") or [""])[0]
                paid = (query.get("paid") or [""])[0] == "1"
                return self._html(200, report.agency_page(agency.public(code), paid))
            match = re.fullmatch(r"/s/([a-z0-9]{6,24})", path)
            if match:
                record = store.load_scan(match.group(1))
                if record is None:
                    raise HTTPProblem(404, "That scorecard does not exist.")
                return self._html(200, report.share_card(record))
            match = re.fullmatch(r"/verify/([a-z0-9]{6,24})", path)
            if match:
                return self._verify_rescan(match.group(1))
            if path == "/vs":
                return self._html(200, vs.vs_page("vs"))
            match = re.fullmatch(r"/vs/([a-z0-9-]{3,40})", path)
            if match:
                page = vs.vs_page(match.group(1))
                if page is None:
                    raise HTTPProblem(404, "Comparison not found.")
                return self._html(200, page)
            if path == "/guides":
                return self._html(200, guides.index_page())
            match = re.fullmatch(r"/guides/([a-z0-9-]{3,60})", path)
            if match:
                page = guides.guide_page(match.group(1))
                if page is None:
                    raise HTTPProblem(404, "Guide not found.")
                return self._html(200, page)
            if path == "/trust":
                return self._html(200, report.legal_page("trust_center"))
            if path == "/trust/questionnaire":
                return self._html(200, questionnaire.html_page())
            if path == "/trust/questionnaire.pdf":
                pdf_bytes = questionnaire.build_pdf()
                return self._send(200, pdf_bytes, "application/pdf", {
                    "Content-Disposition": 'attachment; filename="Trustfield-security-overview.pdf"',
                })
            if path == "/customers":
                return self._html(200, report.legal_page("customers"))
            if path == "/compare":
                return self._html(200, report.legal_page("compare"))
            if path == "/integrations":
                return self._html(200, report.legal_page("integrations"))
            if path == "/api/watch/run":
                if not self._admin_ok(query):
                    raise HTTPProblem(403, "Admin token missing or wrong.")
                return self._json(200, {"ok": True, "checked": _run_due_watches(5)})
            if path == "/watch/manage":
                return self._watch_manage((query.get("token") or [""])[0])
            match = re.fullmatch(r"/watch/start/([a-z0-9]{6,24})", path)
            if match:
                return self._watch_start(match.group(1))
            if path == "/bot":
                return self._html(200, report.legal_page("bot"))
            if path == "/healthz":
                return self._json(200, {"ok": True})
            if path == "/robots.txt":
                body = (
                    f"User-agent: *\nAllow: /\nDisallow: /r/\nDisallow: /api/\nDisallow: /t/\nDisallow: /admin\nDisallow: /unlock-code\nDisallow: /watch/manage\nDisallow: /api/\n"
                    f"Sitemap: {config.BASE_URL}/sitemap.xml\n"
                )
                return self._send(200, body.encode(), "text/plain; charset=utf-8")
            if path == "/sitemap.xml":
                body = (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                    f"<url><loc>{config.BASE_URL}/</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/index</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/privacy</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/terms</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/about</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/security</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/subprocessors</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/refund</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/changelog</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/status</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/methodology</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/integrations</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/compare</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/customers</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/vs</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/vs/scantient</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/vs/vibesafe</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/vs/aikido</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/trust</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/trust/questionnaire</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/guides</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/guides/lovable-app-security</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/guides/supabase-rls-checklist</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/guides/499-report-vs-pentest</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/tools/headers</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/tools/rls</loc><lastmod>2026-10-25</lastmod></url>"
                    f"<url><loc>{config.BASE_URL}/static/sample-report.html</loc><lastmod>2026-10-25</lastmod></url>"
                    "</urlset>"
                )
                return self._send(200, body.encode(), "application/xml; charset=utf-8")
            if path == "/favicon.ico":
                icon = (
                    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
                    b'<path d="M16 2 28 7v9c0 7-5 12-12 14C9 28 4 23 4 16V7z" fill="#5eead4"/>'
                    b"</svg>"
                )
                return self._send(200, icon, "image/svg+xml", {"Cache-Control": "public, max-age=86400"})
            if path.startswith("/static/"):
                return self._static(path.removeprefix("/static/"))
            if path == "/api/kit":
                host = (query.get("host") or [""])[0]
                return self._json(200, {"ok": True, **ai_kit.kit(host)})
            match = re.fullmatch(r"/r/([a-z0-9]{6,24})", path)
            if match:
                return self._report(match.group(1), query)
            match = re.fullmatch(r"/t/([a-z0-9]{6,24})", path)
            if match:
                return self._trust(match.group(1))
            match = re.fullmatch(r"/badge/([a-z0-9]{6,24})\.svg", path)
            if match:
                return self._badge(match.group(1))
            match = re.fullmatch(r"/api/scan/([a-z0-9]{6,24})", path)
            if match:
                return self._api_scan(match.group(1))
            match = re.fullmatch(r"/admin/unlock", path)
            if match:
                return self._admin_unlock(query)
            if path == "/index":
                return self._index_page()
            match = re.fullmatch(r"/pdf/([a-z0-9]{6,24})", path)
            if match:
                return self._pdf(match.group(1), query)
            match = re.fullmatch(r"/fix-pack/([a-z0-9]{6,24})\.md", path)
            if match:
                record = store.load_scan(match.group(1))
                if record is None:
                    raise HTTPProblem(404, "Report not found")
                if not _is_paid(record):
                    raise HTTPProblem(402, "The AI Builder Fix Pack is part of the paid report.")
                return self._send(200, handover.fix_pack(record).encode("utf-8"), "text/markdown; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="Trustfield-fix-pack-{record["id"]}.md"',
                                   "Cache-Control": "private, no-store"})
            if path == "/admin/agency":
                if not self._admin_ok(query):
                    raise HTTPProblem(403, "Admin token missing or wrong.")
                email = (query.get("email") or [""])[0][:200]
                name = (query.get("name") or [""])[0][:80]
                if "@" not in email:
                    raise HTTPProblem(400, "Add ?email=someone@example.com")
                row = agency.create(email, name, 10)
                return self._json(200, {"ok": True, "code": row.get("code"), "credits": row.get("credits")})
            if path == "/admin/key":
                if not self._admin_ok(query):
                    raise HTTPProblem(403, "Admin token missing or wrong.")
                name = (query.get("name") or ["api"])[0][:60]
                webhook = (query.get("webhook") or [""])[0].strip()[:400]
                if webhook:
                    from urllib.parse import urlsplit as _urlsplit
                    if not webhook.startswith("https://"):
                        raise HTTPProblem(400, "Webhook must be an https URL.")
                    try:
                        net.check_public_host(_urlsplit(webhook).hostname or "")
                    except Exception:
                        raise HTTPProblem(400, "Webhook host must be public.")
                return self._json(200, {"ok": True, "key": apikeys.create(name, webhook),
                                        "note": "Copy this key now. It is stored hashed and cannot be shown again."})
            if path == "/admin/keys":
                if not self._admin_ok(query):
                    raise HTTPProblem(403, "Admin token missing or wrong.")
                return self._json(200, {"ok": True, "keys": apikeys.public_list(), "alerts": notify.configured()})
            if path == "/admin/test-alert":
                if not self._admin_ok(query):
                    raise HTTPProblem(403, "Admin token missing or wrong.")
                sent = notify.send("Trustfield alert test", "Alerts are configured correctly.", config.BASE_URL + "/admin")
                return self._json(200, {"ok": sent, "configured": notify.configured()})
            if path == "/admin/last-error":
                if not self._admin_ok(query):
                    raise HTTPProblem(403, "Admin token missing or wrong.")
                try:
                    text = (config.DATA_DIR / "last_error.txt").read_text(encoding="utf-8")
                except OSError:
                    text = "no error recorded"
                return self._send(200, text.encode(), "text/plain; charset=utf-8")
            if path == "/admin/login":
                if self._admin_ok():
                    return self._redirect("/admin")
                return self._login_page()
            if path == "/admin/diag":
                if not self._admin_ok(query):
                    raise HTTPProblem(403, "Admin token missing or wrong.")
                from . import watch as _watch, agency as _agency, apikeys as _apikeys
                return self._json(200, {
                    "storage_enabled": storage.enabled(),
                    "bucket": config.SUPABASE_BUCKET,
                    "supabase_url_set": bool(config.SUPABASE_URL),
                    "service_key_len": len(config.SUPABASE_SERVICE_KEY),
                    "remote_watch": len(storage.get_json("watch.json") or []),
                    "remote_agencies": len(storage.get_json("agencies.json") or []),
                    "remote_keys": len(storage.get_json("apikeys.json") or []),
                    "local_scans": len(list(config.SCANS_DIR.glob("*.json"))),
                    "local_watch": len(_watch.load()),
                    "local_agencies": len(_agency.load()),
                    "local_keys": len(_apikeys.public_list()),
                })
            if path == "/admin/logout":
                return self._redirect("/", f"{self.ADMIN_COOKIE}=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0")
            if path == "/admin":
                return self._admin_dashboard(query)
            match = re.fullmatch(r"/admin/(pdf|email)/([a-z0-9]{6,24})", path)
            if match:
                return self._admin_action(match.group(1), match.group(2), query)
            if path == "/llms.txt":
                if config.FOCUS_MODE:
                    body = (f"# {config.BRAND}\n\nLaunch checks for AI-built apps.\n\n"
                            f"- [Free check]({config.BASE_URL}/#scan): score and every issue title, no signup.\n"
                            f"- [Fix & Handover Report]({config.BASE_URL}/#pricing): Rs {config.PRICE_INR} once; evidence, prioritized fixes, AI-builder prompts, PDF and one same-target re-check within 30 days.\n"
                            f"- [Sample report]({config.BASE_URL}/static/sample-report.html)\n"
                            f"- [Methodology]({config.BASE_URL}/methodology)\n"
                            f"- [Refund policy]({config.BASE_URL}/refund)\n"
                            f"- [Privacy]({config.BASE_URL}/privacy)\n"
                            f"- [Contact](mailto:{config.CONTACT_EMAIL})\n\n"
                            "Public URL checks cannot verify hidden server logic or logged-in flows. Public repositories add static code checks. Not a penetration test or certification.\n"
                            "Watch, agency packs and API sales are not offered during the focused launch. Existing subscribers can manage/cancel their service.\n")
                    return self._send(200, body.encode(), "text/plain; charset=utf-8")
                body = (
                    f"# {config.BRAND}\n\n"
                    f"> Independent, read-only security review for AI-built and hand-written web apps. "
                    f"Free scan: score + every issue title. Full report: evidence, exact fix, fix prompt and PDF. "
                    f"Not a penetration test and not a certification.\n\n"
                    "## Product\n"
                    f"- [Free security scan]({config.BASE_URL}/): paste a URL, get the score and every issue title. No signup, no card.\n"
                    f"- [Full report (Rs {config.PRICE_INR}, one-time)]({config.BASE_URL}/#pricing): evidence for each finding, the exact fix, a copy-paste fix prompt and a PDF.\n"
                    f"- [Sample report]({config.BASE_URL}/static/sample-report.html): what the paid report looks like.\n"
                    f"- [Compare options]({config.BASE_URL}/compare): Trustfield vs pentest vs free scanner.\n"
                    f"- [Security headers checker]({config.BASE_URL}/tools/headers)\n"
                    f"- [Supabase RLS checker]({config.BASE_URL}/tools/rls)\n"
                    f"- [Agency pack]({config.BASE_URL}/agency)\n"
                    f"- [Vulnerability index]({config.BASE_URL}/index)\n"
                    f"- [Integrations]({config.BASE_URL}/integrations): GitHub Action and JSON API.\n"
                    f"- [Security headers checker]({config.BASE_URL}/tools/headers): free, paste any public URL.\n\n"
                    "## Trust pages\n"
                    f"- [Security]({config.BASE_URL}/security)\n"
                    f"- [Methodology]({config.BASE_URL}/methodology)\n"
                    f"- [Subprocessors]({config.BASE_URL}/subprocessors)\n"
                    f"- [Refund policy]({config.BASE_URL}/refund)\n"
                    f"- [Privacy]({config.BASE_URL}/privacy)\n"
                    f"- [Terms]({config.BASE_URL}/terms)\n\n"
                    "## Facts\n"
                    "- Read-only external check of public pages. No login, no exploitation.\n"
                    "- URL scan runs 25-45 checks; attaching a public GitHub repo runs 60+.\n"
                    "- Reports are deleted from our servers 30 days after the scan.\n"
                    "- Watch (daily re-checks with email alerts) is available per app.\n"
                    "- Prices: Rs 499 one-time report; Rs 499/month Watch (auto-renews, cancel anytime); Rs 3,999 agency pack (10 reports). Last updated: 2026-10-25.\n\n"
                    "## Contact\n"
                    f"- [{config.CONTACT_EMAIL}](mailto:{config.CONTACT_EMAIL})\n"
                )
                return self._send(200, body.encode(), "text/plain; charset=utf-8")
            if path == "/.well-known/security.txt":
                body = (
                    f"Contact: mailto:{config.CONTACT_EMAIL}\n"
                    f"Policy: {config.BASE_URL}/security\n"
                    f"Acknowledgments: {config.BASE_URL}/security\n"
                    "Expires: 2027-12-31T23:59:00.000Z\n"
                    "Preferred-Languages: en\n"
                    f"Canonical: {config.BASE_URL}/.well-known/security.txt\n"
                )
                return self._send(200, body.encode(), "text/plain; charset=utf-8")
            return self._error_page(404, "Page not found", "That URL does not exist.")

        if method == "POST":
            if path in ("/webhooks/razorpay", "/webhooks/stripe"):
                return self._webhook(path)
            if path == "/admin/login":
                return self._admin_login()
            if not _rate_ok("post_min", self._client_ip()):
                raise HTTPProblem(429, "Too many requests — slow down a little.")
            if path == "/admin/actions":
                return self._admin_operation()
            if path == "/api/scan":
                return self._create_scan()
            if path == "/api/events":
                body = self._read_json()
                event = str(body.get("event") or "")
                if event not in ("visit", "scan_start", "scan_error"):
                    raise HTTPProblem(400, "Unknown event")
                usage.funnel(event, body.get("source", "direct"))
                return self._json(200, {"ok": True})
            match = re.fullmatch(r"/checkout/([a-z0-9]{6,24})", path)
            if match:
                record = store.load_scan(match.group(1))
                if record is None:
                    raise HTTPProblem(404, "That report does not exist.")
                form = self._read_form()
                email = str((form.get("email") or [""])[0]).strip().lower()[:200]
                if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                    return self._html(400, report.checkout_page(record, "Enter a valid email for your report and receipt."))
                store.update_scan(record["id"], email=email)
                return self._redirect("/pay/" + record["id"])
            if path == "/api/v1/scan":
                raw_key = self.headers.get("X-API-Key", "").strip()
                key_row = apikeys.find(raw_key)
                if key_row is None:
                    raise HTTPProblem(401, "Missing or invalid API key. Create one at /admin or email support.")
                if int(key_row.get("calls", 0)) >= 500:
                    raise HTTPProblem(429, "This API key reached its monthly limit.")
                apikeys.record_use(key_row)
                self._webhook_row = key_row
                return self._create_scan()
            if path == "/agency/start":
                length = int(self.headers.get("Content-Length") or 0)
                if length < 0 or length > 20_000:
                    raise HTTPProblem(413, "That form is too large.")
                raw = self.rfile.read(length) if length else b""
                form = parse_qs(raw.decode("utf-8", "replace"))
                email = (form.get("email") or [""])[0].strip()[:200]
                name = (form.get("name") or [""])[0].strip()[:80]
                if "@" not in email:
                    return self._html(400, report.agency_page(None, False, "Enter a valid email."))
                url = payments.create_agency_link(email, name)
                if not url:
                    return self._html(503, report.agency_page(None, False, "Checkout is unavailable right now."))
                self.send_response(302)
                self.send_header("Location", url)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/unlock-code":
                body = self._read_json()
                code = str(body.get("code") or "").strip()
                scan_id = str(body.get("scan_id") or "").strip()
                client = str(body.get("client") or "").strip()[:80]
                record = store.load_scan(scan_id)
                if record is None:
                    raise HTTPProblem(404, "That report does not exist.")
                if _is_paid(record):
                    return self._json(200, {"ok": True, "already": True})
                row = agency.consume(code)
                if row is None:
                    raise HTTPProblem(402, "That agency code has no credits left.")
                store.unlock(scan_id)
                store.update_scan(scan_id, prepared_for=client, agency_name=row.get("name", ""), agency_code=row.get("code", ""))
                try:
                    emailer.send_report(store.load_scan(scan_id) or record)
                except Exception:
                    pass
                return self._json(200, {"ok": True, "left": agency.credits_left(row)})
            if path == "/watch/cancel":
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if 0 < length <= 20_000 else b""
                ctype = (self.headers.get("Content-Type") or "").lower()
                is_form = "application/x-www-form-urlencoded" in ctype or "multipart/form-data" in ctype
                if is_form:
                    form = parse_qs(raw.decode("utf-8", "replace"))
                    body = {key: values[0] for key, values in form.items() if values}
                else:
                    try:
                        body = json.loads(raw or b"{}")
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        body = {}
                row = watch.by_cancel_token(str(body.get("token") or ""))
                if row is None:
                    raise HTTPProblem(404, "That Watch link is not valid.")
                subscription_id = str(row.get("subscription_id") or "")
                if subscription_id and subscription_id not in ("", "pending"):
                    if not payments.cancel_subscription(subscription_id):
                        raise HTTPProblem(502, "Razorpay did not confirm the cancellation. Nothing changed - try again or email support.")
                    watch.disable_auto_renew(row["id"])
                    if is_form:
                        return self._redirect("/watch/manage?token=" + str(row.get("cancel_token", "")) + "&cancelled=1")
                    return self._json(200, {"ok": True, "note": "Auto-renew stopped. Access continues until the paid-through date."})
                watch.cancel(row["id"])
                if is_form:
                    return self._redirect("/watch/manage?token=" + str(row.get("cancel_token", "")) + "&cancelled=1")
                return self._json(200, {"ok": True})
            if path == "/tools/rls":
                length = int(self.headers.get("Content-Length") or 0)
                if length < 0 or length > 20_000:
                    raise HTTPProblem(413, "That form is too large.")
                raw = self.rfile.read(length) if length else b""
                form = parse_qs(raw.decode("utf-8", "replace"))
                url_value = (form.get("url") or [""])[0][:300]
                key_value = (form.get("key") or [""])[0][:400]
                result = supabase_tool.check(url_value, key_value)
                return self._html(200, report.rls_tool_page(url_value, supabase_tool.result_html(result)))
            if path == "/api/lead":
                return self._lead()
            if path == "/api/grade":
                return self._grade()
            if path == "/api/unlock":
                return self._admin_unlock_json()
            match = re.fullmatch(r"/api/report/([a-z0-9]{6,24})/ask", path)
            if match:
                return self._report_ask(match.group(1))
            match = re.fullmatch(r"/api/scan/([a-z0-9]{6,24})/kit", path)
            if match:
                return self._save_kit(match.group(1))
            return self._error_page(404, "Page not found", "That URL does not exist.")

        raise HTTPProblem(405, "Method not allowed")

    # ------------------------------------------------------------- handlers --
    def _static(self, name: str) -> None:
        if name not in STATIC_FILES:
            raise HTTPProblem(404, "Not found")
        path = config.STATIC_DIR / name
        if not path.exists():
            raise HTTPProblem(404, "Not found")
        body = path.read_bytes()
        self._send(200, body, STATIC_FILES[name], {"Cache-Control": "public, max-age=300"})

    def _report(self, scan_id: str, query: dict) -> None:
        record = store.load_scan(scan_id)
        if record is None:
            return self._error_page(404, "Report not found", "This report does not exist or has expired.")
        if (query.get("paid") or [""])[0] == "1":
            record = self._reconcile_payment(record)
        if config.UNLOCK_ALL and not record.get("unlocked"):
            record = store.unlock(scan_id) or record
        if not record.get("unlocked") and query.get("unlocked", ["0"])[0] == "1" and config.UNLOCK_ALL:
            record = store.unlock(scan_id) or record
        self._html(200, report.report_page(record))

    def _reconcile_payment(self, record: dict) -> dict:
        if _is_paid(record) or not record.get("payment_link"):
            return record
        with _payment_lock:
            current = store.load_scan(record["id"]) or record
            if _is_paid(current) or time.time() - float(current.get("payment_checked_at") or 0) < 30:
                return current
            current = store.update_scan(current["id"], payment_checked_at=time.time()) or current
            payment = payments.find_paid_link(current["id"])
            if payment:
                return _fulfill(current["id"], provider="razorpay", provider_id=payment["id"],
                                email=payment.get("email", ""), amount_minor=int(float(config.PRICE_INR) * 100),
                                verification="gateway_lookup") or current
            return current

    def _trust(self, scan_id: str) -> None:
        record = store.load_scan(scan_id)
        if record is None:
            return self._error_page(404, "Report not found", "This report does not exist or has expired.")
        self._html(200, report.trust_page(record))

    def _badge(self, scan_id: str) -> None:
        record = store.load_scan(scan_id)
        if record is None:
            raise HTTPProblem(404, "Not found")
        svg = report.badge_svg(record)
        self._send(200, svg.encode("utf-8"), "image/svg+xml; charset=utf-8", {"Cache-Control": "public, max-age=600"})

    def _api_scan(self, scan_id: str) -> None:
        record = store.load_scan(scan_id)
        if record is None:
            raise HTTPProblem(404, "Report not found")
        record = self._reconcile_payment(record)
        payload = _record_preview(record)
        if not payload["locked"]:
            payload["findings"] = record.get("findings") or []
            payload["kit_results"] = record.get("kit_results") or []
        return self._json(200, payload)
    def _create_scan(self) -> None:
        body = self._read_json()
        consent = body.get("consent") is True
        if not consent:
            raise HTTPProblem(
                403,
                "Confirm that you own this app or have permission to test it before scanning.",
            )
        kind = (body.get("kind") or "url").strip().lower()
        target = (body.get("target") or "").strip()
        has_ai = bool(body.get("has_ai"))
        email = (body.get("email") or "").strip().lower()

        if len(target) < 3 or len(target) > 300:
            raise HTTPProblem(400, "Enter the app URL or GitHub repo you want to scan.")
        if kind not in ("url", "repo"):
            raise HTTPProblem(400, "kind must be 'url' or 'repo'")
        if config.REQUIRE_EMAIL and "@" not in email:
            raise HTTPProblem(400, "Enter your email to get the report link.")

        if kind == "url":
            try:
                target = net.normalize_url(target)
                net.check_public_host(urlsplit(target).hostname or "")
            except net.BlockedTarget as exc:
                raise HTTPProblem(400, f"Cannot scan that URL: {exc}")
        else:
            parsed = repo.parse_github(target)
            if not parsed:
                raise HTTPProblem(400, "Use a public GitHub repo like https://github.com/owner/repo")
            target = f"{parsed[0]}/{parsed[1]}"

        if not _rate_ok("scan_hour", self._client_ip()):
            raise HTTPProblem(429, "Scan limit reached for this hour. Try again later.")
        if not _scan_slots.acquire(blocking=False):
            raise HTTPProblem(429, "We are scanning a lot right now — try again in a minute.")

        try:
            result = (
                live.scan_live(target, has_ai=has_ai)
                if kind == "url"
                else repo.scan_repo(target, has_ai=has_ai)
            )
        finally:
            _scan_slots.release()

        if result.error and not result.findings:
            raise HTTPProblem(422, f"Could not complete the scan: {result.error}")

        scan_id = store.new_id()
        host = ""
        if kind == "url":
            host = urlsplit(result.final_url or target).hostname or ""
        assessment = score.assess(result.findings, result.meta)
        record = {
            "id": scan_id,
            "kind": kind,
            "target": result.target or target,
            "created_at": config.now_iso(),
            "unlocked": config.UNLOCK_ALL,
            "email": email,
            "source": usage.source(body.get("source", "direct")),
            "has_ai": has_ai,
            "status": "ok",
            "error": "",
            "findings": [f.to_dict() for f in result.findings],
            "checks": result.checks,
            "meta": result.meta,
            "score": assessment,
            "kit_payloads": ai_kit.kit(host)["payloads"],
            "kit_results": [],
            "expires_at": (config.now() + timedelta(days=config.BADGE_VALID_DAYS)).date().isoformat(),
        }
        store.save_scan(record)
        usage.bump("scans")
        usage.funnel("scan_complete", record.get("source", "direct"))
        indexstore.record(record)
        if email and emailer.configured():
            try:
                emailer.send_free_report(record)
            except Exception:
                pass
        if email:
            try:
                store.save_lead(email, scan_id, source=f"scan-{kind}")
            except ValueError:
                pass

        payload = _record_preview(record)
        payload["checks_passed"] = len(result.passed)
        webhook_row = getattr(self, "_webhook_row", None)
        if webhook_row:
            self._webhook_row = None
            try:
                _fire_scan_webhook(webhook_row, payload)
            except Exception:
                pass
        payload["checks_total"] = len(result.checks)
        return self._json(200, payload)

    def _verify_rescan(self, scan_id: str) -> None:
        if not _verification_lock.acquire(blocking=False):
            raise HTTPProblem(429, "A verification is running. Try again shortly.")
        try:
            return self._verify_once(scan_id)
        finally:
            _verification_lock.release()

    def _verify_once(self, scan_id: str) -> None:
        old = store.load_scan(scan_id)
        if old is None:
            raise HTTPProblem(404, "That report does not exist.")
        if not _is_paid(old):
            raise HTTPProblem(402, "Re-scan verification is part of the paid report.")
        try:
            created = datetime.fromisoformat(str(old.get("created_at")))
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            if config.now() - created > timedelta(days=30):
                raise HTTPProblem(410, "This report's 30-day re-check period has ended.")
        except (TypeError, ValueError):
            raise HTTPProblem(410, "This report has no valid re-check date.")
        if old.get("verified_against"):
            return self._redirect("/r/" + scan_id)
        previous = old.get("verification_scan_id")
        if previous and store.load_scan(previous):
            return self._redirect("/r/" + previous)
        payload = json.dumps({"kind": old.get("kind", "url"), "target": old.get("target"),
                              "has_ai": bool(old.get("has_ai")), "consent": True}).encode()
        request = urllib.request.Request(
            config.BASE_URL.rstrip("/") + "/api/scan", data=payload, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "Trustfield-Verify/1.0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=300, context=ssl.create_default_context()) as response:
                data = json.loads(response.read() or b"{}")
        except Exception:
            raise HTTPProblem(503, "The re-scan could not run right now. Try again in a minute.")
        new_id = str(data.get("id") or "")
        if not new_id:
            raise HTTPProblem(503, "The re-scan did not return a report.")
        current = store.load_scan(new_id)
        if current is None:
            raise HTTPProblem(503, "The re-check could not be loaded. Please try again.")
        comparison = handover.compare(old, current)
        if not store.update_scan(new_id, verified_against=scan_id, unlocked=True,
                                 email=old.get("email", ""),
                                 source=old.get("source", "direct"),
                                 comparison=comparison,
                                 fixed_count=sum(r["state"] == "check_passed" for r in comparison),
                                 new_count=sum(r["state"] == "new" for r in comparison)):
            raise HTTPProblem(503, "The re-check could not be saved. Please try again.")
        store.update_scan(scan_id, verification_scan_id=new_id)
        return self._redirect("/r/" + new_id + "?verified=1")

    def _watch_start(self, scan_id: str) -> None:
        record = store.load_scan(scan_id)
        if record is None:
            raise HTTPProblem(404, "That report does not exist.")
        if not _is_paid(record):
            self.send_response(302)
            self.send_header("Location", "/r/" + scan_id)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        email = str(record.get("email") or "").strip()
        if not email:
            raise HTTPProblem(400, "Add an email to the report first, then start Watch.")
        row = watch.create(scan_id, email, str(record.get("target") or ""))
        if not row.get("last_findings"):
            watch.mark_checked(
                row["id"], scan_id,
                [str(f.get("id") or "") for f in (record.get("findings") or []) if f.get("id")],
                hours=24,
            )
        if row.get("active"):
            self.send_response(302)
            self.send_header("Location", "/r/" + scan_id + "?watch=on")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        url = row.get("checkout_url") or ""
        if not url and config.WATCH_SUBSCRIPTIONS:
            sub = payments.create_subscription(scan_id, row["id"])
            url = (sub or {}).get("url", "")
            if url and (sub or {}).get("id"):
                watch.set_subscription(row["id"], sub["id"])
        if not url:
            url = payments.create_watch_link(scan_id, row["id"])
        if not url:
            raise HTTPProblem(503, "Watch checkout is unavailable right now. Email " + config.CONTACT_EMAIL)
        watch.set_checkout(row["id"], url)
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _watch_manage(self, token: str) -> None:
        row = watch.by_cancel_token(token)
        if row is None:
            raise HTTPProblem(404, "That Watch link is not valid.")
        if row.get("active") and row.get("auto_renew") is False:
            status = "active until " + str(row.get("paid_until", "")) + " (auto-renew off)"
        else:
            status = "active — auto-renews" if row.get("active") else "paused"
        body = (
            "<!doctype html><html><head><meta charset='utf-8'><title>Watch · " + config.BRAND + "</title>"
            "<link rel='stylesheet' href='/static/style.css'></head><body class='report-body'>"
            "<main class='wrap narrow legal'><h1>Watch</h1>"
            f"<p class='muted'>{row.get('target','')}</p>"
            f"<p>Status: <strong>{status}</strong> · last checked {row.get('last_checked_at','never')}</p>"
            f"<p class='fine'>Email: {row.get('email','')} · paid until {row.get('paid_until','')}</p>"
            f"<form method='post' action='/watch/cancel'><input type='hidden' name='token' value='{row.get('cancel_token','')}'>"
            "<button class='btn' type='submit'>Cancel Watch</button></form>"
            f"<p><a href='/r/{row.get('scan_id','')}'>Back to report</a></p></main></body></html>"
        )
        return self._html(200, body)

    def _report_ask(self, scan_id: str) -> None:
        body = self._read_json()
        question = str(body.get("question") or "").strip()
        if len(question) < 3:
            raise HTTPProblem(400, "Ask a short question about the report.")
        record = store.load_scan(scan_id)
        if record is None:
            raise HTTPProblem(404, "That report does not exist.")
        if not _is_paid(record):
            raise HTTPProblem(402, "The AI copilot is part of the paid report.")
        chat = list(record.get("chat") or [])
        if len(chat) >= 80:
            raise HTTPProblem(429, "You reached the question limit for this report. Email " + config.CONTACT_EMAIL)
        result = aicopilot.ask(record, question)
        if not result.get("ok"):
            return self._json(200, result)
        chat.append({"role": "user", "content": question, "at": config.now_iso()})
        chat.append({"role": "assistant", "content": result["answer"], "at": config.now_iso()})
        store.update_scan(scan_id, chat=chat[-80:])
        return self._json(200, {"ok": True, "answer": result["answer"]})

    def _lead(self) -> None:
        body = self._read_json()
        email = (body.get("email") or "").strip()
        scan_id = (body.get("scan_id") or "").strip()
        try:
            store.save_lead(email, scan_id if re.fullmatch(r"[a-z0-9]{6,24}", scan_id or "") else "", "landing")
        except ValueError:
            raise HTTPProblem(400, "Enter a valid email address.")
        return self._json(200, {"ok": True})

    def _grade(self) -> None:
        body = self._read_json()
        payload_id = (body.get("payload_id") or "").strip()
        response = (body.get("response") or "")[:6000]
        result = ai_kit.grade(payload_id, response)
        if not result.get("ok"):
            raise HTTPProblem(400, result.get("error", "could not grade that payload"))
        return self._json(200, result)

    def _save_kit(self, scan_id: str) -> None:
        record = store.load_scan(scan_id)
        if record is None:
            raise HTTPProblem(404, "Report not found")
        body = self._read_json()
        if not _is_paid(record) and not _safe_eq(str(body.get("token") or ""), config.ADMIN_TOKEN):
            raise HTTPProblem(402, "The prompt kit results are part of the paid report.")
        items = body.get("results")
        if not isinstance(items, list) or len(items) > 12:
            raise HTTPProblem(400, "Send a list of at most 12 graded results.")
        graded = []
        for item in items:
            if not isinstance(item, dict):
                continue
            payload_id = str(item.get("payload_id") or "")
            response = str(item.get("response") or "")[:6000]
            result = ai_kit.grade(payload_id, response)
            if result.get("ok"):
                result["response_excerpt"] = response[:400]
                graded.append(result)
        record = store.update_scan(scan_id, kit_results=graded[-12:]) or record
        return self._json(200, {"ok": True, "saved": len(graded), "summary": ai_kit.summarize(graded)})

    def _admin_unlock(self, query: dict) -> None:
        scan_id = (query.get("id") or [""])[0]
        if not self._admin_ok(query):
            return self._error_page(403, "Not allowed", "Admin token missing or wrong.")
        record = _fulfill(scan_id, provider="manual", product="report")
        if record is None:
            return self._error_page(404, "Report not found", "No report with that id.")
        return self._html(200, report.report_page(record))

    def _admin_unlock_json(self) -> None:
        body = self._read_json()
        if not config.ADMIN_TOKEN or not _safe_eq(str(body.get("token") or ""), config.ADMIN_TOKEN):
            raise HTTPProblem(403, "Admin token missing or wrong.")
        record = _fulfill(str(body.get("id") or ""), provider="manual", product="report")
        if record is None:
            raise HTTPProblem(404, "Report not found")
        return self._json(200, {"ok": True, "id": record["id"], "report_url": f"/r/{record['id']}"})

    def _index_page(self) -> None:
        self._html(200, report.public_index_page(indexstore.aggregate()))

    def _admin_dashboard(self, query: dict) -> None:
        supplied = (query.get("token") or [""])[0]
        if supplied and config.ADMIN_TOKEN and _safe_eq(supplied, config.ADMIN_TOKEN):
            session = sign.sign("admin", "admin_session", ttl_days=7)
            cookie = (f"{self.ADMIN_COOKIE}={session}; Path=/admin; HttpOnly; Secure; "
                      f"SameSite=Strict; Max-Age=604800")
            return self._redirect("/admin", cookie)
        if not self._admin_ok():
            raise HTTPProblem(403, "Admin token missing or wrong.")
        self._html(
            200,
            report.admin_page(
                _recent_scans(60), orders.summary(), indexstore.aggregate(), "",
                watch.load(), apikeys.public_list(), notify.configured(), agency.list_rows(),
                notice=(query.get("notice") or [""])[0],
            ),
        )

    def _admin_operation(self) -> None:
        if not self._admin_ok():
            raise HTTPProblem(403, "Admin login required.")
        form = self._read_form()
        if sign.verify(str((form.get("csrf") or [""])[0]), "admin_action") != "admin":
            raise HTTPProblem(403, "This form expired. Reload the admin page.")
        action = str((form.get("action") or [""])[0])
        if action == "reconcile":
            checked = 0
            for order in orders.summary()["records"]:
                if checked >= 10:
                    break
                if order.get("provider") != "razorpay" or order["classification"] != "Needs review":
                    continue
                try:
                    last_check = datetime.fromisoformat(str(order.get("receipt", {}).get("checked_at")))
                    if config.now() - last_check < timedelta(minutes=5):
                        continue
                except (TypeError, ValueError):
                    pass
                orders.record_check(str(order.get("provider_id") or ""), payments.lookup_receipt(str(order.get("provider_id") or "")))
                checked += 1
            return self._redirect("/admin?notice=reconciled")
        scan_id = str((form.get("scan_id") or [""])[0])
        record = store.load_scan(scan_id)
        if record is None:
            raise HTTPProblem(404, "Report not found.")
        if action == "grant":
            if (form.get("confirmed") or [""])[0] != "1":
                raise HTTPProblem(400, "Confirm the access grant first.")
            if not record.get("unlocked"):
                store.unlock(scan_id)
                orders.append({"provider": "manual", "provider_id": "", "status": "access_granted",
                               "scan_id": scan_id, "amount_minor": 0, "currency": "INR", "paid_at": config.now_iso()})
            return self._redirect("/admin?notice=granted")
        if action == "email":
            if not record.get("unlocked") or not record.get("email"):
                raise HTTPProblem(400, "Grant report access and add a recipient before sending.")
            result = emailer.send_report(record)
            store.update_scan(scan_id, emailed_at=config.now_iso(), email_result={k: v for k, v in result.items() if k != "path"})
            success = result.get("ok") and result.get("mode") == "resend"
            return self._redirect("/admin?notice=" + ("email-accepted" if success else "email-failed"))
        raise HTTPProblem(400, "Unknown admin action.")

    def _admin_action(self, action: str, scan_id: str, query: dict) -> None:
        if not self._admin_ok(query):
            raise HTTPProblem(403, "Admin token missing or wrong.")
        record = store.load_scan(scan_id)
        if record is None:
            raise HTTPProblem(404, "Report not found")
        if action == "pdf":
            location = f"/pdf/{scan_id}?token={sign.sign(scan_id, 'pdf')}"
        else:
            record = self._send_admin_report(record, query)
            location = "/admin?sent=1"
        return self._send(302, b"", "text/plain; charset=utf-8", {"Location": location})

    def _send_admin_report(self, record: dict, query: dict) -> dict:
        email = (query.get("email") or [record.get("email", "")])[0] or record.get("email", "")
        if email and not record.get("email"):
            record = store.update_scan(record["id"], email=email) or record
        emailer.send_report(record)
        return record

    def _pdf(self, scan_id: str, query: dict) -> None:
        token = (query.get("token") or [""])[0]
        authorised = sign.verify(token, "pdf") == scan_id or bool(config.ADMIN_TOKEN and token == config.ADMIN_TOKEN)
        if not authorised:
            raise HTTPProblem(403, "Invalid or expired download link.")
        record = store.load_scan(scan_id)
        if record is None:
            raise HTTPProblem(404, "Report not found")
        if not _is_paid(record):
            raise HTTPProblem(402, "This report has not been unlocked yet.")
        data = pdf.build_report_pdf(record)
        self._send(
            200,
            data,
            "application/pdf",
            {
                "Content-Disposition": f'attachment; filename="{config.BRAND}-{scan_id}.pdf"',
                "Cache-Control": "private, max-age=0",
            },
        )

    def _webhook(self, path: str) -> None:
        raw = self._read_raw(256 * 1024)
        if not raw:
            raise HTTPProblem(400, "Empty webhook body")
        if path == "/webhooks/razorpay":
            signature = self.headers.get("X-Razorpay-Signature", "")
            if not payments.razorpay_verify(raw, signature, config.RAZORPAY_WEBHOOK_SECRET):
                raise HTTPProblem(400, "Invalid webhook signature")
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise HTTPProblem(400, "Invalid JSON")
            sub_event = payments.razorpay_subscription_event(payload)
            if sub_event:
                watch_id = sub_event.get("watch_id") or ""
                row = watch.by_id(watch_id) if watch_id else None
                if row is None:
                    return self._json(200, {"ok": True, "ignored": "unknown watch subscription"})
                name = sub_event.get("event", "")
                if name in ("subscription.activated", "subscription.charged", "subscription.resumed"):
                    if sub_event.get("subscription_id"):
                        watch.set_subscription(watch_id, sub_event["subscription_id"])
                    row = watch.extend(watch_id, sub_event.get("until") or "") or row
                    try:
                        emailer.send_watch_active(row)
                    except Exception:
                        pass
                elif name in ("subscription.cancelled", "subscription.completed",
                              "subscription.halted", "subscription.paused", "subscription.expired"):
                    watch.cancel(watch_id)
                    try:
                        emailer.send_watch_cancelled(row)
                    except Exception:
                        pass
                return self._json(200, {"ok": True, "watch": watch_id, "event": name})
            event = payments.razorpay_event(payload)
        else:
            signature = self.headers.get("Stripe-Signature", "")
            if not payments.stripe_verify(raw, signature, config.STRIPE_WEBHOOK_SECRET):
                raise HTTPProblem(400, "Invalid webhook signature")
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise HTTPProblem(400, "Invalid JSON")
            event = payments.stripe_event(payload)
        if event is None:
            return self._json(200, {"ok": True, "ignored": True})
        with _payment_lock:
            return self._apply_payment(event)

    def _apply_payment(self, event: dict) -> None:
        payment_id = str(event.get("provider_id") or "")
        if not payment_id:
            return self._json(200, {"ok": True, "ignored": "no payment id"})
        if orders.exists(payment_id):
            return self._json(200, {"ok": True, "duplicate": True})
        product = event.get("product") or "report"
        if product not in ("report", "watch", "agency"):
            return self._json(200, {"ok": True, "ignored": "unknown product"})
        if product != "agency" and not event.get("report_id"):
            return self._json(200, {"ok": True, "ignored": "no report_id"})
        expected = {"INR": int(float(config.PRICE_INR) * 100), "USD": int(float(config.PRICE_USD) * 100)}
        if product in ("agency", "watch"):
            expected = {"INR": int(float(config.AGENCY_INR if product == "agency" else config.WATCH_INR) * 100)}
        if int(event.get("amount_minor") or 0) != expected.get(event.get("currency")):
            return self._json(200, {"ok": True, "ignored": "amount or currency mismatch"})
        order = {**event, "status": "paid", "paid_at": config.now_iso(),
                 "verification": "signed_webhook", "payment_mode": payments.mode(event.get("provider", "razorpay"))}
        if product == "agency":
            if "@" not in str(event.get("email") or ""):
                raise HTTPProblem(503, "Buyer email missing; payment needs operator review.")
            row = agency.create(event.get("email", ""), event.get("agency_name", ""), 10)
            orders.append({**order, "agency_id": row["id"]})
            try:
                emailer.send_agency_welcome(row)
            except Exception:
                pass
            return self._json(200, {"ok": True, "agency": row.get("code")})
        if product == "watch":
            row = watch.by_id(event.get("watch_id") or "")
            if row is None:
                return self._json(200, {"ok": True, "ignored": "unknown watch"})
            row = watch.activate(row["id"], 30) or row
            orders.append(order)
            try:
                emailer.send_watch_active(row)
            except Exception:
                pass
            return self._json(200, {"ok": True, "watch": row["id"]})
        record = _fulfill(
            event["report_id"],
            provider=event["provider"],
            provider_id=event.get("provider_id", ""),
            email=event.get("email", ""),
            amount_minor=event.get("amount_minor", 0),
            currency=event.get("currency", "INR"),
            product=event.get("product", "report"),
            verification="signed_webhook",
        )
        if record is None:
            return self._json(200, {"ok": True, "ignored": "unknown report"})
        return self._json(200, {"ok": True, "id": record.get("id")})

def make_server(host: str = config.HOST, port: int = config.PORT) -> ThreadingHTTPServer:
    config.ensure_dirs()
    store.purge_old(30)
    try:
        from . import storage
        storage.ensure_bucket()
        indexstore.hydrate()
        usage.hydrate()
        try:
            import threading as _threading
            _threading.Thread(target=store.hydrate_from_cloud, kwargs={"limit": 60}, daemon=True).start()
        except Exception:
            pass
    except Exception:
        pass
    if os.environ.get("SHIPPROOF_RETENTION_RUNNER", "1") != "0":
        def _retention_loop() -> None:
            while True:
                try:
                    store.purge_old(30)
                except Exception:
                    pass
                time.sleep(21600)
        threading.Thread(target=_retention_loop, daemon=True).start()
    if config.SECRET_KEY in ("dev-secret-change-me", "") and config.BASE_URL.startswith("https"):
        import secrets as _secrets
        config.SECRET_KEY = _secrets.token_hex(32)
        print("WARNING: SECRET_KEY was the development default; generated an ephemeral production secret.")
    if os.environ.get("SHIPPROOF_WATCH_RUNNER", "1") != "0":
        def _watch_loop() -> None:
            while True:
                try:
                    _run_due_watches(2)
                except Exception:
                    pass
                try:
                    _watch_expiry_check()
                except Exception:
                    pass
                time.sleep(1800)
        threading.Thread(target=_watch_loop, daemon=True).start()
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def main() -> None:
    server = make_server()
    host, port = server.server_address[:2]
    print(f"  {config.BRAND} - {config.TAGLINE}")
    print(f"  running on http://{host}:{port}")
    print(f"  data dir: {config.DATA_DIR}")
    print("  Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  bye")
    finally:
        server.server_close()
