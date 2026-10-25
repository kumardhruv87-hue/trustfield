"""Live-URL scanner: everything we can see from the public internet.

Design notes
  * Passive only. We fetch public pages the app already serves to every visitor.
  * No exploitation, no credential stuffing, no write requests, no fuzzing.
  * Every request goes through net.safe_fetch (SSRF + size + time guards).
"""
from __future__ import annotations

import re
import time
import urllib.parse
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import config, net, secrets, webdeep
from .findings import Finding, dedupe

# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


@dataclass
class Result:
    target: str = ""
    final_url: str = ""
    status: int = 0
    findings: list[Finding] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    error: str = ""

    @property
    def passed(self) -> list[str]:
        return [c["name"] for c in self.checks if c["ok"]]

    @property
    def failed(self) -> list[str]:
        return [c["name"] for c in self.checks if not c["ok"]]


class Collector:
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.checks: list[dict] = []

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def check(self, cid: str, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append({"id": cid, "name": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    def fail(self, cid: str, name: str, finding: Finding, detail: str = "") -> None:
        self.check(cid, name, False, detail)
        self.add(finding)


def _short(text: str, limit: int = 180) -> str:
    text = re.sub(r"\s+", " ", (text or "").strip())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _is_html(res) -> bool:  # noqa: ANN001
    ctype = res.header("content-type", "").lower()
    return "html" in ctype or res.body[:200].lstrip().lower().startswith(b"<!doctype html")


def _looks_like_404(res) -> bool:  # noqa: ANN001
    if res.status == 404:
        return True
    if res.status >= 300:
        return True
    text = res.text[:4000].lower()
    return any(
        marker in text
        for marker in ("page not found", "404 not found", "could not be found", "no such page")
    )


# --------------------------------------------------------------------------
# header checks
# --------------------------------------------------------------------------

ANALYTICS_COOKIES = ("_ga", "_gid", "_gat", "_fbp", "_fbc", "__utm", "_hj", "ph_", "mp_", "intercom", "amplitude")


def _check_headers(res: net.FetchResult, c: Collector) -> None:
    # Edge providers vary headers by user-agent. Measure what a browser receives
    # before declaring a header missing.
    try:
        if not res.header("strict-transport-security") or not res.header("content-security-policy"):
            probe = net.safe_fetch(res.url, max_bytes=30_000, timeout=6, extra_headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml",
            })
            if probe.headers:
                merged = dict(res.headers or {})
                for key, value in probe.headers.items():
                    merged.setdefault(key.lower(), value)
                res.headers = merged
    except Exception:
        pass
    h = res.headers

    # HSTS ------------------------------------------------------------------
    hsts = h.get("strict-transport-security", "")
    max_age = 0
    if hsts:
        match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        max_age = int(match.group(1)) if match else 0
    if not hsts:
        c.fail(
            "header.hsts",
            "HSTS header",
            Finding(
                id="live.no_hsts",
                title="HSTS header is missing",
                severity="medium",
                category="Transport security",
                why="Without HSTS a browser may still try plain HTTP first, which lets "
                "someone on the same Wi-Fi read or change the traffic.",
                fix="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
                "to your responses (Vercel/Netlify: in `next.config.js` headers or "
                "`vercel.json`; Supabase-hosted UI: at the CDN).",
                evidence=f"strict-transport-security: {hsts or '(not sent)'}",
                effort="5 min",
            ),
        )
    elif max_age < 15552000:
        c.fail(
            "header.hsts",
            "HSTS header",
            Finding(
                id="live.weak_hsts",
                title="HSTS max-age is too short",
                severity="low",
                category="Transport security",
                why=f"max-age is {max_age}s; below 6 months most browsers ignore the policy.",
                fix="Set `max-age=31536000; includeSubDomains`.",
                evidence=_short(hsts),
                effort="5 min",
            ),
        )
    else:
        c.check("header.hsts", "HSTS header", True, hsts)

    # CSP -------------------------------------------------------------------
    csp = h.get("content-security-policy", "")
    if not csp:
        c.fail(
            "header.csp",
            "Content-Security-Policy",
            Finding(
                id="live.no_csp",
                title="No Content-Security-Policy",
                severity="medium",
                category="Transport security",
                why="CSP is the seatbelt against injected scripts. Without it, one "
                "malicious script on your page can read tokens from the browser.",
                fix="Start in report-only mode, then ship a policy. Next.js: add a "
                "`headers()` entry in `next.config.js` with "
                "`default-src 'self'; script-src 'self' 'unsafe-inline'; "
                "connect-src 'self' https://*.supabase.co;` and tighten from there.",
                effort="45 min",
            ),
        )
    else:
        weak = "'unsafe-inline'" in csp and "'unsafe-eval'" in csp
        if weak:
            c.fail(
                "header.csp",
                "Content-Security-Policy",
                Finding(
                    id="live.weak_csp",
                    title="CSP allows both unsafe-inline and unsafe-eval",
                    severity="low",
                    category="Transport security",
                    why="That combination blocks almost nothing: an injected inline "
                    "script can still run.",
                    fix="Remove `'unsafe-eval'` first, then move inline scripts to "
                    "hashed or nonce-based scripts.",
                    evidence=_short(csp, 240),
                    effort="1 h",
                ),
            )
        else:
            c.check("header.csp", "Content-Security-Policy", True, _short(csp, 120))

    # clickjacking ----------------------------------------------------------
    xfo = h.get("x-frame-options", "").lower()
    frame_ancestors = "frame-ancestors" in csp.lower()
    if not xfo and not frame_ancestors:
        c.fail(
            "header.frame",
            "Clickjacking protection",
            Finding(
                id="live.no_frame_protection",
                title="Page can be framed by any site",
                severity="low",
                category="Transport security",
                why="Another site can embed your app invisibly and trick a logged-in "
                "user into clicking things (clickjacking).",
                fix="Send `X-Frame-Options: DENY` or add `frame-ancestors 'none'` to "
                "your CSP.",
                evidence="x-frame-options: (not sent)",
                effort="5 min",
            ),
        )
    else:
        c.check("header.frame", "Clickjacking protection", True, xfo or "frame-ancestors")

    # nosniff ---------------------------------------------------------------
    nosniff = h.get("x-content-type-options", "").lower() == "nosniff"
    if not nosniff:
        c.fail(
            "header.nosniff",
            "MIME sniffing protection",
            Finding(
                id="live.no_nosniff",
                title="X-Content-Type-Options is missing",
                severity="low",
                category="Transport security",
                why="Browsers may guess file types and execute an uploaded file as a script.",
                fix="Send `X-Content-Type-Options: nosniff`.",
                evidence="x-content-type-options: (not sent)",
                effort="5 min",
            ),
        )
    else:
        c.check("header.nosniff", "MIME sniffing protection", True)

    # referrer --------------------------------------------------------------
    ref = h.get("referrer-policy", "")
    if not ref:
        c.fail(
            "header.referrer",
            "Referrer-Policy",
            Finding(
                id="live.no_referrer_policy",
                title="Referrer-Policy is missing",
                severity="low",
                category="Transport security",
                why="Full URLs (sometimes with tokens in them) leak to every third "
                "party the page loads from.",
                fix="Send `Referrer-Policy: strict-origin-when-cross-origin`.",
                evidence="referrer-policy: (not sent)",
                effort="5 min",
            ),
        )
    else:
        c.check("header.referrer", "Referrer-Policy", True, ref)

    # banner leak -----------------------------------------------------------
    banner = h.get("x-powered-by", "")
    server = h.get("server", "")
    if banner or (server and re.search(r"/[\d.]+", server)):
        c.add(
            Finding(
                id="live.version_banner",
                title="Server/framework version is advertised",
                severity="info",
                category="Transport security",
                why="Telling the internet your exact version makes it easier to look up "
                "known bugs for it.",
                fix="Hide `X-Powered-By` (Next.js: `poweredByHeader: false`) and keep "
                "the server behind a CDN that strips the banner.",
                evidence=_short(f"server={server or '—'} x-powered-by={banner or '—'}"),
                effort="5 min",
            )
        )

    # CORS ------------------------------------------------------------------
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower() == "true"
    if acao.strip() == "*" and acac:
        c.fail(
            "header.cors",
            "CORS policy",
            Finding(
                id="live.cors_wildcard_credentials",
                title="CORS allows any origin together with credentials",
                severity="high",
                category="Access control",
                why="Browsers normally block this combination, but misconfigured proxies "
                "and older patterns can still expose logged-in users' data to any site.",
                fix="Replace `*` with an explicit allow-list of your own origins, and "
                "never combine `*` with `Access-Control-Allow-Credentials: true`.",
                evidence="access-control-allow-origin: * + allow-credentials: true",
                effort="15 min",
            ),
        )
    elif acao.strip() == "*":
        c.add(
            Finding(
                id="live.cors_wildcard",
                title="CORS is open to every origin",
                severity="low",
                category="Access control",
                why="Fine for a public API, risky if any endpoint returns user data "
                "based on a cookie or a key the browser holds.",
                fix="Restrict CORS to your own domains on endpoints that return user data.",
                evidence="access-control-allow-origin: *",
                effort="15 min",
                confidence="medium",
            )
        )
    else:
        c.check("header.cors", "CORS policy", True, acao or "no wildcard")

    # cookies ---------------------------------------------------------------
    cookie_headers = res.header_all("set-cookie")
    if cookie_headers:
        problems: list[str] = []
        for raw in cookie_headers:
            name = raw.split("=", 1)[0].strip()
            low = raw.lower()
            if name.lower().startswith(ANALYTICS_COOKIES):
                continue
            if not re.search(r"(sess|sid|token|auth|jwt|sb-|supabase|connect\.sid|next-auth|user)", name, re.I):
                continue
            issues = []
            if "httponly" not in low:
                issues.append("no HttpOnly")
            if res.url.startswith("https") and "secure" not in low:
                issues.append("no Secure")
            if "samesite" not in low:
                issues.append("no SameSite")
            if issues:
                problems.append(f"{name}: {', '.join(issues)}")
        if problems:
            c.fail(
                "header.cookies",
                "Session cookie flags",
                Finding(
                    id="live.weak_cookie_flags",
                    title="Session cookie is missing protective flags",
                    severity="medium",
                    category="Access control",
                    why="A cookie without HttpOnly can be stolen by any script on the "
                    "page; without Secure it can travel over plain HTTP.",
                    fix="Set session cookies with `HttpOnly; Secure; SameSite=Lax` "
                    "(or `Strict`).",
                    evidence=_short("; ".join(problems[:3])),
                    effort="20 min",
                ),
            )
        else:
            c.check("header.cookies", "Session cookie flags", True)
    else:
        c.check("header.cookies", "Session cookie flags", True, "no cookies set on /")


# --------------------------------------------------------------------------
# exposed files
# --------------------------------------------------------------------------

EXPOSED_PATHS: tuple[tuple[str, str, str, str], ...] = (
    # path, severity, title fragment, fix
    ("/.env", "critical", ".env file", "Delete the file from the deployment root, rotate every key inside it, and keep env files out of the build output."),
    ("/.env.local", "critical", ".env.local file", "Delete it from the deployment root and rotate every key inside it."),
    ("/.env.production", "critical", ".env.production file", "Delete it from the deployment root and rotate every key inside it."),
    ("/.git/config", "critical", "exposed .git directory", "Stop serving the .git folder (block dotfiles in your host/CDN) and rebuild the deployment from a clean export."),
    ("/.git/HEAD", "critical", "exposed .git directory", "Stop serving the .git folder (block dotfiles in your host/CDN)."),
    ("/.vscode/sftp.json", "critical", "VS Code SFTP config", "Delete the file from the web root — it often contains server credentials."),
    ("/backup.sql", "critical", "database backup file", "Delete the backup from the web root and store backups in private object storage."),
    ("/db.sqlite", "critical", "SQLite database file", "Delete it from the web root and move the database behind your server."),
    ("/database.sqlite", "critical", "SQLite database file", "Delete it from the web root and move the database behind your server."),
    ("/config.json", "high", "config file that may hold secrets", "Delete it from the web root and load config on the server only."),
)

SQLITE_MAGIC = b"SQLite format 3"


def _signature_ok(path: str, res: net.FetchResult) -> str:
    """Return a short evidence string when the response really looks like the file."""
    body = res.body
    text = res.text
    low = text.lower()
    if "html" in res.header("content-type", "").lower() and path not in ("/.env", "/.env.local", "/.env.production"):
        return ""
    if path.startswith("/.env"):
        if re.search(r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=", text) and len(body) > 10:
            keys = re.findall(r"(?m)^\s*([A-Z][A-Z0-9_]{2,})\s*=", text)
            return "keys: " + ", ".join(keys[:6])
        return ""
    if path == "/.git/config":
        return "[core]" in low and "repositoryformatversion" in low and "[core]"
    if path == "/.git/HEAD":
        return text.startswith("ref: refs/") or bool(re.fullmatch(r"[0-9a-f]{40}\s*", text))
    if path == "/.vscode/sftp.json":
        return '"host"' in low and ('"password"' in low or '"privatekeypath"' in low or '"privateKeyPath"' in text)
    if path in ("/backup.sql",):
        return ("create table" in low or "insert into" in low)
    if path in ("/db.sqlite", "/database.sqlite"):
        return body[:16] == SQLITE_MAGIC
    if path == "/config.json":
        return ('"apikey"' in low or '"api_key"' in low or '"secret"' in low) and "html" not in low[:200]
    return ""


def _check_exposed_files(base: str, budget: net.Budget, c: Collector) -> bool:
    """Returns True if any exposed file was found."""
    found_any = False
    for path, severity, label, fix in EXPOSED_PATHS:
        if budget.expired():
            break
        res = net.safe_fetch(net.join(base, path), budget=budget, max_bytes=60_000, timeout=6)
        if res.status != 200 or not res.body:
            continue
        evidence = _signature_ok(path, res)
        if not evidence:
            continue
        found_any = True
        c.add(
            Finding(
                id=f"live.exposed_{path.strip('/').replace('/', '_').replace('.', '')}",
                title=f"Publicly readable {label} at {path}",
                severity=severity,
                category="Exposed files",
                why="This file is served to anyone who guesses the path. It is one of the "
                "most common ways AI-built apps leak keys and customer data.",
                fix=fix,
                evidence=f"{res.url} → HTTP {res.status} ({_short(str(evidence), 120)})",
                effort="30 min",
                ref="https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
            )
        )
    if not found_any:
        c.check("exposed.files", "No exposed .env / .git / backup files", True)
    return found_any


# --------------------------------------------------------------------------
# client-side JavaScript
# --------------------------------------------------------------------------

AI_HOSTS = (
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.groq.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "openrouter.ai",
    "api.together.xyz",
    "api.replicate.com",
)

SCRIPT_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
INLINE_MAP_RE = re.compile(r"sourceMappingURL=([^\s*]+)", re.I)
SUPABASE_URL_RE = re.compile(r"https://([a-z0-9]{15,22})\.supabase\.co", re.I)
SUPABASE_PUBLISHABLE_RE = re.compile(r"\bsb_publishable_[A-Za-z0-9_-]{10,}")
SUPABASE_SECRET_RE = re.compile(r"\bsb_secret_[A-Za-z0-9_-]{10,}")
SUPABASE_FROM_RE = re.compile(r"""\.from\(\s*["']([A-Za-z0-9_]+)["']""")
CHUNK_RE = re.compile(r"""["'`]([^"'`\s]{0,120}-[A-Za-z0-9_-]{6,12}\.js)["'`]""")
JWT_ANON_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")

# Server-side data layers (TanStack Start / Next server actions) expose no table
# names to the browser, so we probe a small set of common names instead.
FALLBACK_TABLES = (
    "profiles",
    "users",
    "organizations",
    "visits",
    "orders",
    "customers",
)


def _fetch_scripts(html_text: str, page_url: str, budget: net.Budget) -> list[tuple[str, str]]:
    """Fetch same-origin JS bundles, then one hop into their lazy chunks.

    Modern builders (Lovable/Bolt/v0) split routes into chunks. The dangerous code
    — auth checks, Supabase queries, API keys — often lives in a lazy chunk that is
    not in the initial HTML, so we follow the chunk imports.
    """
    sources = SCRIPT_RE.findall(html_text[:900_000])
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for src in sources:
        if len(out) >= config.MAX_JS_BUNDLES or budget.expired():
            break
        absolute = net.join(page_url, src.strip())
        if absolute in seen or not net.same_origin(page_url, absolute):
            continue
        seen.add(absolute)
        res = net.safe_fetch(absolute, budget=budget, max_bytes=900_000, timeout=7)
        if res.status == 200 and res.body:
            out.append((absolute, res.text))

    if out and not budget.expired():
        blob = "\n".join(text for _, text in out)
        base_url = out[0][0]
        extra = 0
        for name in dict.fromkeys(CHUNK_RE.findall(blob)):
            if extra >= 8 or budget.expired():
                break
            absolute = urllib.parse.urljoin(base_url, name.strip())
            if absolute in seen or not net.same_origin(page_url, absolute):
                continue
            seen.add(absolute)
            res = net.safe_fetch(absolute, budget=budget, max_bytes=700_000, timeout=6)
            if res.status == 200 and res.body:
                out.append((absolute, res.text))
                extra += 1
    return out


def _supabase_surface(
    project_ref: str,
    blob: str,
    budget: net.Budget,
    c: Collector,
    info: dict,
) -> None:
    """Check what the public Supabase key can reach — counts only, zero rows read."""
    key = ""
    key_type = ""
    publishable = SUPABASE_PUBLISHABLE_RE.search(blob)
    if publishable:
        key = publishable.group(0)
        key_type = "publishable key (new style)"
    else:
        for token in JWT_ANON_RE.finditer(blob):
            if secrets.jwt_role(token.group(0)) == "anon":
                key = token.group(0)
                key_type = "anon JWT (legacy)"
                break
    if not key:
        return

    tables = sorted(set(SUPABASE_FROM_RE.findall(blob)))
    if not tables:
        tables = list(FALLBACK_TABLES)
        info["supabase_tables_source"] = "fallback probes"
    info["supabase_key_type"] = key_type
    info["supabase_tables"] = tables[:12]

    c.add(
        Finding(
            id="live.supabase_public_key",
            title="Supabase public key is visible in the browser",
            severity="info",
            category="Database access",
            why="This key is public by design — it only stays safe while Row Level Security "
            "is enabled on every table. Anyone can take it and query your database directly.",
            fix="Enable RLS on every table and add policies that filter by the logged-in user "
            "or their organisation. Then test with this key: it should return only what the "
            "current user is allowed to see.",
            evidence=f"project {project_ref}, {key_type}",
            effort="30 min",
            ref="https://supabase.com/docs/guides/database/postgres/row-level-security",
        )
    )

    if not tables:
        c.check("supabase.rls", "Supabase tables probed for public access", False, "no table names in bundle")
        return

    readable: list[tuple[str, str]] = []
    existing: list[str] = []
    probed = 0
    for table in tables[:8]:
        if budget.expired():
            break
        url = (
            f"https://{project_ref}.supabase.co/rest/v1/"
            f"{urllib.parse.quote(table)}?select=*&limit=0"
        )
        headers = {
            "apikey": key,
            "Accept": "application/json",
            "Prefer": "count=exact",
            "Range-Unit": "items",
            "Range": "0-0",
        }
        if not key.startswith("sb_"):
            headers["Authorization"] = f"Bearer {key}"
        res = net.safe_fetch(
            url,
            budget=budget,
            max_bytes=4096,
            timeout=6,
            method="HEAD",
            extra_headers=headers,
        )
        probed += 1
        content_range = res.header("content-range", "")
        count = content_range.split("/")[-1] if "/" in content_range else "?"
        if res.status in (200, 206):
            existing.append(table)
            if count not in ("0", "?", "*"):
                readable.append((table, count))

    if readable:
        c.fail(
            "supabase.rls",
            "Supabase tables not readable without login",
            Finding(
                id="live.supabase_table_publicly_readable",
                title="Database table is readable with the public key",
                severity="critical",
                category="Database access",
                why="Anyone who opens your site can copy the public key and query this table "
                "directly — no login, no app, no rate limit. In a multi-tenant app this is "
                "usually cross-company data.",
                fix="Immediately enable RLS on the table and add a policy that filters by the "
                "logged-in user or organisation, for example `using (org_id = "
                "(select org_id from profiles where id = auth.uid()))`. Then re-test with the "
                "public key — it must return 0 rows.",
                evidence="; ".join(f"{name}: ~{rows} rows visible" for name, rows in readable),
                effort="1 h",
                confidence="high",
            ),
        )
        info["supabase_readable_tables"] = [name for name, _ in readable]
    else:
        info["supabase_existing_tables"] = existing
        c.check(
            "supabase.rls",
            "Supabase tables not readable without login",
            True,
            f"{probed} probed · {len(existing)} table(s) answer the public key with 0 rows"
            + (f" ({', '.join(existing[:4])})" if existing else ""),
        )


def _check_client_js(
    page_url: str,
    html_text: str,
    budget: net.Budget,
    c: Collector,
    has_ai: bool,
) -> dict:
    bundles = _fetch_scripts(html_text, page_url, budget)
    blob = "\n".join(text for _, text in bundles)
    info: dict = {"bundles": [u for u, _ in bundles]}

    # 1. secrets anywhere in shipped JS
    for url, text in bundles:
        for f in secrets.scan_text(text, url):
            c.add(f)

    # 2. AI provider called directly from the browser
    if blob:
        found_hosts = sorted({host for host in AI_HOSTS if host in blob})
        if found_hosts:
            c.add(
                Finding(
                    id="live.client_side_ai_call",
                    title="AI provider is called directly from the browser",
                    severity="critical",
                    category="AI cost & abuse",
                    why="If the model call happens in the browser, the API key must be in "
                    "the browser too — which means anyone can take it and spend your "
                    "credits. This is the single fastest way to lose money with an "
                    "AI-built app.",
                    fix="Move the call behind your own server route (Next.js route "
                    "handler / serverless function), keep the key server-side, and add "
                    "a per-user rate limit.",
                    evidence="bundle references: " + ", ".join(found_hosts),
                    effort="1–2 h",
                    ref="https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                )
            )
            info["client_side_ai"] = True
        else:
            c.check("js.no_client_ai", "AI keys not called from the browser", True)

    # 2b. Server-side data access is a good sign (and changes what we can see)
    if blob and ("_serverFn" in blob or "createServerFn" in blob):
        info["server_side_data"] = True
        c.add(
            Finding(
                id="live.server_side_data_access",
                title="Data access runs on the server",
                severity="info",
                category="Database access",
                why="The browser is not querying the database directly — requests go through "
                "your server functions. That is the safer pattern. It does not remove the need "
                "for Row Level Security if the public key can still reach tables.",
                fix="Keep RLS enabled and re-test with the public key once you have real data.",
                evidence="server functions detected in the client bundle",
                effort="—",
            )
        )

    # 3. Supabase: what can the public key actually reach?
    supa = SUPABASE_URL_RE.search(blob)
    if supa:
        project_ref = supa.group(1)
        info["supabase_project"] = project_ref
        if "service_role" in blob:
            c.add(
                Finding(
                    id="live.supabase_service_role_in_client",
                    title="Supabase service_role key referenced in browser code",
                    severity="critical",
                    category="Secrets & keys",
                    why="service_role bypasses Row Level Security — full database access "
                    "for anyone who opens devtools.",
                    fix="Remove every service_role reference from client components. Only "
                    "use it in server code, and rotate the JWT secret in Supabase after "
                    "removing it.",
                    evidence=f"project: {project_ref}",
                    effort="30 min",
                )
            )
        _supabase_surface(project_ref, blob, budget, c, info)

    # 4. source maps
    maps_found: list[str] = []
    inline_maps = INLINE_MAP_RE.findall(html_text[:500_000])
    if inline_maps:
        maps_found.append(inline_maps[0][:120])
    for url, _ in bundles[:4]:
        if budget.expired():
            break
        res = net.safe_fetch(url + ".map", budget=budget, max_bytes=40_000, timeout=6)
        if res.status == 200 and (b'"mappings"' in res.body or res.body[:200].lstrip().startswith(b"{")):
            maps_found.append(url + ".map")
    if maps_found:
        c.fail(
            "js.sourcemaps",
            "No source maps exposed",
            Finding(
                id="live.sourcemap_exposed",
                title="Source maps are publicly downloadable",
                severity="high",
                category="Exposed files",
                why="Source maps reconstruct your original code — comments, internal "
                "endpoint names, sometimes hardcoded values. Attackers read them to "
                "find weak spots.",
                fix="Disable production source maps (`productionBrowserSourceMaps: "
                "false` in Next.js; `build.sourcemap: false` in Vite) or restrict "
                "`.map` files at the CDN.",
                evidence=_short(", ".join(maps_found[:3]), 200),
                effort="10 min",
            ),
        )
    else:
        c.check("js.sourcemaps", "No source maps exposed", True)

    # 5. GraphQL + deeper JS/HTML-level checks
    webdeep.check_graphql(page_url, blob, budget, c)
    webdeep.check_js(page_url, blob, budget, c, info)

    return info


# --------------------------------------------------------------------------
# compliance / trust pages
# --------------------------------------------------------------------------

PRIVACY_PATHS = (
    "/privacy", "/privacy-policy", "/privacy.html", "/legal/privacy", "/legal/privacy-policy",
    "/policies/privacy-policy", "/pages/privacy-policy", "/privacy_policy", "/privacy/",
)
TERMS_PATHS = (
    "/terms", "/terms-of-service", "/terms.html", "/legal/terms", "/legal/terms-of-service",
    "/policies/terms-of-service", "/pages/terms-of-service", "/terms_of_service", "/terms/",
)
DELETE_PATHS = (
    "/delete-account", "/account/delete", "/data-deletion", "/delete-my-data",
    "/account/delete-account", "/pages/delete-account",
)


_HREF_RE = re.compile(r"""href\s*=\s*["']([^"'>]{1,300})["']""", re.I)


def _candidate_links(base: str, html_text: str, keyword: str) -> list[str]:
    """Absolute same-site links whose URL mentions the keyword."""
    from urllib.parse import urljoin, urlsplit
    base_host = (urlsplit(base).hostname or "").lower()
    seen: list[str] = []
    for raw in _HREF_RE.findall(html_text or "")[:4000]:
        low = raw.lower()
        if keyword not in low:
            continue
        absolute = urljoin(base, raw)
        parts = urlsplit(absolute)
        if parts.scheme not in ("http", "https"):
            continue
        if (parts.hostname or "").lower() != base_host:
            continue
        clean = absolute.split("#")[0]
        if clean not in seen:
            seen.append(clean)
    return seen[:4]


def _find_link(base: str, html_text: str, keyword: str, budget: net.Budget) -> tuple[str, net.FetchResult] | None:
    """Follow a link that the page itself advertises (Shopify, WordPress, Webflow...)."""
    for url in _candidate_links(base, html_text, keyword):
        if budget.expired():
            return None
        res = net.safe_fetch(url, budget=budget, max_bytes=250_000, timeout=6)
        if res.status == 200 and not _looks_like_404(res) and keyword in res.text.lower():
            return url, res
    return None


def _find_page(base: str, paths: tuple[str, ...], budget: net.Budget) -> tuple[str, net.FetchResult] | None:
    for path in paths:
        if budget.expired():
            return None
        res = net.safe_fetch(net.join(base, path), budget=budget, max_bytes=200_000, timeout=6)
        if res.status == 200 and not _looks_like_404(res):
            return path, res
    return None


def _check_compliance(base: str, budget: net.Budget, c: Collector, has_ai: bool, html_text: str = "") -> dict:
    out: dict = {}
    privacy = _find_link(base, html_text, "privacy", budget) or _find_page(base, PRIVACY_PATHS, budget)
    if privacy:
        out["privacy"] = privacy[0]
        c.check("compliance.privacy", "Privacy policy page", True, privacy[0])
    else:
        c.fail(
            "compliance.privacy",
            "Privacy policy page",
            Finding(
                id="live.no_privacy_page",
                title="No privacy policy page found",
                severity="medium",
                category="Compliance",
                why="If the app collects an email, a name or analytics data, most "
                "jurisdictions (India DPDP, EU GDPR, UK GDPR, California) require a "
                "privacy notice, and payment providers ask for it during review.",
                fix="Publish a plain-English /privacy page listing what you collect, "
                "why, where it is stored, how long you keep it and how to delete it. "
                "Start from the template in your repo's gtm/17-legal-pages.md.",
                evidence="no privacy link found on the homepage; checked common paths: " + ", ".join(PRIVACY_PATHS[:3]),
                effort="30 min",
            ),
        )

    terms = _find_link(base, html_text, "terms", budget) or _find_page(base, TERMS_PATHS, budget)
    if terms:
        out["terms"] = terms[0]
        c.check("compliance.terms", "Terms of service page", True, terms[0])
    else:
        c.fail(
            "compliance.terms",
            "Terms of service page",
            Finding(
                id="live.no_terms_page",
                title="No terms of service page found",
                severity="low",
                category="Compliance",
                why="Terms set expectations for refunds, acceptable use and liability. "
                "Payment providers and B2B buyers expect them to exist.",
                fix="Publish a /terms page. A plain-language version is enough to start; "
                "see gtm/17-legal-pages.md.",
                evidence="no terms link found on the homepage; checked common paths: " + ", ".join(TERMS_PATHS[:3]),
                effort="30 min",
            ),
        )

    deletion = _find_link(base, html_text, "delete", budget) or _find_page(base, DELETE_PATHS, budget)
    if deletion:
        out["data_deletion"] = deletion[0]
        c.check("compliance.deletion", "Data deletion path", True, deletion[0])
    else:
        c.add(
            Finding(
                id="live.no_deletion_path",
                title="No obvious way for a user to delete their data",
                severity="low",
                category="Compliance",
                why="GDPR and India's DPDP Act both give people a right to erasure. "
                "Without a path, a single request becomes a support emergency.",
                fix="Add a /delete-account page or a documented email request flow, and "
                "make sure it actually deletes rows across tables and storage buckets.",
                evidence="no data-deletion link found on the homepage; checked common paths: " + ", ".join(DELETE_PATHS[:3]),
                effort="1 h",
                confidence="medium",
            )
        )
    return out


# --------------------------------------------------------------------------
# misc
# --------------------------------------------------------------------------

PLATFORM_HINTS = {
    "lovable.app": "Lovable",
    ".lovable.dev": "Lovable",
    "lovableproject.com": "Lovable",
    "bolt.new": "Bolt.new",
    "v0.dev": "v0",
    "replit.app": "Replit",
    "replit.dev": "Replit",
    "base44.app": "Base44",
    "bubble.io": "Bubble",
    "softr.io": "Softr",
    "carrd.co": "Carrd",
    "webflow.io": "Webflow",
    "framer.website": "Framer",
    "_next/static": "Next.js",
    ".supabase.co": "Supabase",
    "firebaseio.com": "Firebase",
    "firebaseapp.com": "Firebase",
}


def _detect_platform(html_text: str, headers: dict[str, str]) -> str:
    haystack = (html_text[:200_000] + " " + " ".join(f"{k}:{v}" for k, v in headers.items())).lower()
    for needle, label in PLATFORM_HINTS.items():
        if needle in haystack:
            return label
    return ""


def _check_mixed_content(page_url: str, html_text: str, c: Collector) -> None:
    if not page_url.startswith("https://"):
        return
    insecure = re.findall(r"""(?:src|href|action)=["']http://([^"'/]+)""", html_text[:500_000], re.I)
    insecure = [h for h in insecure if h and "localhost" not in h][:4]
    if insecure:
        c.fail(
            "transport.mixed_content",
            "No mixed content",
            Finding(
                id="live.mixed_content",
                title="Page loads resources over plain HTTP",
                severity="medium",
                category="Transport security",
                why="Mixed content can be modified in transit; browsers also block some "
                "of it, which breaks the page for some users.",
                fix="Change every http:// resource URL to https:// (or a protocol-relative "
                "CDN URL).",
                evidence="http://" + ", http://".join(insecure),
                effort="15 min",
            ),
        )
    else:
        c.check("transport.mixed_content", "No mixed content", True)


def _check_security_txt(base: str, budget: net.Budget, c: Collector) -> None:
    res = net.safe_fetch(net.join(base, "/.well-known/security.txt"), budget=budget, max_bytes=20_000, timeout=5)
    if res.status == 200 and "contact:" in res.text.lower():
        c.check("misc.security_txt", "security.txt published", True)


# --------------------------------------------------------------------------
# main entry
# --------------------------------------------------------------------------


def scan_live(raw_url: str, has_ai: bool = False, budget_seconds: float | None = None) -> Result:
    budget = net.Budget(budget_seconds or config.SCAN_TIMEOUT_SECONDS)
    started = time.monotonic()
    result = Result(target=raw_url)
    collector = Collector()

    try:
        url = net.normalize_url(raw_url)
    except net.BlockedTarget as exc:
        result.error = str(exc)
        return result

    parts = urlsplit(url)
    host = parts.hostname or ""
    netloc = parts.netloc
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    https_url = f"https://{netloc}{path}{query}"
    http_url = f"http://{netloc}{path}{query}"

    result.target = url
    root = net.safe_fetch(https_url, budget=budget)
    scheme = "https"

    if root.cert_error:
        collector.fail(
            "transport.tls",
            "Valid TLS certificate",
            Finding(
                id="live.invalid_certificate",
                title="TLS certificate is invalid or expired",
                severity="critical",
                category="Transport security",
                why="Browsers show a full-page warning, so most visitors leave. Any data "
                "sent is not trustworthy.",
                fix="Renew the certificate (Vercel/Netlify/Render do this automatically "
                "once the domain is verified; for a custom server use Caddy or certbot).",
                evidence=root.error,
                effort="20 min",
            ),
        )
        root = net.safe_fetch(http_url, budget=budget)
        scheme = "http"
        if not root.status and root.error:
            result.error = f"HTTPS failed and HTTP did not answer ({root.error})"
            result.findings = collector.findings
            result.checks = collector.checks
            result.meta = {"host": host}
            return result
    elif not root.status and root.error:
        http_res = net.safe_fetch(http_url, budget=budget)
        if http_res.status:
            collector.fail(
                "transport.tls",
                "Valid TLS certificate",
                Finding(
                    id="live.no_https",
                    title="Site is not reachable over HTTPS",
                    severity="critical",
                    category="Transport security",
                    why="Everything visitors send — passwords, tokens, payment details — "
                    "travels in clear text and can be read or changed.",
                    fix="Enable HTTPS on your host (free on Vercel, Netlify, Render, "
                    "Cloudflare) and force a redirect from http to https.",
                    evidence=_short(root.error or "https failed"),
                    effort="30 min",
                ),
            )
            root = http_res
            scheme = "http"
        else:
            result.error = root.error or http_res.error or "site could not be reached"
            result.findings = collector.findings
            result.checks = collector.checks
            result.meta = {"host": host}
            return result
    else:
        collector.check("transport.tls", "Valid TLS certificate", True, root.header("server", ""))

    result.final_url = root.url or url
    result.status = root.status
    base = net.origin(result.final_url or url)

    # http -> https redirect
    if scheme == "https" and budget.left() > 3:
        http_res = net.safe_fetch(http_url, budget=budget, max_bytes=30_000, timeout=6)
        if http_res.status and not (http_res.url or "").startswith("https://"):
            # Some edges answer a bot user-agent on http without redirecting but
            # send a real browser to https. Measure what a browser gets.
            probe = net.safe_fetch(http_url, budget=budget, max_bytes=30_000, timeout=6, extra_headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml",
            })
            if (probe.url or "").startswith("https://"):
                http_res = probe
        if http_res.status and not (http_res.url or "").startswith("https://"):
            collector.fail(
                "transport.https_redirect",
                "HTTP redirects to HTTPS",
                Finding(
                    id="live.no_https_redirect",
                    title="Plain HTTP is served without redirecting to HTTPS",
                    severity="high",
                    category="Transport security",
                    why="Visitors who type the bare domain can stay on an insecure "
                    "connection, and an attacker on the network can intercept it.",
                    fix="Return a 301 from http:// to https:// at the host or CDN level "
                    "(Vercel: enable 'Redirect to HTTPS'; Cloudflare: 'Always Use HTTPS').",
                    evidence=f"http:// responds with HTTP {http_res.status}",
                    effort="5 min",
                ),
            )
        else:
            collector.check("transport.https_redirect", "HTTP redirects to HTTPS", True)

    html_text = root.text
    _check_headers(root, collector)

    if _is_html(root):
        _check_mixed_content(result.final_url, html_text, collector)
        js_info = _check_client_js(result.final_url, html_text, budget, collector, has_ai)
        platform = _detect_platform(html_text, root.headers)
        webdeep.check_html(result.final_url, html_text, collector, js_info)
        webdeep.check_seo(result.final_url, html_text, budget, collector, js_info)
    else:
        js_info = {"bundles": []}
        platform = _detect_platform("", root.headers)
        collector.add(
            Finding(
                id="live.not_html",
                title="Root URL does not return an HTML page",
                severity="info",
                category="Scan quality",
                why="We scanned the URL you gave us, but it looks like an API or a file. "
                "Point the scanner at the page your users actually open.",
                fix="Re-run the scan with your app's homepage URL (for example "
                "https://app.yourdomain.com/).",
                evidence=f"content-type: {root.header('content-type', 'unknown')}",
                effort="—",
            )
        )

    _check_exposed_files(base, budget, collector)
    webdeep.check_dns(host, budget, collector, js_info)
    webdeep.check_tls(host, scheme, collector, js_info)
    webdeep.check_methods(base, budget, collector)
    webdeep.check_extra_files(base, budget, collector)
    compliance = _check_compliance(base, budget, collector, has_ai, html_text)
    _check_security_txt(base, budget, collector)

    result.findings = dedupe(collector.findings)
    result.checks = collector.checks
    result.meta = {
        "host": host,
        "status": root.status,
        "server": root.header("server", ""),
        "platform": platform,
        "bundles_scanned": len(js_info.get("bundles", [])),
        "supabase_project": js_info.get("supabase_project", ""),
        "client_side_ai": bool(js_info.get("client_side_ai")),
        "compliance": compliance,
        "has_ai": has_ai,
        "scan_seconds": round(time.monotonic() - started, 1),
    }
    for key, value in js_info.items():
        if key != "bundles":
            result.meta.setdefault(key, value)
    return result
