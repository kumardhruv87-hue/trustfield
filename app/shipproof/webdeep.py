"""Deeper live checks: DNS/email auth, TLS details, HTTP behaviour, HTML and JS
analysis, plus Firebase/GraphQL surface checks.

Everything here is passive or read-only: DNS over HTTPS, one TLS handshake,
OPTIONS, GET requests for public files, and schema/count probes with zero row
data. It all shares the scan's time budget and the SSRF guard in net.py.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.parse

from . import config, net
from .findings import Finding

# Platform subdomains have no email setup of their own — skip email checks there.
PLATFORM_SUFFIXES = (
    "lovable.app",
    "vercel.app",
    "netlify.app",
    "onrender.com",
    "fly.dev",
    "replit.app",
    "bolt.host",
    "pages.dev",
    "web.app",
    "firebaseapp.com",
    "base44.app",
    "softr.app",
    "bubbleapps.io",
)

DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"

TRACKER_DOMAINS = (
    "google-analytics.com",
    "googletagmanager.com",
    "analytics.google.com",
    "facebook.net",
    "connect.facebook.net",
    "hotjar.com",
    "clarity.ms",
    "segment.com",
    "mixpanel.com",
    "amplitude.com",
    "tiktok.com",
    "linkedin.com/px",
    "snap.licdn.com",
    "hubspot.com",
    "intercom.io",
)

CONSENT_MARKERS = (
    "cookie",
    "consent",
    "gdpr",
    "onetrust",
    "cookiebot",
    "cookieyes",
    "termly",
    "iubenda",
    "usercentrics",
)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_platform_host(host: str) -> bool:
    low = host.lower()
    return any(low == suffix or low.endswith("." + suffix) for suffix in PLATFORM_SUFFIXES)


def _doh(name: str, rtype: str, budget: net.Budget) -> dict | None:
    url = f"{DOH_ENDPOINT}?name={urllib.parse.quote(name)}&type={rtype}"
    res = net.safe_fetch(
        url,
        budget=budget,
        max_bytes=24_000,
        timeout=5,
        extra_headers={"Accept": "application/dns-json"},
    )
    if res.status != 200:
        return None
    try:
        data = json.loads(res.text)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _answers(data: dict | None, rtype: int) -> list[str]:
    out: list[str] = []
    for record in (data or {}).get("Answer") or []:
        if record.get("type") == rtype and record.get("data"):
            out.append(str(record["data"]))
    return out


def _txt(data: dict | None) -> list[str]:
    values = []
    for raw in _answers(data, 16):
        values.append(raw.strip('"'))
    return values


# --------------------------------------------------------------------------
# DNS / email authentication
# --------------------------------------------------------------------------


def check_dns(host: str, budget: net.Budget, c: "Collector", info: dict) -> None:  # noqa: F821
    if not host or _is_ip(host) or config.ALLOW_PRIVATE:
        return
    if _is_platform_host(host):
        c.check(
            "dns.email",
            "Email authentication (platform subdomain)",
            True,
            "not applicable on a platform subdomain",
        )
        return

    mx_data = _doh(host, "MX", budget)
    if mx_data is None or int(mx_data.get("Status", 0) or 0) != 0:
        info["dns_mx"] = -1
        c.check("dns.email", "Email authentication (SPF/DMARC)", True, "DNS-over-HTTPS unavailable, not asserted")
        return info
    mx = _answers(mx_data, 15)
    txt = _txt(_doh(host, "TXT", budget))
    spf = [value for value in txt if value.lower().startswith("v=spf1")]
    dmarc_txt = _txt(_doh("_dmarc." + host, "TXT", budget))
    dmarc = [value for value in dmarc_txt if value.lower().startswith("v=dmarc1")]
    caa = _answers(_doh(host, "CAA", budget), 257)

    info["dns_mx"] = len(mx)
    info["dns_spf"] = bool(spf)
    info["dns_dmarc"] = bool(dmarc)

    if not mx and spf:
        # Domain clearly sends mail (SPF present); MX lookup was unreliable for this host.
        info["dns_mx"] = 0
        c.check("dns.email", "Email authentication (SPF/DMARC)", True, "SPF present, MX lookup unreliable")
        return
    if not mx:
        c.add(
            Finding(
                id="deep.no_mx",
                title="Domain does not receive email",
                severity="info",
                category="Email trust",
                why="No MX record. If you plan to send receipts or alerts from this domain, "
                "delivery will fail until you add one.",
                fix="Add an MX record from your email provider (Resend/Postmark/Google Workspace).",
                evidence=f"MX records for {host}: 0",
                effort="15 min",
            )
        )
        c.check("dns.email", "Email authentication (SPF/DMARC)", False, "no MX record")
        return

    # SPF
    if not spf:
        c.fail(
            "dns.spf",
            "SPF record",
            Finding(
                id="deep.no_spf",
                title="No SPF record — anyone can spoof email from this domain",
                severity="medium",
                category="Email trust",
                why="Without SPF, an attacker can send email that looks like it came from your "
                "domain. That is how invoice and password-reset phishing starts.",
                fix="Add one TXT record: `v=spf1 include:<your-provider> -all`. Keep exactly one "
                "SPF record per domain.",
                evidence=f"TXT records checked on {host}: no v=spf1",
                effort="15 min",
            ),
        )
    elif len(spf) > 1:
        c.fail(
            "dns.spf",
            "SPF record",
            Finding(
                id="deep.multiple_spf",
                title="Multiple SPF records",
                severity="low",
                category="Email trust",
                why="More than one SPF record makes receiving servers ignore both.",
                fix="Merge them into a single `v=spf1` record.",
                evidence=f"{len(spf)} SPF records found",
                effort="15 min",
            ),
        )
    elif any("+all" in value.lower() for value in spf):
        c.fail(
            "dns.spf",
            "SPF record",
            Finding(
                id="deep.spf_allow_all",
                title="SPF allows anyone to send as your domain",
                severity="high",
                category="Email trust",
                why="`+all` tells the world that any server may send email for your domain. "
                "Spam filters will punish you and phishers will thank you.",
                fix="Change `+all` to `-all` (or `~all` while you test).",
                evidence=spf[0][:160],
                effort="10 min",
            ),
        )
    else:
        c.check("dns.spf", "SPF record", True, spf[0][:80])

    # DMARC
    if not dmarc:
        c.fail(
            "dns.dmarc",
            "DMARC record",
            Finding(
                id="deep.no_dmarc",
                title="No DMARC record",
                severity="medium",
                category="Email trust",
                why="DMARC tells inboxes what to do when someone spoofs your domain. Without it, "
                "SPF and DKIM failures are advisory only and spoofed mail still lands.",
                fix="Add TXT record `_dmarc` with `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain`.",
                evidence=f"_dmarc.{host}: no v=DMARC1",
                effort="15 min",
            ),
        )
    elif any("p=none" in value.lower() for value in dmarc):
        c.fail(
            "dns.dmarc",
            "DMARC record",
            Finding(
                id="deep.dmarc_monitor_only",
                title="DMARC is monitor-only (p=none)",
                severity="low",
                category="Email trust",
                why="`p=none` collects reports but does not block spoofed mail.",
                fix="Move to `p=quarantine`, then `p=reject` after a week of clean reports.",
                evidence=dmarc[0][:160],
                effort="5 min",
            ),
        )
    else:
        c.check("dns.dmarc", "DMARC record", True, dmarc[0][:80])

    if not caa:
        c.add(
            Finding(
                id="deep.no_caa",
                title="No CAA record",
                severity="low",
                category="Transport security",
                why="CAA limits which certificate authorities may issue certificates for your "
                "domain. Without it, any CA can issue one.",
                fix="Add a CAA record: `0 issue \"letsencrypt.org\"` (plus your CDN's CA).",
                evidence=f"CAA records for {host}: 0",
                effort="10 min",
            )
        )
    else:
        c.check("dns.caa", "CAA record", True, ", ".join(caa[:3]))


# --------------------------------------------------------------------------
# TLS details
# --------------------------------------------------------------------------


def check_tls(host: str, scheme: str, c: "Collector", info: dict) -> None:  # noqa: F821
    if scheme != "https" or not host or _is_ip(host) or config.ALLOW_PRIVATE:
        return
    context = ssl.create_default_context()
    details: dict = {}
    try:
        with socket.create_connection((host, 443), timeout=6) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                details = {
                    "version": tls.version() or "",
                    "cipher": (tls.cipher() or ("", "", 0))[0],
                    "alpn": tls.selected_alpn_protocol() or "",
                    "cert": tls.getpeercert() or {},
                }
    except (socket.timeout, TimeoutError):
        return
    except (ssl.SSLError, OSError):
        return

    cert = details.get("cert") or {}
    info["tls_version"] = details.get("version")
    info["tls_cipher"] = details.get("cipher")
    info["http2"] = details.get("alpn") == "h2"

    version = details.get("version") or ""
    if version in ("SSLv3", "TLSv1", "TLSv1.1"):
        c.fail(
            "tls.version",
            "TLS 1.2 or newer",
            Finding(
                id="deep.old_tls",
                title=f"Server still negotiates {version}",
                severity="high",
                category="Transport security",
                why=f"{version} is deprecated and has known weaknesses; browsers are removing it.",
                fix="Disable TLS 1.0/1.1 at your host or CDN and allow TLS 1.2 and 1.3 only.",
                evidence=f"negotiated {version}",
                effort="20 min",
            ),
        )
    else:
        c.check("tls.version", "TLS 1.2 or newer", True, version)

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expires = ssl.cert_time_to_seconds(not_after)
            days = int((expires - time.time()) / 86400)
            info["cert_days_left"] = days
            info["cert_issuer"] = dict(x[0] for x in cert.get("issuer", ()) if x).get("organizationName", "")
            if days < 0:
                c.fail(
                    "tls.expiry",
                    "Certificate is current",
                    Finding(
                        id="deep.cert_expired",
                        title="TLS certificate has expired",
                        severity="critical",
                        category="Transport security",
                        why="Every visitor sees a full-page browser warning and most leave.",
                        fix="Renew the certificate and turn on auto-renewal.",
                        evidence=f"expired {abs(days)} day(s) ago",
                        effort="20 min",
                    ),
                )
            elif days < 14:
                c.fail(
                    "tls.expiry",
                    "Certificate is current",
                    Finding(
                        id="deep.cert_expiring",
                        title=f"TLS certificate expires in {days} day(s)",
                        severity="high",
                        category="Transport security",
                        why="If auto-renewal is broken, your site goes down with a browser warning.",
                        fix="Renew now and check that auto-renewal is enabled at your host/CDN.",
                        evidence=f"notAfter={not_after}",
                        effort="20 min",
                    ),
                )
            elif days < 30:
                c.fail(
                    "tls.expiry",
                    "Certificate is current",
                    Finding(
                        id="deep.cert_expiring_soon",
                        title=f"TLS certificate expires in {days} days",
                        severity="medium",
                        category="Transport security",
                        why="Renewal is close. Verify auto-renewal now, not on launch day.",
                        fix="Confirm auto-renewal at your host/CDN.",
                        evidence=f"notAfter={not_after}",
                        effort="10 min",
                    ),
                )
            else:
                c.check("tls.expiry", "Certificate is current", True, f"{days} days left")
        except (ValueError, TypeError):
            pass

    issuer = info.get("cert_issuer") or ""
    if issuer:
        c.check("tls.issuer", "Certificate issuer recognized", True, issuer)


# --------------------------------------------------------------------------
# HTTP behaviour
# --------------------------------------------------------------------------


def check_methods(base_url: str, budget: net.Budget, c: "Collector") -> None:  # noqa: F821
    res = net.safe_fetch(base_url, budget=budget, method="OPTIONS", max_bytes=4096, timeout=6)
    allow = res.header("allow", "")
    if not allow:
        return
    if "TRACE" in allow.upper():
        c.fail(
            "http.trace",
            "TRACE method disabled",
            Finding(
                id="deep.trace_enabled",
                title="HTTP TRACE method is enabled",
                severity="medium",
                category="Transport security",
                why="TRACE can echo request headers (including cookies) back to an attacker who "
                "tricks a browser into sending them (Cross-Site Tracing).",
                fix="Turn TRACE off in your server or CDN config.",
                evidence=f"Allow: {allow[:120]}",
                effort="10 min",
            ),
        )
    else:
        c.check("http.trace", "TRACE method disabled", True)

    risky = [verb for verb in ("PUT", "DELETE", "PATCH") if verb in allow.upper()]
    if risky:
        c.add(
            Finding(
                id="deep.risky_methods",
                title="Write methods advertised on the root URL",
                severity="low",
                category="Transport security",
                why="Advertised write methods are not automatically a bug, but they widen the "
                "attack surface if any endpoint forgets an auth check.",
                fix="Only allow the methods each route needs, and confirm auth on every write route.",
                evidence=f"Allow: {allow[:120]}",
                effort="20 min",
                confidence="medium",
            )
        )


# --------------------------------------------------------------------------
# Extra exposed files (build/config/ops files)
# --------------------------------------------------------------------------

EXTRA_FILES: tuple[tuple[str, str, str, str], ...] = (
    ("/package.json", "medium", "package.json", "publish-lockfile"),
    ("/package-lock.json", "low", "package-lock.json", "publish-lockfile"),
    ("/next.config.js", "low", "next.config.js", "publish-build-config"),
    ("/vercel.json", "low", "vercel.json", "publish-build-config"),
    ("/docker-compose.yml", "critical", "docker-compose.yml", "publish-ops-file"),
    ("/Dockerfile", "low", "Dockerfile", "publish-ops-file"),
    ("/.DS_Store", "low", ".DS_Store", "publish-junk"),
    ("/server-status", "high", "server-status page", "expose-server-status"),
    ("/actuator/env", "critical", "Spring Boot actuator env", "expose-actuator"),
    ("/.gitignore", "low", ".gitignore", "publish-junk"),
)


def _extra_signature(path: str, res: net.FetchResult) -> str:
    body = res.body
    text = res.text
    low = text.lower()
    is_html = "html" in res.header("content-type", "").lower()
    if path != "/.DS_Store" and is_html and not path.startswith("/actuator"):
        return ""
    if path == "/package.json":
        return '"dependencies"' in low or '"devDependencies"' in low
    if path == "/package-lock.json":
        return '"lockfileVersion"' in low
    if path == "/next.config.js":
        return "module.exports" in text or "nextconfig" in low
    if path == "/vercel.json":
        return any(key in low for key in ('"rewrites"', '"headers"', '"redirects"'))
    if path == "/docker-compose.yml":
        return "services:" in low and ("image:" in low or "build:" in low)
    if path == "/Dockerfile":
        return bool(re.search(r"(?m)^\s*FROM\s+\S+", text))
    if path == "/.DS_Store":
        return body[:8] == b"\x00\x00\x00\x01Bud1"
    if path == "/server-status":
        return "apache server status" in low
    if path == "/actuator/env":
        return "propertysources" in low or "systemenvironment" in low
    if path == "/.gitignore":
        return "node_modules" in low or ".env" in low
    return ""


def check_extra_files(base_url: str, budget: net.Budget, c: "Collector") -> None:  # noqa: F821
    id_map = {
        "publish-lockfile": "deep.exposed_lockfile",
        "publish-build-config": "deep.exposed_build_config",
        "publish-ops-file": "deep.exposed_ops_file",
        "publish-junk": "deep.exposed_junk",
        "expose-server-status": "deep.exposed_server_status",
        "expose-actuator": "deep.exposed_actuator_env",
    }
    found_any = False
    for path, severity, label, kind in EXTRA_FILES:
        if budget.expired():
            break
        res = net.safe_fetch(net.join(base_url, path), budget=budget, max_bytes=80_000, timeout=6)
        if res.status != 200 or not res.body:
            continue
        if not _extra_signature(path, res):
            continue
        found_any = True
        evidence = f"{path} → HTTP {res.status}"
        if kind == "publish-lockfile":
            evidence += " · dependency versions exposed"
        c.add(
            Finding(
                id=id_map.get(kind, "deep.exposed_file"),
                title=f"Publicly readable {label}",
                severity=severity,
                category="Exposed files",
                why="Build and ops files were not meant for visitors. They reveal exact dependency "
                "versions, routes, infrastructure names and sometimes credentials.",
                fix="Block dotfiles and build files at the CDN (Vercel/Netlify: headers/redirects; "
                "Cloudflare: rule to block `/*.json` on non-API paths) and redeploy clean.",
                evidence=evidence,
                effort="20 min",
                ref="https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
            )
        )
    if not found_any:
        c.check("exposed.build_files", "No build/ops files exposed", True)


# --------------------------------------------------------------------------
# GraphQL introspection
# --------------------------------------------------------------------------


def check_graphql(base_url: str, blob: str, budget: net.Budget, c: "Collector") -> None:  # noqa: F821
    if "graphql" not in (blob or "").lower():
        return
    for path in ("/graphql", "/api/graphql"):
        if budget.expired():
            return
        query = urllib.parse.quote("{__schema{queryType{name}}}")
        res = net.safe_fetch(
            net.join(base_url, path) + f"?query={query}",
            budget=budget,
            max_bytes=20_000,
            timeout=6,
            extra_headers={"Accept": "application/json"},
        )
        if res.status == 200 and "__schema" in res.text:
            c.fail(
                "graphql.introspection",
                "GraphQL introspection disabled",
                Finding(
                    id="deep.graphql_introspection",
                    title="GraphQL schema is publicly introspectable",
                    severity="medium",
                    category="API surface",
                    why="Introspection hands an attacker your full API map — every type, field and "
                    "mutation — which makes finding missing auth checks much easier.",
                    fix="Disable introspection in production (Apollo: `introspection: false`; "
                    "GraphQL Yoga: `disableIntrospection: true`).",
                    evidence=f"{path}?query=__schema → HTTP {res.status}",
                    effort="15 min",
                ),
            )
            return
    c.check("graphql.introspection", "GraphQL introspection disabled", True)


# --------------------------------------------------------------------------
# HTML analysis
# --------------------------------------------------------------------------


def _resolve(page_url: str, href: str) -> str:
    try:
        return urllib.parse.urljoin(page_url, href.strip())
    except ValueError:
        return href


def check_html(page_url: str, html_text: str, c: "Collector", info: dict) -> None:  # noqa: F821
    if not html_text:
        return
    scheme = urllib.parse.urlsplit(page_url).scheme
    page_host = urllib.parse.urlsplit(page_url).hostname or ""

    # 1. forms / password inputs
    forms = re.findall(r"""<form[^>]*action=["']([^"']+)["']""", html_text, re.I)
    insecure_forms = [
        form for form in forms if _resolve(page_url, form).startswith("http://")
    ]
    if insecure_forms and scheme == "https":
        c.fail(
            "html.secure_forms",
            "Forms submit over HTTPS",
            Finding(
                id="deep.form_over_http",
                title="A form submits to a plain-HTTP URL",
                severity="critical",
                category="Transport security",
                why="Whatever a user types into that form — email, password, card number — travels "
                "in clear text and can be read or changed on the network.",
                fix="Change every form action to `https://`.",
                evidence=", ".join(insecure_forms[:3]),
                effort="10 min",
            ),
        )
    else:
        c.check("html.secure_forms", "Forms submit over HTTPS", True)

    has_password = bool(re.search(r"""<input[^>]+type=["']password["']""", html_text, re.I))
    if has_password and scheme == "http":
        c.fail(
            "html.password_http",
            "Password fields are served over HTTPS",
            Finding(
                id="deep.password_over_http",
                title="Password field on a plain-HTTP page",
                severity="critical",
                category="Transport security",
                why="Credentials typed into this page are sent unencrypted.",
                fix="Serve the whole site over HTTPS and redirect HTTP to it.",
                evidence="input[type=password] on an http:// page",
                effort="30 min",
            ),
        )

    # 2. external scripts without integrity
    external = re.findall(r"""<script[^>]+src=["'](https?://[^"']+)["'][^>]*>""", html_text, re.I)
    no_sri = [src for src in external if "integrity=" not in src.lower() and "cdn" in src.lower()]
    if no_sri:
        c.add(
            Finding(
                id="deep.missing_sri",
                title="Third-party scripts load without integrity checks",
                severity="low",
                category="Supply chain",
                why="If the CDN is compromised or serves different code, your page runs it without "
                "any check.",
                fix="Add `integrity` + `crossorigin` attributes to CDN script tags (or self-host).",
                evidence=f"{len(no_sri)} script(s), e.g. {no_sri[0][:90]}",
                effort="20 min",
                confidence="medium",
            )
        )

    # 3. target=_blank without noopener
    blanks = re.findall(r"""<a[^>]+target=["']_blank["'][^>]*>""", html_text, re.I)
    unsafe_blank = [tag for tag in blanks if "noopener" not in tag.lower() and "noreferrer" not in tag.lower()]
    if unsafe_blank:
        c.add(
            Finding(
                id="deep.target_blank",
                title="Links open with window.opener access",
                severity="low",
                category="Client security",
                why="The opened page can redirect your tab (reverse tabnabbing).",
                fix="Add `rel=\"noopener noreferrer\"` to every `target=\"_blank\"` link.",
                evidence=f"{len(unsafe_blank)} link(s) without rel=noopener",
                effort="10 min",
                confidence="medium",
            )
        )

    # 4. trackers before consent
    lower_html = html_text.lower()
    trackers = sorted({domain for domain in TRACKER_DOMAINS if domain in lower_html})
    has_consent = any(marker in lower_html for marker in CONSENT_MARKERS)
    if trackers and not has_consent:
        c.fail(
            "html.consent",
            "Analytics loads after consent",
            Finding(
                id="deep.trackers_no_consent",
                title="Tracking scripts load without a consent gate",
                severity="medium",
                category="Compliance",
                why="Under GDPR/UK GDPR (and India's DPDP for personal data) analytics and ad pixels "
                "should not fire before consent. This is one of the most common regulator findings.",
                fix="Add a consent banner (Cookiebot/OneTrust/your own) and load analytics only after "
                "the visitor agrees.",
                evidence="trackers: " + ", ".join(trackers[:5]),
                effort="1–2 h",
                confidence="medium",
            ),
        )
    elif trackers:
        c.check("html.consent", "Analytics loads after consent", True, "consent UI detected")

    # 5. secrets / TODOs in HTML comments
    comments = re.findall(r"<!--(.*?)-->", html_text, re.S)
    secretish = []
    todoish = 0
    for comment in comments[:80]:
        low = comment.lower()
        if re.search(r"(api[_-]?key|secret|password|token)\s*[:=]", low) and len(comment.strip()) > 8:
            secretish.append(comment.strip()[:120])
        elif "todo" in low or "fixme" in low:
            todoish += 1
    if secretish:
        c.fail(
            "html.comments",
            "No secrets in HTML comments",
            Finding(
                id="deep.secret_in_html_comment",
                title="Possible secret left in an HTML comment",
                severity="high",
                category="Secrets & keys",
                why="HTML comments are shipped to every visitor and survive in caches and archives.",
                fix="Remove the comment from the template, then rotate anything it contained.",
                evidence=secretish[0][:140],
                effort="10 min",
            ),
        )
    else:
        c.check("html.comments", "No secrets in HTML comments", True, f"{todoish} TODO comment(s)")

    # 6. iframes without sandbox
    iframes = re.findall(r"<iframe[^>]*>", html_text, re.I)
    unsafe_iframes = [tag for tag in iframes if "sandbox" not in tag.lower()]
    if unsafe_iframes:
        c.add(
            Finding(
                id="deep.iframe_sandbox",
                title="Embedded frames are not sandboxed",
                severity="low",
                category="Client security",
                why="An embedded third-party page can run scripts with more access than it needs.",
                fix="Add a `sandbox` attribute with only the permissions the embed needs.",
                evidence=f"{len(unsafe_iframes)} iframe(s) without sandbox",
                effort="15 min",
                confidence="medium",
            )
        )

    # 7. accessibility basics (quality, not security)
    a11y: list[str] = []
    if not re.search(r"<html[^>]+lang=", html_text, re.I):
        a11y.append("missing <html lang>")
    images = re.findall(r"<img[^>]*>", html_text, re.I)
    missing_alt = [tag for tag in images if "alt=" not in tag.lower()]
    if missing_alt:
        a11y.append(f"{len(missing_alt)} image(s) without alt text")
    if a11y:
        c.add(
            Finding(
                id="deep.accessibility_basics",
                title="Accessibility basics need attention",
                severity="low",
                category="Quality",
                why="Screen readers and search engines both rely on this markup. It also matters for "
                "public-sector and enterprise buyers.",
                fix="Add `lang` to <html>, alt text to meaningful images (alt=\"\" for decorative ones), "
                "and labels to inputs.",
                evidence="; ".join(a11y),
                effort="30 min",
                confidence="medium",
            )
        )
    else:
        c.check("html.accessibility", "Accessibility basics", True)

    # 8. third-party inventory + meta
    hosts = set()
    for src in re.findall(r"""(?:src|href)=["'](https?://[^/"']+)""", html_text[:600_000], re.I):
        host = urllib.parse.urlsplit(src).hostname or ""
        if host and host != page_host:
            hosts.add(host)
    info["third_party_hosts"] = sorted(hosts)[:12]
    info["third_party_count"] = len(hosts)

    title_match = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.I | re.S)
    if not title_match or not title_match.group(1).strip():
        c.add(
            Finding(
                id="deep.missing_title",
                title="Page has no <title>",
                severity="info",
                category="Quality",
                why="A missing title looks broken in tabs, search results and link previews.",
                fix="Add a unique 50–60 character title.",
                evidence="<title> missing or empty",
                effort="5 min",
            )
        )


# --------------------------------------------------------------------------
# SEO / GEO basics
# --------------------------------------------------------------------------


def check_seo(page_url: str, html_text: str, budget: net.Budget, c: "Collector", info: dict) -> None:  # noqa: F821
    if not html_text:
        return
    low = html_text.lower()

    has_desc = bool(re.search(r'<meta[^>]+name=["\']description["\'][^>]*content=["\'][^"\']{20,}', html_text, re.I))
    has_canonical = 'rel="canonical"' in low or "rel='canonical'" in low
    has_og = 'property="og:title"' in low
    has_jsonld = "application/ld+json" in low

    if has_desc:
        c.check("seo.description", "Meta description", True)
    else:
        c.add(Finding(id="deep.no_meta_description", title="No meta description", severity="low",
                      category="SEO & GEO",
                      why="Search results and link previews show a blank or auto-generated snippet, which lowers click-through.",
                      fix="Add a 140-160 character description that says what the app does and who it is for.",
                      evidence="<meta name=\"description\"> missing", effort="10 min"))
    if has_canonical:
        c.check("seo.canonical", "Canonical URL", True)
    else:
        c.add(Finding(id="deep.no_canonical", title="No canonical URL", severity="low",
                      category="SEO & GEO",
                      why="With query strings and preview URLs, search engines can index duplicates and split your ranking.",
                      fix="Add <link rel=\"canonical\" href=\"https://yourdomain.com/\"> on every page.",
                      evidence="rel=canonical missing", effort="10 min"))
    if has_og:
        c.check("seo.open_graph", "Open Graph tags", True)
    else:
        c.add(Finding(id="deep.no_open_graph", title="No Open Graph tags", severity="low",
                      category="SEO & GEO",
                      why="Shared links on X, WhatsApp and LinkedIn show no title, description or image — they look broken.",
                      fix="Add og:title, og:description, og:image and og:url.",
                      evidence="og:title missing", effort="15 min"))
    if has_jsonld:
        c.check("seo.structured_data", "Structured data", True)
    else:
        c.add(Finding(id="deep.no_structured_data", title="No structured data", severity="info",
                      category="SEO & GEO",
                      why="Schema.org markup helps search engines and AI answer engines understand what the page offers.",
                      fix="Add JSON-LD (Organization + SoftwareApplication, or FAQPage for a landing page).",
                      evidence="application/ld+json missing", effort="30 min", confidence="medium"))

    # GEO: machine-readable summary for AI crawlers
    if budget.left() > 4:
        llms = net.safe_fetch(net.join(net.origin(page_url), "/llms.txt"), budget=budget, max_bytes=20_000, timeout=5)
        if llms.status == 200 and llms.body:
            c.check("seo.llms_txt", "llms.txt for AI crawlers", True)
            info["llms_txt"] = True
        else:
            c.add(Finding(id="deep.no_llms_txt", title="No llms.txt", severity="info",
                          category="SEO & GEO",
                          why="AI assistants increasingly read llms.txt to summarise a site correctly. Without it they guess.",
                          fix="Publish /llms.txt with what the product does, key pages and contact details.",
                          evidence="/llms.txt returned " + str(llms.status or "no response"), effort="20 min", confidence="medium"))


# --------------------------------------------------------------------------
# JavaScript analysis
# --------------------------------------------------------------------------

API_PATH_RE = re.compile(r"""[`"'](/api/[A-Za-z0-9/_{}.-]{2,80})[`"']""")
ABS_API_RE = re.compile(r"""https?://[A-Za-z0-9.-]+/(?:api|v1|v2)/[A-Za-z0-9/_{}.-]{2,80}""")


def check_js(page_url: str, blob: str, budget: net.Budget, c: "Collector", info: dict) -> None:  # noqa: F821
    if not blob:
        return
    low = blob.lower()

    # 1. token storage
    if re.search(r"""localStorage\.setItem\(\s*["'](?:token|jwt|auth|session|access_token|id_token)""", blob, re.I):
        c.fail(
            "js.token_storage",
            "Auth tokens are not kept in localStorage",
            Finding(
                id="deep.token_in_localstorage",
                title="Auth token stored in localStorage",
                severity="medium",
                category="Access control",
                why="Any script on the page — including one injected through a dependency or an XSS "
                "bug — can read localStorage and steal the session.",
                fix="Prefer httpOnly, Secure, SameSite cookies for session tokens. If you must use "
                "localStorage, keep access tokens short-lived and add a strict CSP.",
                evidence="localStorage.setItem(...token...) in the bundle",
                effort="1–2 h",
            ),
        )
    else:
        c.check("js.token_storage", "Auth tokens are not kept in localStorage", True)

    # 2. DOM XSS surface
    sinks = [name for name in ("innerHTML", "insertAdjacentHTML", "dangerouslySetInnerHTML", "document.write") if name in blob]
    if sinks:
        c.add(
            Finding(
                id="deep.dom_xss_sink",
                title="Raw HTML sinks used in the browser",
                severity="low",
                category="Client security",
                why="Writing strings into HTML can turn user or model-provided text into executable "
                "script (DOM XSS).",
                fix="Render text instead of HTML, or sanitise with DOMPurify before every sink.",
                evidence=", ".join(sinks[:4]),
                effort="1 h",
                confidence="medium",
            )
        )

    # 3. eval in shipped code
    if re.search(r"(?<![\w.])eval\s*\(", blob) or re.search(r"new\s+Function\s*\(", blob):
        c.add(
            Finding(
                id="deep.eval_in_bundle",
                title="Dynamic code execution in the bundle",
                severity="medium",
                category="Client security",
                why="`eval` / `new Function` execute whatever string they receive and defeat CSP.",
                fix="Replace with an explicit mapping or JSON.parse.",
                evidence="eval()/new Function() found in shipped JavaScript",
                effort="45 min",
                confidence="medium",
            )
        )

    # 4. postMessage listener without origin check
    if re.search(r"""addEventListener\(\s*["']message["']""", blob) and "origin" not in low:
        c.add(
            Finding(
                id="deep.postmessage_no_origin",
                title="postMessage listener does not check the sender",
                severity="medium",
                category="Client security",
                why="Any page that can frame or open yours can post messages to it. Without an origin "
                "check the handler may act on attacker-controlled data.",
                fix="Compare `event.origin` against an allow-list before using `event.data`.",
                evidence="message listener without event.origin in the bundle",
                effort="30 min",
                confidence="medium",
            )
        )

    # 5. Stripe test key in production
    if re.search(r"\bpk_test_[0-9A-Za-z]{10,}", blob):
        c.add(
            Finding(
                id="deep.stripe_test_key",
                title="Stripe test key in a production bundle",
                severity="low",
                category="Payments",
                why="A test publishable key in production usually means checkout is running in test "
                "mode: no real payments, or a half-finished migration.",
                fix="Switch to the live publishable key and test checkout end to end.",
                evidence="pk_test_… found in the bundle",
                effort="20 min",
            )
        )

    # 6. API surface inventory
    endpoints = sorted(set(ABS_API_RE.findall(blob)) | set(API_PATH_RE.findall(blob)))
    if endpoints:
        info["api_endpoints"] = [e[:100] for e in endpoints[:12]]
        info["api_endpoint_count"] = len(endpoints)

    # 7. Firebase: config + open rules
    project = re.search(r"""["']projectId["']\s*:\s*["']([a-z0-9-]{4,40})["']""", blob)
    if project and "firebase" in low:
        project_id = project.group(1)
        info["firebase_project"] = project_id
        open_db = ""
        for candidate in (
            f"https://{project_id}-default-rtdb.firebaseio.com/.json?shallow=true",
            f"https://{project_id}.firebaseio.com/.json?shallow=true",
        ):
            if budget.expired():
                break
            res = net.safe_fetch(candidate, budget=budget, max_bytes=20_000, timeout=6)
            body = res.text.strip()
            if res.status == 200 and body not in ("null", "{}", ""):
                open_db = candidate
                break
        firestore_url = (
            f"https://firestore.googleapis.com/v1/projects/{project_id}"
            "/databases/(default)/documents?pageSize=1&mask.fieldPaths=__name__"
        )
        firestore_open = False
        if budget.left() > 4:
            res = net.safe_fetch(firestore_url, budget=budget, max_bytes=40_000, timeout=6)
            firestore_open = res.status == 200 and '"documents"' in res.text

        if open_db or firestore_open:
            c.fail(
                "firebase.rules",
                "Firebase rules are not in test mode",
                Finding(
                    id="deep.firebase_open_rules",
                    title="Firebase database is readable without login",
                    severity="critical",
                    category="Database access",
                    why="Firebase was left in test mode. Anyone with the project id (it is public) can "
                    "read your data directly — no login, no app.",
                    fix="Deploy real rules now: `allow read, write: if request.auth != null && "
                    "request.auth.uid == resource.data.user_id;` (adapt per collection).",
                    evidence=(open_db or "firestore.googleapis.com returned documents"),
                    effort="1 h",
                ),
            )
        else:
            c.check("firebase.rules", "Firebase rules are not in test mode", True, project_id)
