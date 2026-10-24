"""Free tools (no login): security headers grader."""
from __future__ import annotations

from . import net

CHECKS = [
    ("strict-transport-security", "HSTS", "Strict-Transport-Security", 25,
     "Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("content-security-policy", "Content-Security-Policy", "Content-Security-Policy", 25,
     "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none'"),
    ("x-frame-options", "Clickjacking protection", "X-Frame-Options", 10,
     "X-Frame-Options: DENY"),
    ("x-content-type-options", "MIME sniffing", "X-Content-Type-Options", 5,
     "X-Content-Type-Options: nosniff"),
    ("referrer-policy", "Referrer policy", "Referrer-Policy", 5,
     "Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy", "Permissions policy", "Permissions-Policy", 5,
     "Permissions-Policy: camera=(), microphone=(), geolocation=()"),
]


def _header(headers: dict, name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return str(value)
    return ""


def grade(headers: dict, https: bool = True) -> dict:
    score = 100
    checks = []
    for key, label, header_name, weight, fix in CHECKS:
        value = _header(headers, header_name)
        ok = bool(value)
        if not ok:
            score -= weight
        checks.append({"key": key, "label": label, "ok": ok, "value": value, "fix": fix})
    if not https:
        score -= 20
    server = _header(headers, "Server")
    if server:
        score -= 5
    score = max(0, min(100, score))
    letter = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return {"score": score, "grade": letter, "checks": checks, "server": server, "https": https}


def headers_report(url: str) -> dict:
    target = (url or "").strip()
    if not target:
        return {"ok": False, "error": "Paste a URL first."}
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    budget = net.Budget(12)
    try:
        res = net.safe_fetch(target, budget=budget, max_bytes=150_000, timeout=8)
    except Exception:
        return {"ok": False, "error": "Could not open that URL. Check it is public and reachable."}
    if getattr(res, "status", 0) == 0 or not getattr(res, "headers", None):
        return {"ok": False, "error": "Could not read the response headers from that URL."}
    https = str(getattr(res, "final_url", target)).startswith("https://") or target.startswith("https://")
    report = grade(dict(res.headers), https=https)
    report.update({"ok": True, "url": getattr(res, "final_url", target), "status": res.status})
    return report


def result_html(report: dict) -> str:
    if not report.get("ok"):
        return f'<div class="note" style="background:#fef2f2;border-color:#fecaca;color:#991b1b">{report.get("error", "Could not check that URL.")}</div>'
    rows = ""
    for check in report["checks"]:
        value = check["value"] or "— missing —"
        color = "#0f766e" if check["ok"] else "#b91c1c"
        fix = "" if check["ok"] else f'<br><code style="font-size:12px">{check["fix"]}</code>'
        rows += (
            f"<tr><td>{check['label']}</td>"
            f"<td style='color:{color};font-weight:600'>{'present' if check['ok'] else 'missing'}</td>"
            f"<td style='word-break:break-word'><code>{value}</code>{fix}</td></tr>"
        )
    return f"""
    <div class="note" style="margin-bottom:16px">
      <strong>{report['url']}</strong> scored <strong>{report['score']}/100 ({report['grade']})</strong> on security headers.
      HTTP {report.get('status', '')} · {report.get('server') or 'server header hidden'}
    </div>
    <table>
      <tr><th>Header</th><th>Status</th><th>Value / fix</th></tr>
      {rows}
    </table>
    <p class="note">Headers are only one layer. Trustfield checks keys in your bundle, database rules, payment webhooks and AI prompt injection: <a href="/#scan">run the free scan</a>.</p>"""
