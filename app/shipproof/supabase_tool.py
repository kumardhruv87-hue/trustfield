"""Free tool: check whether your Supabase tables are readable with the anon key.

Only the project owner should run this: they paste their own project URL and anon
key. The key is used for one request batch, never stored.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request

REF_RE = re.compile(r"^[a-z0-9]{20}$")


def _normalise(url: str) -> tuple[str, str]:
    raw = (url or "").strip().rstrip("/")
    if not raw:
        return "", "Paste your Supabase project URL."
    raw = raw if raw.startswith(("http://", "https://")) else "https://" + raw
    host = raw.split("//", 1)[1].split("/", 1)[0].lower()
    ref = ""
    if host.endswith(".supabase.co"):
        ref = host.split(".")[0]
    elif REF_RE.match(host):
        ref = host
    if not REF_RE.match(ref or ""):
        return "", "Use your project URL like https://abcdefghijklmnopqrst.supabase.co"
    return f"https://{ref}.supabase.co", ""


def _get(url: str, key: str, timeout: float = 8.0):
    request = urllib.request.Request(
        url,
        headers={"apikey": key, "Authorization": f"Bearer {key}", "Accept": "application/json",
                 "User-Agent": "Trustfield-RLS-Checker/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
        return response.status, response.read()


def check(url: str, key: str) -> dict:
    base, error = _normalise(url)
    if error:
        return {"ok": False, "error": error}
    key = (key or "").strip()
    if len(key) < 20:
        return {"ok": False, "error": "Paste the anon (public) key from Project Settings -> API."}
    try:
        status, body = _get(base + "/rest/v1/", key)
        spec = json.loads(body or b"{}")
        paths = list((spec.get("paths") or {}).keys())
        tables = sorted({p.strip("/").split("/")[0] for p in paths if p.strip("/") and not p.startswith("/rpc")})
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"Supabase answered HTTP {exc.code}. Check the URL and anon key."}
    except Exception:
        return {"ok": False, "error": "Could not reach that Supabase project."}
    rows = []
    for table in tables[:10]:
        state = "unknown"
        try:
            status, body = _get(f"{base}/rest/v1/{table}?select=*&limit=1", key)
            data = json.loads(body or b"[]")
            if status == 200 and isinstance(data, list):
                state = "readable-with-rows" if data else "readable-empty"
        except urllib.error.HTTPError as exc:
            state = "blocked" if exc.code in (401, 403) else f"http-{exc.code}"
        except Exception:
            state = "unclear"
        rows.append({"table": table, "state": state})
    open_tables = [r for r in rows if r["state"] == "readable-with-rows"]
    empty_open = [r for r in rows if r["state"] == "readable-empty"]
    verdict = "danger" if open_tables else "review" if empty_open else "good"
    return {"ok": True, "base": base, "tables": rows, "open": open_tables,
            "empty_open": empty_open, "verdict": verdict}


def result_html(report: dict) -> str:
    if not report.get("ok"):
        return f'<div class="note" style="background:#fef2f2;border-color:#fecaca;color:#991b1b">{report.get("error")}</div>'
    rows = ""
    for row in report["tables"]:
        state = row["state"]
        label = {"readable-with-rows": "READABLE — rows visible", "readable-empty": "readable (no rows)",
                 "blocked": "blocked by RLS", }.get(state, state)
        color = "#b91c1c" if state == "readable-with-rows" else "#92400e" if state == "readable-empty" else "#0f766e"
        rows += f"<tr><td><code>{row['table']}</code></td><td style='color:{color};font-weight:600'>{label}</td></tr>"
    verdict = {
        "danger": "At least one table returned rows with your public anon key. If that data is not meant to be public, enable RLS and add policies now.",
        "review": "Tables responded but returned no rows. That may be fine (empty tables) — verify RLS is on for the ones that will hold customer data.",
        "good": "No table returned rows with the public key. Keep RLS enabled on every new table.",
    }[report["verdict"]]
    return f"""
    <div class="note" style="margin-bottom:16px"><strong>{report['base']}</strong><br>{verdict}</div>
    <table><tr><th>Table</th><th>Result with anon key</th></tr>{rows}</table>
    <p class="note">This tests one thing: whether the public anon key can read rows. It is not a full audit. Trustfield's paid report also checks keys in your bundle, payment webhooks and AI prompt injection: <a href="/#scan">run the free scan</a>.</p>"""
