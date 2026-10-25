"""Free PageSpeed Insights tool (Google API, no key, graceful on errors)."""
from __future__ import annotations

import json
import ssl
import urllib.parse
import urllib.request

from . import config


def fetch(target: str) -> dict:
    url = ("https://www.googleapis.com/pagespeedonline/v5/runPagespeed?"
           "strategy=mobile&category=performance&url=" + urllib.parse.quote(target, safe=""))
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Trustfield/1.0"})
        with urllib.request.urlopen(request, timeout=45, context=ssl.create_default_context()) as response:
            return json.loads(response.read() or b"{}")
    except Exception as exc:
        return {"error": str(exc)[:160]}


def _fmt(value) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "-"
    return f"{number/1000:.2f} s" if number >= 1000 else f"{number:.2f}"


def page_html(data: dict | None, target: str = "", error: str = "") -> str:
    from .report import esc

    result = ""
    if data and not data.get("error") and data.get("lighthouseResult"):
        lr = data["lighthouseResult"]
        score = int(round((lr.get("categories", {}).get("performance", {}).get("score") or 0) * 100))
        audits = lr.get("audits", {})
        rows = "".join(
            f"<tr><td>{esc(label)}</td><td><strong>{esc(_fmt((audits.get(key) or {}).get('numericValue')))}</strong></td></tr>"
            for label, key in (("LCP (loads)", "largest-contentful-paint"), ("CLS (layout shift)", "cumulative-layout-shift"),
                               ("INP (interaction)", "interaction-to-next-paint"), ("FCP (first paint)", "first-contentful-paint"))
        )
        tone = "#0f766e" if score >= 90 else ("#b45309" if score >= 50 else "#b91c1c")
        result = f"""<div class="note"><strong>Performance: {score}/100</strong> (mobile)</div>
<table><tr><th>Metric</th><th>Value</th></tr>{rows}</table>
<p class="fine">Source: Google PageSpeed Insights. Performance is not a security rating.</p>"""
    elif error or (data and data.get("error")):
        result = f'<div class="note" style="background:#fef2f2;border-color:#fecaca;color:#991b1b">Could not measure: {esc(error or (data or {{}}).get("error", ""))}</div>'
    form = f"""<form method="get" action="/tools/speed" style="display:flex;gap:8px;flex-wrap:wrap;margin:18px 0">
<input name="url" value="{esc(target)}" placeholder="https://your-app.com" style="flex:1;min-width:260px;height:48px;border:1px solid #d7dce3;border-radius:12px;padding:0 14px;font:inherit">
<button class="btn primary" type="submit" style="height:48px">Check speed</button></form>"""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PageSpeed checker · {esc(config.BRAND)}</title><meta name="description" content="Free mobile PageSpeed Insights check for your web app — LCP, CLS, INP and performance score.">
<link rel="canonical" href="{esc(config.BASE_URL)}/tools/speed">
<link rel="stylesheet" href="/static/style.css"><link rel="stylesheet" href="/static/landing.css">
<script src="https://analytics.ahrefs.com/analytics.js" data-key="gLBPCAyOg9uZUDtLmDAQ3Q" async></script></head>
<body class="landing-v2 legal-page"><header class="site-head"><div class="wrap head-in"><a class="logo" href="/"><span>{esc(config.BRAND)}</span></a><a class="btn small" href="/#scan">Free security scan</a></div></header>
<main class="legal-doc wrap"><h1>PageSpeed checker</h1>
<p>Google PageSpeed Insights se mobile performance — LCP, CLS, INP. Free, no signup.</p>{form}{result}
<p class="fine">Security is a different question: <a href="/#scan">run the free security scan</a>.</p></main></body></html>"""
