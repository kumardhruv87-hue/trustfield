"""Competitor comparison pages — capture decision-stage brand traffic honestly."""
from __future__ import annotations

import datetime

from . import config

PAGES: list[dict] = [
    {
        "slug": "scantient",
        "title": "Trustfield vs Scantient",
        "description": "Honest comparison: Trustfield (₹499 one-time, AI-builder fixes, agency handover) vs Scantient (subscription external scanner with continuous monitoring).",
        "body": """
<p><strong>Short answer:</strong> Scantient is a solid continuous external scanner for teams on a subscription. Trustfield is a one-time ₹499 review for a solo builder or agency that needs the fix today and a client-ready report. Different jobs.</p>
<h2>Side by side</h2>
<table>
<tr><th></th><th>Trustfield</th><th>Scantient</th></tr>
<tr><td>Price model</td><td><strong>₹499 one-time</strong> report; Watch ₹499/month optional</td><td>Monthly subscription (see their pricing)</td></tr>
<tr><td>Best for</td><td>Solo devs, AI-built apps, agencies handing over to clients</td><td>Teams wanting always-on monitoring across apps</td></tr>
<tr><td>AI-builder focus</td><td>Keys in bundle, open Supabase/Firebase rules, unverified webhooks, 12-attack prompt-injection kit, copy-paste fix prompt</td><td>External checks (20 per scan) incl. keys, headers, auth, deps, SSL</td></tr>
<tr><td>Report</td><td>Plain-English evidence + exact fix + prompt + PDF; "Prepared for client" handover</td><td>Security report + compliance-aligned templates, dashboard</td></tr>
<tr><td>Verification</td><td>Re-scan "X fixed / Y new" + dated proof page/badge</td><td>Continuous scans and alerts over time</td></tr>
<tr><td>Integrations</td><td>GitHub Action, API + completion webhook, Slack/Discord alerts (webhook)</td><td>Jira, GitHub, Teams, PagerDuty, Okta, Vercel, Netlify, Datadog, Linear, MCP</td></tr>
<tr><td>Honesty</td><td>No certification claimed; refund on a wrong finding; methodology + changelog public</td><td>SOC 2 Type II / GDPR claims on their site</td></tr>
<tr><td>India / pricing</td><td>INR, UPI, Hinglish support, ₹499 vs subscription fatigue</td><td>Global pricing (usually USD)</td></tr>
</table>
<h2>When to pick Scantient instead</h2>
<p>You need continuous monitoring across many apps, Jira/Okta/PagerDuty integration, compliance templates, or an enterprise vendor with a SOC 2 report. That is their product, and it is legitimate.</p>
<h2>When Trustfield wins</h2>
<p>You shipped an AI-built app, need to know what is exposed before launch, want the exact fix and an AI prompt, and want to hand a client a dated report without a monthly contract. Start with the <a href="/#scan">free scan</a> — the report is ₹499 only if the free results worry you.</p>
""",
    },
    {
        "slug": "vibesafe",
        "title": "Trustfield vs VibeSafe",
        "description": "Trustfield vs VibeSafe: one-time ₹499 AI-app security report with fix prompts and agency handover, compared with VibeSafe's freemium subscription.",
        "body": """
<p><strong>Short answer:</strong> VibeSafe targets the same vibe-coded apps with a freemium subscription and plain-English findings. Trustfield's difference is a ₹499 one-time decision, deeper AI-builder fixes, a client-ready handover, and a verification re-scan.</p>
<h2>Side by side</h2>
<table>
<tr><th></th><th>Trustfield</th><th>VibeSafe</th></tr>
<tr><td>Price</td><td><strong>₹499 one-time</strong>; Watch ₹499/month optional, cancel anytime</td><td>Freemium with a paid subscription (about $29/month at the time of writing — check their site)</td></tr>
<tr><td>AI-builder checks</td><td>Keys in bundle, DB rules, webhooks, prompt injection, deps (repo), legal/SEO trust pages</td><td>Exposed keys, security flaws, runtime errors, plain-English fixes</td></tr>
<tr><td>Output</td><td>Score, evidence, fix, copy-paste prompt, PDF, client handover label, dated proof page</td><td>Findings with plain-English fixes</td></tr>
<tr><td>Verification loop</td><td>Re-scan "X fixed / Y new", Watch, badge</td><td>Re-scan after fixes</td></tr>
<tr><td>Agency use</td><td>10-report agency pack, "Prepared for client" label</td><td>Not a core feature</td></tr>
<tr><td>Payment / region</td><td>INR, UPI, India-first + global</td><td>USD-first</td></tr>
</table>
<h2>Fair verdict</h2>
<p>If you want a low monthly subscription and a friendly dashboard, VibeSafe is a reasonable choice. If you want one honest report for the price of two coffees, the exact fix for your AI builder, and something you can show a client, use <a href="/#scan">Trustfield's free scan</a> first.</p>
""",
    },
    {
        "slug": "aikido",
        "title": "Trustfield vs Aikido Security",
        "description": "Trustfield vs Aikido: a narrow ₹499 AI-built-app trust review vs a broad code/cloud/runtime security platform. Which one a solo builder actually needs.",
        "body": """
<p><strong>Short answer:</strong> Aikido is a broad AppSec platform (code, cloud, runtime, many integrations). Trustfield is a narrow, cheap, AI-builder-focused external review with a client-ready report. They are not substitutes — Aikido is for teams with a security workflow; Trustfield is for "I need to launch this week".</p>
<h2>Why breadth is not automatically better</h2>
<p>A platform gives you a dashboard of many findings, but a solo builder needs the three that matter before launch, in plain English, with the fix. Buying a platform for one app usually means paying for features you never configure.</p>
<h2>Side by side</h2>
<table>
<tr><th></th><th>Trustfield</th><th>Aikido</th></tr>
<tr><td>Scope</td><td>External review of a public app + optional public repo</td><td>Code, dependencies, cloud, runtime, containers</td></tr>
<tr><td>Price</td><td><strong>₹499 one-time</strong>; Watch ₹499/month optional</td><td>Subscription tiers, free tier available</td></tr>
<tr><td>Setup</td><td>Paste a URL, no signup needed to start</td><td>Connect repos/cloud accounts, configuration</td></tr>
<tr><td>Fit</td><td>Solo/AI-built app, agency client handover</td><td>Teams with CI/CD and a security owner</td></tr>
</table>
<p>Use Aikido when you have a team and a pipeline. Use <a href="/#scan">Trustfield's free scan</a> when you have a launch date and no security team.</p>
""",
    },
]


def _page(title: str, description: str, body: str, slug: str) -> str:
    canonical = f"{config.BASE_URL}/vs" if slug == "vs" else f"{config.BASE_URL}/vs/{slug}"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · {config.BRAND}</title>
<meta name="description" content="{description}">
<link rel="canonical" href="{canonical}">
<meta property="og:title" content="{title} · {config.BRAND}">
<meta property="og:description" content="{description}">
<meta property="og:image" content="{config.BASE_URL}/static/og.png">
<meta name="twitter:card" content="summary_large_image">
<link rel="stylesheet" href="/static/style.css"><link rel="stylesheet" href="/static/landing.css">
<script type="application/ld+json">{{"@context":"https://schema.org","@type":"WebPage","name":"{title}","description":"{description}","dateModified":"{datetime.date.today().isoformat()}","url":"{canonical}"}}</script>
<script src="https://analytics.ahrefs.com/analytics.js" data-key="gLBPCAyOg9uZUDtLmDAQ3Q" async></script>
</head><body class="landing-v2 legal-page">
<header class="site-head"><div class="wrap head-in"><a class="logo" href="/"><svg viewBox="0 0 32 32" width="24" height="24" aria-hidden="true"><path d="M16 2 28 7v9c0 7-5 12-12 14C9 28 4 23 4 16V7z" fill="currentColor"/><path d="M11 16l4 4 7-8" stroke="#fff" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg><span>{config.BRAND}</span></a><a class="btn small" href="/compare">Compare all options</a></div></header>
<main class="legal-doc wrap"><h1>{title}</h1><p class="updated">Updated {datetime.date.today().isoformat()} · written by the operator, not a sales team</p>{body}
<p class="fine">Prices and features can change on both sides; verify current details on the vendor's own site. Trustfield is not a penetration test and not a certification. <a href="/methodology">Methodology</a> · <a href="/trust">Trust center</a></p></main>
<footer class="site-foot"><div class="wrap"><div class="foot-legal"><span>© {datetime.date.today().year} {config.BRAND} · Independent security review for AI-built apps</span><span><a href="/#scan">Free scan</a> · <a href="/privacy">Privacy</a> · <a href="mailto:{config.CONTACT_EMAIL}">{config.CONTACT_EMAIL}</a></span></div></div></footer>
</body></html>"""


def vs_page(slug: str) -> str | None:
    if slug == "vs":
        cards = "".join(
            f'<div class="check-card" style="margin-bottom:16px"><h3><a href="/vs/{p["slug"]}">{p["title"]}</a></h3><p>{p["description"]}</p></div>'
            for p in PAGES
        )
        return _page("Comparisons", "Honest comparisons: Trustfield vs Scantient, VibeSafe and Aikido Security.", f"<p>Decision-stage comparisons, written honestly.</p>{cards}", "vs")
    page = next((p for p in PAGES if p["slug"] == slug), None)
    if page is None:
        return None
    return _page(page["title"], page["description"], page["body"], slug)
