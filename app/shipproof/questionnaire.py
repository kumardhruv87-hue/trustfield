"""Trust center + security questionnaire pack (HTML page and PDF).

Written so an enterprise buyer, a lawyer or a platform reviewer can read the
answers without a sales call. No certifications are claimed that we do not have.
"""
from __future__ import annotations

import datetime

from . import config
from . import pdf as pdfmod

QUESTIONS: list[tuple[str, str]] = [
    ("What does Trustfield do?",
     "It performs an external, read-only security review of a public web app and produces a report: "
     "leaked keys in the client bundle, open database rules, unverified payment webhooks, missing headers, "
     "exposed files, dependency CVEs (repo scans) and AI prompt-injection exposure. It is not a penetration "
     "test and not a security certification."),
    ("Do you access our database, source code or user data?",
     "No. Scans read public pages and headers only. A GitHub scan requires you to attach a public repo; "
     "we download a read-only archive, analyse it, and do not keep the source. We never ask for database "
     "credentials or model API keys."),
    ("Where is data stored and for how long?",
     "Reports are stored in Supabase (United States) for 30 days after the scan, then deleted. Email addresses "
     "are kept until you ask us to delete them. Anonymous aggregate statistics (no target, no email) may be kept "
     "to publish issue trends. Rate-limit data is kept for a few hours."),
    ("Who are your subprocessors?",
     "Render (hosting, US), Supabase (report storage, US), Cloudflare (DNS/TLS/proxy, global edge), Razorpay "
     "(payments, India), Resend (transactional email, US), Hostinger (domain and mailbox, EU), and Ahrefs "
     "(cookieless aggregate analytics). Full table: /subprocessors. A DPA is available on request."),
    ("How is payment data handled?",
     "Payments run through Razorpay's hosted checkout. Card details are entered on Razorpay's page and never "
     "touch Trustfield servers. Webhooks are verified with HMAC-SHA256 signatures, and the expected amount, "
     "currency and report id are checked before a report is unlocked."),
    ("Do you use AI, and is our data used for training?",
     "The report copilot (Ask about this report) sends the report text and your question to DeepSeek's API "
     "to generate an answer. We do not train models on customer data and we do not send your source code or "
     "database. The copilot is optional for buyers."),
    ("What security controls are in place?",
     "TLS everywhere with HSTS (max-age 31536000, includeSubDomains); CSP that only allows our own scripts and "
     "the analytics origin; X-Frame-Options DENY; nosniff; Referrer-Policy; Permissions-Policy; no advertising "
     "cookies; admin access behind a long random token; rate limits per IP; SSRF protection blocks private IPs "
     "and re-checks redirects. We do not claim SOC 2, ISO 27001 or a third-party audit."),
    ("Can you sign an NDA or DPA?",
     "Yes to an NDA by email. A data-processing addendum is available on request for business customers; write to "
     "the contact address and we will send the current template for review. We are a sole proprietorship in India; "
     "we will not pretend to be a larger entity."),
    ("How do we delete our data?",
     "Use /delete-account or email us with the report link. We delete the report, the stored email and related "
     "records within 7 days and confirm by email. Reports also auto-delete 30 days after the scan."),
    ("What happens after a payment if the report does not arrive?",
     "Email us with the payment id. We re-run the scan or refund the full amount within 7 days. If a finding is "
     "factually wrong, we fix the check, add a regression test, and refund that report. Policy: /refund."),
    ("Do you have a vulnerability disclosure programme?",
     "Yes. Email the contact address with 'security report' in the subject and steps to reproduce. We acknowledge "
     "within 2 business days and will not pursue legal action for good-faith testing limited to your own account "
     "and data. Details: /security."),
    ("What is your uptime and SLA?",
     "There is no SLA. The service runs on a small stack and is best-effort; the public /status page lists known "
     "incidents honestly. The free tier can cold-start in under a minute; paid reports are stored so they remain "
     "available after restarts."),
    ("Is scanning a third party allowed?",
     "No. The requester must confirm they own the app or have explicit permission. We rate-limit scans, never run "
     "exploitation, and block private-network targets. Our scanner identifies itself and offers an opt-out page at "
     "/bot."),
    ("Which compliance frameworks do you follow?",
     "We apply data-minimisation and deletion principles consistent with India's DPDP Act and GDPR, but we are not "
     "certified under either and we do not claim 'compliance'. Enterprise questionnaires that require a certificate "
     "should be answered by your own auditor."),
    ("Can we get the report for a client handover?",
     "Yes. The agency pack gives ten client-ready reports; each report can carry 'Prepared for <client> · handover "
     "by <agency>'. See /agency. Same scope and limits as the standard report."),
    ("How do we contact you?",
     "Email the address on every page. A real person answers, usually within one business day. The operator is "
     "Dhruv Kumar, Faridabad, India (sole proprietorship), named in /about and /terms."),
]


def _answer_slug(question: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in question).strip("-")[:60]


def html_page() -> str:
    from .report import esc

    rows = "".join(
        f'<details id="{esc(_answer_slug(q))}" style="border-bottom:1px solid #e5e7eb;padding:14px 0">'
        f'<summary style="cursor:pointer;font-weight:600;font-size:16px">{esc(q)}</summary>'
        f'<p style="color:#4b5563;margin:10px 0 0">{esc(a)}</p></details>'
        for q, a in QUESTIONS
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security questionnaire answers · {esc(config.BRAND)}</title>
<meta name="description" content="Plain answers to the security questionnaire questions enterprise buyers ask Trustfield.">
<link rel="canonical" href="{esc(config.BASE_URL)}/trust/questionnaire">
<link rel="stylesheet" href="/static/style.css"><link rel="stylesheet" href="/static/landing.css">
<script src="https://analytics.ahrefs.com/analytics.js" data-key="gLBPCAyOg9uZUDtLmDAQ3Q" async></script>
</head><body class="landing-v2 legal-page">
<header class="site-head"><div class="wrap head-in"><a class="logo" href="/"><svg viewBox="0 0 32 32" width="24" height="24" aria-hidden="true"><path d="M16 2 28 7v9c0 7-5 12-12 14C9 28 4 23 4 16V7z" fill="currentColor"/><path d="M11 16l4 4 7-8" stroke="#fff" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg><span>{esc(config.BRAND)}</span></a><a class="btn small" href="/trust">Trust center</a></div></header>
<main class="legal-doc wrap">
  <h1>Security questionnaire answers</h1>
  <p class="updated">Last updated: {datetime.date.today().isoformat()} · written for buyers, not for a sales call.</p>
  <p class="note">This is the same content as the downloadable PDF. If an enterprise questionnaire needs a certificate, an audit report or a legal opinion, we do not have one — and we will say so rather than invent it.</p>
  <p><a class="btn" href="/trust/questionnaire.pdf">Download the PDF pack</a> · <a class="btn ghost" href="/trust">Trust center</a></p>
  {rows}
  <p class="fine" style="margin-top:26px">Questions not answered here? Email <a href="mailto:{esc(config.CONTACT_EMAIL)}">{esc(config.CONTACT_EMAIL)}</a> — answered by the operator, usually in one business day.</p>
</main></body></html>"""


def build_pdf() -> bytes:
    doc = pdfmod.Doc()
    page = doc.new_page()
    page.rect(0, pdfmod.A4_H - 5, pdfmod.A4_W, 5, pdfmod.TEAL)
    y = pdfmod.A4_H - 90
    page.text(pdfmod.MARGIN, y, 22, "Security overview", bold=True, color=pdfmod.DARK)
    y -= 22
    page.text(pdfmod.MARGIN, y, 22, "and questionnaire answers", bold=True, color=pdfmod.DARK)
    y -= 26
    page.text(pdfmod.MARGIN, y, 10, f"{config.BRAND} - {config.BASE_URL}", color=(0.20, 0.45, 0.42))
    y -= 16
    page.text(pdfmod.MARGIN, y, 9, f"Generated {datetime.date.today().isoformat()} - written for enterprise buyers", color=pdfmod.MUTED)
    y -= 34
    intro = ("This document answers the questions a security reviewer, lawyer or platform team usually asks. "
             "It describes mechanisms that are live today. We do not claim SOC 2, ISO 27001 or an external audit, "
             "and we will say so rather than invent a certificate.")
    for line in pdfmod._wrap(intro, 9.5, pdfmod.CONTENT_W):
        page.text(pdfmod.MARGIN, y, 9.5, line, color=pdfmod.DARK)
        y -= 14
    y -= 10
    for q, a in QUESTIONS:
        block = [("Q", q), ("A", a)]
        needed = 34 + sum(len(pdfmod._wrap(text, 9, pdfmod.CONTENT_W - 22)) * 13 for _label, text in block)
        if y - needed < 60:
            page = doc.new_page()
            page.rect(0, pdfmod.A4_H - 4, pdfmod.A4_W, 4, pdfmod.TEAL)
            y = pdfmod.A4_H - 60
        page.text(pdfmod.MARGIN, y, 10, q, bold=True, color=pdfmod.DARK)
        y -= 14
        for line in pdfmod._wrap(a, 9, pdfmod.CONTENT_W - 22):
            page.text(pdfmod.MARGIN + 10, y, 9, line, color=(0.22, 0.27, 0.35))
            y -= 13
        y -= 10
        page.line(pdfmod.MARGIN, y, pdfmod.A4_W - pdfmod.MARGIN, y, (0.88, 0.90, 0.93), 0.4)
        y -= 12
    for _page_no in range(0):
        pass
    return doc.build()
