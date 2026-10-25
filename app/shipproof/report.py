"""HTML rendering. Templates live in templates/, every dynamic value is escaped."""
from __future__ import annotations

from urllib.parse import quote

import html
import re
from pathlib import Path

from . import config, sign, usage, handover
from .findings import SEVERITY_COLOR, SEVERITY_LABEL, Finding, sort_findings

BACKTICK_RE = re.compile(r"`([^`]{1,120})`")


def esc(value) -> str:  # noqa: ANN001
    return html.escape("" if value is None else str(value), quote=True)


def inline_code(text: str) -> str:
    """Escape, then turn `backticks` into <code> spans."""
    safe = esc(text)
    return BACKTICK_RE.sub(lambda m: f"<code>{m.group(1)}</code>", safe)


def _template(name: str) -> str:
    return (config.TEMPLATES_DIR / name).read_text(encoding="utf-8")


def _fill(template: str, mapping: dict) -> str:
    for key, value in mapping.items():
        template = template.replace("{{" + key + "}}", str(value))
    return template


def _as_finding(item) -> Finding:  # noqa: ANN001
    return item if isinstance(item, Finding) else Finding(**item)


# --------------------------------------------------------------------------
# fragments
# --------------------------------------------------------------------------


def severity_pill(severity: str) -> str:
    label = SEVERITY_LABEL.get(severity, severity.title())
    return f'<span class="pill sev-{esc(severity)}">{esc(label)}</span>'


def counts_grid(counts: dict) -> str:
    cells = []
    for severity in ("critical", "high", "medium", "low", "info"):
        cells.append(
            f'<div class="count sev-{severity}">'
            f'<span class="count-n">{int(counts.get(severity, 0))}</span>'
            f'<span class="count-l">{esc(SEVERITY_LABEL[severity])}</span></div>'
        )
    return '<div class="counts">' + "".join(cells) + "</div>"


def finding_card(item, open_card: bool = False, scan_id: str = "") -> str:  # noqa: ANN001
    finding = _as_finding(item)
    marker = " open" if open_card else ""
    dispute = (
        f'<p class="fine"><a href="mailto:{config.CONTACT_EMAIL}'
        f'?subject={quote("Wrong finding: " + finding.title)}'
        f'&body={quote("Report: " + config.BASE_URL + "/r/" + scan_id + chr(10) + chr(10) + "Finding: " + finding.title + chr(10) + "Why I think it is wrong: ")}">'
        f'Is this wrong? Tell us</a> — we fix the check, add a test, and refund if you paid.</p>'
    )
    return f"""
    <details class="finding sev-border-{esc(finding.severity)}"{marker}>
      <summary>
        {severity_pill(finding.severity)}
        <span class="f-title">{esc(finding.title)}</span>
        <span class="f-effort">{esc(finding.effort)}</span>
      </summary>
      <div class="f-body">
        <p class="f-why">{inline_code(finding.why)}</p>
        <p class="f-label">Evidence</p>
        <p class="f-evidence"><code>{esc(finding.evidence) or "—"}</code></p>
        <p class="f-label">Fix</p>
        <p class="f-fix">{inline_code(finding.fix)}</p>
        <p><button type="button" class="btn ghost small copy-fix-btn" data-prompt="{esc(_fix_prompt(finding))}">Copy fix prompt</button></p>
        <p class="f-meta">{esc(finding.category)} · confidence {esc(finding.confidence)}</p>
        {dispute}
      </div>
    </details>"""


def findings_html(findings: list, limit: int | None = None, scan_id: str = "") -> str:
    items = [_as_finding(f) for f in findings]
    items = sort_findings(items)
    if limit is not None:
        items = items[:limit]
    if not items:
        return '<p class="muted">Nothing to show here.</p>'
    return '<div class="findings">' + "".join(finding_card(f, scan_id=scan_id) for f in items) + "</div>"


def risk_card(risk: dict, kind: str) -> str:
    level = esc(risk.get("level", "low"))
    math = risk.get("math", "")
    math_html = f'<p class="risk-math">{esc(math)}</p>' if math else ""
    return f"""
    <div class="risk risk-{level}">
      <div class="risk-head"><span class="dot dot-{level}"></span>{esc(risk.get("title", ""))}</div>
      <p>{inline_code(risk.get("explain", ""))}</p>
      {math_html}
      <p class="risk-kind">{esc(kind)}</p>
    </div>"""


def top_actions_html(actions: list) -> str:
    if not actions:
        return ""
    rows = []
    for i, action in enumerate(actions, 1):
        rows.append(
            f'<li><span class="num">{i}</span><div>'
            f'<div class="action-title">{esc(action["title"])}</div>'
            f'<div class="action-meta">{severity_pill(action["severity"])}'
            f'<span class="effort">~{esc(action["effort"])}</span></div>'
            f"</div></li>"
        )
    return '<ol class="actions">' + "".join(rows) + "</ol>"


def checks_html(checks: list) -> str:
    if not checks:
        return '<p class="muted">No checks recorded.</p>'
    rows = []
    for check in checks:
        icon = "✓" if check.get("ok") else "✕"
        css = "ok" if check.get("ok") else "miss"
        detail = check.get("detail", "")
        detail_html = f'<span class="check-detail">{esc(detail)}</span>' if detail else ""
        rows.append(
            f'<li class="{css}"><span class="check-icon">{icon}</span>'
            f'<span class="check-name">{esc(check.get("name", ""))}</span>{detail_html}</li>'
        )
    return '<ul class="checks">' + "".join(rows) + "</ul>"


def meta_table(meta: dict) -> str:
    interesting = {
        "host": "Host",
        "status": "HTTP status",
        "platform": "Detected platform",
        "stack": "Stack",
        "files_scanned": "Files scanned",
        "bundles_scanned": "JS bundles scanned",
        "api_routes": "API routes",
        "tables": "Tables in migrations",
        "rls_enabled": "Tables with RLS",
        "supabase_project": "Supabase project",
        "supabase_key_type": "Supabase key type",
        "supabase_tables": "Tables probed with the public key",
        "supabase_readable_tables": "Tables readable without login",
        "server_side_data": "Data access is server-side",
        "client_side_ai": "AI called from browser",
        "scan_seconds": "Scan time (s)",
    }
    rows = []
    for key, label in interesting.items():
        if key not in meta or meta[key] in ("", None, [], 0, False):
            if not (key in ("client_side_ai", "server_side_data") and meta.get(key) is False):
                continue
        value = meta[key]
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        elif isinstance(value, bool):
            value = "yes" if value else "no"
        rows.append(f"<tr><th>{esc(label)}</th><td>{esc(value)}</td></tr>")
    if not rows:
        return ""
    return '<table class="meta-table">' + "".join(rows) + "</table>"


def kit_html(record: dict, unlocked: bool) -> str:
    results = {r.get("payload_id"): r for r in (record.get("kit_results") or [])}
    cards = []
    for payload in (record.get("kit_payloads") or [])[:12]:
        pid = payload["id"]
        result = results.get(pid)
        if result:
            verdict = result.get("verdict", "UNCLEAR")
            verdict_html = (
                f'<div class="verdict verdict-{esc(verdict.lower())}">'
                f'{esc(verdict)}<span>{esc(result.get("evidence", ""))}</span></div>'
            )
        else:
            verdict_html = '<div class="verdict verdict-none">Not tested</div>'
        interactive = ""
        if unlocked:
            interactive = (
                f'<div class="kit-test" data-payload="{esc(pid)}">'
                f'<textarea rows="2" placeholder="Paste the reply your app gave…"></textarea>'
                f'<button type="button" class="btn small grade-btn">Grade answer</button>'
                f"</div>"
            )
        cards.append(
            f'<div class="kit-card" data-payload="{esc(pid)}">'
            f'<div class="kit-head"><span class="kit-name">{esc(payload["name"])}</span>'
            f'{severity_pill(payload["severity_if_leaked"])}</div>'
            f'<p class="kit-goal">{esc(payload["goal"])}</p>'
            f'<pre class="kit-payload">{esc(payload["payload"])}</pre>'
            f'<button type="button" class="btn ghost small copy-btn">Copy prompt</button>'
            f'<p class="kit-expect"><strong>Safe looks like:</strong> {esc(payload["safe_example"])}</p>'
            f"{interactive}{verdict_html}</div>"
        )
    return '<div class="kit-grid">' + "".join(cards) + "</div>"


# --------------------------------------------------------------------------
# pages
# --------------------------------------------------------------------------


def index_page() -> str:
    return _fill(
        _template("index.html"),
        {
            "BRAND": esc(config.BRAND),
            "TAGLINE": esc(config.TAGLINE),
            "PRICE_INR": esc(config.PRICE_INR),
            "PRICE_USD": esc(config.PRICE_USD),
            "WATCH_INR": esc(config.WATCH_INR),
            "WATCH_USD": esc(config.WATCH_USD),
            "AGENCY_INR": esc(config.AGENCY_INR),
            "AGENCY_USD": esc(config.AGENCY_USD),
            "PAYMENT_LINK": esc(config.PAYMENT_LINK),
            "CONTACT_EMAIL": esc(config.CONTACT_EMAIL),
            "BASE_URL": esc(config.BASE_URL),
            "YEAR": config.now().year,
            "BADGE_DAYS": config.BADGE_VALID_DAYS,
        },
    )


def legal_page(name: str) -> str:
    return _fill(
        _template(f"{name}.html"),
        {
            "BRAND": esc(config.BRAND),
            "CONTACT_EMAIL": esc(config.CONTACT_EMAIL),
            "CITY": esc(config.CITY),
            "LEGAL_NAME": esc(config.LEGAL_NAME),
            "SUPPORT_EMAIL": esc(config.SUPPORT_EMAIL),
            "SECURITY_EMAIL": esc(config.SECURITY_EMAIL),
            "BASE_URL": esc(config.BASE_URL),
            "YEAR": config.now().year,
        },
    )


def _fix_prompt(finding: Finding) -> str:
    """A prompt the founder can paste into Cursor / Lovable / Bolt / Claude."""
    parts = [
        f"Fix this security finding in my app: {finding.title}.",
        f"Why it matters: {finding.why}",
    ]
    if finding.evidence:
        parts.append(f"Evidence: {finding.evidence}.")
    parts.append(f"Suggested fix: {finding.fix}")
    parts.append(
        "Make the smallest change that fixes it, keep the existing behaviour, and tell me "
        "exactly which files you changed."
    )
    return " ".join(parts)


def category_summary(findings: list) -> str:
    if not findings:
        return ""
    items = [_as_finding(f) for f in findings]
    groups: dict[str, list[Finding]] = {}
    for finding in items:
        groups.setdefault(finding.category, []).append(finding)
    rows = []
    for category, group in sorted(groups.items(), key=lambda pair: (-len(pair[1]), pair[0])):
        worst = sort_findings(group)[0].severity
        rows.append(
            f"<tr><td>{esc(category)}</td><td>{severity_pill(worst)}</td>"
            f"<td class=\"num-cell\">{len(group)}</td></tr>"
        )
    return (
        '<table class="meta-table category-table"><tr><th>Area</th><th>Worst finding</th>'
        '<th>Count</th></tr>' + "".join(rows) + "</table>"
    )


def not_checked_html() -> str:
    items = "".join(
        f'<li class="miss"><span class="check-icon">–</span>'
        f'<span class="check-name">{esc(item)}</span></li>'
        for item in config.NOT_CHECKED
    )
    return f'<ul class="checks not-checked">{items}</ul>'


def upsell_html(record: dict) -> str:
    if not config.FREE_REPORTS:
        return ""
    pay_target = config.PAYMENT_LINK or f"mailto:{config.CONTACT_EMAIL}?subject=Watch%20plan"
    sep = "&" if "?" in pay_target else "?"
    pay_url = f"{pay_target}{sep}ref={record.get('id', '')}"
    return f"""
    <div class="locked free-upsell">
      <div class="lock-icon">🛡️</div>
      <h3>This scan is free — the watching is not.</h3>
      <p>Every finding above is yours to keep, for free. What you can pay for is proof and
         follow-through: a dated badge, re-scans after every deploy, and someone to call when
         something looks wrong.</p>
      <p class="fine">Watch — ₹{esc(config.WATCH_INR)} / ${esc(config.WATCH_USD)} per month ·
         Agency pack — ₹{esc(config.AGENCY_INR)} / ${esc(config.AGENCY_USD)} for 10 audits</p>
      <a class="btn primary" href="{esc(pay_url)}" target="_blank" rel="noopener">
        Start Watch — ₹{esc(config.WATCH_INR)}/month
      </a>
    </div>"""


def focus_coming_soon() -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Coming soon · {esc(config.BRAND)}</title>
<link rel="stylesheet" href="/static/style.css"><link rel="stylesheet" href="/static/landing.css"></head>
<body class="landing-v2 legal-page"><main class="legal-doc wrap" style="max-width:620px">
<h1>Coming soon</h1>
<p>We are focused on the core review right now: a free scan and a ₹{esc(config.PRICE_INR)} report with evidence, the exact fix, a copy-paste AI prompt and a PDF.</p>
<p>Watch, agency packs and the API return after the first customers. <a href="/#scan">Run the free scan</a> or email <a href="mailto:{esc(config.CONTACT_EMAIL)}">{esc(config.CONTACT_EMAIL)}</a>.</p>
</main></body></html>"""


def checkout_page(record: dict, error: str = "") -> str:
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Your Fix &amp; Handover Report · {esc(config.BRAND)}</title>
<link rel="stylesheet" href="/static/style.css"><link rel="stylesheet" href="/static/landing.css"></head>
<body class="landing-v2 legal-page"><main class="legal-doc wrap" style="max-width:600px">
<a class="logo" href="/">{esc(config.BRAND)}</a><h1>Get your fix report.</h1>
<p>₹{esc(config.PRICE_INR)} once · no subscription</p><p class="fine">For {esc(record.get("target"))}</p>
<ul><li>Evidence and prioritized fix instructions</li><li>Copy-paste prompts for your AI builder</li><li>Downloadable PDF and one re-check within 30 days</li></ul>
<p>Where should we send your report link?</p><p role="alert">{esc(error)}</p>
<form method="post" action="/checkout/{esc(record.get('id'))}">
<label class="field"><span>Email for your report</span><input type="email" name="email" required maxlength="200" autocomplete="email" placeholder="you@example.com"></label>
<button class="btn primary big" type="submit">Continue to Razorpay — ₹{esc(config.PRICE_INR)}</button></form>
<p class="fine">UPI or card. Payment details stay with Razorpay. We send service emails, not marketing subscriptions.</p>
<p class="fine"><a href="/refund">7-day refund policy</a> · <a href="/privacy">Privacy</a> · <a href="mailto:{esc(config.CONTACT_EMAIL)}">Need help?</a></p>
<p><a href="/r/{esc(record.get('id'))}">Back to my free results</a></p></main></body></html>'''


def teaser_html(findings: list) -> str:
    """Free scan: every issue is visible as a title + severity. Evidence and fix are paid."""
    items = [_as_finding(f) for f in findings]
    items = sort_findings(items)
    if not items:
        return '<p class="muted">No issues found in this scan.</p>'
    rows = []
    for finding in items[:40]:
        rows.append(
            f'<div class="finding teaser sev-border-{esc(finding.severity)}">'
            f'<div class="teaser-row">{severity_pill(finding.severity)}'
            f'<span class="f-title">{esc(finding.title)}</span>'
            f'<span class="f-effort">evidence + fix locked</span></div></div>'
        )
    more = ""
    if len(items) > 40:
        more = f'<p class="fine">+ {len(items) - 40} more issues in the paid report.</p>'
    return '<div class="findings teaser-list">' + "".join(rows) + "</div>" + more


def pdf_button(record: dict) -> str:
    scan_id = str(record.get("id", ""))
    token = sign.sign(scan_id, "pdf")
    return (
        f'<a class="btn primary" href="/pdf/{esc(scan_id)}?token={esc(token)}">'
        f"Download the PDF report</a>"
    )


def fix_pack_html(record: dict) -> str:
    if not record.get("findings"):
        return ""
    scan_id = esc(record.get("id"))
    return f'''<section class="block"><h2>Your AI Builder Fix Pack</h2>
<p>One prioritized brief for the AI tool or developer that built your app: evidence, proposed fixes, regression checks and owner actions. Generated from this scan; no extra AI call.</p>
<p><a class="btn primary" href="/fix-pack/{scan_id}.md">Download Fix Pack (.md)</a></p>
<details><summary>Read or copy the complete plan</summary>
<textarea id="fix-pack-text" class="fix-pack-text" readonly aria-label="AI Builder Fix Pack">{esc(handover.fix_pack(record))}</textarea>
<p><button type="button" class="btn ghost small copy-fix-btn" data-copy-target="#fix-pack-text">Copy the complete fix plan</button></p></details>
<p class="fine">Paste it into your builder after reviewing the evidence. It does not change your app automatically. Keep the file private and test changes before deploying.</p></section>'''


def verification_html(record: dict) -> str:
    if not record.get("verified_against"):
        return ""
    labels = {"check_passed": ("Relevant check passed", "low"),
              "still_detected": ("Still detected", "high"),
              "not_confirmed": ("Not observed — not confirmed", "medium"),
              "new": ("New finding", "high")}
    rows = []
    for row in record.get("comparison") or []:
        label, tone = labels.get(row.get("state"), labels["not_confirmed"])
        rows.append(f'<tr><td>{esc(row.get("title"))}<br><code>{esc(row.get("id"))}</code></td><td><span class="pill sev-{tone}">{esc(label)}</span></td></tr>')
    table = '<div class="comparison-table"><table class="meta-table"><tr><th>Finding</th><th>Re-check result</th></tr>' + ''.join(rows) + '</table></div>' if rows else '<p>No check-level comparison is available for this report.</p>'
    return ('<section class="block"><h2>What changed after your fixes?</h2>'
            f'<p>Compared with <a href="/r/{esc(record.get("verified_against"))}">your original report</a>.</p>'
            + table + '<p class="fine">“Relevant check passed” means the mapped check ran and passed in this snapshot. It does not prove all instances are fixed. Missing findings without a passing mapped check remain unconfirmed, including older scans without check mappings.</p></section>')


def watch_upsell_html(record: dict) -> str:
    if config.FOCUS_MODE:
        return ""
    watch_price = esc(config.WATCH_INR)
    scan_id = esc(record.get("id", ""))
    return f"""
    <div class="locked free-upsell">
      <div class="lock-icon">🛡️</div>
      <h3>Watch this app</h3>
      <p>Daily re-checks after your next deploy. We email you only when a new finding appears, and the report page updates with the newest score.</p>
      <p class="fine">₹{watch_price} per month · auto-renews · cancel anytime</p>
      <a class="btn primary" href="/watch/start/{scan_id}">Start Watch — ₹{watch_price} / month</a>
    </div>"""


def ai_panel_html(record: dict) -> str:
    chat = record.get("chat") or []
    messages = []
    for item in chat[-20:]:
        role = "you" if item.get("role") == "user" else "ai"
        messages.append(
            f'<div class="ai-msg ai-{role}"><span>{esc(item.get("content", ""))}</span></div>'
        )
    seeded = "".join(messages)
    return f"""
    <section class="block ai-panel" data-scan="{esc(record.get('id', ''))}">
      <h2>Ask about this report</h2>
      <p class="muted">Answers are grounded in this report only. It will say "I don't know" rather than invent something.</p>
      <div class="ai-log" id="ai-log">{seeded}</div>
      <div class="ai-row">
        <input id="ai-question" type="text" maxlength="500" placeholder="e.g. Which finding should I fix first?" autocomplete="off">
        <button class="btn primary" type="button" id="ai-ask">Ask</button>
      </div>
      <p class="fine" id="ai-note">Answers are AI-generated from your report. Not a new security test.</p>
    </section>"""


def report_page(record: dict) -> str:
    score = record.get("score") or {}
    findings = record.get("findings") or []
    paid = (
        bool(record.get("unlocked"))
        or config.UNLOCK_ALL
        or config.FREE_REPORTS
    )
    counts = score.get("counts") or {}
    critical_count = int(counts.get("critical", 0))
    checks = record.get("checks") or []
    checks_run = len(checks)
    checks_passed = sum(1 for c in checks if c.get("ok") is True)
    pay_url = f"{config.BASE_URL}/pay/{record.get('id', '')}"

    if paid:
        findings_block = findings_html(findings, scan_id=record.get('id',''))
        lock_block = watch_upsell_html(record)
        kit_block = kit_html(record, unlocked=True)
        kit_note = "Free for everyone: paste each prompt into your own app's chat, then paste the reply back to grade it."
        pdf_block = pdf_button(record)
        mode_note = "Full report unlocked - evidence, fixes and the PDF report are below."
        price_note = ""
    else:
        findings_block = teaser_html(findings)
        lock_block = f"""
        <div class="locked">
          <div class="lock-icon">🔒</div>
          <h3>Unlock the fixes. Know what to give your AI builder.</h3>
          <p>The free scan gives you the score and all {len(findings)} issue titles.
             The paid report adds the evidence for each one, the plain-English fix,
             the copy-paste fix prompt, a PDF and one verification re-check.</p>
          <a class="btn primary" href="{esc(pay_url)}">
            Get my Fix &amp; Handover Report — ₹{esc(config.PRICE_INR)}
          </a>
          <p class="fine">One-time payment. No subscription. Report link stays live for 30 days.</p>
          <div class="agency-unlock">
            <p class="fine">Agency handover? Unlock with your agency code:</p>
            <input id="agency-code" placeholder="TF-AG-XXXXXX" maxlength="20" autocomplete="off">
            <input id="agency-client" placeholder="Client name (optional)" maxlength="80" autocomplete="off">
            <button class="btn ghost small" type="button" id="agency-unlock">Unlock with code</button>
            <p class="fine hidden" id="agency-note"></p>
          </div>
        </div>"""
        if config.FOCUS_MODE:
            lock_block = re.sub(r'<div class="agency-unlock">.*?</div>', '', lock_block, flags=re.S)
        if not findings:
            lock_block = '<div class="note"><h3>No fixes to buy from this scan.</h3><p>No issues were found in the checks we ran. Keep your free result and check again after changes. Logged-in flows and hidden server logic still need a separate review.</p></div>'
        kit_block = kit_html(record, unlocked=True)
        kit_note = "Free for everyone: paste each prompt into your own app's chat, then paste the reply back to grade it."
        pdf_block = ""
        mode_note = "Free scan: score + every issue we found. Evidence, fixes and PDF are in the paid report."
        price_note = f"₹{config.PRICE_INR} / ${config.PRICE_USD}"

    target_label = esc(record.get("target", ""))
    kind_label = "Live URL" if record.get("kind") == "url" else "GitHub repo"
    actions = score.get("top_actions") or []

    return _fill(
        _template("report.html"),
        {
            "BRAND": esc(config.BRAND),
            "SCAN_ID": esc(record.get("id", "")),
            "TARGET": target_label,
            "KIND": kind_label,
            "SCANNED_AT": esc(record.get("created_at", "")),
            "SCORE": int(score.get("score", 0)),
            "GRADE": esc(score.get("grade", "?")),
            "HEADLINE": esc(score.get("headline", "")),
            "VERDICT": esc(score.get("verdict", "")),
            "SUMMARY_HI": esc(score.get("summary_hi", "")),
            "SUMMARY_EN": esc(score.get("summary_en") or score.get("summary_hi", "")),
            "COUNTS": counts_grid(counts),
            "TOTAL": int(score.get("total", 0)),
            "ACTIONS": top_actions_html(actions),
            "RISKS": risk_card(score.get("cost_risk") or {}, "Money risk")
            + risk_card(score.get("breach_risk") or {}, "Data risk"),
            "FINDINGS": findings_block,
            "LOCK": lock_block,
            "KIT_SECTION": ('<section class="block"><h2>Guided chatbot checks</h2><p class="muted">You run these prompts against your own chatbot. They are not automatic tests.</p>' + kit_block + '</section>') if record.get("has_ai") else "",
            "KIT": kit_block,
            "KIT_NOTE": esc(kit_note),
            "PDF_BUTTON": pdf_block,
            "FIX_PACK": fix_pack_html(record) if paid else "",
            "SHARE_BUTTON": share_button(record),
            "AI_PLAN": (
                f'<section class="block ai-plan"><h2>Your action plan (AI)</h2><p>{esc(record.get("ai_plan")).replace(chr(10), "<br>")}</p><p class="fine">Generated from this report only. Not a guarantee.</p></section>'
            ) if record.get("ai_plan") else "",
            "RESCAN_LINK": (f'<a class="btn" href="/verify/{esc(record.get("id",""))}">{"View your re-check" if record.get("verification_scan_id") else "Re-check after fixes (included)"}</a>' if paid and not record.get("verified_against") else ""),
            "VERIFY_BANNER": verification_html(record),
            "PREPARED_FOR": (
                f'<p class="fine" style="color:#0f766e">Prepared for <strong>{esc(record.get("prepared_for"))}</strong>'
                + (f' — handover by {esc(record.get("agency_name"))}' if record.get("agency_name") else "")
                + "</p>"
            ) if record.get("prepared_for") else "",
            "AI_PANEL": ai_panel_html(record) if paid else "",
            "MODE_NOTE": esc(mode_note),
            "CHECKS": checks_html(record.get("checks") or []),
            "CHECKS_RUN": checks_run,
            "CHECKS_PASSED": checks_passed,
            "CATEGORIES": category_summary(findings),
            "NOT_CHECKED": not_checked_html(),
            "FREE_MODE": "" if paid else "1",
            "META": meta_table(record.get("meta") or {}),
            "UNLOCKED": "1" if paid else "",
            "PAY_LINK": esc(config.PAYMENT_LINK),
            "PRICE_INR": esc(config.PRICE_INR),
            "PRICE_USD": esc(config.PRICE_USD),
            "CONTACT_EMAIL": esc(config.CONTACT_EMAIL),
            "YEAR": config.now().year,
            "BADGE_DAYS": config.BADGE_VALID_DAYS,
            "CRITICAL_COUNT": critical_count,
        },
    )


def trust_page(record: dict) -> str:
    score = record.get("score") or {}
    checks = record.get("checks") or []
    passed = [c["name"] for c in checks if c.get("ok")]
    import datetime as _dt
    expires = str(record.get("expires_at") or "")
    expired = bool(expires) and expires < _dt.date.today().isoformat()
    eligible = int(score.get("score", 0)) >= 80 and not score.get("has_critical") and not expired
    page = _fill(
        _template("trust.html"),
        {
            "BRAND": esc(config.BRAND),
            "TARGET": esc(record.get("target", "")),
            "PREPARED_FOR": (
                f'<p class="fine" style="color:#0f766e">Prepared for <strong>{esc(record.get("prepared_for"))}</strong>'
                + (f' — handover by {esc(record.get("agency_name"))}' if record.get("agency_name") else "")
                + "</p>"
            ) if record.get("prepared_for") else "",
            "PREPARED_FOR": (
                f'<p class="fine" style="color:#0f766e">Prepared for <strong>{esc(record.get("prepared_for"))}</strong>'
                + (f' · handover by {esc(record.get("agency_name"))}' if record.get("agency_name") else "")
                + "</p>"
            ) if record.get("prepared_for") else "",
            "SCORE": esc(score.get("score", 0)),
            "GRADE": esc(score.get("grade", "?")),
            "SCANNED_AT": esc(record.get("created_at", "")),
            "EXPIRES_AT": esc(record.get("expires_at", "")),
            "PASSED_COUNT": len(passed),
            "CHECKS": checks_html(checks),
            "ELIGIBLE": "1" if eligible else "",
            "SCAN_ID": esc(record.get("id", "")),
            "BADGE_DAYS": config.BADGE_VALID_DAYS,
            "YEAR": config.now().year,
        },
    )
    if not eligible:
        page = page.replace(f"{esc(config.BRAND)} Verified", f"{esc(config.BRAND)} scanned - not verified")
    return page


def badge_svg(record: dict) -> str:
    score = record.get("score") or {}
    value = int(score.get("score", 0))
    eligible = value >= 80 and not (score.get("has_critical"))
    color = "#16a34a" if eligible and value >= 85 else "#eab308" if eligible else "#64748b"
    label = config.BRAND if eligible else config.BRAND + " (not verified)"
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="190" height="28" role="img" aria-label="{esc(label)}: {value}/100">
  <rect width="190" height="28" rx="6" fill="#0f172a"/>
  <rect x="98" width="92" height="28" rx="6" fill="{color}"/>
  <text x="12" y="19" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" fill="#e2e8f0">{esc(label)}</text>
  <text x="144" y="19" font-family="Verdana,DejaVu Sans,sans-serif" font-size="12" font-weight="bold" fill="#ffffff" text-anchor="middle">{value}/100</text>
</svg>"""


ISSUE_LABELS = {
    "deep.dom_xss_sink": "DOM XSS sink in the browser",
    "deep.no_meta_description": "Missing meta description",
    "deep.no_canonical": "No canonical URL",
    "deep.no_structured_data": "No structured data",
    "deep.no_llms_txt": "No llms.txt for AI agents",
    "live.no_deletion_path": "No data-deletion path",
    "live.cors_wildcard": "CORS open to every origin",
    "live.no_hsts": "Missing HSTS header",
    "live.no_csp": "Missing Content-Security-Policy",
}


def _issue_label(raw: str) -> str:
    if raw in ISSUE_LABELS:
        return ISSUE_LABELS[raw]
    return raw.replace("deep.", "").replace("live.", "").replace("_", " ").strip().title()


def public_index_page(data: dict) -> str:
    rows = ""
    for issue in data.get("top_issues") or []:
        rows += (
            f'<tr><td>{esc(_issue_label(issue["id"]))}</td>'
            f'<td class="num-cell">{issue["count"]}</td>'
            f'<td class="num-cell"><strong>{issue["rate"]}%</strong></td></tr>'
        )
    platforms = "".join(
        f'<li><span>{esc("Other / unknown" if item["name"] == "Other" else item["name"])}</span><strong>{item["rate"]}%</strong></li>'
        for item in data.get("platforms") or []
    )
    return _fill(
        _template("public_index.html"),
        {
            "BRAND": esc(config.BRAND),
            "BASE_URL": config.BASE_URL,
            "SCANS": int(data.get("scans", 0)),
            "BETA_NOTE": "The index is live; it gets more useful with every scan." if int(data.get("scans", 0)) >= 25 else "The index stays in beta until 25 scans.",
            "UPDATED": esc(str(data.get("updated", ""))[:10] or "just now"),
            "ROWS": rows or '<tr><td colspan="3" class="muted">Not enough scans yet. Be the first.</td></tr>',
            "PLATFORMS": platforms or '<li class="muted">No platform data yet.</li>',
            "CONTACT_EMAIL": esc(config.CONTACT_EMAIL),
            "YEAR": config.now().year,
        },
    )


def agency_page(row: dict | None, paid: bool = False, error: str = "") -> str:
    note = ""
    if paid:
        note = '<div class="note" style="background:#ecfdf5;border-color:#a7f3d0;color:#065f46">Payment received. Your agency code is on its way by email (usually within a minute).</div>'
    if error:
        note = f'<div class="note" style="background:#fef2f2;border-color:#fecaca;color:#991b1b">{esc(error)}</div>'
    status = ""
    if row:
        status = (f'<div class="note" style="margin-top:18px"><strong>{esc(row.get("name") or row.get("email"))}</strong><br>'
                  f'Code <strong>{esc(row.get("code") or "")}</strong> · {row.get("left", 0)} of {row.get("credits", 0)} reports left</div>')
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agency pack · {esc(config.BRAND)}</title>
<meta name="description" content="Ten client-ready security reports for agencies that ship AI-built apps. Rs 3999.">
<link rel="canonical" href="{esc(config.BASE_URL)}/agency">
<link rel="stylesheet" href="/static/style.css"><link rel="stylesheet" href="/static/landing.css">
</head><body class="landing-v2 legal-page">
<header class="site-head"><div class="wrap head-in"><a class="logo" href="/"><svg viewBox="0 0 32 32" width="24" height="24" aria-hidden="true"><path d="M16 2 28 7v9c0 7-5 12-12 14C9 28 4 23 4 16V7z" fill="currentColor"/><path d="M11 16l4 4 7-8" stroke="#fff" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg><span>{esc(config.BRAND)}</span></a><a class="btn small" href="/">Back to site</a></div></header>
<main class="legal-doc wrap">
  <h1>Agency pack</h1>
  <p class="updated">10 client-ready reports · ₹{esc(config.AGENCY_INR)} one-time · no subscription</p>
  {note}
  <p>You ship AI-built apps to clients. Scan the app, unlock the report with one code, and hand over a PDF with the client's name on it — evidence, fixes and a fix prompt, without a ₹25k pentest invoice.</p>
  <ul>
    <li>10 report credits, use them on any 10 scans</li>
    <li>Each report carries the client name and your agency name ("Prepared for X · handover by Y")</li>
    <li>Shareable report link + PDF, same checks as the ₹{esc(config.PRICE_INR)} report</li>
    <li>Not a penetration test and not a certification — the report says so</li>
  </ul>
  <form method="post" action="/agency/start" style="display:grid;gap:10px;max-width:460px;margin:22px 0">
    <input name="email" type="email" placeholder="you@agency.com" style="height:48px;border:1px solid var(--line);border-radius:10px;padding:0 14px;font:inherit">
    <input name="name" placeholder="Agency name (shown on reports)" style="height:48px;border:1px solid var(--line);border-radius:10px;padding:0 14px;font:inherit">
    <button class="btn primary" type="submit" style="height:48px;justify-self:start">Buy agency pack — ₹{esc(config.AGENCY_INR)}</button>
  </form>
  <h2>Already bought?</h2>
  <form method="get" action="/agency" style="display:flex;gap:8px;max-width:460px">
    <input name="code" placeholder="TF-AG-XXXXXX" style="flex:1;height:48px;border:1px solid var(--line);border-radius:10px;padding:0 14px;font:inherit">
    <button class="btn" type="submit" style="height:48px">Check credits</button>
  </form>
  {status}
  <p class="fine">Codes are single-use per report. Refunds: <a href="/refund">/refund</a> · Questions: <a href="mailto:{esc(config.CONTACT_EMAIL)}">{esc(config.CONTACT_EMAIL)}</a></p>
</main></body></html>"""


def rls_tool_page(url_value: str, result_html: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Supabase RLS checker · {esc(config.BRAND)}</title>
  <meta name="description" content="Free Supabase RLS check: paste your project URL and anon key to see whether any table returns rows to the public key.">
  <link rel="canonical" href="{esc(config.BASE_URL)}/tools/rls">
  <link rel="stylesheet" href="/static/style.css">
  <link rel="stylesheet" href="/static/landing.css">
</head>
<body class="landing-v2 legal-page">
  <header class="site-head"><div class="wrap head-in"><a class="logo" href="/"><svg viewBox="0 0 32 32" width="24" height="24" aria-hidden="true"><path d="M16 2 28 7v9c0 7-5 12-12 14C9 28 4 23 4 16V7z" fill="currentColor"/><path d="M11 16l4 4 7-8" stroke="#fff" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg><span>{esc(config.BRAND)}</span></a><a class="btn small" href="/">Back to site</a></div></header>
  <main class="legal-doc wrap">
    <h1>Supabase RLS checker</h1>
    <p class="updated">Free · only for projects you own · the key is used for this check and not stored.</p>
    <form method="post" action="/tools/rls" style="display:grid;gap:10px;margin:20px 0 26px">
      <input name="url" value="{esc(url_value)}" placeholder="https://abcdefghijklmnopqrst.supabase.co" style="height:48px;border:1px solid var(--line);border-radius:10px;padding:0 14px;font:inherit">
      <input name="key" type="password" placeholder="anon / publishable key" autocomplete="off" style="height:48px;border:1px solid var(--line);border-radius:10px;padding:0 14px;font:inherit">
      <button class="btn primary" type="submit" style="height:48px;justify-self:start">Check my tables</button>
    </form>
    {result_html}
    <p class="fine">Use the <strong>anon/public</strong> key, never the service_role key. This checks one thing: whether the public key can read rows. Not a full audit. <a href="/methodology">Methodology</a></p>
  </main>
</body>
</html>"""


def headers_tool_page(url_value: str, result_html: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security headers checker · {esc(config.BRAND)}</title>
  <meta name="description" content="Free security headers check: HSTS, CSP, X-Frame-Options, referrer and permissions policy. Paste a URL, get a grade and copy-paste fixes.">
  <link rel="canonical" href="{esc(config.BASE_URL)}/tools/headers">
  <link rel="stylesheet" href="/static/style.css">
  <link rel="stylesheet" href="/static/landing.css">
  <script src="https://analytics.ahrefs.com/analytics.js" data-key="gLBPCAyOg9uZUDtLmDAQ3Q" async></script>
</head>
<body class="landing-v2 legal-page">
  <header class="site-head"><div class="wrap head-in"><a class="logo" href="/"><svg viewBox="0 0 32 32" width="24" height="24" aria-hidden="true"><path d="M16 2 28 7v9c0 7-5 12-12 14C9 28 4 23 4 16V7z" fill="currentColor"/><path d="M11 16l4 4 7-8" stroke="#fff" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg><span>{esc(config.BRAND)}</span></a><a class="btn small" href="/">Back to site</a></div></header>
  <main class="legal-doc wrap">
    <h1>Security headers checker</h1>
    <p class="updated">Free · no signup · one request.</p>
    <form method="get" action="/tools/headers" style="display:flex;gap:8px;margin:20px 0 26px;flex-wrap:wrap">
      <input name="url" value="{esc(url_value)}" placeholder="https://your-app.com" style="flex:1 1 320px;min-width:0;height:48px;border:1px solid var(--line);border-radius:10px;padding:0 14px;font:inherit">
      <button class="btn primary" type="submit" style="height:48px">Check headers</button>
    </form>
    {result_html}
    <p class="fine">We only read the public response headers. No login, no exploitation. <a href="/methodology">Methodology</a> · <a href="/security">Security</a></p>
  </main>
</body>
</html>"""


def admin_page(scans: list[dict], revenue: dict, index_data: dict, token: str, watches: list | None = None, keys: list | None = None, alerts_on: bool = False, agencies: list | None = None) -> str:
    from . import usage

    emails_today = usage.today("emails")
    emails_month = usage.month("emails")
    ai_today = usage.today("ai")
    ai_month = usage.month("ai")
    scans_month = usage.month("scans")
    ai_cost = round(ai_month * 0.12, 2)
    gross = float(revenue.get("revenue_inr", 0) or 0)
    fee = round(gross * 0.0236, 2)
    payout = round(gross - fee, 2)
    alerts = []
    if emails_today >= 80:
        alerts.append("Email: 80/day free-tier limit is close. Resend paid plan or slow down.")
    if emails_month >= 2400:
        alerts.append("Email: 2,400 of 3,000 monthly free emails used.")
    if ai_today >= 240:
        alerts.append("AI: 240 of 300 daily answers used. Watch the balance.")
    if ai_cost > 0 and ai_cost >= 200:
        alerts.append("AI: estimated spend crossed Rs 200 this month. Top up / raise guard?")
    if gross <= 0:
        alerts.append("Revenue: Rs 0 so far - distribution is the bottleneck, not the product.")
    alert_html = "".join(f'<li>{esc(a)}</li>' for a in alerts) or "<li>All clear.</li>"
    email_left_day = max(0, 100 - emails_today)
    email_left_month = max(0, 3000 - emails_month)
    rows = ""
    for scan in scans:
        score = (scan.get("score") or {}).get("score", 0)
        counts = (scan.get("score") or {}).get("counts") or {}
        status = "PAID" if scan.get("unlocked") else "free"
        rows += (
            f"<tr><td><a href='/r/{esc(scan.get('id',''))}'>{esc(scan.get('id',''))}</a></td>"
            f"<td>{esc(str(scan.get('target',''))[:48])}</td>"
            f"<td class='num-cell'>{score}</td>"
            f"<td class='num-cell'>{int(counts.get('critical', 0))}</td>"
            f"<td>{status}</td>"
            f"<td>{esc(str(scan.get('created_at',''))[:16])}</td>"
            f"<td><a href='/admin/pdf/{esc(scan.get('id',''))}?token={esc(token)}'>PDF</a> · "
            f"<a href='/admin/email/{esc(scan.get('id',''))}?token={esc(token)}'>Email</a> · "
            f"<a href='/admin/unlock?id={esc(scan.get('id',''))}&token={esc(token)}'>Unlock</a></td></tr>"
        )
    return _fill(
        _template("admin.html"),
        {
            "BRAND": esc(config.BRAND),
            "TOKEN": esc(token),
            "SCAN_COUNT": len(scans),
            "PAID_COUNT": int(revenue.get("orders", 0)),
            "REVENUE": esc(f"{revenue.get('revenue_inr', 0):,.0f}"),
            "FUNNEL_ROWS": "".join(f'<tr><td>{esc(row["source"])}</td><td>{row["visit"]}</td><td>{row["scan_complete"]}</td><td>{row["checkout"]}</td><td>{row["purchase"]}</td></tr>' for row in usage.funnel_summary()),
            "TEST_ORDERS": int(revenue.get("test_orders", 0)),
            "INDEX_SCANS": int(index_data.get("scans", 0)),
            "ROWS": rows or '<tr><td colspan="7" class="muted">No scans yet.</td></tr>',
            "SCANS_MONTH": scans_month,
            "EMAIL_TODAY": emails_today,
            "EMAIL_MONTH": emails_month,
            "EMAIL_LEFT_DAY": email_left_day,
            "EMAIL_LEFT_MONTH": email_left_month,
            "AI_TODAY": ai_today,
            "AI_MONTH": ai_month,
            "AI_COST": f"{ai_cost:,.2f}",
            "FEE": f"{fee:,.2f}",
            "PAYOUT": f"{payout:,.2f}",
            "WATCH_COUNT": len(watches or []),
            "ALERTS_STATUS": "Slack/Discord configured" if alerts_on else "email fallback active (add SLACK_WEBHOOK_URL for channel alerts)",
            "AGENCY_ROWS": "".join(
                f"<tr><td>{esc(str(a.get('name','') or a.get('email','')))}</td><td><code>{esc(str(a.get('code','')))}</code></td>"
                f"<td>{int(a.get('credits',0))}</td><td>{int(a.get('used',0))}</td></tr>"
                for a in (agencies or [])[-10:]
            ) or '<tr><td colspan="4" class="muted">No agency packs yet.</td></tr>',
            "KEY_ROWS": "".join(
                f"<tr><td>{esc(str(k.get('name','')))}</td><td><code>{esc(str(k.get('prefix','')))}…</code></td>"
                f"<td>{int(k.get('calls',0))}</td><td>{esc(str(k.get('last_used',''))[:16] or 'never')}</td></tr>"
                for k in (keys or [])[-10:]
            ) or '<tr><td colspan="4" class="muted">No API keys yet.</td></tr>',
            "WATCH_ROWS": "".join(
                f"<tr><td>{esc(str(w.get('target',''))[:44])}</td><td>{esc(w.get('email',''))}</td>"
                f"<td>{'active' if w.get('active') else 'paused'}</td><td>{esc(str(w.get('next_check_at',''))[:16])}</td>"
                f"<td><a href='/watch/manage?token={esc(w.get('cancel_token',''))}'>manage</a></td></tr>"
                for w in (watches or [])[-20:]
            ) or '<tr><td colspan="5" class="muted">No Watch subscriptions yet.</td></tr>',
            "ALERTS": alert_html,
            "YEAR": config.now().year,
        },
    )


def admin_login_page(error: str = "") -> str:
    note = f'<p class="note" style="background:#fef2f2;border-color:#fecaca;color:#991b1b">{esc(error)}</p>' if error else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin login · {esc(config.BRAND)}</title>
<meta name="robots" content="noindex">
<link rel="stylesheet" href="/static/style.css">
</head><body class="report-body">
<main class="wrap narrow" style="max-width:420px;margin:12vh auto">
  <a class="brand" href="/" style="text-decoration:none"><span>{esc(config.BRAND)}</span></a>
  <h1 style="margin-top:18px">Admin login</h1>
  <p class="muted">Operator access only.</p>
  {note}
  <form method="post" action="/admin/login" style="display:grid;gap:12px;margin-top:18px">
    <input name="password" type="password" autocomplete="current-password" placeholder="Admin password" required
           style="height:52px;border:1px solid #d7dce3;border-radius:12px;padding:0 14px;font:inherit">
    <button class="btn primary" type="submit" style="height:48px">Log in</button>
  </form>
  <p class="fine" style="margin-top:18px"><a href="/">← Back to site</a></p>
</main></body></html>"""


def share_card(record: dict) -> str:
    from urllib.parse import urlsplit, quote as _q
    score = record.get("score") or {}
    value = int(score.get("score") or 0)
    grade = esc(score.get("grade") or "?")
    target = str(record.get("target") or "")
    host = urlsplit(target).hostname or target
    sid = esc(str(record.get("id") or ""))
    share_url = f"{config.BASE_URL}/s/{sid}"
    message = f"My AI-built app scored {value}/100 on Trustfield. Check yours free in 60 seconds: {config.BASE_URL}/#scan"
    wa = "https://wa.me/?text=" + _q(message)
    tw = "https://twitter.com/intent/tweet?text=" + _q(message)
    li = "https://www.linkedin.com/sharing/share-offsite/?url=" + _q(share_url)
    tone = "#0f766e" if value >= 80 else ("#b45309" if value >= 50 else "#b91c1c")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(host)} scored {value}/100 · {esc(config.BRAND)}</title>
<meta name="description" content="Independent 60-second security check for AI-built apps. Free score, paid evidence + fixes.">
<meta property="og:title" content="{esc(host)} scored {value}/100 on Trustfield">
<meta property="og:description" content="Free 60-second security check for AI-built apps. See what a stranger can reach.">
<meta property="og:image" content="{esc(config.BASE_URL)}/static/og.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="robots" content="noindex">
<link rel="canonical" href="{esc(share_url)}">
<link rel="stylesheet" href="/static/style.css"><link rel="stylesheet" href="/static/landing.css">
</head><body class="landing-v2 legal-page"><main class="legal-doc wrap" style="max-width:640px;text-align:center">
<p class="fine">Independent security check · {esc(config.BRAND)}</p>
<h1 style="margin:6px 0">{esc(host)}</h1>
<p style="font-size:64px;font-weight:800;color:{tone};line-height:1;margin:14px 0">{value}<span style="font-size:22px">/100</span></p>
<p style="font-size:18px;color:#5b6675">Grade {grade} · scanned {esc(str(record.get("created_at",""))[:10])}</p>
<p style="margin:18px 0">Free scan shows your score and every issue title.<br>The ₹{esc(config.PRICE_INR)} report adds evidence, the exact fix, a copy-paste AI prompt and a PDF.</p>
<p style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin:20px 0">
  <a class="btn" href="{wa}" rel="noopener">Share on WhatsApp</a>
  <a class="btn ghost" href="{tw}" rel="noopener">Share on X</a>
  <a class="btn ghost" href="{li}" rel="noopener">LinkedIn</a>
</p>
<p><a class="btn primary" href="/#scan">Scan your own app — free</a></p>
<p class="fine">Scores are produced by an automated passive check and are not a certification or an audit. Targets are only shown at host level.</p>
</main></body></html>"""


def share_button(record: dict) -> str:
    sid = esc(str(record.get("id") or ""))
    return f'<p class="fine" style="margin:10px 0"><a class="btn ghost small" href="/s/{sid}" rel="noopener">Share this score</a></p>'
