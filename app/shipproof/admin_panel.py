"""Operator dashboard: explicit data sources, confirmed receipts, safe actions."""
from __future__ import annotations

import html
from datetime import datetime, timedelta, timezone

from . import config, emailer, sign, storage, usage


def esc(value) -> str:
    return html.escape(str(value or ""), quote=True)


def ist(value) -> str:
    try:
        stamp = datetime.fromisoformat(str(value))
        return stamp.replace(tzinfo=stamp.tzinfo or timezone.utc).astimezone(timezone(timedelta(hours=5, minutes=30))).strftime("%d %b %Y, %H:%M IST")
    except (TypeError, ValueError):
        return "Not recorded"


def email_status(record: dict) -> str:
    result = record.get("email_result") or {}
    if result.get("ok") and result.get("mode") == "resend":
        return "Accepted by email provider"
    if result.get("mode") == "outbox":
        return "Local outbox only — not sent"
    if result and not result.get("ok"):
        return "Send failed"
    if record.get("unlocked"):
        return "No email attempt recorded" if record.get("email") else "Recipient missing"
    return "Not requested"


def watch_current(row: dict) -> bool:
    try:
        until = datetime.fromisoformat(str(row.get("paid_until")))
        until = until.replace(tzinfo=until.tzinfo or timezone.utc)
        return bool(row.get("active")) and until > config.now()
    except (TypeError, ValueError):
        return False


def context(scans, revenue, index_data, watches, keys, alerts_on, agencies, notice="") -> dict:
    csrf = sign.sign("admin", "admin_action", ttl_days=1)
    def form(action, label, scan_id="", confirm=False):
        fields = f'<input type="hidden" name="csrf" value="{esc(csrf)}"><input type="hidden" name="action" value="{esc(action)}"><input type="hidden" name="scan_id" value="{esc(scan_id)}">'
        checkbox = '<label><input type="checkbox" name="confirmed" value="1" required> I verified payment or intend a complimentary grant. This does not record revenue.</label>' if confirm else ''
        return f'<form method="post" action="/admin/actions">{fields}{checkbox}<button class="btn small" type="submit">{esc(label)}</button></form>'
    alerts = []
    attention = [s for s in scans if s.get("unlocked") and email_status(s) != "Accepted by email provider" and not s.get("verified_against")]
    if attention:
        alerts.append(f'{len(attention)} access-granted report(s) have missing, failed or unconfirmed email delivery. Review the recent reports table.')
    if revenue.get("review_count"):
        alerts.append(f'{revenue["review_count"]} payment record(s) need gateway review. Legacy records are not counted as confirmed sales.')
    if not storage.enabled():
        alerts.append('Cloud storage is not configured. Local records may be lost on an ephemeral host restart.')
    if not emailer.configured():
        alerts.append('Transactional email is not configured. Local outbox files are not delivery to customers.')
    if usage.today("ai_attempts") >= config.AI_DAILY_LIMIT:
        alerts.append('AI daily allowance is exhausted; report and fix-pack downloads still work.')
    notices = {"reconciled": "Checked up to 10 eligible Razorpay references. Review each gateway result below; no payments were changed.",
               "granted": "Report access granted. This is not a recorded sale.",
               "email-accepted": "The email provider accepted the request. Inbox delivery is not confirmed.",
               "email-failed": "The report was not accepted for email delivery. Review its delivery status."}
    report_rows = []
    for scan in scans:
        sid = esc(scan.get("id"))
        access = "Included re-check" if scan.get("verified_against") else ("Access granted" if scan.get("unlocked") else "Free / locked")
        actions = f'<a href="/r/{sid}">Open report</a>'
        if scan.get("unlocked"):
            actions += f' · <a href="/admin/pdf/{sid}">PDF</a>'
            if scan.get("email"):
                actions += form("email", "Send report email", scan.get("id"))
        else:
            actions += '<details><summary>Grant access</summary>' + form("grant", "Confirm access grant", scan.get("id"), True) + '</details>'
        report_rows.append(f'<tr><td><a href="/r/{sid}">{sid}</a><br><span class="fine">{esc(scan.get("target"))}</span></td><td>{int((scan.get("score") or {}).get("score") or 0)}</td><td>{access}</td><td>{esc(email_status(scan))}<br><span class="fine">{esc(scan.get("email") or "No recipient")}</span></td><td>{ist(scan.get("created_at"))}</td><td class="admin-actions">{actions}</td></tr>')
    payment_rows = []
    for row in revenue.get("records", [])[:100]:
        receipt = row.get("receipt") or {}
        payment_rows.append(f'<tr><td>{esc(row.get("provider_id") or "Manual grant")}<br><span class="fine">{esc(row.get("provider"))} · {esc(row.get("product") or "report")}</span></td><td>{esc(row.get("currency") or "INR")} {int(row.get("amount_minor") or 0)/100:,.2f}</td><td>{esc(row.get("classification"))}<br><span class="fine">{esc(receipt.get("reason") or row.get("verification") or "No provider evidence recorded")} · mode: {esc(row.get("payment_mode") or "unknown")}</span></td><td>{esc(row.get("scan_id") or row.get("report_id") or "—")}</td><td>{ist(row.get("paid_at"))}</td></tr>')
    active = sum(watch_current(w) for w in watches)
    legacy = f'<p>{active} active/current Watch records of {len(watches)} total; {len(agencies)} agency records; {len(keys)} API key records. New sales are paused in focus mode.</p>'
    legacy += '<ul>' + ''.join(f'<li>{esc(w.get("target"))} — {"active flag" if w.get("active") else "paused"}; paid through {esc(w.get("paid_until") or "not recorded")} · <a href="/watch/manage?token={esc(w.get("cancel_token"))}">Manage existing service</a></li>' for w in watches) + '</ul>'
    funnel = ''.join(f'<tr><td>{esc(r["source"])}</td><td>{r["visit"]}</td><td>{r["scan_complete"]}</td><td>{r["checkout"]}</td><td>{r["purchase"]}</td></tr>' for r in usage.funnel_summary())
    return {"BRAND": esc(config.BRAND), "YEAR": config.now().year,
            "NOTICE": f'<p class="note" role="status">{esc(notices[notice])}</p>' if notice in notices else '',
            "ALERTS": ''.join(f'<li>{esc(a)}</li>' for a in alerts) or '<li>No outstanding warning in the loaded data. Provider balances and settlements are not checked here.</li>',
            "CONFIRMED_ORDERS": revenue.get("confirmed_orders", 0), "CONFIRMED_INR": f'{revenue.get("confirmed_inr", 0):,.2f}',
            "REVIEW_COUNT": revenue.get("review_count", 0), "SCAN_COUNT": len(scans),
            "RECORDED_INR": f'{revenue.get("revenue_inr", 0):,.2f}', "TEST_COUNT": revenue.get("test_orders", 0), "MANUAL_COUNT": revenue.get("manual_grants", 0),
            "PAYMENT_ROWS": ''.join(payment_rows) or '<tr><td colspan="5">No payment records available.</td></tr>',
            "RECONCILE_FORM": form("reconcile", "Check recorded Razorpay payments"),
            "REPORT_ROWS": ''.join(report_rows) or '<tr><td colspan="6">No reports loaded.</td></tr>',
            "FUNNEL_ROWS": funnel, "SCANS_MONTH": usage.month("scans"),
            "EMAIL_TODAY": usage.today("emails"), "EMAIL_MONTH": usage.month("emails"),
            "AI_ATTEMPTS": usage.today("ai_attempts"), "AI_LIMIT": config.AI_DAILY_LIMIT,
            "AI_ANSWERS": usage.today("ai"),
            "STORAGE_STATE": "Configured (restore/write success not verified here)" if storage.enabled() else "Not configured — local only",
            "EMAIL_STATE": "Configured" if emailer.configured() else "Not configured — local outbox only",
            "ALERT_STATE": "Channel webhook configured" if alerts_on else ("Email fallback configured" if emailer.configured() else "No outbound alert delivery configured"),
            "LEGACY": legacy}
