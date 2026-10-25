"""Transactional email via Resend. Without an API key it writes to data/outbox/."""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path

from . import config, pdf, sign, usage


def configured() -> bool:
    return bool(config.RESEND_API_KEY)


def _outbox(to: str, subject: str, html: str) -> dict:
    try:
        config.EMAIL_OUTBOX.mkdir(parents=True, exist_ok=True)
        name = f"{config.now().strftime('%Y%m%d-%H%M%S')}-{to.replace('@', '_at_')[:60]}.html"
        path = config.EMAIL_OUTBOX / name
        Path(path).write_text(f"<!-- to: {to} | subject: {subject} -->\n{html}", encoding="utf-8")
        return {"ok": True, "mode": "outbox", "path": str(path)}
    except OSError as exc:
        return {"ok": False, "error": str(exc)[:200]}


def send(to: str, subject: str, html: str, attachments: list | None = None) -> dict:
    if not to or "@" not in to:
        return {"ok": False, "error": "no recipient"}
    if not configured():
        return _outbox(to, subject, html)
    payload = {"from": config.EMAIL_FROM, "to": [to], "subject": subject, "html": html}
    if attachments:
        payload["attachments"] = attachments
    request = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {config.RESEND_API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": f"{config.BRAND}/1.0 (+{config.BASE_URL})",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20, context=ssl.create_default_context()) as response:
            ok = 200 <= response.status < 300
            if ok:
                usage.bump("emails")
            return {"ok": ok, "mode": "resend", "status": response.status}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"ok": False, "error": str(exc)[:200]}


def _shell(title: str, intro: str, body: str, cta_label: str, cta_url: str, footer: str) -> str:
    button = (
        f'<a href="{cta_url}" style="display:inline-block;background:#0f766e;color:#ffffff;'
        f'font-weight:600;padding:13px 22px;border-radius:10px;text-decoration:none;font-size:15px">{cta_label}</a>'
        if cta_url
        else ""
    )
    return f"""<!doctype html><html><body style="margin:0;background:#f6f8fa;padding:28px 16px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;color:#0b1220">
<div style="max-width:560px;margin:0 auto;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden">
  <div style="padding:18px 24px;border-bottom:1px solid #e5e7eb">
    <span style="font-size:17px;font-weight:700;color:#0b1220">{config.BRAND}</span>
    <span style="font-size:11px;color:#0f766e;letter-spacing:.06em;margin-left:8px">SECURITY REVIEW</span>
  </div>
  <div style="padding:26px 24px">
    <h1 style="margin:0 0 8px;font-size:21px;line-height:1.3;color:#0b1220">{title}</h1>
    <p style="margin:0 0 18px;color:#5b6675;font-size:14px;line-height:1.65">{intro}</p>
    {body}
    <p style="margin:24px 0 0">{button}</p>
  </div>
  <div style="padding:16px 24px;border-top:1px solid #e5e7eb;color:#8a94a3;font-size:11px;line-height:1.7">
    {footer}<br>Only scan apps you own or are authorised to test. A check is a point in time, not a guarantee.<br>
    <a href="{config.BASE_URL}/security" style="color:#0f766e;text-decoration:none">Security</a> ·
    <a href="{config.BASE_URL}/refund" style="color:#0f766e;text-decoration:none">Refunds</a> ·
    <a href="{config.BASE_URL}/privacy" style="color:#0f766e;text-decoration:none">Privacy</a>
  </div>
</div></body></html>"""


def report_email_html(record: dict) -> tuple[str, str]:
    scan_id = str(record.get("id", ""))
    score = record.get("score") or {}
    report_url = f"{config.BASE_URL}/r/{scan_id}"
    pdf_url = f"{config.BASE_URL}/pdf/{scan_id}?token={sign.sign(scan_id, 'pdf')}"
    counts = score.get("counts") or {}
    body = f"""
    <table role="presentation" style="width:100%;border-collapse:collapse;margin:0 0 18px">
      <tr>
        <td style="padding:14px;background:#f6f8fa;border-radius:10px;text-align:center">
          <div style="font-size:30px;font-weight:800;color:#0f766e">{score.get('score', 0)}<span style="font-size:13px;color:#5b6675">/100</span></div>
          <div style="font-size:11px;color:#5b6675;letter-spacing:.08em">SCORE</div>
        </td>
        <td style="width:12px"></td>
        <td style="padding:14px;background:#f6f8fa;border-radius:10px;text-align:center">
          <div style="font-size:20px;font-weight:800;color:#b91c1c">{counts.get('critical', 0)}</div>
          <div style="font-size:11px;color:#5b6675">CRITICAL</div>
        </td>
        <td style="width:8px"></td>
        <td style="padding:14px;background:#f6f8fa;border-radius:10px;text-align:center">
          <div style="font-size:20px;font-weight:800;color:#9a3412">{counts.get('high', 0)}</div>
          <div style="font-size:11px;color:#5b6675">HIGH</div>
        </td>
        <td style="width:8px"></td>
        <td style="padding:14px;background:#f6f8fa;border-radius:10px;text-align:center">
          <div style="font-size:20px;font-weight:800;color:#92400e">{counts.get('medium', 0)}</div>
          <div style="font-size:11px;color:#5b6675">MEDIUM</div>
        </td>
      </tr>
    </table>
    <p style="margin:0 0 10px;color:#0b1220;font-size:14px"><strong>{score.get('headline', '')}</strong></p>
    <p style="margin:0 0 16px;color:#5b6675;font-size:13px;line-height:1.6">{score.get('summary_en') or score.get('summary_hi', '')}</p>
    <p style="margin:0 0 8px;font-size:13px;color:#5b6675">Your full report is unlocked: evidence for every finding, the exact fix, a copy-paste fix prompt, and the PDF report.</p>
    <p style="margin:0;font-size:13px"><a href="{pdf_url}" style="color:#0f766e">Download the PDF report</a></p>
    """
    subject = f"Your {config.BRAND} report - {score.get('score', 0)}/100 ({counts.get('critical', 0)} critical)"
    return subject, _shell(
        "Your report is ready",
        f"Scan of {record.get('target', '')}",
        body,
        "Open the full report",
        report_url,
        f"Questions? Reply to this email. - {config.BRAND}",
    )


def send_report(record: dict) -> dict:
    email = str(record.get("email") or "").strip().lower()
    if not email:
        return {"ok": False, "error": "no email on record"}
    subject, html = report_email_html(record)
    attachments = []
    try:
        blob = pdf.build_report_pdf(record)
        attachments = [{"filename": f"Trustfield-report-{record.get('id')}.pdf",
                        "content": base64.b64encode(blob).decode()}]
    except Exception:
        attachments = []
    result = send(email, subject, html, attachments)
    if result.get("ok") and config.ADMIN_EMAIL:
        send(
            config.ADMIN_EMAIL,
            f"[{config.BRAND}] new paid report - {record.get('id')}",
            _shell(
                "New paid report",
                f"{record.get('target', '')} - {record.get('email', '')}",
                f"<p style='color:#5b6675;font-size:13px'>Score {(record.get('score') or {}).get('score')}/100</p>",
                "Open report",
                f"{config.BASE_URL}/r/{record.get('id')}",
                "Admin notification",
            ),
        )
    return result


def send_welcome(email: str) -> dict:
    return send(
        email,
        f"Your {config.BRAND} scan is ready",
        _shell(
            "Thanks for scanning",
            "Here is what we do next: read the findings, fix the critical ones, then re-scan.",
            "<p style='color:#5b6675;font-size:13px'>If you want the fixes, PDF and badge, the Fix &amp; Proof pack is Rs. 499.</p>",
            "See your options",
            f"{config.BASE_URL}/#pricing",
            f"- {config.BRAND}",
        ),
    )


def send_free_report(record: dict) -> dict:
    """Free scan email: score, issue titles, unlock CTA. No PDF, no paid claims."""
    email = str(record.get("email") or "").strip().lower()
    if not email:
        return {"ok": False, "error": "no email on record"}
    score = record.get("score") or {}
    value = score.get("score")
    grade = score.get("grade") or ""
    findings = record.get("findings") or []
    titles = "".join(
        f"<li style='margin:6px 0;color:#38414d'>{f.get('title', '')} "
        f"<span style='color:#5b6675'>({f.get('severity', '')})</span></li>"
        for f in findings[:5]
    )
    link = f"{config.BASE_URL}/r/{record.get('id', '')}"
    html = _shell(
        "Your free scan is ready",
        f"Score {value}/100 ({grade}). You are seeing every issue we found - the evidence and fixes are in the paid report.",
        f"<ul style='padding-left:18px;margin:10px 0'>{titles}</ul>",
        f"See the full report",
        link,
        f"One-time report: {config.BASE_URL}/r/{record.get('id', '')}",
    )
    return send(email, f"Your {config.BRAND} scan - {value}/100 ({grade})", html)


def send_watch_alert(watch_row: dict, new_findings: list, scan_data: dict) -> dict:
    email = str(watch_row.get("email") or "").strip().lower()
    if not email:
        return {"ok": False, "error": "no email on watch"}
    rows = "".join(
        f"<li style='margin:6px 0;color:#38414d'>{f.get('title', '')} "
        f"<span style='color:#5b6675'>({f.get('severity', '')})</span></li>"
        for f in new_findings[:8]
    )
    report_url = f"{config.BASE_URL}/r/{scan_data.get('id', '')}"
    html = _shell(
        "New issue found on your app",
        f"Watch re-scanned {watch_row.get('target', '')} and found {len(new_findings)} new finding(s). "
        f"Score is now {scan_data.get('score', '?')}/100.",
        f"<ul style='padding-left:18px;margin:10px 0'>{rows}</ul>"
        f"<p style='color:#5b6675;font-size:13px'>Open the report for evidence and the exact fix.</p>",
        "Open the new report",
        report_url,
        f"You receive this because Watch is active for this app. Manage: {config.BASE_URL}/watch/manage?token="
        + str(watch_row.get("cancel_token", "")),
    )
    return send(email, f"{config.BRAND} Watch: {len(new_findings)} new finding(s)", html)


def send_watch_active(watch_row: dict) -> dict:
    email = str(watch_row.get("email") or "").strip().lower()
    if not email:
        return {"ok": False, "error": "no email on watch"}
    html = _shell(
        "Watch is active",
        f"We will re-scan {watch_row.get('target', '')} daily and email you only when something new appears.",
        f"<p style='color:#5b6675;font-size:13px'>Paid until {watch_row.get('paid_until', '')}. "
        f"Cancel anytime: <a href='{config.BASE_URL}/watch/manage?token={watch_row.get('cancel_token', '')}'>manage Watch</a>.</p>",
        "See the report",
        f"{config.BASE_URL}/r/{watch_row.get('scan_id', '')}",
        "Watch (beta): one payment per 30 days, no auto-renew.",
    )
    return send(email, f"{config.BRAND} Watch is active", html)


def send_watch_cancelled(watch_row: dict) -> dict:
    email = str(watch_row.get("email") or "").strip().lower()
    if not email:
        return {"ok": False, "error": "no email on watch"}
    html = _shell(
        "Watch cancelled",
        f"Watch for {watch_row.get('target', '')} has been cancelled. No further charges. You can start it again any time from your report.",
        "",
        "Open the report",
        f"{config.BASE_URL}/r/{watch_row.get('scan_id', '')}",
        "No auto-renew is active for this app.",
    )
    return send(email, f"{config.BRAND} Watch cancelled", html)
