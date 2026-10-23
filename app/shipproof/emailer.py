"""Transactional email via Resend. Without an API key it writes to data/outbox/."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path

from . import config, sign


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


def send(to: str, subject: str, html: str) -> dict:
    if not to or "@" not in to:
        return {"ok": False, "error": "no recipient"}
    if not configured():
        return _outbox(to, subject, html)
    payload = {"from": config.EMAIL_FROM, "to": [to], "subject": subject, "html": html}
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
            return {"ok": 200 <= response.status < 300, "mode": "resend", "status": response.status}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"ok": False, "error": str(exc)[:200]}


def _shell(title: str, intro: str, body: str, cta_label: str, cta_url: str, footer: str) -> str:
    button = (
        f'<a href="{cta_url}" style="display:inline-block;background:#5eead4;color:#04211d;'
        f'font-weight:700;padding:12px 20px;border-radius:10px;text-decoration:none">{cta_label}</a>'
        if cta_url
        else ""
    )
    return f"""<!doctype html><html><body style="margin:0;background:#070b14;padding:24px;font-family:Arial,Helvetica,sans-serif;color:#e8eefb">
<div style="max-width:560px;margin:0 auto;background:#0f172a;border:1px solid rgba(148,163,184,.2);border-radius:16px;overflow:hidden">
  <div style="padding:20px 24px;border-bottom:1px solid rgba(148,163,184,.15)">
    <span style="font-size:18px;font-weight:800;color:#fff">{config.BRAND}</span>
    <span style="font-size:11px;color:#5eead4;letter-spacing:.08em;margin-left:8px">PROOF BEFORE YOU SHIP</span>
  </div>
  <div style="padding:24px">
    <h1 style="margin:0 0 8px;font-size:22px;color:#fff">{title}</h1>
    <p style="margin:0 0 18px;color:#93a1b8;font-size:14px;line-height:1.6">{intro}</p>
    {body}
    <p style="margin:22px 0 0">{button}</p>
  </div>
  <div style="padding:16px 24px;border-top:1px solid rgba(148,163,184,.15);color:#6b7789;font-size:11px;line-height:1.6">
    {footer}<br>Only scan apps you own or are authorised to test. A check is a point in time, not a guarantee.
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
        <td style="padding:14px;background:#0b1222;border-radius:10px;text-align:center">
          <div style="font-size:30px;font-weight:800;color:#5eead4">{score.get('score', 0)}<span style="font-size:13px;color:#93a1b8">/100</span></div>
          <div style="font-size:11px;color:#93a1b8;letter-spacing:.08em">SCORE</div>
        </td>
        <td style="width:12px"></td>
        <td style="padding:14px;background:#0b1222;border-radius:10px;text-align:center">
          <div style="font-size:20px;font-weight:800;color:#ff4d6d">{counts.get('critical', 0)}</div>
          <div style="font-size:11px;color:#93a1b8">CRITICAL</div>
        </td>
        <td style="width:8px"></td>
        <td style="padding:14px;background:#0b1222;border-radius:10px;text-align:center">
          <div style="font-size:20px;font-weight:800;color:#ff9f43">{counts.get('high', 0)}</div>
          <div style="font-size:11px;color:#93a1b8">HIGH</div>
        </td>
        <td style="width:8px"></td>
        <td style="padding:14px;background:#0b1222;border-radius:10px;text-align:center">
          <div style="font-size:20px;font-weight:800;color:#ffd93d">{counts.get('medium', 0)}</div>
          <div style="font-size:11px;color:#93a1b8">MEDIUM</div>
        </td>
      </tr>
    </table>
    <p style="margin:0 0 10px;color:#e8eefb;font-size:14px"><strong>{score.get('headline', '')}</strong></p>
    <p style="margin:0 0 16px;color:#93a1b8;font-size:13px;line-height:1.6">{score.get('summary_en') or score.get('summary_hi', '')}</p>
    <p style="margin:0 0 8px;font-size:13px;color:#93a1b8">Your report is unlocked: evidence, fixes, fix prompts, the 12-attack prompt kit and the PDF report.</p>
    <p style="margin:0;font-size:13px"><a href="{pdf_url}" style="color:#5eead4">Download the PDF report</a></p>
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
    result = send(email, subject, html)
    if result.get("ok") and config.ADMIN_EMAIL:
        send(
            config.ADMIN_EMAIL,
            f"[{config.BRAND}] new paid report - {record.get('id')}",
            _shell(
                "New paid report",
                f"{record.get('target', '')} - {record.get('email', '')}",
                f"<p style='color:#93a1b8;font-size:13px'>Score {(record.get('score') or {}).get('score')}/100</p>",
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
            "<p style='color:#93a1b8;font-size:13px'>If you want the fixes, PDF and badge, the Fix &amp; Proof pack is Rs. 499.</p>",
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
        f"<li style='margin:6px 0;color:#cbd5e1'>{f.get('title', '')} "
        f"<span style='color:#93a1b8'>({f.get('severity', '')})</span></li>"
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
