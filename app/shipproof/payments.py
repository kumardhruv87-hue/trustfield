"""Payment webhook verification (Razorpay + Stripe) — stdlib only."""
from __future__ import annotations

import hashlib
import hmac
import time

MAX_SKEW_SECONDS = 300


def razorpay_verify(raw: bytes, signature: str, secret: str) -> bool:
    if not secret or not signature:
        return False
    expected = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.strip())


def stripe_verify(raw: bytes, header: str, secret: str, tolerance: int = MAX_SKEW_SECONDS) -> bool:
    if not secret or not header:
        return False
    parts: dict[str, str] = {}
    for item in header.split(","):
        if "=" in item:
            key, value = item.strip().split("=", 1)
            parts.setdefault(key, value)
    timestamp, signature = parts.get("t", ""), parts.get("v1", "")
    if not timestamp or not signature:
        return False
    try:
        if abs(time.time() - int(timestamp)) > tolerance:
            return False
    except ValueError:
        return False
    expected = hmac.new(
        secret.encode("utf-8"), f"{timestamp}.".encode("utf-8") + raw, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def _safe_report_id(value: str) -> str:
    value = str(value or "").strip().lower()
    return value if 6 <= len(value) <= 24 and all(ch.isalnum() for ch in value) else ""


def razorpay_event(payload: dict) -> dict | None:
    event = str(payload.get("event") or "")
    if event not in ("payment.captured", "order.paid"):
        return None
    wrapper = payload.get("payload") or {}
    entity = ((wrapper.get("payment") or {}).get("entity")) or ((wrapper.get("order") or {}).get("entity")) or {}
    if not entity:
        return None
    notes = entity.get("notes") or {}
    return {
        "provider": "razorpay",
        "event": event,
        "provider_id": str(entity.get("id") or ""),
        "email": str(entity.get("email") or "").strip().lower()[:200],
        "amount_minor": int(entity.get("amount") or 0),
        "currency": str(entity.get("currency") or "INR").upper(),
        "product": str(notes.get("product") or "report").lower(),
        "report_id": _safe_report_id(str(notes.get("report_id") or entity.get("receipt") or "")),
    }


def stripe_event(payload: dict) -> dict | None:
    if str(payload.get("type") or "") != "checkout.session.completed":
        return None
    session = (payload.get("data") or {}).get("object") or {}
    metadata = session.get("metadata") or {}
    email = ((session.get("customer_details") or {}).get("email") or "").strip().lower()[:200]
    return {
        "provider": "stripe",
        "event": "checkout.session.completed",
        "provider_id": str(session.get("id") or ""),
        "email": email,
        "amount_minor": int(session.get("amount_total") or 0),
        "currency": str(session.get("currency") or "inr").upper(),
        "product": str(metadata.get("product") or "report").lower(),
        "report_id": _safe_report_id(str(metadata.get("report_id") or session.get("client_reference_id") or "")),
    }


def create_payment_link(scan_id: str, amount_inr: int) -> str:
    """Create a Razorpay payment link that carries this report's id."""
    import base64 as _b64, json as _json, ssl as _ssl, urllib.request as _url
    if not (config.RAZORPAY_KEY_ID and config.RAZORPAY_KEY_SECRET):
        return ""
    auth = _b64.b64encode(f"{config.RAZORPAY_KEY_ID}:{config.RAZORPAY_KEY_SECRET}".encode()).decode()
    payload = {
        "amount": int(amount_inr) * 100,
        "currency": "INR",
        "accept_partial": False,
        "description": f"{config.BRAND} full report",
        "notes": {"report_id": scan_id, "product": "report"},
        "callback_url": f"{config.BASE_URL}/r/{scan_id}?paid=1",
        "callback_method": "get",
    }
    request = _url.Request(
        "https://api.razorpay.com/v1/payment_links",
        data=_json.dumps(payload).encode(),
        method="POST",
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
    )
    try:
        with _url.urlopen(request, timeout=20, context=_ssl.create_default_context()) as resp:
            return _json.loads(resp.read()).get("short_url", "")
    except Exception:
        return ""
