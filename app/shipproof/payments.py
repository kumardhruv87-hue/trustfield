"""Payment webhook verification (Razorpay + Stripe) — stdlib only."""
from __future__ import annotations

from . import config

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
        "watch_id": str(notes.get("watch_id") or "")[:40],
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


def create_watch_link(scan_id: str, watch_id: str) -> str:
    """One-time link for 30 days of Watch (beta billing)."""
    import base64 as _b64, json as _json, ssl as _ssl, urllib.request as _url
    if not (config.RAZORPAY_KEY_ID and config.RAZORPAY_KEY_SECRET):
        return ""
    auth = _b64.b64encode(f"{config.RAZORPAY_KEY_ID}:{config.RAZORPAY_KEY_SECRET}".encode()).decode()
    amount = int(float(config.WATCH_INR)) * 100
    payload = {
        "amount": amount,
        "currency": "INR",
        "accept_partial": False,
        "description": f"{config.BRAND} Watch - 30 days",
        "notes": {"report_id": scan_id, "product": "watch", "watch_id": watch_id},
        "callback_url": f"{config.BASE_URL}/r/{scan_id}?watch=1",
        "callback_method": "get",
    }
    request = _url.Request(
        "https://api.razorpay.com/v1/payment_links",
        data=_json.dumps(payload).encode(),
        method="POST",
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json",
                 "User-Agent": "Trustfield/1.0"},
    )
    try:
        with _url.urlopen(request, timeout=20, context=_ssl.create_default_context()) as resp:
            return _json.loads(resp.read()).get("short_url", "")
    except Exception:
        return ""


def _basic_auth() -> str:
    import base64 as _b64
    return _b64.b64encode(f"{config.RAZORPAY_KEY_ID}:{config.RAZORPAY_KEY_SECRET}".encode()).decode()


def _rzp(method: str, path: str, payload: dict | None = None, timeout: float = 20) -> dict:
    import json as _json, ssl as _ssl, urllib.request as _url
    data = _json.dumps(payload).encode() if payload is not None else None
    request = _url.Request(
        "https://api.razorpay.com" + path, data=data, method=method,
        headers={"Authorization": f"Basic {_basic_auth()}", "Content-Type": "application/json",
                 "User-Agent": "Trustfield/1.0"},
    )
    with _url.urlopen(request, timeout=timeout, context=_ssl.create_default_context()) as response:
        return _json.loads(response.read() or b"{}")


def create_or_get_plan() -> str:
    """Create (once) a monthly Rs 499 plan and cache its id in Supabase storage."""
    import json as _json
    from . import storage
    cached = storage.get_json("razorpay_plan.json") or {}
    if cached.get("plan_id"):
        return str(cached["plan_id"])
    if not (config.RAZORPAY_KEY_ID and config.RAZORPAY_KEY_SECRET):
        return ""
    payload = {
        "period": "monthly",
        "interval": 1,
        "item": {
            "name": f"{config.BRAND} Watch",
            "amount": int(float(config.WATCH_INR)) * 100,
            "currency": "INR",
            "description": "Daily security re-checks with email alerts",
        },
        "notes": {"product": "watch"},
    }
    try:
        plan = _rzp("POST", "/v1/plans", payload)
    except Exception:
        return ""
    plan_id = str(plan.get("id") or "")
    if plan_id:
        storage.put_json("razorpay_plan.json", {"plan_id": plan_id})
    return plan_id


def create_subscription(scan_id: str, watch_id: str) -> str:
    """Recurring subscription checkout URL for Watch (auto-renews monthly)."""
    plan_id = create_or_get_plan()
    if not plan_id:
        return ""
    payload = {
        "plan_id": plan_id,
        "total_count": 120,
        "quantity": 1,
        "customer_notify": 1,
        "notes": {"report_id": scan_id, "product": "watch", "watch_id": watch_id},
    }
    try:
        sub = _rzp("POST", "/v1/subscriptions", payload)
    except Exception:
        return ""
    return str(sub.get("short_url") or "")


def cancel_subscription(subscription_id: str) -> bool:
    if not subscription_id:
        return False
    try:
        _rzp("POST", f"/v1/subscriptions/{subscription_id}/cancel", {"cancel_at_cycle_end": 1})
        return True
    except Exception:
        return False


def razorpay_subscription_event(payload: dict) -> dict | None:
    event = str(payload.get("event") or "")
    if not event.startswith("subscription."):
        return None
    wrapper = payload.get("payload") or {}
    entity = ((wrapper.get("subscription") or {}).get("entity")) or {}
    if not entity:
        return None
    notes = entity.get("notes") or {}
    current_end = entity.get("current_end")
    import datetime as _dt
    until = ""
    if isinstance(current_end, (int, float)) and current_end > 0:
        until = _dt.datetime.fromtimestamp(current_end, _dt.timezone.utc).isoformat(timespec="seconds")
    return {
        "event": event,
        "subscription_id": str(entity.get("id") or ""),
        "status": str(entity.get("status") or ""),
        "watch_id": str(notes.get("watch_id") or "")[:40],
        "report_id": _safe_report_id(str(notes.get("report_id") or "")),
        "until": until,
        "email": str((entity.get("customer") or {}).get("email") or "").strip().lower()[:200] if isinstance(entity.get("customer"), dict) else "",
    }
