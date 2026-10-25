"""Watch subscriptions: scheduled re-scans with new-finding alerts.

Storage: local data/watch.json + Supabase mirror, so it survives free-tier redeploys.
Billing for the beta: a one-time Razorpay link per 30 days (no auto-renew yet).
"""
from __future__ import annotations

import datetime as dt
import secrets

from . import config, storage


def _path():
    return config.DATA_DIR / "watch.json"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return value.isoformat(timespec="seconds")


def load() -> list[dict]:
    import json
    try:
        rows = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        rows = storage.get_json("watch.json") or []
    return rows if isinstance(rows, list) else []


def save(rows: list[dict]) -> None:
    import json
    config.ensure_dirs()
    try:
        _path().write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass
    storage.put_json("watch.json", rows)


def create(scan_id: str, email: str, target: str, days: int = 30) -> dict:
    rows = load()
    existing = next((r for r in rows if r.get("scan_id") == scan_id and r.get("active")), None)
    if existing:
        return existing
    record = {
        "id": "w_" + secrets.token_hex(6),
        "scan_id": scan_id,
        "email": email,
        "target": target,
        "active": False,
        "created_at": _iso(_now()),
        "paid_until": "",
        "last_checked_at": "",
        "next_check_at": _iso(_now() + dt.timedelta(days=1)),
        "last_scan_id": "",
        "last_findings": [],
        "interval_days": 1,
        "checkout_pending": True,
        "cancel_token": secrets.token_urlsafe(16),
    }
    rows.append(record)
    save(rows)
    return record


def by_id(watch_id: str) -> dict | None:
    return next((r for r in load() if r.get("id") == watch_id), None)


def by_cancel_token(token: str) -> dict | None:
    return next((r for r in load() if r.get("cancel_token") == token), None)


def activate(watch_id: str, days: int = 30) -> dict | None:
    rows = load()
    for row in rows:
        if row.get("id") == watch_id:
            now = _now()
            row["active"] = True
            row["checkout_pending"] = False
            row["paid_until"] = _iso(now + dt.timedelta(days=days))
            row["next_check_at"] = _iso(now)
            save(rows)
            return row
    return None


def cancel(watch_id: str) -> bool:
    rows = load()
    for row in rows:
        if row.get("id") == watch_id:
            row["active"] = False
            row["cancelled_at"] = _iso(_now())
            save(rows)
            return True
    return False


def due(limit: int = 3) -> list[dict]:
    now = _now()
    out = []
    for row in load():
        if not row.get("active"):
            continue
        try:
            next_at = dt.datetime.fromisoformat(str(row.get("next_check_at")))
        except ValueError:
            next_at = now
        if next_at <= now:
            out.append(row)
        if len(out) >= limit:
            break
    return out


def mark_checked(watch_id: str, last_scan_id: str, findings: list[str], hours: int = 24) -> None:
    rows = load()
    for row in rows:
        if row.get("id") == watch_id:
            row["last_checked_at"] = _iso(_now())
            row["last_scan_id"] = last_scan_id
            row["last_findings"] = findings[-200:]
            row["next_check_at"] = _iso(_now() + dt.timedelta(hours=hours))
            save(rows)
            return


def set_checkout(watch_id: str, url: str) -> None:
    rows = load()
    for row in rows:
        if row.get("id") == watch_id:
            row["checkout_url"] = url
            save(rows)
            return


def count_active() -> int:
    return sum(1 for r in load() if r.get("active"))


def set_subscription(watch_id: str, subscription_id: str) -> None:
    rows = load()
    for row in rows:
        if row.get("id") == watch_id:
            row["subscription_id"] = subscription_id
            save(rows)
            return


def extend(watch_id: str, until_iso: str = "", days: int = 30) -> dict | None:
    """Activate or extend a subscription watch until the paid-through date."""
    rows = load()
    for row in rows:
        if row.get("id") == watch_id:
            now = _now()
            row["active"] = True
            row["checkout_pending"] = False
            row["auto_renew"] = True
            if until_iso:
                row["paid_until"] = until_iso[:19]
            else:
                row["paid_until"] = _iso(now + dt.timedelta(days=days))
            row["next_check_at"] = _iso(now)
            save(rows)
            return row
    return None


def disable_auto_renew(watch_id: str) -> dict | None:
    """Stop future renewals but keep access until paid_until."""
    rows = load()
    for row in rows:
        if row.get("id") == watch_id:
            row["auto_renew"] = False
            row["checkout_pending"] = False
            save(rows)
            return row
    return None


def expiring(days: int = 3) -> list[dict]:
    """Active rows whose paid_until is within N days and not yet reminded for that date."""
    now = _now()
    out = []
    for row in load():
        if not row.get("active"):
            continue
        paid_until = str(row.get("paid_until") or "")
        if not paid_until:
            continue
        try:
            until = dt.datetime.fromisoformat(paid_until[:19]).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
        if now <= until <= now + dt.timedelta(days=days) and row.get("expiry_reminded_for") != paid_until:
            out.append(row)
    return out


def mark_expiry_reminded(watch_id: str) -> None:
    rows = load()
    for row in rows:
        if row.get("id") == watch_id:
            row["expiry_reminded_for"] = str(row.get("paid_until") or "")
            save(rows)
            return
