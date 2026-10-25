"""Payment records (JSONL). Kept separate from scans so invoices never get deleted."""
from __future__ import annotations

import json
import threading

from . import config, storage

_lock = threading.Lock()


def append(order: dict) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    with _lock:
        with config.ORDERS_FILE.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(order, ensure_ascii=False) + "\n")
        if storage.enabled():
            rows = storage.get_json("orders.json") or []
            rows.append(order)
            storage.put_json("orders.json", rows[-5000:])


def all_orders(limit: int = 5000) -> list[dict]:
    if storage.enabled():
        remote = storage.get_json("orders.json")
        if remote:
            return remote[-limit:]
    if not config.ORDERS_FILE.exists():
        return []
    out: list[dict] = []
    with _lock:
        with config.ORDERS_FILE.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out[-limit:]


def exists(provider_id: str) -> bool:
    if not provider_id:
        return False
    return any(order.get("provider_id") == provider_id for order in all_orders())


def _is_test_order(order: dict) -> bool:
    provider_id = str(order.get("provider_id") or "").lower()
    return bool(order.get("is_test") is True or order.get("payment_mode") == "test"
                or provider_id.startswith(("pay_test_", "pay_audit_", "pay_fake_", "pay_demo_", "cs_test_")))


def _checks() -> dict:
    path = config.DATA_DIR / "payment_checks.json"
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        result = storage.get_json("payment_checks.json") or {}
    return result if isinstance(result, dict) else {}


def record_check(provider_id: str, receipt: dict) -> None:
    """Keep reconciliation evidence separately; never rewrite the original ledger."""
    with _lock:
        config.ensure_dirs()
        checks = _checks()
        checks[provider_id] = {**receipt, "checked_at": config.now_iso()}
        path = config.DATA_DIR / "payment_checks.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(checks), encoding="utf-8")
        temporary.replace(path)
        storage.put_json("payment_checks.json", checks)


def summary() -> dict:
    checks = _checks()
    unique = {}
    for index, order in enumerate(all_orders()):
        key = (str(order.get("provider") or ""), str(order.get("provider_id") or f"manual-row-{index}"))
        unique[key] = order
    records = []
    for original in unique.values():
        row = dict(original)
        receipt = checks.get(str(row.get("provider_id"))) or {}
        if receipt.get("verified"):
            row.update(amount_minor=receipt["amount_minor"], currency=receipt["currency"],
                       payment_mode=receipt.get("payment_mode", "unknown"), verification="gateway_lookup")
        row["receipt"] = receipt
        amount = int(row.get("amount_minor") or 0)
        if _is_test_order(row):
            category = "Test payment"
        elif row.get("provider") == "manual" or not row.get("provider_id"):
            category = "Manual access / grant"
        elif row.get("status") == "paid" and amount > 0 and row.get("verification") in ("signed_webhook", "gateway_lookup") and row.get("payment_mode") == "live":
            category = "Provider confirmed"
        else:
            category = "Needs review"
        row["classification"] = category
        records.append(row)
    paid = [r for r in records if r.get("status") == "paid"]
    sales = [r for r in paid if r["classification"] not in ("Test payment", "Manual access / grant")
             and int(r.get("amount_minor") or 0) > 0 and r.get("currency", "INR") == "INR"]
    confirmed = [r for r in sales if r["classification"] == "Provider confirmed"]
    records.sort(key=lambda r: str(r.get("paid_at") or ""), reverse=True)
    return {
        "orders": len(sales),
        "revenue_inr": round(sum(int(r.get("amount_minor") or 0) for r in sales) / 100, 2),
        "confirmed_orders": len(confirmed),
        "confirmed_inr": round(sum(int(r.get("amount_minor") or 0) for r in confirmed) / 100, 2),
        "review_count": sum(r["classification"] == "Needs review" for r in records),
        "test_orders": sum(r["classification"] == "Test payment" for r in records),
        "manual_grants": sum(r["classification"] == "Manual access / grant" for r in records),
        "records": records,
        "recent": records[:10],
    }
