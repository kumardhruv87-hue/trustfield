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


TEST_MARKERS = ("test", "audit", "fake", "demo")


def _is_test_order(order: dict) -> bool:
    provider_id = str(order.get("provider_id") or "").lower()
    email = str(order.get("email") or "").lower()
    if any(marker in provider_id for marker in TEST_MARKERS):
        return True
    if provider_id.startswith(("manual", "link:")):
        return True
    if email.endswith(("example.com", "example.org", "test.com", "test.local")):
        return True
    return False


def summary() -> dict:
    orders = all_orders()
    paid = [order for order in orders if order.get("status") == "paid"]
    sales = [order for order in paid if not _is_test_order(order)]
    revenue = sum(int(order.get("amount_minor") or 0) for order in sales)
    return {
        "orders": len(sales),
        "revenue_inr": round(revenue / 100, 2),
        "test_orders": len(paid) - len(sales),
        "recent": sales[-10:] or paid[-10:],
    }
