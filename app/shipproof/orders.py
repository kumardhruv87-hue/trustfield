"""Payment records (JSONL). Kept separate from scans so invoices never get deleted."""
from __future__ import annotations

import json
import threading

from . import config

_lock = threading.Lock()


def append(order: dict) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    with _lock:
        with config.ORDERS_FILE.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(order, ensure_ascii=False) + "\n")


def all_orders(limit: int = 5000) -> list[dict]:
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


def summary() -> dict:
    orders = all_orders()
    paid = [order for order in orders if order.get("status") == "paid"]
    revenue = sum(int(order.get("amount_minor") or 0) for order in paid)
    return {
        "orders": len(paid),
        "revenue_inr": round(revenue / 100, 2),
        "recent": paid[-10:],
    }
