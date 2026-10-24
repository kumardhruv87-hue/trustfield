"""Service usage counters for the admin cost dashboard (AI, email, scans)."""
from __future__ import annotations

import datetime as dt
import json

from . import config, storage


def _path():
    return config.DATA_DIR / "usage.json"


def _today() -> str:
    return dt.date.today().isoformat()


def _month() -> str:
    return _today()[:7]


def _load() -> dict:
    try:
        return json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    config.ensure_dirs()
    try:
        _path().write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass
    storage.put_json("usage.json", data)


def hydrate() -> int:
    """Restore counters from Supabase after a redeploy (Render free disk is ephemeral)."""
    if _path().exists() and _path().stat().st_size > 0:
        return 0
    data = storage.get_json("usage.json") or {}
    if not data:
        return 0
    try:
        config.ensure_dirs()
        _path().write_text(json.dumps(data), encoding="utf-8")
        return len(data)
    except OSError:
        return 0


def bump(kind: str, amount: int = 1) -> None:
    data = _load()
    bucket = data.setdefault(kind, {})
    bucket[_today()] = int(bucket.get(_today(), 0)) + int(amount)
    _save(data)


def today(kind: str) -> int:
    return int((_load().get(kind) or {}).get(_today(), 0))


def month(kind: str) -> int:
    prefix = _month()
    return sum(int(v) for k, v in (_load().get(kind) or {}).items() if str(k).startswith(prefix))
