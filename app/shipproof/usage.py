"""Service usage counters for the admin cost dashboard (AI, email, scans)."""
from __future__ import annotations

import datetime as dt
import json
import os
import threading

from . import config, storage

_lock = threading.RLock()
SOURCES = {"direct", "google", "linkedin", "youtube", "x", "community", "other"}


def source(value: str) -> str:
    value = str(value or "direct").strip().lower()
    return value if value in SOURCES else "other"


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


def _save(data: dict, required: bool = False) -> None:
    config.ensure_dirs()
    temporary = _path().with_suffix(".tmp")
    try:
        temporary.write_text(json.dumps(data), encoding="utf-8")
        os.replace(temporary, _path())
    except OSError:
        if required:
            raise
    saved = storage.put_json("usage.json", data)
    if required and storage.enabled() and not saved:
        raise OSError("Could not persist AI allowance")


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
    with _lock:
        data = _load()
        bucket = data.setdefault(kind, {})
        bucket[_today()] = int(bucket.get(_today(), 0)) + int(amount)
        _save(data)


def reserve(kind: str, limit: int) -> bool:
    """Reserve before a paid call; serialized on the single application instance."""
    with _lock:
        if not _path().exists() and storage.enabled():
            restored = storage.get_json("usage.json")
            if restored is None:
                raise OSError("AI quota storage is unavailable")
            _save(restored, required=True)
        data = _load()
        bucket = data.setdefault(kind, {})
        used = int(bucket.get(_today(), 0))
        if used >= limit:
            return False
        bucket[_today()] = used + 1
        _save(data, required=True)
        return True


def funnel(event: str, channel: str = "direct") -> None:
    if event not in {"visit", "scan_start", "scan_error", "scan_complete", "checkout", "purchase"}:
        return
    bump("funnel_" + event + "_" + source(channel))


def funnel_summary() -> list[dict]:
    return [{"source": channel, **{event: month("funnel_" + event + "_" + channel)
            for event in ("visit", "scan_complete", "checkout", "purchase")}}
            for channel in sorted(SOURCES)]


def today(kind: str) -> int:
    return int((_load().get(kind) or {}).get(_today(), 0))


def month(kind: str) -> int:
    prefix = _month()
    return sum(int(v) for k, v in (_load().get(kind) or {}).items() if str(k).startswith(prefix))
