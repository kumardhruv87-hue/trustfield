"""Per-team API keys for the public scan API (hashed at rest)."""
from __future__ import annotations

import datetime as dt
import hashlib
import secrets

from . import config, storage


def _path():
    return config.DATA_DIR / "apikeys.json"


def load() -> list[dict]:
    import json
    try:
        rows = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        rows = storage.get_json("apikeys.json") or []
    return rows if isinstance(rows, list) else []


def save(rows: list[dict]) -> None:
    import json
    config.ensure_dirs()
    try:
        _path().write_text(json.dumps(rows), encoding="utf-8")
    except OSError:
        pass
    storage.put_json("apikeys.json", rows)


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create(name: str) -> str:
    raw = "tf_" + secrets.token_urlsafe(24)
    rows = load()
    rows.append({
        "name": (name or "default")[:60],
        "prefix": raw[:11],
        "hash": _hash(raw),
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "calls": 0,
        "last_used": "",
        "revoked": False,
    })
    save(rows)
    return raw


def find(raw: str) -> dict | None:
    if not raw or not raw.startswith("tf_"):
        return None
    digest = _hash(raw)
    return next((r for r in load() if r.get("hash") == digest and not r.get("revoked")), None)


def record_use(row: dict) -> None:
    rows = load()
    for item in rows:
        if item.get("hash") == row.get("hash"):
            item["calls"] = int(item.get("calls", 0)) + 1
            item["last_used"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
            save(rows)
            return


def revoke(prefix: str) -> bool:
    rows = load()
    for item in rows:
        if item.get("prefix") == prefix:
            item["revoked"] = True
            save(rows)
            return True
    return False


def public_list() -> list[dict]:
    return [{"name": r.get("name"), "prefix": r.get("prefix"), "calls": r.get("calls", 0),
             "created_at": r.get("created_at"), "last_used": r.get("last_used"), "revoked": r.get("revoked", False)}
            for r in load()]
