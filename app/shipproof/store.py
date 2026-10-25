"""Tiny file-backed store: scans as JSON, leads as JSONL.

No database, no dependencies. Every record is written atomically so a crash
cannot leave a half-written report behind.
"""
from __future__ import annotations

import base64
import json
import os
import secrets as _secrets
import threading
import time
from pathlib import Path

from . import config, storage

ID_RE = __import__("re").compile(r"^[a-z0-9]{6,24}$")
_lock = threading.Lock()


def new_id() -> str:
    raw = _secrets.token_bytes(8)
    return base64.b32encode(raw).decode("ascii").lower().rstrip("=")[:10]


def _path(scan_id: str) -> Path:
    if not ID_RE.match(scan_id or ""):
        raise ValueError("invalid scan id")
    return config.SCANS_DIR / f"{scan_id}.json"


def save_scan(record: dict) -> str:
    config.ensure_dirs()
    scan_id = record["id"]
    target = _path(scan_id)
    tmp = target.with_suffix(f".{os.getpid()}.tmp")
    payload = json.dumps(record, ensure_ascii=False, indent=None)
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, target)
    storage.put_json(f"scans/{scan_id}.json", record)
    return scan_id


def load_scan(scan_id: str) -> dict | None:
    try:
        path = _path(scan_id)
    except ValueError:
        return None
    if not path.exists():
        remote = storage.get_json(f"scans/{scan_id}.json")
        if remote is not None:
            try:
                path.write_text(json.dumps(remote, ensure_ascii=False), encoding="utf-8")
            except OSError:
                pass
            return remote
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def update_scan(scan_id: str, **changes) -> dict | None:
    with _lock:
        record = load_scan(scan_id)
        if record is None:
            return None
        record.update(changes)
        save_scan(record)
        return record


def unlock(scan_id: str) -> dict | None:
    return update_scan(scan_id, unlocked=True, unlocked_at=config.now_iso())


def save_lead(email: str, scan_id: str = "", source: str = "web") -> None:
    config.ensure_dirs()
    email = (email or "").strip().lower()[:200]
    if "@" not in email or "." not in email:
        raise ValueError("invalid email")
    line = json.dumps(
        {"email": email, "scan_id": scan_id, "source": source, "at": config.now_iso()},
        ensure_ascii=False,
    )
    with _lock:
        with config.LEADS_FILE.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    if storage.enabled():
        leads = storage.get_json("leads.json") or []
        leads.append(json.loads(line))
        storage.put_json("leads.json", leads[-5000:])


def counts() -> dict:
    config.ensure_dirs()
    scans = len(list(config.SCANS_DIR.glob("*.json"))) if config.SCANS_DIR.exists() else 0
    leads = 0
    if config.LEADS_FILE.exists():
        with config.LEADS_FILE.open("r", encoding="utf-8") as fh:
            leads = sum(1 for line in fh if line.strip())
    return {"scans": scans, "leads": leads}


def purge_old(days: int = 30) -> int:
    """Delete scan records older than N days (privacy-friendly default)."""
    config.ensure_dirs()
    cutoff = time.time() - days * 86400
    removed = 0
    for path in config.SCANS_DIR.glob("*.json"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except OSError:
            continue
    if storage.enabled():
        cutoff_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(cutoff))
        stale = []
        for item in storage.list_prefix("scans/"):
            created = str(item.get("created_at") or "")
            if created and created[:19] < cutoff_iso:
                stale.append("scans/" + str(item.get("name") or ""))
        if stale:
            storage.delete_many(stale)
            removed += len(stale)
    return removed


def hydrate_from_cloud(limit: int = 60) -> int:
    """Pull recent scans from Supabase Storage into the local cache (admin + report reads)."""
    from . import storage
    if not storage.enabled():
        return 0
    try:
        objects = storage.list_prefix("scans/", limit=limit, newest=True)
    except Exception:
        return 0
    config.ensure_dirs()
    written = 0
    for obj in objects[:limit]:
        name = str((obj or {}).get("name") or "")
        if not name.endswith(".json"):
            continue
        target = config.SCANS_DIR / name.rsplit("/", 1)[-1]
        if target.exists():
            continue
        data = storage.get_json("scans/" + name.rsplit("/", 1)[-1])
        if not isinstance(data, dict) or not data.get("id"):
            continue
        try:
            target.write_text(json.dumps(data), encoding="utf-8")
            written += 1
        except OSError:
            continue
    return written
