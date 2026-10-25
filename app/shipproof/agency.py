"""Agency pack: 10 report credits per purchase, code-based handover."""
from __future__ import annotations

import datetime as dt
import secrets

from . import config, storage


def _path():
    return config.DATA_DIR / "agencies.json"


def load() -> list[dict]:
    import json
    rows = []
    try:
        rows = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        rows = []
    if not isinstance(rows, list):
        rows = []
    remote = storage.get_json("agencies.json") or []
    if isinstance(remote, list) and remote:
        if not rows:
            rows = remote
        elif len(remote) > len(rows):
            seen = {str(r.get("id") or "") for r in rows}
            rows = remote + [r for r in rows if str(r.get("id") or "") not in seen]
    return rows


def save(rows: list[dict]) -> None:
    import json
    config.ensure_dirs()
    try:
        _path().write_text(json.dumps(rows), encoding="utf-8")
    except OSError:
        pass
    storage.put_json("agencies.json", rows)


def create(email: str, name: str = "", credits: int = 10) -> dict:
    rows = load()
    existing = next((r for r in rows if r.get("email") == email and int(r.get("credits", 0)) > int(r.get("used", 0))), None)
    if existing:
        existing["credits"] = int(existing.get("credits", 0)) + credits
        save(rows)
        return existing
    row = {
        "id": "ag_" + secrets.token_hex(5),
        "code": "TF-AG-" + secrets.token_hex(3).upper(),
        "email": (email or "").strip().lower(),
        "name": (name or "")[:80],
        "credits": int(credits),
        "used": 0,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }
    rows.append(row)
    save(rows)
    return row


def find(code: str) -> dict | None:
    wanted = (code or "").strip().upper()
    return next((r for r in load() if str(r.get("code", "")).upper() == wanted), None)


def credits_left(row: dict) -> int:
    return max(0, int(row.get("credits", 0)) - int(row.get("used", 0)))


def consume(code: str) -> dict | None:
    rows = load()
    for row in rows:
        if str(row.get("code", "")).upper() == (code or "").strip().upper() and credits_left(row) > 0:
            row["used"] = int(row.get("used", 0)) + 1
            save(rows)
            return row
    return None


def public(code: str) -> dict | None:
    row = find(code)
    if row is None:
        return None
    return {"name": row.get("name", ""), "email": row.get("email", ""), "code": row.get("code", ""),
            "credits": int(row.get("credits", 0)), "used": int(row.get("used", 0)),
            "left": credits_left(row)}


def list_rows() -> list[dict]:
    return load()
