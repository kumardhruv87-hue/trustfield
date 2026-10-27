"""Opt-in, revocable client summaries. Public data never contains a report ID."""
from __future__ import annotations

import json
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import config, handover, repo, storage, store

TOKEN = re.compile(r"^[A-Za-z0-9_-]{32}$")
STATES = ("check_passed", "still_detected", "not_confirmed", "new")
_lock = threading.RLock()


def _stamp(value) -> datetime:
    parsed = datetime.fromisoformat(str(value))
    return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc)


def snapshot(before: dict, after: dict, include_target: bool = False) -> dict:
    if not after.get("unlocked") or after.get("verified_against") != before.get("id"):
        raise ValueError("A paid, linked re-check is required.")
    if before.get("target") != after.get("target") or before.get("kind") != after.get("kind"):
        raise ValueError("Both scans must cover the same target and scan type.")
    if before.get("error") or after.get("error"):
        raise ValueError("Incomplete scans cannot be published as a client handover.")
    expires = _stamp(before.get("created_at")) + timedelta(days=30)
    if expires <= config.now():
        raise ValueError("The original report's 30-day sharing window has ended.")
    counts = {state: 0 for state in STATES}
    for row in handover.compare(before, after):
        counts[row["state"]] += 1
    kind = "repo" if after.get("kind") == "repo" else "url"
    target = "Target hidden by owner"
    if include_target:
        parsed = repo.parse_github(str(after.get("target"))) if kind == "repo" else None
        target = "/".join(parsed) if parsed else (urlsplit(str(after.get("target"))).hostname or "Target hidden by owner")
    # Explicit allowlist: never serialize findings, evidence, source IDs or email.
    return {
        "schema": "trustfield.client-handover.v1", "target": target,
        "scope": "Public repository static checks" if kind == "repo" else "Public URL exposure checks",
        "original_observed_at": _stamp(before.get("created_at")).isoformat(),
        "rechecked_at": _stamp(after.get("created_at")).isoformat(),
        "issued_at": config.now_iso(), "expires_at": expires.isoformat(),
        "before_score": max(0, min(100, int((before.get("score") or {}).get("score", 0)))),
        "after_score": max(0, min(100, int((after.get("score") or {}).get("score", 0)))),
        "original_findings": len({f["id"] for f in before.get("findings") or []}),
        "current_findings": len({f["id"] for f in after.get("findings") or []}),
        "comparison": counts,
        "limits": ["A mapped check passing is not proof that all instances are fixed.",
                   "A missing finding without a passing mapped check stays unconfirmed.",
                   "No logged-in testing, exploitation or database contents were reviewed.",
                   "Static repository checks do not verify the deployed environment.",
                   "This is a point-in-time summary, not a penetration test or security certification."],
    }


def _path(token: str) -> Path:
    if not TOKEN.fullmatch(token or ""):
        raise ValueError("Invalid summary link.")
    return config.DATA_DIR / "handover_links" / (token + ".json")


def _write(token: str, row: dict) -> None:
    path = _path(token)
    if storage.enabled() and not storage.put_json("handover_links/" + path.name, row):
        raise OSError("Summary storage is unavailable. Please try again.")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(row), encoding="utf-8")
    temporary.replace(path)


def _read(token: str) -> dict | None:
    path = _path(token)
    # Cloud is authoritative: a failed read must not resurrect a revoked link
    # from another process's stale local copy.
    if storage.enabled():
        row = storage.get_json("handover_links/" + path.name)
    else:
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            row = None
    return row if isinstance(row, dict) else None


def load(token: str) -> dict | None:
    try:
        row = _read(token)
        if row and row.get("active") is True and _stamp(row["summary"]["expires_at"]) > config.now():
            return row["summary"]
    except (ValueError, KeyError, TypeError):
        pass
    return None


def publish(before: dict, after: dict, include_target: bool = False) -> tuple[str, dict]:
    summary = snapshot(before, after, include_target)
    with _lock:
        current = store.load_scan(after["id"])
        if current is None:
            raise ValueError("The re-check is no longer available.")
        token = str(current.get("handover_token") or "")
        if token:
            existing = _read(token)
            if existing is None and storage.enabled():
                raise OSError("The existing link's status is unavailable. Try again later.")
            if existing and existing.get("active") is True and _stamp(existing["summary"]["expires_at"]) > config.now():
                return token, existing["summary"]
        token = secrets.token_urlsafe(24)
        _write(token, {"active": True, "summary": summary})
        try:
            if not store.update_scan(after["id"], handover_token=token):
                raise OSError("The owner controls could not be saved.")
            if storage.enabled():
                remote = storage.get_json("scans/" + after["id"] + ".json") or {}
                if remote.get("handover_token") != token:
                    raise OSError("The owner controls could not be persisted.")
        except OSError:
            # Never return a live link whose owner controls were not saved.
            _write(token, {"active": False, "revoked_at": config.now_iso()})
            raise
        return token, summary


def revoke(after: dict) -> None:
    with _lock:
        current = store.load_scan(after["id"]) or {}
        token = str(current.get("handover_token") or "")
        if not token:
            return
        # Write a tombstone even if the existing object cannot be read.
        _write(token, {"active": False, "revoked_at": config.now_iso()})


def purge_expired() -> None:
    """Remove only expired/revoked objects in this feature's own namespace."""
    root = config.DATA_DIR / "handover_links"
    names = {p.name for p in root.glob("*.json")} if root.exists() else set()
    if storage.enabled():
        offset = 0
        while True:
            batch = storage.list_prefix("handover_links/", limit=1000, offset=offset)
            names.update(str(row.get("name") or "") for row in batch)
            if len(batch) < 1000:
                break
            offset += len(batch)
    expired = []
    for name in names:
        token = name.removesuffix(".json")
        if not TOKEN.fullmatch(token):
            continue
        row = _read(token)
        # Failed remote reads are not evidence of expiration.
        if row is None:
            continue
        try:
            inactive = row.get("active") is False or _stamp(row["summary"]["expires_at"]) <= config.now()
        except (ValueError, KeyError, TypeError):
            continue
        if inactive:
            expired.append("handover_links/" + name)
            _path(token).unlink(missing_ok=True)
    if expired and storage.enabled():
        storage.delete_many(expired)


def sample() -> dict:
    return {"schema": "trustfield.client-handover.v1", "sample": True,
            "target": "Example app · fictional data", "scope": "Public repository static checks",
            "original_observed_at": "Illustrative original scan", "rechecked_at": "Illustrative re-check",
            "issued_at": "Sample only", "expires_at": "Real links expire with the original report's 30-day window",
            "before_score": 54, "after_score": 81, "original_findings": 5, "current_findings": 2,
            "comparison": {"check_passed": 3, "still_detected": 1, "not_confirmed": 1, "new": 1},
            "limits": ["This page uses fictional numbers to demonstrate the feature.",
                       "A higher score does not certify an app as secure.",
                       "Not observed is not the same as confirmed fixed.",
                       "Real summaries contain no evidence snippets, email addresses or full report links."]}
