"""Signed links (PDF downloads, admin actions). HMAC only, stdlib only."""
from __future__ import annotations

import base64
import hashlib
import hmac
import time

from . import config


def _key() -> bytes:
    return config.SECRET_KEY.encode("utf-8")


def sign(scan_id: str, purpose: str = "pdf", ttl_days: int | None = None) -> str:
    expires = int(time.time()) + (ttl_days if ttl_days is not None else config.TOKEN_TTL_DAYS) * 86400
    body = f"{purpose}:{scan_id}:{expires}"
    digest = hmac.new(_key(), body.encode(), hashlib.sha256).hexdigest()[:40]
    raw = f"{body}:{digest}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def verify(token: str, purpose: str) -> str | None:
    """Return the scan id when the token is valid for this purpose, else None."""
    if not token or len(token) > 300:
        return None
    try:
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        token_purpose, scan_id, expires, digest = raw.split(":", 3)
    except (ValueError, UnicodeDecodeError):
        return None
    if token_purpose != purpose:
        return None
    try:
        if int(expires) < time.time():
            return None
    except ValueError:
        return None
    expected = hmac.new(_key(), f"{token_purpose}:{scan_id}:{expires}".encode(), hashlib.sha256).hexdigest()[:40]
    if not hmac.compare_digest(expected, digest):
        return None
    return scan_id
