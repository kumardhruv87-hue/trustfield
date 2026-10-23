"""Supabase Storage adapter — keeps reports alive on Render's free plan.

Uses the private Storage bucket (no SQL editor needed). Service key stays server-side.
Falls back to local files when SUPABASE_URL / SUPABASE_SERVICE_KEY are not set.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request

from . import config


def enabled() -> bool:
    return bool(config.SUPABASE_URL and config.SUPABASE_SERVICE_KEY)


def _headers(extra: dict | None = None) -> dict:
    base = {
        "apikey": config.SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {config.SUPABASE_SERVICE_KEY}",
    }
    base.update(extra or {})
    return base


def _request(method: str, path: str, data: bytes | None = None, extra: dict | None = None, timeout: float = 15):
    url = config.SUPABASE_URL + path
    request = urllib.request.Request(url, data=data, method=method, headers=_headers(extra))
    with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
        return response.status, response.read()


def ensure_bucket() -> bool:
    if not enabled():
        return False
    try:
        _request("GET", f"/storage/v1/bucket/{config.SUPABASE_BUCKET}")
        return True
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            return False
    try:
        body = json.dumps({"id": config.SUPABASE_BUCKET, "name": config.SUPABASE_BUCKET, "public": False}).encode()
        _request("POST", "/storage/v1/bucket", body, {"Content-Type": "application/json"})
        return True
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return False


def put_json(key: str, obj) -> bool:
    if not enabled():
        return False
    try:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        _request("POST", f"/storage/v1/object/{config.SUPABASE_BUCKET}/{key}", body,
                 {"Content-Type": "application/json", "x-upsert": "true"})
        return True
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return False


def get_json(key: str):
    if not enabled():
        return None
    try:
        _, data = _request("GET", f"/storage/v1/object/{config.SUPABASE_BUCKET}/{key}")
        return json.loads(data) if data else None
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None
