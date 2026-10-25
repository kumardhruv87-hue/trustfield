"""Slack / Discord alerts for sales and watch events (no SDK, no cost)."""
from __future__ import annotations

import json
import ssl
import urllib.request

from . import config


def configured() -> bool:
    return bool(config.SLACK_WEBHOOK_URL or config.DISCORD_WEBHOOK_URL)


def _post(url: str, payload: dict) -> bool:
    try:
        request = urllib.request.Request(
            url, data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "Trustfield/1.0"},
        )
        with urllib.request.urlopen(request, timeout=8, context=ssl.create_default_context()) as response:
            return 200 <= response.status < 300
    except Exception:
        return False


def send(title: str, message: str, link: str = "") -> bool:
    if not configured():
        return False
    text = f"*{title}*\n{message}" + (f"\n{link}" if link else "")
    ok = False
    if config.SLACK_WEBHOOK_URL:
        ok = _post(config.SLACK_WEBHOOK_URL, {"text": text}) or ok
    if config.DISCORD_WEBHOOK_URL:
        ok = _post(config.DISCORD_WEBHOOK_URL, {"content": text.replace("*", "**")}) or ok
    return ok
