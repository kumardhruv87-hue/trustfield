"""Anonymised scan aggregate — the data moat behind the public Vulnerability Index.

We store only: timestamp, kind, platform/stack, which checks failed, which
finding ids appeared. No target, no host, no email, no evidence.
"""
from __future__ import annotations

import json
import threading
from collections import Counter

from . import config, storage

_lock = threading.Lock()


def record(scan: dict) -> None:
    meta = scan.get("meta") or {}
    findings = scan.get("findings") or []
    checks = scan.get("checks") or []
    row = {
        "ts": scan.get("created_at", ""),
        "kind": scan.get("kind", ""),
        "platform": meta.get("platform") or "",
        "stack": (meta.get("stack") or [])[:6],
        "checks": len(checks),
        "failed_checks": [c.get("id") for c in checks if not c.get("ok")][:40],
        "findings": [{"id": f.get("id"), "severity": f.get("severity")} for f in findings][:40],
    }
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    with _lock:
        with config.INDEX_FILE.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    if storage.enabled():
        rows = storage.get_json("index.json") or []
        rows.append(row)
        storage.put_json("index.json", rows[-20000:])


def aggregate(limit: int = 20000) -> dict:
    if not config.INDEX_FILE.exists():
        return {
            "scans": 0,
            "platforms": [],
            "top_issues": [],
            "top_checks": [],
            "updated": "",
            "severity": {},
        }
    rows: list[dict] = []
    with _lock:
        with config.INDEX_FILE.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    rows = rows[-limit:]
    total = len(rows)
    platforms: Counter[str] = Counter()
    issues: Counter[str] = Counter()
    checks: Counter[str] = Counter()
    severity: Counter[str] = Counter()
    for row in rows:
        platform = row.get("platform") or "Other"
        platforms[platform] += 1
        for finding in row.get("findings") or []:
            if finding.get("id"):
                issues[finding["id"]] += 1
                severity[finding.get("severity", "info")] += 1
        for check in row.get("failed_checks") or []:
            if check:
                checks[check] += 1

    def serialize(counter: Counter[str], names: dict[str, str] | None = None) -> list[dict]:
        return [
            {
                "id": key,
                "label": (names or {}).get(key, key),
                "count": count,
                "rate": round(count * 100.0 / total, 1) if total else 0.0,
            }
            for key, count in counter.most_common(10)
        ]

    return {
        "scans": total,
        "platforms": [
            {"name": name, "count": count, "rate": round(count * 100.0 / total, 1) if total else 0}
            for name, count in platforms.most_common(6)
        ],
        "top_issues": serialize(issues),
        "top_checks": serialize(checks),
        "severity": dict(severity),
        "updated": rows[-1].get("ts", "") if rows else "",
    }
