"""Known CVEs for repo dependencies, via the free OSV.dev API (no key)."""
from __future__ import annotations

import json
import ssl
import urllib.request

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITY_MAP = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def query(dependencies: list[dict], timeout: float = 15) -> list:
    """dependencies: [{name, version, ecosystem}] -> raw OSV results per query."""
    if not dependencies:
        return []
    payload = {"queries": [
        {"package": {"name": item["name"], "ecosystem": item["ecosystem"]}, "version": item["version"]}
        for item in dependencies[:40]
    ]}
    request = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Trustfield/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            return json.loads(response.read() or b"{}").get("results") or []
    except Exception:
        return []


def severity(vuln: dict) -> str:
    raw = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(raw, str) and raw.upper() in SEVERITY_MAP:
        return SEVERITY_MAP[raw.upper()]
    return "medium"


def fixed_version(vuln: dict) -> str:
    for affected in vuln.get("affected") or []:
        for interval in affected.get("ranges") or []:
            for event in interval.get("events") or []:
                if event.get("fixed"):
                    return str(event["fixed"])
    return ""


def collect(results: list, dependencies: list[dict]) -> list[dict]:
    """Flatten OSV results into [{package, version, id, summary, severity, fixed}]."""
    out: list[dict] = []
    for index, result in enumerate(results):
        if index >= len(dependencies):
            break
        dep = dependencies[index]
        for vuln in (result or {}).get("vulns") or []:
            out.append({
                "package": dep["name"],
                "version": dep["version"],
                "id": str(vuln.get("id") or ""),
                "summary": str(vuln.get("summary") or "")[:160],
                "severity": severity(vuln),
                "fixed": fixed_version(vuln),
            })
    return out


def parse_requirements(text: str) -> list[dict]:
    deps = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        line = line.split(";")[0].strip()
        if "==" in line:
            name, version = line.split("==", 1)
        elif ">=" in line:
            name, version = line.split(">=", 1)
        else:
            continue
        name = name.strip().split("[")[0]
        version = version.strip().split(",")[0].strip()
        if name and version[:1].isdigit():
            deps.append({"name": name, "version": version, "ecosystem": "PyPI"})
    return deps
