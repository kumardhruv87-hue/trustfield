"""Finding model shared by every scanner."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {name: len(SEVERITY_ORDER) - i for i, name in enumerate(SEVERITY_ORDER)}
SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}
SEVERITY_COLOR = {
    "critical": "#ff4d6d",
    "high": "#ff9f43",
    "medium": "#ffd93d",
    "low": "#6bcBff",
    "info": "#8b93a7",
}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    why: str = ""
    fix: str = ""
    evidence: str = ""
    effort: str = "10 min"
    ref: str = ""
    confidence: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def finding(
    id: str,
    title: str,
    severity: str,
    category: str,
    why: str,
    fix: str,
    evidence: str = "",
    effort: str = "10 min",
    ref: str = "",
    confidence: str = "high",
) -> Finding:
    if severity not in SEVERITY_RANK:
        raise ValueError(f"unknown severity: {severity}")
    return Finding(
        id=id,
        title=title,
        severity=severity,
        category=category,
        why=why,
        fix=fix,
        evidence=evidence,
        effort=effort,
        ref=ref,
        confidence=confidence,
    )


def counts(findings: list[Finding]) -> dict[str, int]:
    out = {name: 0 for name in SEVERITY_ORDER}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def worst_severity(findings: list[Finding]) -> str:
    if not findings:
        return "none"
    return min(findings, key=lambda f: SEVERITY_RANK[f.severity]).severity


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Worst first, then by category for stable output."""
    return sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], f.category, f.id))


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.id, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
