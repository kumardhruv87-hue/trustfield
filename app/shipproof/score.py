"""Scoring, grading, risk assessment and the Hinglish verdict."""
from __future__ import annotations

from .findings import SEVERITY_ORDER, Finding, counts as count_severities, sort_findings

WEIGHTS = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
MAX_DEDUCTION_PER_RULE = 3  # one repeated rule should not zero the whole score

GRADE_BANDS: tuple[tuple[int, str], ...] = (
    (95, "A+"),
    (85, "A"),
    (75, "B+"),
    (65, "B"),
    (50, "C"),
    (35, "D"),
    (0, "F"),
)

# Findings that mean "this can cost you real money fast".
COST_IDS = {
    "live.client_side_ai_call",
    "live.exposed_env",
    "live.supabase_service_role_in_client",
    "secret.openai_key",
    "secret.anthropic_key",
    "secret.groq",
    "secret.replicate",
    "secret.huggingface",
    "secret.google_api_key",
    "secret.supabase_service_role_jwt",
    "repo.public_env_secret",
    "repo.server_secret_in_client",
    "repo.ai_route_no_auth",
}

NO_CAP_IDS = {"repo.no_rate_limit", "repo.ai_route_no_auth", "live.client_side_ai_call"}

# Findings that mean "customer data can leak".
BREACH_IDS = {
    "repo.rls_missing",
    "repo.rls_no_policy",
    "repo.firebase_test_mode",
    "repo.firebase_test_mode_json",
    "live.supabase_service_role_in_client",
    "live.supabase_table_publicly_readable",
    "secret.supabase_secret_key",
    "secret.supabase_service_role_jwt",
    "live.exposed_env",
    "live.exposed_git_config",
    "repo.server_secret_in_client",
    "repo.webhook_unsigned",
    "repo.no_auth_middleware",
    "repo.ai_route_no_auth",
    "live.weak_cookie_flags",
    "repo.public_env_secret",
    "deep.firebase_open_rules",
    "deep.form_over_http",
    "deep.password_over_http",
    "deep.exposed_actuator_env",
    "deep.exposed_ops_file",
    "deep.token_in_localstorage",
    "repo.insecure_tls",
    "repo.ssrf",
    "repo.cors_default",
    "repo.prompt_injection",
    "repo.jwt_ignore_expiry",
    "repo.jwt_none_algorithm",
}


def grade_for(score: int) -> str:
    for floor, letter in GRADE_BANDS:
        if score >= floor:
            return letter
    return "F"


def _deduct(findings: list[Finding]) -> int:
    per_rule: dict[str, int] = {}
    per_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity == "info":
            continue
        used = per_rule.get(f.id, 0)
        if used >= MAX_DEDUCTION_PER_RULE:
            continue
        per_rule[f.id] = used + 1
        per_severity[f.severity] += WEIGHTS[f.severity]
    caps = {"critical": 100, "high": 60, "medium": 40, "low": 10}
    return sum(min(per_severity[sev], cap) for sev, cap in caps.items())


def _ids(findings: list[Finding]) -> set[str]:
    return {f.id for f in findings}


def cost_risk(findings: list[Finding], meta: dict) -> dict:
    ids = _ids(findings)
    money_key = bool(ids & COST_IDS)
    no_cap = bool(ids & NO_CAP_IDS)
    exposed_env = "live.exposed_env" in ids or "repo.env_committed" in ids

    if money_key and no_cap:
        return {
            "level": "critical",
            "title": "High risk of a runaway bill",
            "explain": "A paid AI key is exposed and there is no rate limit in front of the "
            "route that spends it. That is the exact combination behind most surprise AI "
            "bills.",
            "math": "Example maths (not a quote): 1 leaked key × 2,000 requests/day × "
            "~$0.01 per request ≈ $600/month — and a scraper can do that from one script.",
        }
    if money_key:
        return {
            "level": "high",
            "title": "A paid key is exposed",
            "explain": "Someone holding this key can spend your credits. A rate limit helps, "
            "but a leaked key bypasses your app entirely.",
            "math": "Example maths: 1 leaked key used at 500 requests/day × ~$0.01 ≈ "
            "$150/month, plus whatever the limit on your provider account allows.",
        }
    if exposed_env:
        return {
            "level": "medium",
            "title": "Configuration was exposed",
            "explain": "An env/config file is readable. Even if the values look harmless "
            "today, rotate whatever is inside it and re-check after every deploy.",
            "math": "No direct estimate — depends on which keys were inside.",
        }
    return {
        "level": "low",
        "title": "No obvious money leak found",
        "explain": "We did not find a paid key exposed to the browser. Keep a hard monthly "
        "spend cap with your AI provider anyway.",
        "math": "Add a spend cap: it is the cheapest insurance you can buy.",
    }


def breach_risk(findings: list[Finding]) -> dict:
    ids = _ids(findings)
    hits = sorted(ids & BREACH_IDS)
    critical = any(f.severity == "critical" for f in findings if f.id in BREACH_IDS)
    if critical:
        return {
            "level": "critical",
            "title": "Customer data is probably reachable by others",
            "explain": "One or more findings give an outsider a path to data your users "
            "trusted you with. Fix these before you take another signup.",
        }
    if hits:
        return {
            "level": "high",
            "title": "Data-access gaps found",
            "explain": "These findings either widen access or hide it. Review each one "
            "against how your app really reads data.",
        }
    return {
        "level": "low",
        "title": "No obvious data-exposure path found",
        "explain": "We could not see one from outside. That is not a guarantee — run the "
        "prompt-injection kit too if your app has a chatbot.",
    }


def headline(score: int, findings: list[Finding]) -> str:
    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    if crit:
        return f"{crit} critical issue{'s' if crit > 1 else ''} to fix before launch"
    if high:
        return f"{high} high-severity issue{'s' if high > 1 else ''} to fix before launch"
    if score >= 85:
        return "Looks solid — a few small things to tidy up"
    if score >= 70:
        return "Launch-ready after a couple of small fixes"
    if score >= 50:
        return "Fixable before launch — start with the top three"
    return "Several fixes needed before you announce"


def verdict_for(score: int, findings: list[Finding]) -> str:
    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    if crit:
        return "Do not launch yet. Fix the critical items first — each one is a way in."
    if high:
        return "Close, but not yet. Fix the high items, then re-scan before you announce."
    if score >= 75:
        return "Launch-ready. Apply the remaining fixes when you can, then re-scan after your next deploy."
    if score >= 55:
        return "Not blocking, but clear the medium items before you promote it — they are cheap to fix now."
    return "No critical issue, but the score is low enough that a small mistake becomes a real one."


def summary_en(score: int, findings: list[Finding], cost: dict, breach: dict) -> str:
    total = len(findings)
    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    top = sort_findings(findings)[0].title if findings else ""
    lines = [f"We ran the scan and found {total} issue{'s' if total != 1 else ''}: {crit} critical and {high} high. Score: {score}/100."]
    if top:
        lines.append(f"Start with: {top}.")
    if breach["level"] == "critical":
        lines.append("Customer data is reachable in a way we could see from outside. Fix this before launch.")
    elif cost["level"] in ("critical", "high"):
        lines.append("A paid key is exposed, so a stranger can spend your credits. Rotate the key and add a spend cap.")
    if crit:
        lines.append("Do not ship until the critical items are closed.")
    elif high:
        lines.append("Fix the high items, then re-scan before you announce.")
    else:
        lines.append("No blocker found. Keep re-scanning after each deploy — a check is a point in time.")
    return " ".join(lines)


def summary_hi(score: int, findings: list[Finding], cost: dict, breach: dict) -> str:
    total = len(findings)
    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    top = sort_findings(findings)[0].title if findings else ""
    lines = [
        f"Scan me {total} issue mile — {crit} critical aur {high} high.",
        f"Score {score}/100 hai.",
    ]
    if top:
        lines.append(f"Sabse pehle ye theek karo: {top}.")
    if breach["level"] == "critical":
        lines.append("User data leak ka risk high hai — ise launch se pehle fix karna zaroori hai.")
    elif cost["level"] in ("critical", "high"):
        lines.append("AI key leak ka paisa risk hai — key rotate karo aur spend cap laga do.")
    if crit:
        lines.append("Critical issues clear hone tak app public mat karo.")
    elif high:
        lines.append("High issues fix karke dubara scan chala lo, phir launch karo.")
    else:
        lines.append("Launch ke liye theek hai — roz naye issues nahi aa rahe, ye check karte raho.")
    return " ".join(lines)


def top_actions(findings: list[Finding], limit: int = 3) -> list[dict]:
    out: list[dict] = []
    for f in sort_findings(findings):
        if f.severity == "info":
            continue
        out.append({"title": f.title, "severity": f.severity, "effort": f.effort, "fix": f.fix})
        if len(out) >= limit:
            break
    return out


def assess(findings: list[Finding], meta: dict | None = None) -> dict:
    meta = meta or {}
    ordered = sort_findings(findings)
    sev = count_severities(findings)
    score = max(0, 100 - _deduct(findings))
    if sev["critical"] >= 3:
        score = min(score, 30)
    elif sev["critical"] >= 1:
        score = min(score, 45)

    cost = cost_risk(findings, meta)
    breach = breach_risk(findings)
    grade = grade_for(score)
    return {
        "score": score,
        "grade": grade,
        "headline": headline(score, ordered),
        "verdict": verdict_for(score, ordered),
        "counts": sev,
        "total": len(findings),
        "has_critical": sev["critical"] > 0,
        "has_high": sev["high"] > 0,
        "cost_risk": cost,
        "breach_risk": breach,
        "summary_hi": summary_hi(score, ordered, cost, breach),
        "summary_en": summary_en(score, ordered, cost, breach),
        "top_actions": top_actions(ordered),
        "severity_order": SEVERITY_ORDER,
    }
