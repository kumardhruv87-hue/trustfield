"""Secret / credential detection.

Every rule is deliberately high-signal: false positives destroy trust in the
report, so we skip anything that looks like a placeholder or example value.
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass

from .findings import Finding

# Values that are obviously placeholders, not real credentials.
PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "your_",
    "your-",
    "xxx",
    "changeme",
    "replace",
    "dummy",
    "sample",
    "test_",
    "fake",
    "000000",
    "abcdef",
    "<",
    "{{",
    "${",
)


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    pattern: re.Pattern[str]
    severity: str
    why: str
    fix: str
    effort: str = "10 min"


def _rule(
    rid: str,
    name: str,
    pattern: str,
    severity: str,
    why: str,
    fix: str,
    effort: str = "10 min",
) -> Rule:
    return Rule(rid, name, re.compile(pattern), severity, why, fix, effort)


RULES: tuple[Rule, ...] = (
    _rule(
        "secret.anthropic_key",
        "Anthropic API key",
        r"\bsk-ant-[A-Za-z0-9_-]{20,}",
        "critical",
        "Anyone holding this key can spend your Anthropic credits. Keys in shipped "
        "code have already reached every visitor's browser cache.",
        "Revoke the key in the Anthropic console, create a new one, and keep it "
        "server-side only (move the call behind an API route).",
    ),
    _rule(
        "secret.openai_key",
        "OpenAI API key",
        r"\bsk-(?!ant-|live_|test_)(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}",
        "critical",
        "A leaked OpenAI key is money: it is metered, so a scraper can burn your "
        "credit balance in hours. This is the most common way AI-built apps get "
        "an unexpected four-figure bill.",
        "Revoke it at platform.openai.com/api-keys, issue a new key, and add a "
        "monthly hard spend limit on the account today.",
    ),
    _rule(
        "secret.supabase_secret_key",
        "Supabase secret key",
        r"\bsb_secret_[A-Za-z0-9_-]{10,}",
        "critical",
        "This is Supabase's new-style secret key. It bypasses Row Level Security and is "
        "equivalent to full database access — it must never reach a browser.",
        "Rotate the key in Supabase → Project Settings → API keys, then use it only in "
        "server-side code or edge functions.",
    ),
    _rule(
        "secret.stripe_live",
        "Stripe live secret key",
        r"\bsk_live_[0-9A-Za-z]{16,}",
        "critical",
        "This key can create charges, issue refunds and read your customers' "
        "payment data. In a client bundle it is equivalent to handing over your "
        "Stripe account.",
        "Roll the key in the Stripe dashboard immediately, then keep it in a "
        "server-only environment variable.",
    ),
    _rule(
        "secret.stripe_restricted",
        "Stripe restricted key",
        r"\brk_live_[0-9A-Za-z]{16,}",
        "critical",
        "A restricted live key still moves real money within its scope.",
        "Roll the key in the Stripe dashboard and move it to a server-only "
        "environment variable.",
    ),
    _rule(
        "secret.resend",
        "Resend API key",
        r"\bre_[0-9A-Za-z]{20,}",
        "critical",
        "This key can send email as your domain — a gift to phishing campaigns "
        "and a fast way to get your domain blacklisted.",
        "Revoke it in the Resend dashboard and issue a new server-side key.",
    ),
    _rule(
        "secret.github_token",
        "GitHub token",
        r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})",
        "critical",
        "A GitHub token in front-end code can read or write private repos, "
        "including secrets you thought were hidden.",
        "Revoke the token in GitHub settings and re-issue it with the minimum "
        "scope; never ship it to the browser.",
    ),
    _rule(
        "secret.aws_access_key",
        "AWS access key id",
        r"\bAKIA[0-9A-Z]{16}\b",
        "critical",
        "AWS keys are the classic cloud-bill bomb: a leaked pair can spin up "
        "instances and run up thousands of dollars.",
        "Deactivate the key in IAM, rotate credentials, and add an AWS budget "
        "alert while you are there.",
    ),
    _rule(
        "secret.google_api_key",
        "Google API key",
        r"\bAIza[0-9A-Za-z_-]{30,}",
        "high",
        "This key may be usable against paid Google APIs depending on how it is "
        "restricted.",
        "Add HTTP-referrer and API restrictions in Google Cloud Console, or move "
        "the call server-side.",
    ),
    _rule(
        "secret.slack_token",
        "Slack token",
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}",
        "critical",
        "A Slack token can read private messages and post as your workspace apps.",
        "Revoke the token in Slack and re-issue it server-side only.",
    ),
    _rule(
        "secret.huggingface",
        "Hugging Face token",
        r"\bhf_[A-Za-z0-9]{30,}",
        "high",
        "The token grants access to your private models and inference quota.",
        "Revoke it at huggingface.co/settings/tokens and keep it server-side.",
    ),
    _rule(
        "secret.groq",
        "Groq API key",
        r"\bgsk_[A-Za-z0-9]{20,}",
        "critical",
        "A metered inference key — someone else can spend your quota.",
        "Rotate the key in the Groq console and keep it server-side.",
    ),
    _rule(
        "secret.replicate",
        "Replicate token",
        r"\br8_[A-Za-z0-9]{24,}",
        "critical",
        "Replicate is pay-per-run; a leaked token is a direct bill.",
        "Rotate the token at replicate.com/account/api-tokens.",
    ),
    _rule(
        "secret.sendgrid",
        "SendGrid API key",
        r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}",
        "critical",
        "This key can send mail as your domain.",
        "Delete the key in SendGrid and issue a restricted, server-side one.",
    ),
    _rule(
        "secret.private_key",
        "Private key committed",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        "critical",
        "A committed private key compromises every certificate, server or token "
        "pair it belongs to.",
        "Treat it as compromised, regenerate the key pair, and remove it from git "
        "history (not just the latest commit).",
    ),
    _rule(
        "secret.database_url",
        "Database connection string with password",
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:@/'\"]+:[^\s@/'\"]+@",
        "high",
        "A connection string with a live password usually means full read/write "
        "access to your production data from anywhere.",
        "Rotate the database password, then load it from a server-side secret "
        "store.",
    ),
    _rule(
        "secret.generic_assignment",
        "Hardcoded secret-looking value",
        r"(?i)\b(?:api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|password)\b['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-./+=]{20,}['\"]",
        "high",
        "A credential-looking literal is baked into the code. If this file ships "
        "to the browser, so does the secret.",
        "Move the value into a server-side environment variable and rotate it.",
        "20 min",
    ),
)

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
MAX_HITS_PER_RULE = 8


def _looks_placeholder(value: str) -> bool:
    low = value.lower()
    return any(marker in low for marker in PLACEHOLDER_MARKERS)


def redact(value: str) -> str:
    value = value.strip().strip("'\"")
    if len(value) <= 12:
        return value[:2] + "…" + value[-2:]
    return value[:8] + "…" + value[-4:]


def jwt_role(token: str) -> str:
    """Decode a JWT payload and return its role claim (or '')."""
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        role = data.get("role") or data.get("user_role") or ""
        return str(role)
    except Exception:
        return ""


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def scan_text(text: str, filename: str) -> list[Finding]:
    """Return findings for one file's text content."""
    if not text:
        return []
    out: list[Finding] = []
    seen_spans: set[tuple[int, int]] = set()

    for rule in RULES:
        hits = 0
        for match in rule.pattern.finditer(text):
            if hits >= MAX_HITS_PER_RULE:
                break
            start, end = match.span()
            if (start, end) in seen_spans:
                continue
            value = match.group(0)
            if _looks_placeholder(value):
                continue
            seen_spans.add((start, end))
            line = _line_of(text, start)
            out.append(
                Finding(
                    id=rule.id,
                    title=f"{rule.name} found in {filename}",
                    severity=rule.severity,
                    category="Secrets & keys",
                    why=rule.why,
                    fix=rule.fix,
                    evidence=f"{filename}:{line} — {redact(value)}",
                    effort=rule.effort,
                    ref="https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                )
            )
            hits += 1

    # Supabase service_role JWTs are the single most damaging leak in
    # AI-built apps: the key bypasses Row Level Security entirely.
    for match in JWT_RE.finditer(text):
        token = match.group(0)
        if jwt_role(token) != "service_role":
            continue
        line = _line_of(text, match.start())
        out.append(
            Finding(
                id="secret.supabase_service_role_jwt",
                title=f"Supabase service_role key in {filename}",
                severity="critical",
                category="Secrets & keys",
                why="The service_role key bypasses Row Level Security completely. "
                "With it, anyone can read, edit and delete every row in every table "
                "of your database.",
                fix="Rotate the JWT secret in Supabase (Project Settings → API → "
                "JWT Settings), then use the key only in a server-side context.",
                evidence=f"{filename}:{line} — {redact(token)}",
                effort="15 min",
                ref="https://supabase.com/docs/guides/api/api-keys",
            )
        )
    return out


def scan_value(value: str) -> bool:
    """True if a single value looks like a real credential (used for env files)."""
    if not value or _looks_placeholder(value):
        return False
    return any(rule.pattern.search(value) for rule in RULES)
