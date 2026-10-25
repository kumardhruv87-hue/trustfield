"""Repository scanner for public GitHub repos.

We download a zipball, read text files in memory, and look for the mistakes AI
code generators make again and again. Nothing is written to disk, nothing is
executed, and the zip is size-capped (zip-bomb guard).
"""
from __future__ import annotations

import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from typing import Iterable

from . import config, osv, net, repoextra, secrets
from .findings import Finding, dedupe

# --------------------------------------------------------------------------
# setup
# --------------------------------------------------------------------------

SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    "out",
    "coverage",
    "vendor",
    "venv",
    ".venv",
    "env",
    "__pycache__",
    ".cache",
    ".turbo",
    ".vercel",
    "target",
    "bin",
    "obj",
    "pods",
    "playwright-report",
}

TEXT_EXT = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro",
    ".py", ".rb", ".go", ".php", ".java", ".kt", ".swift", ".dart", ".cs",
    ".sql", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".sh", ".bash", ".ps1", ".tf", ".gradle", ".properties", ".xml",
    ".html", ".htm", ".md", ".txt", ".prisma", ".graphql", ".gql", ".dockerfile",
}

TEXT_NAMES = {
    ".env", ".env.local", ".env.production", ".env.development", ".env.example",
    ".gitignore", ".dockerignore", "dockerfile", "procfile", "makefile",
    "firestore.rules", "storage.rules", "database.rules.json", "next.config.js",
    "next.config.mjs", "vite.config.js", "vite.config.ts", "vercel.json",
    "netlify.toml", "package.json", "pyproject.toml", "requirements.txt",
    "cors.json", "app.yaml", "render.yaml", "fly.toml",
}

MAX_UNPACKED_TEXT_BYTES = 40 * 1024 * 1024
MIN_MEANINGFUL_FILES = 1

GITHUB_RE = re.compile(r"^https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:/.*)?$")
SHORT_RE = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$")


@dataclass
class Result:
    target: str = ""
    final_url: str = ""
    status: int = 0
    findings: list[Finding] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    error: str = ""

    @property
    def passed(self) -> list[str]:
        return [c["name"] for c in self.checks if c["ok"]]

    @property
    def failed(self) -> list[str]:
        return [c["name"] for c in self.checks if not c["ok"]]


class Collector:
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.checks: list[dict] = []

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def check(self, cid: str, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append({"id": cid, "name": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    def fail(self, cid: str, name: str, finding: Finding, detail: str = "") -> None:
        self.check(cid, name, False, detail)
        self.add(finding)


def parse_github(target: str) -> tuple[str, str] | None:
    raw = (target or "").strip()
    match = GITHUB_RE.match(raw)
    if match:
        owner, repo = match.group(1), match.group(2)
    else:
        match = SHORT_RE.match(raw)
        if not match:
            return None
        owner, repo = match.group(1), match.group(2)
    if owner in (".", "..") or repo in (".", ".."):
        return None
    return owner, repo


# --------------------------------------------------------------------------
# download + read
# --------------------------------------------------------------------------


def _download_zip(owner: str, repo: str, budget: net.Budget) -> bytes:
    branches = ["main", "master", "dev", "develop"]
    errors: list[str] = []
    for branch in branches:
        if budget.expired():
            break
        url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"
        res = net.safe_fetch(url, budget=budget, max_bytes=config.MAX_REPO_ZIP_BYTES, timeout=30)
        if res.status == 200 and res.body[:2] == b"PK":
            return res.body
        errors.append(f"{branch}:{res.status or res.error}")
    raise ValueError(
        "could not download the repo zip (is it public? tried branches: "
        + ", ".join(errors[:4])
        + ")"
    )


def _is_text_candidate(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    if name in TEXT_NAMES or name.startswith(".env"):
        return True
    dot = name.rfind(".")
    if dot == -1:
        return False
    return name[dot:] in TEXT_EXT


def _iter_text_files(zip_bytes: bytes) -> tuple[dict[str, str], dict]:
    """Return {relative_path: text} plus stats. Never extracts to disk."""
    files: dict[str, str] = {}
    stats = {"entries": 0, "skipped_large": 0, "skipped_binary": 0, "bytes": 0}
    total = 0
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        infos = zf.infolist()
        stats["entries"] = len(infos)
        if len(infos) > config.MAX_REPO_FILES:
            raise ValueError(f"repo has too many files ({len(infos)})")
        for info in infos:
            if info.is_dir():
                continue
            parts = info.filename.split("/")
            if len(parts) < 2:
                continue
            rel = "/".join(parts[1:])
            if not rel or any(p in SKIP_DIRS for p in parts[:-1]):
                continue
            if info.file_size > config.MAX_FILE_BYTES:
                stats["skipped_large"] += 1
                continue
            if not _is_text_candidate(rel):
                continue
            if total + info.file_size > MAX_UNPACKED_TEXT_BYTES:
                break
            try:
                data = zf.read(info)
            except Exception:
                continue
            if b"\x00" in data[:8192]:
                stats["skipped_binary"] += 1
                continue
            total += len(data)
            stats["bytes"] = total
            files[rel] = data.decode("utf-8", "replace")
    return files, stats


# --------------------------------------------------------------------------
# individual checks
# --------------------------------------------------------------------------

CLIENT_DIR_RE = re.compile(
    r"^(?:src/)?(?:app|pages|components|public|src/components|src/app|src/pages|src/hooks|src/lib/client)/",
    re.I,
)
CLIENT_EXT = (".tsx", ".jsx", ".vue", ".svelte", ".html")
SERVER_SECRET_NAMES = re.compile(
    r"\b(SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|"
    r"STRIPE_SECRET_KEY|STRIPE_WEBHOOK_SECRET|DATABASE_URL|PRIVATE_KEY|JWT_SECRET|"
    r"supabase\.auth\.admin|service_role)\b"
)
PUBLIC_SECRET_NAME = re.compile(
    r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC|GATSBY|NUXT_PUBLIC)_"
    r"[A-Z0-9_]*(?:SECRET|SERVICE|PRIVATE|ADMIN|PASSWORD|TOKEN|SERVICE_ROLE)[A-Z0-9_]*",
)
LLM_TOKEN = re.compile(
    r"\b(openai|anthropic|gemini|generativelanguage|groq|mistral|cohere|replicate|"
    r"together|openrouter|ollama|langchain|llamaindex)\b",
    re.I,
)
AUTH_TOKEN = re.compile(
    r"\b(getUser|getSession|getServerSession|auth\(\)|verifyToken|verifyIdToken|"
    r"requireAuth|currentUser|session\.user|supabase\.auth|clerk|firebase\.auth|"
    r"createServerClient|withAuth|isAuthenticated|req\.user)\b",
    re.I,
)
RATE_LIMIT_TOKEN = re.compile(
    r"(ratelimit|rate-limit|rate_limit|limiter|throttle|slowDown|bottleneck|upstash)",
    re.I,
)
CREATE_TABLE_RE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?[\"']?(?:(?:\w+)\.)?(\w+)[\"']?", re.I
)
RLS_RE = re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?[\"']?(?:(?:\w+)\.)?(\w+)[\"']?\s+enable\s+row\s+level\s+security",
    re.I,
)
POLICY_RE = re.compile(
    r"create\s+policy\s+(?:\w+\s+)?on\s+[\"']?(?:(?:\w+)\.)?(\w+)", re.I
)
STRIPE_SIG = re.compile(r"(constructEvent|constructEventAsync|verifySignature|svix|webhooks\.construct|stripe-signature)", re.I)


def _route_files(files: dict[str, str]) -> list[str]:
    out: list[str] = []
    for rel in files:
        low = rel.lower()
        if re.match(r"^(?:src/)?app/api/.+/route\.(ts|js|mjs|tsx|jsx)$", low):
            out.append(rel)
        elif re.match(r"^(?:src/)?pages/api/.+\.(ts|js|mjs)$", low):
            out.append(rel)
        elif re.match(r"^(?:src/)?(?:routes|server|backend|api)/.+\.(ts|js|py|go|php|rb)$", low):
            out.append(rel)
    return out


def _check_env_files(files: dict[str, str], c: Collector) -> None:
    committed = [
        rel
        for rel in files
        if rel.rsplit("/", 1)[-1].lower() in (".env", ".env.local", ".env.production", ".env.development")
        and rel.count("/") <= 2
    ]
    if committed:
        c.fail(
            "repo.env_committed",
            "No .env files committed",
            Finding(
                id="repo.env_committed",
                title="Environment file is committed to the repository",
                severity="critical",
                category="Secrets & keys",
                why="A committed .env is readable by anyone with repo access and stays in "
                "git history even after you delete it. If the repo ever leaks, every key "
                "inside it leaks with it.",
                fix="Remove the file from the repo (`git rm --cached .env`), add it to "
                ".gitignore, commit, and rotate every key it contained. Rewrite history "
                "if the repo is public.",
                evidence=", ".join(committed[:5]),
                effort="20 min",
            ),
        )
    else:
        c.check("repo.env_committed", "No .env files committed", True)

    gitignore = next((text for rel, text in files.items() if rel.lower() == ".gitignore"), "")
    if not gitignore:
        c.fail(
            "repo.gitignore",
            ".gitignore covers env files",
            Finding(
                id="repo.no_gitignore",
                title="No .gitignore file",
                severity="medium",
                category="Secrets & keys",
                why="Without one, it takes a single `git add .` to commit .env, node_modules "
                "or build output.",
                fix="Add a .gitignore that includes `.env*`, `node_modules/`, `.next/`, "
                "`dist/` and `*.log`.",
                evidence=".gitignore not found",
                effort="5 min",
            ),
        )
    elif not re.search(r"(?m)^\s*\.env", gitignore):
        c.fail(
            "repo.gitignore",
            ".gitignore covers env files",
            Finding(
                id="repo.gitignore_env",
                title=".gitignore does not ignore .env",
                severity="high",
                category="Secrets & keys",
                why="The next time anyone runs `git add .`, your keys get committed.",
                fix="Add `.env*` and `!.env.example` to .gitignore.",
                evidence="no `.env` line in .gitignore",
                effort="2 min",
            ),
        )
    else:
        c.check("repo.gitignore", ".gitignore covers env files", True)

    # NEXT_PUBLIC_ style variables that look like secrets
    hits: list[str] = []
    for rel, text in files.items():
        if rel.rsplit("/", 1)[-1].lower().startswith(".env.example"):
            continue
        for match in PUBLIC_SECRET_NAME.finditer(text):
            hits.append(f"{rel}: {match.group(0)}")
            if len(hits) >= 6:
                break
        if len(hits) >= 6:
            break
    if hits:
        c.fail(
            "repo.public_env_secret",
            "No secrets behind public env prefixes",
            Finding(
                id="repo.public_env_secret",
                title="Secret-looking variable uses a public env prefix",
                severity="critical",
                category="Secrets & keys",
                why="NEXT_PUBLIC_/VITE_/REACT_APP_ variables are inlined into the JavaScript "
                "shipped to every visitor. Putting a secret behind one of those prefixes "
                "publishes it.",
                fix="Rename it without the public prefix and read it only in server code. "
                "If it was ever deployed that way, rotate the secret.",
                evidence="; ".join(hits[:4]),
                effort="20 min",
            ),
        )
    else:
        c.check("repo.public_env_secret", "No secrets behind public env prefixes", True)


def _check_client_secrets(files: dict[str, str], c: Collector) -> None:
    hits: list[str] = []
    for rel, text in files.items():
        low = rel.lower()
        is_client = bool(CLIENT_DIR_RE.match(low)) or low.endswith(CLIENT_EXT) or ('"use client"' in text or "'use client'" in text)
        if not is_client:
            continue
        for match in SERVER_SECRET_NAMES.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            hits.append(f"{rel}:{line} → {match.group(0)}")
            if len(hits) >= 6:
                break
        if len(hits) >= 6:
            break
    if hits:
        c.fail(
            "repo.server_secret_in_client",
            "No server secrets in client code",
            Finding(
                id="repo.server_secret_in_client",
                title="Server-only secret referenced from browser code",
                severity="critical",
                category="Secrets & keys",
                why="Anything referenced from a component that runs in the browser can be "
                "read by a visitor. A service_role or provider secret here means full "
                "access for anyone who opens devtools.",
                fix="Move the call into a server route/action. Keep these names out of "
                "client components entirely, and rotate the key if it was ever bundled.",
                evidence="; ".join(hits[:4]),
                effort="30–60 min",
                confidence="medium",
            ),
        )
    else:
        c.check("repo.server_secret_in_client", "No server secrets in client code", True)


def _check_sql(files: dict[str, str], c: Collector) -> dict:
    sql_files = {rel: text for rel, text in files.items() if rel.lower().endswith(".sql")}
    info: dict = {"sql_files": len(sql_files)}
    if not sql_files:
        info["note"] = "no SQL migrations in repo"
        return info

    tables: dict[str, str] = {}
    rls: set[str] = set()
    policies: set[str] = set()
    for rel, text in sql_files.items():
        for match in CREATE_TABLE_RE.finditer(text):
            tables.setdefault(match.group(1).lower(), rel)
        for match in RLS_RE.finditer(text):
            rls.add(match.group(1).lower())
        for match in POLICY_RE.finditer(text):
            policies.add(match.group(1).lower())

    info["tables"] = len(tables)
    info["rls_enabled"] = len(rls)

    missing = sorted(name for name in tables if name not in rls)
    if missing:
        c.fail(
            "repo.rls",
            "Row Level Security in migrations",
            Finding(
                id="repo.rls_missing",
                title=f"Row Level Security not enabled on {len(missing)} table(s)",
                severity="critical",
                category="Database access",
                why="Supabase exposes your tables to the browser through the anon key. "
                "Without RLS, that public key can read, edit and delete every row — the "
                "most common data leak in AI-built apps.",
                fix="For every table run `alter table public.<name> enable row level "
                "security;` and add policies for select/insert/update/delete, for example "
                "`create policy \"own rows\" on public.<name> for all using (auth.uid() = "
                "user_id);` Dashboard-created tables are invisible here, so verify those "
                "too.",
                evidence="tables without RLS: " + ", ".join(missing[:8]),
                effort="1–2 h",
                confidence="high",
                ref="https://supabase.com/docs/guides/database/postgres/row-level-security",
            ),
        )
    else:
        c.check("repo.rls", "Row Level Security in migrations", True, f"{len(tables)} table(s)")

    no_policy = sorted(name for name in rls if name not in policies)
    if no_policy:
        c.fail(
            "repo.rls_policy",
            "RLS policies exist for each table",
            Finding(
                id="repo.rls_no_policy",
                title="RLS enabled but no policy found for some tables",
                severity="high",
                category="Database access",
                why="RLS with zero policies blocks everyone (including your app) or, if "
                "the table is used through a service key, silently bypasses the protection "
                "you think you have.",
                fix="Add explicit policies per table. Test by calling the REST endpoint "
                "with the anon key and confirming it returns only the rows that user owns.",
                evidence="tables with RLS but no policy: " + ", ".join(no_policy[:8]),
                effort="1 h",
                confidence="medium",
            ),
        )
    else:
        c.check("repo.rls_policy", "RLS policies exist for each table", True)
    return info


def _check_firebase(files: dict[str, str], c: Collector) -> None:
    found = False
    for rel, text in files.items():
        low = rel.lower()
        if low.endswith("firestore.rules") or low.endswith("storage.rules"):
            found = True
            if re.search(r"allow\s+(?:read\s*,\s*write|write\s*,\s*read|read|write)\s*:\s*if\s+true", text, re.I):
                c.fail(
                    "repo.firebase_test_mode",
                    "Firebase rules are not in test mode",
                    Finding(
                        id="repo.firebase_test_mode",
                        title=f"{rel} allows public access",
                        severity="critical",
                        category="Database access",
                        why="`allow read, write: if true` is the test-mode default. It means "
                        "anyone with your project id can read and write the whole database.",
                        fix="Replace the rule with an auth check, for example "
                        "`allow read, write: if request.auth != null && "
                        "request.auth.uid == resource.data.user_id;` and deploy with "
                        "`firebase deploy --only firestore:rules`.",
                        evidence=f"{rel}: allow ... if true",
                        effort="45 min",
                    ),
                )
        if low.endswith("database.rules.json"):
            found = True
            if re.search(r'"(?:\.read|\.write)"\s*:\s*true', text):
                c.fail(
                    "repo.firebase_test_mode",
                    "Firebase rules are not in test mode",
                    Finding(
                        id="repo.firebase_test_mode_json",
                        title=f"{rel} allows public access",
                        severity="critical",
                        category="Database access",
                        why="`true` on .read/.write means anyone can read and write the "
                        "whole Realtime Database.",
                        fix="Scope rules to `auth != null` and to the owner's uid.",
                        evidence=f"{rel}: .read/.write true",
                        effort="45 min",
                    ),
                )
    if found:
        c.check("repo.firebase_rules", "Firebase rules reviewed", True)
    else:
        c.check("repo.firebase_rules", "Firebase rules reviewed", True, "no Firebase rules in repo")


def _check_rate_limits(files: dict[str, str], c: Collector) -> dict:
    routes = _route_files(files)
    info = {"api_routes": len(routes)}
    if not routes:
        info["note"] = "no API routes found"
        return info
    has_limit = any(RATE_LIMIT_TOKEN.search(text) for text in files.values())
    if not has_limit:
        c.fail(
            "repo.rate_limit",
            "Rate limiting on paid API routes",
            Finding(
                id="repo.no_rate_limit",
                title="No rate limiting anywhere in the codebase",
                severity="high",
                category="AI cost & abuse",
                why="Any endpoint that calls a paid model can be scripted. Without a limit, "
                "one bot — or one leaked key — turns into a bill you cannot cap.",
                fix="Add a per-user and per-IP limit in front of every paid route "
                "(`@upstash/ratelimit` + Redis is the quickest for Next.js; "
                "`express-rate-limit` for Express) and set a monthly hard spend cap with "
                "your AI provider as a second layer.",
                evidence=f"{len(routes)} API route file(s), no limiter found",
                effort="2 h",
                confidence="medium",
            ),
        )
    else:
        c.check("repo.rate_limit", "Rate limiting on paid API routes", True, f"{len(routes)} route(s)")

    # AI routes without an auth check
    flagged: list[str] = []
    for rel in routes:
        text = files.get(rel, "")
        if not LLM_TOKEN.search(text):
            continue
        if AUTH_TOKEN.search(text):
            continue
        flagged.append(rel)
    if flagged:
        c.fail(
            "repo.ai_route_unauthenticated",
            "AI routes require authentication",
            Finding(
                id="repo.ai_route_no_auth",
                title="Paid-AI route has no visible auth check",
                severity="critical",
                category="AI cost & abuse",
                why="An endpoint that calls a paid model but never checks who is calling is "
                "free for anyone who finds the URL. This is the exact shape of a surprise "
                "four-figure bill.",
                fix="Check the session at the top of the handler "
                "(`const { data: { user } } = await supabase.auth.getUser()`), return 401 "
                "when missing, then attach the rate limit.",
                evidence=", ".join(flagged[:5]),
                effort="1 h",
                confidence="medium",
            ),
        )
    else:
        c.check("repo.ai_route_unauthenticated", "AI routes require authentication", True)

    # webhooks without signature verification
    webhooks = [rel for rel in routes if "webhook" in rel.lower()]
    unsigned = [rel for rel in webhooks if not STRIPE_SIG.search(files.get(rel, ""))]
    if unsigned:
        c.fail(
            "repo.webhook_signature",
            "Webhook signatures are verified",
            Finding(
                id="repo.webhook_unsigned",
                title="Webhook handler does not verify the signature",
                severity="critical",
                category="Payments",
                why="An unverified webhook endpoint lets anyone POST a fake 'payment "
                "succeeded' event and get your product for free, or mark their own "
                "subscription paid.",
                fix="Verify with the provider SDK before trusting the body: "
                "`stripe.webhooks.constructEvent(rawBody, sig, endpointSecret)` (use the "
                "raw body, not the parsed JSON).",
                evidence=", ".join(unsigned[:4]),
                effort="45 min",
            ),
        )
    else:
        c.check("repo.webhook_signature", "Webhook signatures are verified", True)

    # global auth middleware
    has_middleware = any(
        rel.lower().rsplit("/", 1)[-1] in ("middleware.ts", "middleware.js", "middleware.py", "auth.py", "auth.ts")
        for rel in files
    )
    any_auth = any(AUTH_TOKEN.search(text) for text in files.values())
    if routes and not has_middleware and not any_auth:
        c.fail(
            "repo.auth_middleware",
            "Authentication middleware present",
            Finding(
                id="repo.no_auth_middleware",
                title="No auth checks found anywhere",
                severity="high",
                category="Access control",
                why="If none of your API routes check a session, every endpoint is public — "
                "including the ones that read user data.",
                fix="Add an auth check to each route (or a shared middleware) and default to "
                "deny: return 401 before touching the database.",
                evidence="no auth helper or middleware file found",
                effort="2 h",
                confidence="medium",
            ),
        )
    else:
        c.check("repo.auth_middleware", "Authentication middleware present", True)
    return info


def _check_cors(files: dict[str, str], c: Collector) -> None:
    hits: list[str] = []
    pattern = re.compile(r"origin\s*:\s*[\"'`]\*[\"'`]|Access-Control-Allow-Origin[\"'`]?\s*[,:]\s*[\"'`]\*", re.I)
    for rel, text in files.items():
        if not re.search(r"(config|middleware|cors|route|server|api)", rel, re.I) and not rel.lower().endswith((".ts", ".js", ".py", ".json")):
            continue
        match = pattern.search(text)
        if match:
            line = text.count("\n", 0, match.start()) + 1
            hits.append(f"{rel}:{line}")
            if len(hits) >= 4:
                break
    if hits:
        c.fail(
            "repo.cors_wildcard",
            "CORS restricted to your own origins",
            Finding(
                id="repo.cors_wildcard",
                title="CORS allows every origin",
                severity="high",
                category="Access control",
                why="With `*`, any website can call your API from a visitor's browser. Fine "
                "for a public read-only API; dangerous for anything using cookies or keys.",
                fix="Replace `*` with an explicit list of your app's origins, and keep "
                "credentialed routes on the same origin.",
                evidence=", ".join(hits),
                effort="20 min",
                confidence="medium",
            ),
        )
    else:
        c.check("repo.cors_wildcard", "CORS restricted to your own origins", True)


DANGEROUS_PATTERNS: tuple[tuple[str, str, str, str, str], ...] = (
    ("eval", r"(?<![\w.])eval\s*\(", "Eval of dynamic code", "high",
     "`eval` runs whatever string it is given. If any part of it comes from a user, that "
     "is remote code execution; even without that it breaks CSP and is hard to audit.",
     "Replace eval with an explicit mapping (object lookup or JSON.parse)."),
    ("new_function", r"new\s+Function\s*\(", "Dynamic Function constructor", "medium",
     "`new Function` is eval with extra steps: same injection surface, same CSP problems.",
     "Use a normal function or a lookup table."),
    ("pickle", r"pickle\.loads?\s*\(", "Unsafe pickle deserialization", "high",
     "Unpickling data from an untrusted source can execute code on your server.",
     "Use JSON for data interchange, or a signed format."),
    ("yaml_load", r"yaml\.load\s*\((?![^)]*SafeLoader)", "Unsafe YAML load", "high",
     "`yaml.load` without SafeLoader can construct arbitrary Python objects.",
     "Use `yaml.safe_load()`."),
    ("shell_true", r"subprocess\.[a-z_]+\([^)]*shell\s*=\s*True", "Shell command injection risk", "high",
     "shell=True plus user input is a command injection. A single `;` in a filename runs "
     "your attacker's command.",
     "Pass an argument list with shell=False, and validate every value."),
    ("dangerous_html", r"dangerouslySetInnerHTML", "Raw HTML injection surface", "medium",
     "Rendering unsanitised HTML is how XSS gets in — including HTML that an AI model "
     "generated and a user influenced.",
     "Sanitise with DOMPurify or render text instead of HTML."),
    ("sql_concat", r"""(?:(?:\.query|\.raw|\.execute|\.sql)\s*\(|sql\s*:)\s*[`"'][^`\n]*(?:\$\{|['"]\s*\+)""", "Possible SQL injection", "high",
     "Building SQL by string concatenation lets user input change the query itself.",
     "Use parameterised queries: `.query('select * from t where id = $1', [id])`."),
    ("console_secret", r"console\.log\([^)]*(?:token|password|secret|api[_-]?key|authorization)", "Secret printed to console", "low",
     "Browser console logs are visible to users and often captured by session replay "
     "tools. Tokens in logs leak.",
     "Remove the log or log a fixed, non-sensitive string."),
)


def _check_patterns(files: dict[str, str], c: Collector) -> None:
    found: dict[str, list[str]] = {key: [] for key, *_ in DANGEROUS_PATTERNS}
    for rel, text in files.items():
        for key, pattern, _title, _sev, _why, _fix in DANGEROUS_PATTERNS:
            if len(found[key]) >= 4:
                continue
            compiled = re.compile(pattern)
            match = compiled.search(text)
            if match:
                line = text.count("\n", 0, match.start()) + 1
                found[key].append(f"{rel}:{line}")
    for key, pattern, title, severity, why, fix in DANGEROUS_PATTERNS:
        hits = found[key]
        if not hits:
            continue
        c.add(
            Finding(
                id=f"repo.pattern_{key}",
                title=title,
                severity=severity,
                category="Code patterns",
                why=why,
                fix=fix,
                evidence=", ".join(hits),
                effort="20 min",
                confidence="medium",
            )
        )
    risky = [k for k, v in found.items() if v]
    c.check("repo.patterns", "No dangerous code patterns", not risky, ", ".join(risky) or "clean")


def _check_package(files: dict[str, str], c: Collector) -> dict:
    info: dict = {}
    raw = files.get("package.json") or next(
        (text for rel, text in files.items() if rel.endswith("package.json") and rel.count("/") <= 1), ""
    )
    if not raw:
        c.check("repo.dependencies", "Dependencies pinned and current", True, "no package.json")
        return info
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return info
    deps = {}
    for key in ("dependencies", "devDependencies"):
        deps.update(data.get(key) or {})
    info["dependencies"] = len(deps)

    risky = {"lodash": "4.17.21", "axios": "1.6.0", "jsonwebtoken": "9.0.0", "next": "13.5.0"}
    outdated: list[str] = []
    for name, minimum in risky.items():
        version = str(deps.get(name, ""))
        if not version:
            continue
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
        if not match:
            continue
        current = tuple(int(x) for x in match.groups())
        floor = tuple(int(x) for x in minimum.split("."))
        if current < floor:
            outdated.append(f"{name}@{version} (→ {minimum}+)")
    if outdated:
        c.fail(
            "repo.dependencies",
            "Dependencies pinned and current",
            Finding(
                id="repo.outdated_deps",
                title="Known-outdated dependencies",
                severity="low",
                category="Code patterns",
                why="Older versions of these packages have publicly known vulnerabilities. "
                "AI tools often pin whatever was in their training data.",
                fix="Update to the listed versions, then run `npm audit` and your build to "
                "catch breaking changes.",
                evidence=", ".join(outdated),
                effort="30 min",
                confidence="medium",
            ),
        )
    else:
        c.check("repo.dependencies", "Dependencies pinned and current", True)

    runtime = data.get("dependencies") or {}
    dep_inputs = []
    for name, version in list(runtime.items())[:40]:
        cleaned = re.sub(r"^[^0-9]*", "", str(version)).split(" ")[0]
        if cleaned[:1].isdigit():
            dep_inputs.append({"name": name, "version": cleaned, "ecosystem": "npm"})
    _add_cve_findings(dep_inputs, c)
    scripts = data.get("scripts") or {}
    info["has_test_script"] = bool(scripts.get("test"))
    return info


def _add_cve_findings(dep_inputs: list[dict], c: Collector) -> None:
    if not dep_inputs:
        return
    vulns = osv.collect(osv.query(dep_inputs), dep_inputs)
    if not vulns:
        c.check("repo.cve_dependencies", "No known CVEs in dependencies", True, f"{len(dep_inputs)} checked")
        return
    worst = max(vulns, key=lambda v: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(v["severity"], 2))
    evidence = "; ".join(
        f"{v['package']}@{v['version']} {v['id']}" + (f" (fix {v['fixed']})" if v["fixed"] else "")
        for v in vulns[:5]
    )
    c.add(
        Finding(
            id="repo.cve_dependencies",
            title=f"Known vulnerabilities in {len({v['package'] for v in vulns})} dependency package(s)",
            severity=worst["severity"] if worst["severity"] in ("critical", "high", "medium") else "medium",
            category="Dependencies",
            why="These package versions have public CVEs. AI builders often pin whatever version was in their training data, and scanners that only check your own code miss this.",
            fix="Upgrade the listed packages to the fixed version (or latest), run your build and tests, then re-scan. Use `npm audit` / `pip-audit` for the full list.",
            evidence=evidence,
            effort="1 h",
            confidence="high",
            ref=f"https://osv.dev/vulnerability/{vulns[0]['id']}" if vulns[0]["id"] else "",
        )
    )



def _check_python_dependencies(files: dict[str, str], c: Collector) -> None:
    raw = files.get("requirements.txt") or next(
        (text for rel, text in files.items() if rel.endswith("requirements.txt") and rel.count("/") <= 1), ""
    )
    if not raw:
        return
    deps = osv.parse_requirements(raw)
    if deps:
        _add_cve_findings(deps, c)


def _check_tests(files: dict[str, str], c: Collector, package_info: dict) -> None:
    test_files = [
        rel
        for rel in files
        if re.search(r"(?:\.(?:test|spec)\.(?:[jt]sx?|py|rb|php|go)$)|(?:^|/)(?:tests?|__tests__)/", rel)
    ]
    if package_info.get("has_test_script") or test_files:
        c.check("repo.tests", "Test files present", True, f"{len(test_files)} test file(s)")
    else:
        c.fail(
            "repo.tests",
            "Test files present",
            Finding(
                id="repo.no_tests",
                title="No tests in the repo",
                severity="low",
                category="Quality",
                why="Zero tests means every AI edit can silently break signup, checkout or "
                "auth, and you find out from a customer.",
                fix="Add one smoke test for the paths that matter: signup, login, the main "
                "write action and payment webhook. Playwright or Vitest is enough to start.",
                evidence="no test files or test script found",
                effort="3 h",
            ),
        )


def _detect_stack(files: dict[str, str]) -> dict:
    names = set(files)
    stack: list[str] = []
    if any(n.endswith("next.config.js") or n.endswith("next.config.mjs") for n in names):
        stack.append("Next.js")
    if any(n.endswith("vite.config.ts") or n.endswith("vite.config.js") for n in names):
        stack.append("Vite")
    if any(n.endswith("angular.json") for n in names):
        stack.append("Angular")
    if any(n.endswith("nuxt.config.ts") for n in names):
        stack.append("Nuxt")
    if any(n.endswith("manage.py") for n in names):
        stack.append("Django")
    if any(n.endswith("requirements.txt") for n in names) and not any(n.endswith("manage.py") for n in names):
        stack.append("Python")
    if any(n.endswith("Gemfile") for n in names):
        stack.append("Rails")
    if any(n.endswith("composer.json") for n in names):
        stack.append("PHP")
    if any(n.endswith("pubspec.yaml") for n in names):
        stack.append("Flutter")
    if any(n.endswith("app.json") or n.endswith("app.config.js") for n in names):
        stack.append("Expo")
    blob = "\n".join(files.values())[:500_000]
    if "supabase" in blob.lower():
        stack.append("Supabase")
    if "firebase" in blob.lower():
        stack.append("Firebase")
    if "stripe" in blob.lower():
        stack.append("Stripe")
    if not stack:
        stack.append("unknown")
    return {"stack": stack}


# --------------------------------------------------------------------------
# main entry
# --------------------------------------------------------------------------


def scan_repo(
    target: str,
    has_ai: bool = False,
    budget_seconds: float | None = None,
    zip_bytes: bytes | None = None,
) -> Result:
    budget = net.Budget(budget_seconds or max(config.SCAN_TIMEOUT_SECONDS, 60))
    result = Result(target=target)
    collector = Collector()

    parsed = parse_github(target)
    if not parsed:
        result.error = "not a GitHub repository (use https://github.com/owner/repo)"
        return result
    owner, repo_name = parsed
    result.target = f"{owner}/{repo_name}"
    result.final_url = f"https://github.com/{owner}/{repo_name}"

    if zip_bytes is None:
        try:
            zip_bytes = _download_zip(owner, repo_name, budget)
        except ValueError as exc:
            result.error = str(exc)
            return result
    result.status = 200

    try:
        files, stats = _iter_text_files(zip_bytes)
    except (ValueError, zipfile.BadZipFile) as exc:
        result.error = f"could not read repo archive: {exc}"
        return result

    if len(files) < MIN_MEANINGFUL_FILES:
        result.error = "no readable source files found in this repository"
        return result

    # 1. secrets across every text file
    for rel, text in files.items():
        collector.findings.extend(secrets.scan_text(text, rel))

    # 2. structural checks
    _check_env_files(files, collector)
    _check_client_secrets(files, collector)
    sql_info = _check_sql(files, collector)
    _check_firebase(files, collector)
    route_info = _check_rate_limits(files, collector)
    _check_cors(files, collector)
    _check_patterns(files, collector)
    package_info = _check_package(files, collector)
    _check_tests(files, collector, package_info)
    extra_info: dict = {}
    repoextra.check_all(files, collector, extra_info)

    stack_info = _detect_stack(files)

    result.findings = dedupe(collector.findings)
    result.checks = collector.checks
    result.meta = {
        "owner": owner,
        "repo": repo_name,
        "files_scanned": len(files),
        "zip_entries": stats["entries"],
        "skipped_large": stats["skipped_large"],
        "skipped_binary": stats["skipped_binary"],
        "bytes_read": stats["bytes"],
        "stack": stack_info["stack"],
        "has_ai": has_ai,
        **sql_info,
        **route_info,
        **extra_info,
        **{f"pkg_{k}": v for k, v in package_info.items()},
    }
    return result
