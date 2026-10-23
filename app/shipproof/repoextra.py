"""Extra repository checks that need the whole codebase, not just one file.

These are the mistakes AI code generators make in backend code that a live scan
cannot see: disabled TLS verification, JWTs without algorithm checks, SSRF,
default CORS, prompt injection into system prompts, destructive migrations.
"""
from __future__ import annotations

import re

from . import secrets
from .findings import Finding


def _line(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _first_match(files: dict[str, str], pattern: str, flags: int = re.IGNORECASE, limit: int = 4) -> list[str]:
    compiled = re.compile(pattern, flags)
    hits: list[str] = []
    for rel, text in files.items():
        match = compiled.search(text)
        if match:
            hits.append(f"{rel}:{_line(text, match.start())}")
            if len(hits) >= limit:
                break
    return hits


def _skip_examples(rel: str) -> bool:
    low = rel.lower()
    return any(
        part in low
        for part in (
            ".example",
            ".sample",
            "/test/",
            "/tests/",
            "/__tests__/",
            ".test.",
            ".spec.",
            "_test.",
            "/fixtures/",
            "/spec/",
        )
    )


def check_all(files: dict[str, str], collector, info: dict) -> None:  # noqa: ANN001
    real_files = {rel: text for rel, text in files.items() if not _skip_examples(rel)}
    blob = "\n".join(real_files.values())
    low_blob = blob.lower()

    # 1. TLS verification disabled -----------------------------------------
    hits = _first_match(
        real_files,
        r"(rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*[\"']?0|verify\s*=\s*False|_create_unverified_context)",
    )
    if hits:
        collector.fail(
            "repo.tls_verify",
            "TLS certificates are verified",
            Finding(
                id="repo.insecure_tls",
                title="TLS certificate verification is disabled",
                severity="high",
                category="Transport security",
                why="With verification off, any network attacker can impersonate the API you call and "
                "read the traffic — including the API keys inside it.",
                fix="Remove the flag. If you have a self-signed certificate in development, fix the "
                "certificate instead of disabling verification.",
                evidence=", ".join(hits),
                effort="20 min",
            ),
        )
    else:
        collector.check("repo.tls_verify", "TLS certificates are verified", True)

    # 2. JWT verification ---------------------------------------------------
    ignores_expiry = _first_match(real_files, r"ignoreExpiration\s*:\s*true")
    none_alg = _first_match(real_files, r"algorithms?\s*:\s*\[\s*[\"']none")
    verify_calls = _first_match(real_files, r"\bjwt\.(?:verify|decode)\s*\(", limit=8, flags=0)
    if none_alg:
        collector.fail(
            "repo.jwt_algorithms",
            "JWT algorithms are pinned",
            Finding(
                id="repo.jwt_none_algorithm",
                title="JWT accepts the 'none' algorithm",
                severity="critical",
                category="Access control",
                why="If `none` is accepted, an attacker can mint their own token with any user id and "
                "no signature — full account takeover.",
                fix="Pin the algorithm explicitly: `jwt.verify(token, secret, { algorithms: ['HS256'] })`.",
                evidence=", ".join(none_alg),
                effort="20 min",
            ),
        )
    elif ignores_expiry:
        collector.fail(
            "repo.jwt_algorithms",
            "JWT algorithms are pinned",
            Finding(
                id="repo.jwt_ignore_expiry",
                title="JWT expiration is ignored",
                severity="high",
                category="Access control",
                why="Expired tokens are still accepted, so a stolen token works forever.",
                fix="Remove `ignoreExpiration: true` and keep token lifetimes short.",
                evidence=", ".join(ignores_expiry),
                effort="15 min",
            ),
        )
    elif verify_calls and "algorithms" not in low_blob:
        collector.fail(
            "repo.jwt_algorithms",
            "JWT algorithms are pinned",
            Finding(
                id="repo.jwt_no_algorithm_pin",
                title="JWT verified without an algorithm allow-list",
                severity="medium",
                category="Access control",
                why="Without `algorithms`, some libraries will happily accept a token signed with a "
                "weaker algorithm than you intended.",
                fix="Always pass `{ algorithms: ['HS256'] }` (or your chosen algorithm) to verify.",
                evidence=", ".join(verify_calls),
                effort="20 min",
            ),
        )
    else:
        collector.check("repo.jwt_algorithms", "JWT algorithms are pinned", True)

    # 3. SSRF ---------------------------------------------------------------
    hits = _first_match(
        real_files,
        r"(?:fetch|axios\.(?:get|post|put)|urlopen|requests\.(?:get|post)|http\.get)\s*\(\s*(?:req(?:uest)?\.(?:query|body|params)|ctx\.request|request\.(?:args|form))",
    )
    if hits:
        collector.fail(
            "repo.ssrf",
            "Server-side requests use an allow-list",
            Finding(
                id="repo.ssrf",
                title="User input is fetched server-side (SSRF risk)",
                severity="high",
                category="API surface",
                why="If the server fetches a URL supplied by the user, it can be tricked into reaching "
                "internal services or the cloud metadata endpoint (169.254.169.254).",
                fix="Validate the URL against an allow-list of hosts, block private/link-local IPs after "
                "DNS resolution, and never follow redirects blindly.",
                evidence=", ".join(hits),
                effort="2 h",
            ),
        )
    else:
        collector.check("repo.ssrf", "Server-side requests use an allow-list", True)

    # 4. CORS default -------------------------------------------------------
    hits = _first_match(
        real_files,
        r"(app\.use\(\s*cors\(\s*\)\s*\)|cors\(\s*\{\s*origin\s*:\s*true|Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*)",
    )
    if hits:
        collector.fail(
            "repo.cors_default",
            "CORS is restricted to your domains",
            Finding(
                id="repo.cors_default",
                title="CORS allows every origin",
                severity="high",
                category="Access control",
                why="`cors()` with no options reflects any origin. Any website can call your API from a "
                "visitor's browser, and credentialed routes become cross-site readable.",
                fix="Pass an explicit allow-list: `cors({ origin: ['https://yourapp.com'] })`.",
                evidence=", ".join(hits),
                effort="20 min",
            ),
        )
    else:
        collector.check("repo.cors_default", "CORS is restricted to your domains", True)

    # 5. Express without helmet --------------------------------------------
    uses_express = "express" in low_blob and ("app.use(" in blob or "app.get(" in blob)
    if uses_express and "helmet" not in low_blob:
        collector.fail(
            "repo.helmet",
            "Security headers middleware installed",
            Finding(
                id="repo.no_helmet",
                title="Express app has no security-headers middleware",
                severity="medium",
                category="Transport security",
                why="Without helmet you ship no CSP, no HSTS and no clickjacking protection by default.",
                fix="`npm i helmet` and `app.use(helmet())` (add a CSP policy after testing).",
                evidence="express detected, no helmet import",
                effort="20 min",
            ),
        )
    else:
        collector.check("repo.helmet", "Security headers middleware installed", True)

    # 6. File uploads -------------------------------------------------------
    uploads = _first_match(real_files, r"\bmulter\s*\(|\bupload\.(?:single|array|fields)\s*\(", limit=8)
    if uploads:
        validates = any(token in low_blob for token in ("filefilter", "mimetype", "limits:", "maxfilesize", "allowedtypes"))
        if not validates:
            collector.fail(
                "repo.upload_validation",
                "File uploads are validated",
                Finding(
                    id="repo.upload_unvalidated",
                    title="File upload accepts any type or size",
                    severity="medium",
                    category="API surface",
                    why="An unrestricted upload can fill your disk, host malware on your domain, or "
                    "upload a script that your server later executes.",
                    fix="Add `limits: { fileSize: 5 * 1024 * 1024 }` and a `fileFilter` that allows only "
                    "the MIME types you need; store uploads outside the web root.",
                    evidence=", ".join(uploads),
                    effort="1 h",
                ),
            )
        else:
            collector.check("repo.upload_validation", "File uploads are validated", True)
    else:
        collector.check("repo.upload_validation", "File uploads are validated", True, "no uploads found")

    # 7. Prompt injection into system prompt -------------------------------
    hits = _first_match(
        real_files,
        r"(role\s*:\s*[\"']system[\"'][^}]{0,160}(?:\+|\$\{)|system[_ ]?prompt\s*[:=][^;\n]{0,120}(?:\+|\$\{)\s*(?:req|body|input|message|query))",
        limit=4,
    )
    if hits:
        collector.fail(
            "repo.prompt_injection",
            "User input is not concatenated into the system prompt",
            Finding(
                id="repo.prompt_injection",
                title="User input is concatenated into a system prompt",
                severity="high",
                category="AI safety",
                why="Anything the user types becomes part of your instructions. A crafted message can "
                "override the rules and reach tools or data the user should not have.",
                fix="Keep user content in a separate user message, wrap it in a clearly delimited block, "
                "never put it in the system prompt, and enforce permissions in code rather than in the prompt.",
                evidence=", ".join(hits),
                effort="1 h",
            ),
        )
    else:
        collector.check("repo.prompt_injection", "User input is not concatenated into the system prompt", True)

    # 8. Destructive migrations --------------------------------------------
    destructive: list[str] = []
    for rel, text in real_files.items():
        if not rel.lower().endswith(".sql"):
            continue
        match = re.search(r"(?i)\b(drop\s+table|truncate\s+table|drop\s+database|delete\s+from\s+\w+\s*;)", text)
        if match:
            destructive.append(f"{rel}:{_line(text, match.start())}")
    if destructive:
        collector.add(
            Finding(
                id="repo.destructive_migration",
                title="Destructive statement in a migration",
                severity="medium",
                category="Database access",
                why="One `DROP TABLE` in a migration file that runs on deploy deletes production data. "
                "It happens often enough to be worth flagging every time.",
                fix="Move destructive changes into a reviewed, manual, backed-up step.",
                evidence=", ".join(destructive[:4]),
                effort="30 min",
                confidence="medium",
            )
        )

    # 9. Open redirect ------------------------------------------------------
    hits = _first_match(real_files, r"(?:res\.)?redirect\(\s*(?:req(?:uest)?\.(?:query|params|body)|ctx\.request)", limit=4)
    if hits:
        collector.fail(
            "repo.open_redirect",
            "Redirects do not trust a user-supplied target",
            Finding(
                id="repo.open_redirect",
                title="Redirect target comes from user input",
                severity="medium",
                category="API surface",
                why="Attackers use your domain as a trusted hop to phishing pages, and OAuth flows can "
                "be redirected with the token attached.",
                fix="Allow only relative paths or an explicit allow-list of hosts before redirecting.",
                evidence=", ".join(hits),
                effort="30 min",
            ),
        )
    else:
        collector.check("repo.open_redirect", "Redirects do not trust a user-supplied target", True)

    # 10. Real-looking values in .env.example -------------------------------
    examples = {rel: text for rel, text in files.items() if rel.lower().rsplit("/", 1)[-1].startswith(".env.example")}
    example_findings = []
    for rel, text in examples.items():
        example_findings.extend(secrets.scan_text(text, rel))
    if example_findings:
        collector.fail(
            "repo.env_example",
            "No real values in .env.example",
            Finding(
                id="repo.env_example_real_values",
                title=".env.example contains what looks like real credentials",
                severity="medium",
                category="Secrets & keys",
                why="Example files get copied, committed and shared. If the values are real, the secret "
                "is already out.",
                fix="Replace every value with a placeholder and rotate anything that was real.",
                evidence="; ".join(f.evidence for f in example_findings[:3]),
                effort="15 min",
            ),
        )
    else:
        collector.check("repo.env_example", "No real values in .env.example", True)

    # 11. Test-mode payment keys -------------------------------------------
    if re.search(r"\bsk_test_[0-9A-Za-z]{10,}", blob):
        collector.add(
            Finding(
                id="repo.stripe_test_key",
                title="Stripe test key present in the codebase",
                severity="low",
                category="Payments",
                why="Fine in development, dangerous if it ships — checkout silently runs in test mode.",
                fix="Use `sk_test_` only in `.env.local`; production must use live keys set at the host.",
                evidence="sk_test_… found",
                effort="10 min",
            )
        )

    # 12. Input validation --------------------------------------------------
    route_files = [
        rel
        for rel in real_files
        if re.search(r"(?:^|/)(?:api|routes|route|controllers?)/", rel.lower())
        or re.search(r"route\.(?:ts|js)$", rel.lower())
    ]
    if len(route_files) >= 3 and not any(token in low_blob for token in ("zod", "yup", "joi", "valibot", "pydantic", "marshmallow")):
        collector.fail(
            "repo.input_validation",
            "Request bodies are validated",
            Finding(
                id="repo.no_input_validation",
                title="No request-validation library in a multi-route API",
                severity="medium",
                category="API surface",
                why="AI-generated routes often trust `req.body` directly. Missing validation turns small "
                "assumptions into crashes, data corruption and injection paths.",
                fix="Add a schema per route (zod/yup/joi on Node, pydantic on Python) and reject unknown fields.",
                evidence=f"{len(route_files)} route file(s), no validation library found",
                effort="2–4 h",
                confidence="medium",
            ),
        )
    else:
        collector.check("repo.input_validation", "Request bodies are validated", True)

    info["extra_repo_checks"] = True
