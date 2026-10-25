# Trustfield — Focus & guardrails

**Core promise (do not dilute):** an independent, external, evidence-backed review of a public web app — score, findings, the exact fix, and a way to verify the fix later. Not a pentest, not a certification, not a hacking tool.

## The test every new check must pass (all five)
1. **Evidence** — we can show the URL, header, file or byte where we saw it.
2. **Action** — for a non-technical builder there is a concrete fix and a copy-paste prompt.
3. **Honest limits** — the check can be explained, including how it can be wrong.
4. **Passive only** — no login, no exploitation, no brute force, no write requests.
5. **Trust value** — it helps a buyer verify an app faster; it does not exist to inflate the check count.

If a check fails any of these, it does not ship. No "1,471 checks" theatre.

## Who it is for
- Solo developers and small teams who shipped with Lovable / Bolt / v0 / Cursor / Replit or by hand.
- Agencies handing an app to a client.
- Any public web app: generic checks (TLS, headers, exposed files, keys in JS, CORS, cookies, DNS/email trust, legal pages, SEO/GEO) apply whether AI wrote the code or not. The AI prompt-injection kit is the extra for apps with a chatbot.

## What we may add (aligned)
- More **passive** checks with evidence: DNS/email trust, cookie scope, CSP quality, `.git`/source-map exposure, dependency CVEs via OSV, open GraphQL introspection, security.txt/robots, accessibility/SEO basics.
- **Verification features**: re-scan after fixes, "fix verified" state, dated badge/proof page, Watch for continuous re-checks, comparison "before vs after".
- **Buyer features**: sample report, agency handover label, API + webhook, trust center/questionnaire, refund on a wrong finding.

## What we refuse (drift)
- Authenticated pentesting, exploitation, lateral movement — a different product with different liability.
- Fake certifications (SOC 2, ISO, "audited"), fake customer counts or testimonials.
- "Unhackable" or "guaranteed secure" claims.
- Auto-scanning third-party apps without permission.
- A generic all-in-one scanner (performance, SEO-audit, uptime, vulnerability management). Tools like the headers/RLS checkers stay free, narrow and honest — they feed trust in the core report, they are not the product.

## Cross-verification model (the trust moat)
1. Free scan → score + every issue title.
2. Paid report → evidence + fix + prompt + PDF.
3. Watch → periodic re-scan, new-finding alert, badge stays current.
4. Public proof page/badge → anyone can check the date, score and checks.
5. Methodology + changelog + refunds → the claim is testable: if we are wrong, we fix the check and say so publicly.

That is why a developer can use Trustfield as a **trust place**: the report is not a black box, and the same scanner is used on Trustfield itself (current self-scan: 100/100, A+).
