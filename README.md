# Trustfield

**Proof your AI-built app is safe to ship.** A 60-second security, cost-risk and
AI-safety audit for apps built with Lovable, Bolt.new, v0, Cursor, Replit or
ChatGPT — **no GitHub connection required**.

Built as a single deployable Python service with **zero third-party
dependencies**. One repo, one container, one command.

---

## Why this exists

AI builders ship auth, database access, API keys and payment webhooks faster than
anyone can review them. The mistakes are predictable:

| Mistake | What it costs |
|---|---|
| Supabase `service_role` key in browser code, RLS off | every row of every table is public |
| OpenAI / Anthropic key in the client bundle | the key is spent by strangers, not you |
| AI route with no auth or rate limit | a script turns your credits into their free product |
| Unverified Stripe webhook | anyone can POST "paid" and get your product free |
| `.env` / `.git` / source maps served publicly | full code and credential disclosure |
| No privacy page, no deletion path | payment gateway review fails, B2B deals stall |

This tool finds those, explains them in plain English, and gives a fix you can
hand straight to the AI that wrote the app.

It is **not** a penetration test, and the report never claims otherwise.

## Pricing model (freemium by design)

**Every scan and every finding is free.** The paywall is on proof and
follow-through, not on the results:

| Free | Paid |
|---|---|
| 25–45 live checks (60+ with a repo) | Fix & Proof pack ₹499 — PDF, badge, priority reply, re-scan |
| Every finding with evidence and a fix | Watch ₹499/mo — weekly re-scan, badge stays current |
| Copy-paste fix prompt per finding | Agency pack ₹3,999 — 10 audits, white-label |
| 12-attack prompt-injection kit | Done-for-you fixes (later) |

Set `SHIPPROOF_FREE_REPORTS=0` if you ever want the old "top 3 findings only"
paywall back.

---

## Quick start (local)

```bash
cd shipproof
python app/run.py
# open http://localhost:8000
```

Python 3.11+ is enough. Nothing to install.

Optional settings live in `.env.example`; copy it to `.env` and export the
variables your shell needs, or set them in your host's dashboard.

### Try the scanner without the internet

```bash
python tools/make_fixtures.py          # builds a deliberately vulnerable demo app
python -m unittest discover -s tests -t .   # 150 tests
```

---

## How it works

```
Browser â”€â”€POST /api/scanâ”€â”€â–º server.py
                              â”‚
              â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
              â–¼                                â–¼
        live.py (URL scan)              repo.py (GitHub zip)
        · HTTPS/TLS/HSTS/CSP            · secrets & committed .env
        · exposed files + sourcemaps    · client-side secret refs
        · secrets in JS bundle          · RLS / Firestore rules
        · cookies / CORS                · rate limits / auth on AI routes
        · privacy & terms pages         · webhook signatures, SQL concat,
        · security.txt                    eval/pickle/YAML, deps, tests
              â”‚                               â”‚
        webdeep.py (deeper web)         repoextra.py (deeper code)
        · DNS: SPF, DMARC, CAA, MX      · disabled TLS verification
        · TLS version/expiry/issuer     · JWT algorithm + expiry
        · OPTIONS/TRACE methods         · SSRF, open redirect, default CORS
        · build/ops files exposed       · upload limits, helmet, validation
        · forms, SRI, trackers/consent  · prompt injection into system prompt
        · HTML-comment secrets, a11y    · destructive migrations
        · localStorage tokens, eval     · real values in .env.example
        · GraphQL introspection
        · Firebase open-rules check
        · Supabase table access (counts only)
              â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                              â–¼
                         score.py  → 0–100, grade, cost risk, breach risk,
                                      Hinglish verdict, top 3 actions
                              â–¼
                         store.py  → data/scans/<id>.json (atomic write)
                              â–¼
       report.py → report page, proof page, SVG badge, print-to-PDF
                  ai_kit.py → 12 prompt-injection attacks + deterministic grader
```

Design rules that are enforced in code, not just documented:

- **SSRF guard**: only public IPs; every redirect hop re-checked; loopback, RFC1918,
  link-local and `169.254.169.254` are refused (`net.py`).
- **Hard caps**: body size, per-request bytes, JS bundle count, repo zip size,
  unpacked text size, file count, total scan time (`config.py`, `repo.py`).
- **No exploitation**: GET/HEAD-style passive reads only. The prompt-injection kit is
  run by the founder against their own app; we never call an LLM ourselves.
- **No code retention**: repo scans are read from memory and discarded.
- **Secrets are redacted** in evidence (`sk-proj-ab…W3xY` style).
- **Output escaping**: every value that reaches HTML passes through `html.escape`.

---

## HTTP API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Landing page + free scanner |
| `POST` | `/api/scan` | `{kind:"url"\|"repo", target, has_ai, email, consent:true}` → full preview |
| `GET` | `/api/scan/<id>` | Scan JSON (all findings in free mode) |
| `GET` | `/r/<id>` | Full report page (free findings + paid proof/monitoring upsell) |
| `GET` | `/t/<id>` | Public proof page (only meaningful for score ≥ 80) |
| `GET` | `/badge/<id>.svg` | Embeddable SVG badge |
| `GET` | `/api/kit?host=` | The 12 attack prompts |
| `POST` | `/api/grade` | `{payload_id, response}` → `LEAK` / `SAFE` / `UNCLEAR` |
| `POST` | `/api/scan/<id>/kit` | Persist graded answers into the report |
| `POST` | `/api/lead` | `{email, scan_id}` |
| `GET` | `/admin/unlock?id=&token=` | Manual unlock after a real payment |
| `GET` | `/healthz` | Health + counts |
| `GET` | `/privacy`, `/terms`, `/robots.txt`, `/sitemap.xml` | Static |

All responses send `X-Content-Type-Options`, `X-Frame-Options`, a CSP and a
`Referrer-Policy`. Rate limits: 10 scans/hour/IP and 20 POSTs/minute/IP (can be
disabled with `SHIPPROOF_RATE_LIMIT=0` for local dev).

---

## Configuration

Everything lives in `app/shipproof/config.py`; the important ones:

| Variable | Default | Meaning |
|---|---|---|
| `SHIPPROOF_BRAND` | `Trustfield` | Rename the product everywhere |
| `SHIPPROOF_BASE_URL` | `http://localhost:8000` | Canonical URL (sitemap, links) |
| `SHIPPROOF_PAYMENT_LINK` | *(empty)* | Checkout link used by every unlock button |
| `SHIPPROOF_ADMIN_TOKEN` | *(empty)* | Secret for `/admin/unlock` |
| `SHIPPROOF_DATA` | `./data` | Where scan JSON is written |
| `SHIPPROOF_PRICE_INR` / `_USD` | `499` / `9` | Prices shown on the page |
| `SHIPPROOF_MAX_SCANS` | `2` | Concurrent scans |
| `SHIPPROOF_SCAN_TIMEOUT` | `60` | Wall-clock budget per scan |
| `SHIPPROOF_BADGE_DAYS` | `14` | How long a proof page stays "current" |

Full list with comments: `.env.example`.

---

## Deploy

### Render (fastest, has a blueprint)

1. Push this repo to GitHub.
2. Render → **New → Blueprint** → pick the repo (it reads `render.yaml`).
3. Fill `SHIPPROOF_BASE_URL`, `SHIPPROOF_PAYMENT_LINK`, `SHIPPROOF_CONTACT_EMAIL`.
4. Add your domain in Render → DNS in Cloudflare (proxied, "Always Use HTTPS" on).

### Any Docker host

```bash
docker build -t shipproof .
docker run -p 8000:8000 -v shipproof_data:/data \
  -e SHIPPROOF_BASE_URL=https://yourdomain.com \
  -e SHIPPROOF_PAYMENT_LINK=https://rzp.io/l/your-link \
  -e SHIPPROOF_ADMIN_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(32))") \
  shipproof
```

### VPS (no Docker)

```bash
python3 app/run.py            # behind Caddy or nginx
```

Put Cloudflare (or Caddy) in front for TLS and a WAF. The app itself speaks plain
HTTP and expects a proxy to terminate TLS.

---

## Before you charge money

The MVP ships with **manual fulfillment** — deliberately, because a broken payment
webhook is worse than no payment webhook:

1. Create a Razorpay **Payment Page** (₹499 report, ₹499/mo Watch) or a Stripe
   **Payment Link**.
2. Set its success/redirect URL to:
   `https://yourdomain.com/r/REPORT_ID?unlocked=1` — but do **not** rely on that
   for security. The flag only works when `SHIPPROOF_UNLOCK_ALL=1`.
3. After each payment, open:
   `https://yourdomain.com/admin/unlock?id=REPORT_ID&token=ADMIN_TOKEN`
   and send the customer the report link.

When volume justifies it, replace step 3 with a webhook:

```
POST /api/unlock   { "id": "<report id>", "token": "<admin token>" }
```

Add signature verification for the provider you use (`razorpay.webhooks` /
`stripe.webhooks.constructEvent`) before calling that route. **Never** trust an
unsigned webhook body.

Also do before launch:

- Replace `[CITY]` in `/terms` and add your legal name/address.
- Get a lawyer to skim `/privacy` and `/terms` (they are templates, not advice).
- Set a real `SHIPPROOF_CONTACT_EMAIL` and monitor it.
- Add a hard monthly spend cap in your hosting and AI provider accounts.

---

## Honest limits

What we **do not** check (and the report says so):

- Your actual database contents or dashboard-created tables (only migrations in a repo).
- Git history for previously committed secrets.
- Live exploitation, privilege escalation, business-logic abuse.
- Anything behind a login (no credentials are used).
- Mobile binaries, Chrome extensions, Shopify apps.
- Whether a fix actually works — the customer must re-scan.

A check is a point in time. That is why badges expire and Watch re-scans.

---

## Development

```bash
python -m compileall -q app
python -m unittest discover -s tests -t .      # 150 tests
python tools/make_fixtures.py                  # regenerate the vulnerable fixture
python tools/make_demo.py                      # build demo/report-demo.html
```

Adding a check: write a function that appends to a `Collector`
(`live.py` or `repo.py`), give the finding a stable `id`, a severity, a
plain-English `why`, a copy-paste `fix`, and record the matching check so the
proof page can show it. Add a fixture + test. Keep false positives near zero.

---

## Roadmap (in order of revenue impact)

1. Razorpay/Stripe webhook → instant unlock (no manual step).
2. Transactional email: report link + "your badge expires in 3 days".
3. Scheduled re-scans for Watch customers (cron hitting the same scanner).
4. White-label agency pack (logo + client name on the PDF).
5. GitHub App for private repos (read-only, no write scopes).
6. Hindi UI toggle for the report.
7. Server-side PDF render (currently browser print).

---

## Rename checklist

The brand is one constant. To rename: `SHIPPROOF_BRAND`, page copy in
`templates/index.html`, the shield SVG in the templates, the badge text in
`report.badge_svg`, and the domain. Search for `Trustfield` when you are done.

---

Built to be boring to operate and honest to read. If a finding is wrong, that is a
bug — fix the rule, not the message.

