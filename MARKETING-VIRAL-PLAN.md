# Trustfield — Marketing, Ads, SEO & GEO plan (built for compounding virality)

Goal: not "viral once", but **three loops that compound**. Every asset below is already live unless marked.

---

## Positioning (one line everywhere)
**"Trust, verified. In plain English."** — an independent, read-only security review for AI-built and hand-written web apps. Free scan → ₹499 evidence+fixes+PDF → Watch (auto re-scans).

Buyer: solo dev / small team shipping with Lovable, Bolt, v0, Cursor, Replit or by hand; agencies handing apps to clients.
Enemy: **fear and black-box reports.** We publish methodology, limits and refunds. That is the brand.

---

## Loop 1 — Free tools → search traffic → scan → report
Live tools, each targets a real query and ends in the free scan:
| Tool | URL | Search intent |
|---|---|---|
| Security headers checker | `/tools/headers` | "security headers test", "missing HSTS" |
| Supabase RLS checker | `/tools/rls` | "supabase RLS check", "anon key readable" |
| Sample report | `/static/sample-report.html` | "security report example" |

Play: every tool result is **screenshot-shareable** ("your app scored 62"), with a one-click free scan. Add 1 new tool/quarter only if it passes the FOCUS.md test.

## Loop 2 — Badge & proof links → backlinks → authority
- Public proof page `/t/<id>` + embeddable badge `/badge/<id>.svg` ("scanned on <date> · <score>/100").
- Every paid report gets the badge HTML snippet ("Add to your site").
- Agencies put the report in client handovers → the badge/link travels to the client's site.
- Free users can share their scorecard link; the page links back to `/` (rel nofollow not needed; it is real content).

## Loop 3 — Guides → AI-search citations → signups
Live guides with answer-first structure + Article schema:
- `/guides/lovable-app-security` — "is my Lovable app secure"
- `/guides/supabase-rls-checklist` — "supabase RLS checklist"
- `/guides/499-report-vs-pentest` — "pentest cost vs automated scan"
Next: `/guides/bolt-app-security`, `/guides/vibe-coding-security`, `/guides/razorpay-webhook-verification`.
Each: 600–900 words, one H2 per question, code snippets, link to one free tool + free scan. Quarterly data post: **"We scanned N AI-built apps: X% leaked a key, Y% had an open table"** (only from consented anonymous index data) → PR + LinkedIn + X thread + Hacker News.

---

## GEO (AI search / agentic browsing) — already done, keep it
- `llms.txt` with H1 + markdown links ✅ (Agentic Browsing 3/3)
- `/methodology`, `/compare`, `/trust`, `/trust/questionnaire.pdf` ✅
- JSON-LD: SoftwareApplication + FAQPage + Article on guides + WebPage dates ✅
- Answer-first paragraphs ("Short answer: …") in every guide ✅
- Keep `/security`, `/status`, `/changelog` fresh — AI engines cite dated, specific pages.
- Target prompts people type into ChatGPT/Gemini: "is lovable secure", "check supabase RLS", "do I need a pentest for my MVP". Answer them literally in guides.

---

## Channels & cadence (90 days)

**Weeks 1–2 (foundation):** 10 DMs/day (see `gtm/OUTREACH.md`), 1 X post/day, 2 LinkedIn posts/week, join 3 builder communities, submit tools to 2 directories.
**Weeks 3–4 (launch):** Product Hunt (Tue–Thu), Show HN, r/SideProject + r/lovable (follow rules), IndieHackers launch post. Ask every paid buyer for a 1-line quote.
**Month 2 (content engine):** 2 guides/month, 1 data post, 3 agency outreach emails/day, 2 Hinglish reels/week (screen-record a real scan + fix).
**Month 3 (paid + partnerships):** start ads only on proven keywords; 3 agency partnerships; ask 3 customers for referrals.

## Ads plan (only after organic proves the message)
- **Budget:** ₹5,000 test → ₹15,000/mo if CAC < ₹250 (₹499 product; watch LTV).
- **Google Search:** exact/phrase on `supabase rls check`, `lovable security`, `bolt app security`, `website security scan india`, `check api keys in website`. Landing pages: `/guides/*` and `/tools/*` (not homepage).
- **X/LinkedIn:** retarget people who visited `/` or `/tools/*` with the sample report + free scan; small budget.
- **No** broad "website security" keywords (enterprise CPC, wrong buyer).
- Measure: scan start rate, paid conversion, CAC by keyword; kill anything above ₹400 CAC.

## India wedge (highest virality per rupee)
- Hinglish reels/shorts: "Lovable se app banaya? ye 3 cheezein check karo" — screen recording of scan + fix (30–45s).
- College/incubator workshops: free scans for 20 teams, collect testimonials.
- Agencies/studios in Faridabad–Delhi NCR: in-person intro, white-label handover (agency pack).
- UPI + Hinglish support is a real differentiator vs US tools.

## Referral & retention
- After a paid report: "Give a friend a free scan + ₹100 off their report" (manual code until automated).
- Watch is the retention loop: daily re-checks + new-finding email; ask for a quote after 2 successful Watch alerts.

## Metrics (weekly dashboard)
Scans, scan→paid %, paid revenue, Watch active, CAC by channel, organic clicks, guide impressions, badge installs, refund rate (<2%), AI-search citations (manual check of ChatGPT/Gemini answers).

## Guardrails (do not break trust for growth)
No fake reviews/counters, no fear-marketing ("you are hacked"), no scanning without consent, no "unhackable", no paid placement of fake rankings. Every claim links to a live page (tool, guide, methodology, refund).

**Order of operations:** free tools + guides + badge links compound for years; ads only amplify what already converts.
