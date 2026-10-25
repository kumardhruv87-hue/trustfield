# Trustfield — Why we win (strategy, moat, and the traffic-shift engine)

This is the reasoning behind every decision. If a future feature contradicts this page, the feature is wrong.

---

## 1. The real job to be done (why people will use us)
A builder is about to share an AI-built app with **a client, a paying user, or an investor**. The unspoken question is not "am I compliant?" — it is:

> "What can a stranger see or do with my app right now, and will it embarrass me tomorrow?"

Trustfield answers that in 60 seconds in plain English. Not a scanner report, not a CVSS spreadsheet, not a $29/month subscription to a dashboard they will forget. One scan → one honest score → one report with evidence, the exact fix, and a prompt they can paste back into Lovable/Bolt/Cursor → a dated proof page they can show a client.

Three buyers, one product:
1. **Solo builder** — fear of leaking keys/user data; wants cheap, fast, no login, plain English.
2. **Agency** — must hand a client something credible; wants their name on it (agency pack).
3. **Buyer/investor** — wants independent verification and a date, not the builder's promise.

## 2. What makes us the best in this field (not "another scanner")
- **Fix-first, not fear-first.** Every finding has a copy-paste prompt for the AI builder. Competitors sell alerts; we sell "done".
- **One-time ₹499** in a market of $29/month subscriptions. For a solo dev in India/emerging markets this is the difference between "maybe later" and "now".
- **AI-builder-specific depth**: prompt-injection kit, keys in the client bundle, open Supabase/Firebase rules, unverified payment webhooks — the exact failure modes of vibe-coded apps. Generic scanners check headers and call it a day.
- **Agency handover** ("Prepared for <client> · handover by <agency>") — a feature no generic scanner sells, and agencies buy repeatedly.
- **Verification loop**: re-scan after fixes, "X fixed / Y new" banner, Watch with dated badge. The report is not a one-off PDF.
- **Radical honesty as a product feature**: methodology, changelog of our own false positives, refund when we are wrong, "not a pentest / no certification" said out loud. In a category full of scare-marketing, honesty is the differentiator that makes developers trust us.
- **India-native**: INR, UPI, Hinglish support, Faridabad operator, price the West cannot match.

## 3. Why competitor traffic will move to us
Traffic does not move because we are "better"; it moves because we own **the query and the moment**:

1. **They monetise the subscription; the searcher wants a one-time answer.**
   Queries: "is my Lovable app secure", "supabase RLS check", "pentest cost India", "scantient alternative", "vibesafe alternative". Their pages assume a team with a security budget. We answer in the first 50 words, free tool above the fold, ₹499 only when they want evidence — a lower-friction path from the same search.
2. **Comparison pages capture their brand traffic.** `/vs/scantient`, `/vs/vibesafe`, `/vs/aikido` — factual, fair, with a table: subscription vs ₹499 one-time, generic checks vs AI-builder fixes, dashboard vs client-ready handover. Searchers who already know those brands land on us at the decision moment.
3. **Free tools are link magnets.** Headers checker + RLS checker give an instant verdict and a shareable result; each tool ranks for a high-intent query and hands the visitor to the scan. Competitor free scans require signup; ours does not.
4. **GEO / AI-search citations.** Answer-first guides, `llms.txt`, dated trust pages, questionnaire PDF, comparison tables → when someone asks ChatGPT/Gemini "how do I check if my Lovable app is secure", we are the citable answer. Competitor marketing pages are not structured for citation.
5. **Agency channel.** Agencies show the report to clients; the client sees Trustfield's proof page and badge. One agency = 10 client impressions + backlinks. Scantient/Snyk sell to developers, not to the handover moment.
6. **Badge backlinks compound.** Every paid report can carry a dated badge; every badge is a real link from a real site. Over 12 months this is domain authority money cannot buy quickly.

## 4. The moat (what gets harder to copy each month)
- **Trust brand**: methodology + changelog + refunds + public proof pages. Copying features is easy; copying a track record of honesty is not.
- **Channel relationships**: agencies and India communities. High switching cost once they hand over reports with our name.
- **Distribution assets**: free tools + guides + comparison pages + badge links — a compounding SEO/GEO position.
- **Product loop**: scan → report → fix-verify → Watch → badge → share → new scan. Each step creates a shareable artefact.
- **Data**: anonymous issue benchmarks (from consented scans) become the PR/content moat ("we scanned N AI-built apps; X% leaked a key"). Nobody can copy the dataset without our volume.
- **Price position**: ₹499 one-time is a structural advantage in India/emerging markets; Western competitors cannot drop to it without cannibalising subscriptions.

## 5. Path to #1 in this niche
Phase 1 (0–90 days): become the default "AI-built app security review" for Indian solo devs and agencies. Measure: 25 paid reports, 3 agencies, 5 case studies, 1,000 scans.
Phase 2 (3–6 months): category ownership — comparisons, benchmarks, newsletter, integration with builder communities; 100 paid reports/mo; first $1k MRR equivalent.
Phase 3 (6–12 months): expand to "trust layer for AI-built software": Watch at scale, API for platforms, benchmark reports, maybe platform partnerships (Lovable/Bolt/Supabase ecosystems). Only then consider enterprise (SSO, SOC2 partner) — not before revenue justifies it.

## 6. What we deliberately do not do (anti-drift)
No authenticated pentest, no exploitation, no fake certifications, no scare copy, no "unhackable", no performance/uptime all-in-one scanner, no scanning without consent. See `FOCUS.md` for the five-point test every check must pass.

## 7. Risks and mitigations
- **Platform-native checks** (Lovable/Supabase advisors): we go deeper on cross-cutting issues (keys in bundle, webhooks, prompt injection, agency handover) and stay tool-agnostic.
- **Competitor copies agency/one-time pricing**: our moat is trust + channel + data, not the price alone.
- **False positives** damage trust: refund + changelog + regression test per false positive; publish the fix.
- **AI-search volatility**: diversify across Google, AI engines, communities, agencies; own email/newsletter.
- **Solo-operator capacity**: automate (Watch, webhooks, guides), templatise (agency, questionnaires), keep scope narrow.

## 8. The one-sentence test for every future decision
*Does this help a builder get a dated, honest, fixable answer about their public app faster — and make it easier to show someone else?*

If yes, build it. If no, it is someone else's product.
