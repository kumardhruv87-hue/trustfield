# Trustfield: focused launch, 25 October 2026

## The offer

For a solo founder or small agency about to launch or hand over an AI-built app: find common public security mistakes, understand the evidence, give the AI builder a fix prompt, then re-check.

Free: score and every issue title. Rs 499 once: evidence, prioritized fixes, individual AI-builder prompts, a complete downloadable AI Builder Fix Pack (.md), dated PDF and one same-target verification re-check during the report's 30-day lifetime. Fix implementation is not included. A clean scan is not a certificate. URL-only scanning does not verify hidden payment/auth logic.

The Fix Pack includes acceptance checklists and owner actions, generated deterministically from findings with no additional AI API cost. Re-check outcomes distinguish relevant mapped checks that passed, issues still detected, new findings, and absent findings that could not be confirmed. Older scans without check mappings remain unconfirmed. The comparison is a point-in-time observation, not proof that every instance is fixed.

Admin login: https://trustfield.dev/admin/login (also in the homepage footer). Existing credentials are unchanged.

Admin totals distinguish recorded orders, test/manual grants and provider-confirmed live INR payments. Legacy records need gateway review; use “Check recorded Razorpay payments” for a read-only check of up to ten references at a time. Original ledger entries remain intact; lookup evidence is stored separately. Failed lookups remain unconfirmed and can be retried after five minutes. Confirm bank settlements, actual fees and refunds in the payment provider dashboard. Report “access granted” and provider email acceptance do not prove a sale or inbox delivery respectively.

New Watch, Agency and API sales remain paused in focus mode. Existing subscriber management and cancellation routes stay available. Keep the old features for existing obligations; do not advertise them during this experiment.

## First customer acceptance

- Open the live page on mobile. Run a scan of your own app.
- Buy the report through Razorpay using your own payment method. Confirm the exact amount before paying.
- Confirm that the report unlocks, email arrives and PDF downloads. Check the email spam folder too.
- Apply a known fix, run the included re-check and confirm it is already unlocked. Repeated clicks must reuse that same re-check.
- Record a refund/recovery procedure in the payment dashboard. Do not claim a live purchase/refund was tested unless it was actually completed.
- In Render, confirm fixed SHIPPROOF_SECRET_KEY, RESEND_API_KEY and the private Supabase bucket. Verify storage survives a redeploy. Never paste those secrets into a public issue or this repository.

The implementation is designed for one application instance. Before scaling to multiple instances, move quotas, fulfillment idempotency and credit balances into transactional shared storage.

## Daily operator routine (10 minutes)

1. Open /admin/login. Check new paid orders against Razorpay, including email delivery results.
2. Answer support mail. If someone paid but has no report, verify the payment ID in Razorpay before manual unlock. Never ask them to pay again.
3. Check source funnel and refunds. Record acquisition spend separately. Visit/scan/checkout numbers are events, not unique people.
4. Check hosting/storage/email alerts and available provider quotas. Keep a provider-side AI budget cap.
5. Do not deploy experimental features while a payment incident is unresolved.

## First 14 days: validate before buying reach

Cash budget: Rs 0 initially. Five relevant conversations a day with small Lovable/Bolt agencies or founders preparing a launch. Offer the free check and sample report. Ask permission before scanning their app. No bulk spam or invented vulnerability claims.

Message:

> Hi [name], do you hand AI-built apps to clients? I built Trustfield to turn common public security mistakes into a fix list and prompts for the AI builder. Would you try a free check on one app you own and tell me whether the report helps your handover? The optional full report is Rs 499; you can view a sample first.

Post three short recordings using your own demo: issue -> evidence -> fix prompt -> re-check. Share only where promotion is allowed. Ask paying customers for a quote only after delivery, and publish it only with consent.

Working experiment targets: 20 relevant completed scans, five buyer conversations, three paid orders, one repeat-use signal. These are decision targets, not forecasts. No scans: revise audience/message. Scans but no buyers: investigate trust/usefulness/payment friction. Do not respond by simply increasing ad spend.

## Small paid experiment after real delivery works

Use one Google Search campaign with narrow problem terms such as Lovable security scan or AI app security check. Exclude jobs, courses and certificates. Start with an experiment you can afford to lose, for example Rs 1,000 total, and monitor accumulated spend. Daily budget is an average, not a hard total cap.

Landing URL: https://trustfield.dev/?utm_source=google
LinkedIn URL: https://trustfield.dev/?utm_source=linkedin
Community URL: https://trustfield.dev/?utm_source=community

Ad concept:

> Built With AI? Check Before Launch.
> Find exposed keys and common public security mistakes. Free check. Optional Rs 499 report with evidence, fix prompts, PDF and one re-check.

Measure actual paid orders, not clicks. Rs 499 price x an assumed 2% purchase conversion permits only Rs 9.98 per click before fees, refunds, service costs and profit. Rs 10/click at that conversion already loses money. Measure your own conversion before increasing spend. Do not run broad boosts to everyone interested in AI.

## Verification and release

Backend regression suite: `python -m unittest discover -s tests -t .`
Browser QA (Playwright + Edge installed): `node tools/verify_launch.cjs http://127.0.0.1:8766`
Browser harness mocks scan results. It does not make payments.

Keep a dated deployment commit. Deploy only from the latest main branch. Do not publish the older D:/idea/shipproof checkout over the current deployment without merging the newer GitHub changes first.

No ad campaign, paid hosting upgrade, subscription purchase or live refund is initiated by this release.
