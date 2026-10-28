"""Single place for every brandable / tunable value.

Rename the product by changing SHIPPROOF_BRAND — nothing else hardcodes it.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent          # .../app/shipproof
APP_ROOT = APP_DIR.parent                           # .../app
PROJECT_ROOT = APP_ROOT.parent                      # .../shipproof
TEMPLATES_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"

# ---------------------------------------------------------------- brand ----
BRAND = os.environ.get("SHIPPROOF_BRAND", "Trustfield")
TAGLINE = "Trust, verified."
TAGLINE_HI = "Bharosa, verified."
BASE_URL = os.environ.get("SHIPPROOF_BASE_URL", "https://trustfield.dev").rstrip("/")
CONTACT_EMAIL = os.environ.get("SHIPPROOF_CONTACT_EMAIL", "info@trustfield.dev")
SUPPORT_EMAIL = os.environ.get("SHIPPROOF_SUPPORT_EMAIL", "support@trustfield.dev")
SECURITY_EMAIL = os.environ.get("SHIPPROOF_SECURITY_EMAIL", "security@trustfield.dev")
SUPPORT_WHATSAPP = os.environ.get("SHIPPROOF_WHATSAPP", "")
LEGAL_NAME = os.environ.get("SHIPPROOF_LEGAL_NAME", "[YOUR LEGAL NAME]")
CITY = os.environ.get("SHIPPROOF_CITY", "Bengaluru")

# -------------------------------------------------------------- pricing ----
PAYMENT_LINK = os.environ.get("SHIPPROOF_PAYMENT_LINK", "").strip()
WATCH_PAYMENT_LINK = os.environ.get("SHIPPROOF_WATCH_PAYMENT_LINK", "").strip()
PRICE_INR = os.environ.get("SHIPPROOF_PRICE_INR", "499")
PRICE_USD = os.environ.get("SHIPPROOF_PRICE_USD", "9")
WATCH_INR = os.environ.get("SHIPPROOF_WATCH_INR", "499")
WATCH_USD = os.environ.get("SHIPPROOF_WATCH_USD", "9")
AGENCY_INR = os.environ.get("SHIPPROOF_AGENCY_INR", "3999")
AGENCY_USD = os.environ.get("SHIPPROOF_AGENCY_USD", "79")

# ------------------------------------------------------------- payments ----
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "")
RAZORPAY_WEBHOOK_SECRET = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

# ---------------------------------------------------------------- email ----
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
EMAIL_FROM = os.environ.get("SHIPPROOF_EMAIL_FROM", "Trustfield <reports@trustfield.dev>")
ADMIN_EMAIL = os.environ.get("SHIPPROOF_ADMIN_EMAIL", CONTACT_EMAIL)

# Signed links + admin. SECRET_KEY signs PDF/download links.
ADMIN_TOKEN = os.environ.get("SHIPPROOF_ADMIN_TOKEN", "")
ADMIN_PASSWORD = os.environ.get("SHIPPROOF_ADMIN_PASSWORD", "") or ADMIN_TOKEN
SECRET_KEY = os.environ.get("SHIPPROOF_SECRET_KEY", "") or ADMIN_TOKEN or "dev-secret-change-me"
TOKEN_TTL_DAYS = int(os.environ.get("SHIPPROOF_TOKEN_TTL_DAYS", "90"))

# ------------------------------------------------------------ ai copilot ----
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
DEEPSEEK_URL = os.environ.get("DEEPSEEK_URL", "https://api.deepseek.com/chat/completions")
# Hard stop: maximum AI answers per day across the whole service (loss guard).
AI_DAILY_LIMIT = int(os.environ.get("SHIPPROOF_AI_DAILY_LIMIT", "300"))

# ---------------------------------------------------------- supabase store ----
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
SUPABASE_BUCKET = os.environ.get("SUPABASE_BUCKET", "trustfield")

# ------------------------------------------------------------- runtime -----
PORT = int(os.environ.get("PORT", "8000"))
HOST = os.environ.get("HOST", "0.0.0.0")

DATA_DIR = Path(os.environ.get("SHIPPROOF_DATA", str(PROJECT_ROOT / "data")))
SCANS_DIR = DATA_DIR / "scans"
LEADS_FILE = DATA_DIR / "leads.jsonl"
ORDERS_FILE = DATA_DIR / "orders.jsonl"
INDEX_FILE = DATA_DIR / "index.jsonl"
EMAIL_OUTBOX = DATA_DIR / "outbox"

# Allow scanning private/loopback targets (tests + local dev only).
ALLOW_PRIVATE = os.environ.get("SHIPPROOF_ALLOW_PRIVATE", "") == "1"
# Never gate reports (demo / self-hosted).
UNLOCK_ALL = os.environ.get("SHIPPROOF_UNLOCK_ALL", "") == "1"
# Free full reports: every finding with evidence/fixes visible to everyone.
# Default is OFF for the paid model: free scan shows the score + every issue
# title, paid unlocks evidence, fixes, prompt kit and the PDF report.
FREE_REPORTS = os.environ.get("SHIPPROOF_FREE_REPORTS", "0") == "1"
# Scans are free by default; set to 1 to require an email before scanning.
REQUIRE_EMAIL = os.environ.get("SHIPPROOF_REQUIRE_EMAIL", "") == "1"

MAX_BODY_BYTES = 32 * 1024
MAX_CONCURRENT_SCANS = max(1, int(os.environ.get("SHIPPROOF_MAX_SCANS", "2")))
SCAN_TIMEOUT_SECONDS = float(os.environ.get("SHIPPROOF_SCAN_TIMEOUT", "75"))

# Repo download limits (zip-bomb protection lives in repo.py as well).
MAX_REPO_ZIP_BYTES = 40 * 1024 * 1024
MAX_REPO_UNPACKED_BYTES = 160 * 1024 * 1024
MAX_REPO_FILES = 6000
MAX_FILE_BYTES = 300 * 1024

# Live scan limits.
MAX_BYTES_PER_URL = 1_200_000
MAX_JS_BUNDLES = 6
HTTP_TIMEOUT = float(os.environ.get("SHIPPROOF_HTTP_TIMEOUT", "8"))
USER_AGENT = "TrustfieldAudit/1.0 (+https://trustfield.dev/bot)"

# Badges stay honest by expiring.
BADGE_VALID_DAYS = int(os.environ.get("SHIPPROOF_BADGE_DAYS", "14"))

# Report unlock is a signed flag in the MVP. Replace with a payment webhook
# before taking real money (see README "Before you charge money").
UNLOCK_PARAM = "unlocked"

# Shown on every report so nobody thinks a scan is a guarantee.
NOT_CHECKED = (
    "Git history for secrets that were deleted later",
    "Anything behind a login (no credentials are used)",
    "Live exploitation or privilege escalation",
    "Business-logic abuse and payment edge cases",
    "Your database contents beyond what the public key can count",
    "Mobile binaries, Chrome extensions and Shopify apps",
    "Server-side code unless you attach a GitHub repo",
)


def now() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now().isoformat(timespec="seconds")


def ensure_dirs() -> None:
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------- analytics ----
AHREFS_KEY = os.environ.get("AHREFS_KEY", "gLBPCAyOg9uZUDtLmDAQ3Q")

# Watch billing mode: "1" = Razorpay recurring subscription, "0" = one-time 30-day link.
WATCH_SUBSCRIPTIONS = os.environ.get("SHIPPROOF_WATCH_SUBSCRIPTIONS", "1") == "1"

# Alerts (optional): paste a Slack or Discord webhook in Render env.
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")

# Focus mode: only the core free scan + Rs 499 report are public.
FOCUS_MODE = os.environ.get("SHIPPROOF_FOCUS_MODE", "1") == "1"

# 100% free mode: full reports are free; monetisation is sponsorship / display ads.
FREE_MODE = os.environ.get("SHIPPROOF_FREE_MODE", "0") == "1"
ADSENSE_CLIENT = os.environ.get("SHIPPROOF_ADSENSE_CLIENT", "")
