"""Test bootstrap: private-network scanning + no rate limits + throwaway data dir."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("SHIPPROOF_ALLOW_PRIVATE", "1")
os.environ.setdefault("SHIPPROOF_RATE_LIMIT", "0")
os.environ.setdefault("SHIPPROOF_UNLOCK_ALL", "0")
# Paywall behaviour is the default in tests; free-mode is covered explicitly.
os.environ["SHIPPROOF_FREE_REPORTS"] = "0"
# Force a dedicated data dir: tests truncate it, so it must never point at real reports.
os.environ["SHIPPROOF_DATA"] = str(ROOT / "data" / "test")
os.environ.setdefault("SHIPPROOF_ADMIN_TOKEN", "test-token")
os.environ.setdefault("SHIPPROOF_SECRET_KEY", "test-secret-key")
os.environ.setdefault("RAZORPAY_WEBHOOK_SECRET", "test-whsec")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "test-stripe-whsec")

sys.path.insert(0, str(ROOT / "app"))
