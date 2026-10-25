"""30-day retention must be enforceable at runtime, not only at boot."""
from __future__ import annotations

import os
import time
import unittest

from shipproof import config, store


class RetentionTests(unittest.TestCase):
    def test_purge_old_removes_expired_scan(self):
        config.ensure_dirs()
        target = config.SCANS_DIR / "retentiontest.json"
        target.write_text("{}", encoding="utf-8")
        old = time.time() - 40 * 86400
        os.utime(target, (old, old))
        store.purge_old(30)
        self.assertFalse(target.exists())

    def test_purge_old_keeps_fresh_scan(self):
        config.ensure_dirs()
        target = config.SCANS_DIR / "retentionfresh.json"
        target.write_text("{}", encoding="utf-8")
        store.purge_old(30)
        self.assertTrue(target.exists())
        target.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
