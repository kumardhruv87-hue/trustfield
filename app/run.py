#!/usr/bin/env python3
"""Entry point: `python run.py` (or `python -m shipproof.server`)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from shipproof.server import main  # noqa: E402

if __name__ == "__main__":
    main()
