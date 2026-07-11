#!/usr/bin/env python3
"""Real-code precision signal: run the engine on the kit's OWN production source (a real ~1.5k
-line Python codebase, not a tuned fixture) and require it to stay quiet. Unlike the fixture
numbers, this is a false-positive check against real, non-planted code — the honest complement
to the fixture-tuned recall/precision. If a detector starts flagging the tool's own clean code,
that is a real precision regression to fix (or the detector to refine)."""
from __future__ import annotations

import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KIT)

from secaudit_core import engine                         # noqa: E402
from secaudit_core.schema import Severity                # noqa: E402

SRC = os.path.join(KIT, "secaudit_core")


def main() -> int:
    res = engine.scan(SRC, run_deps=False, use_scanners=False)
    high = [f for f in res.findings if f.severity.rank >= Severity.HIGH.rank]
    total = len(res.findings)

    print(f"Dogfood scan of real production code ({os.path.relpath(SRC, os.path.dirname(KIT))}): "
          f"{total} finding(s), {len(high)} High/Critical.")
    for f in high:
        print(f"  [{f.severity.value}] {f.detector_id} {f.file}:{f.line} — {f.evidence[:80]}")

    if high:
        print("DOGFOOD FAILED — the kit flags High/Critical issues in its own clean source "
              "(false-positive regression; refine the detector or fix the code).")
        return 1
    print("DOGFOOD PASSED — 0 High/Critical false positives on the kit's own real source.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
