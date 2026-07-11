#!/usr/bin/env python3
"""Measure the Claude-free Tier-0 engine against the two shipped corpora:

  * recall    — how many of the 20 golden sinks (V1–V20) the deterministic pack finds on
                fixtures/vulnerable-app.
  * precision — how many HIGH-confidence findings it raises on fixtures/secure-app (the
                negative control). A HIGH finding on safe code is a false positive.

This runs with NO LLM and NO external tools — it is the reproducible floor. It also documents,
by design, which classes the deterministic tier CANNOT reach (IDOR / missing authz = V3),
i.e. exactly what the optional LLM backend is for.

Exit 0 = the floor holds (recall >= threshold, zero HIGH-confidence false positives).
"""
from __future__ import annotations

import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(KIT)
sys.path.insert(0, KIT)

from secaudit_core import engine                      # noqa: E402
from secaudit_core.schema import Confidence, Severity  # noqa: E402

VULN = os.path.join(REPO, "tests", "fixtures", "vulnerable-app")
SECURE = os.path.join(REPO, "tests", "fixtures", "secure-app")

ALL_SINKS = {f"V{i}" for i in range(1, 21)}
# Honest, documented exclusion: broken-access-control / IDOR is a logic flaw with no reliable
# static signature — it needs the enrichment tier. The floor target is everything else.
LLM_TIER_ONLY = {"V3"}
RECALL_TARGET = ALL_SINKS - LLM_TIER_ONLY   # 19 classes the deterministic tier should catch


def main() -> int:
    fails: list[str] = []

    # ---- recall on the vulnerable fixture ----
    vres = engine.scan(VULN, run_deps=False)
    found = {f.maps_to for f in vres.findings if f.maps_to}
    missed = sorted(RECALL_TARGET - found, key=lambda v: int(v[1:]))
    recall_hits = len(found & RECALL_TARGET)
    if missed:
        fails.append(f"recall: expected {len(RECALL_TARGET)} classes, missed {missed}")

    # ---- precision on the secure negative control ----
    sres = engine.scan(SECURE, run_deps=False)
    high_fps = [f for f in sres.findings if f.confidence == Confidence.HIGH]
    if high_fps:
        for f in high_fps:
            fails.append(f"precision: HIGH-confidence false positive {f.detector_id} "
                        f"at {f.file}:{f.line}")

    med_leads = [f for f in sres.findings if f.confidence == Confidence.MEDIUM]

    print("Tier-0 (deterministic, no LLM) — measured on the shipped corpora")
    print("-" * 68)
    print(f"  recall (vulnerable-app):  {recall_hits}/{len(RECALL_TARGET)} deterministic classes"
          f"  ({recall_hits + 0}/{len(ALL_SINKS)} of all 20; V3/IDOR is LLM-tier by design)")
    print(f"  precision (secure-app):   {len(high_fps)} HIGH-confidence false positive(s)"
          f"  ·  {len(med_leads)} medium lead(s) left for triage")
    print(f"  classes reserved for the LLM tier: {sorted(LLM_TIER_ONLY)}")
    print("-" * 68)

    if fails:
        print("FAIL:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print(f"PASS — deterministic floor holds: {recall_hits}/{len(RECALL_TARGET)} recall, "
          f"0 HIGH-confidence false positives.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
