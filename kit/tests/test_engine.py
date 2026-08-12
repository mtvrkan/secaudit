#!/usr/bin/env python3
"""Measure the Claude-free Tier-0 engine against the two shipped corpora:

  * recall    — how many of the golden sinks the deterministic pack finds on
                fixtures/vulnerable-app.
  * precision — how many HIGH-confidence findings it raises on fixtures/secure-app (the
                negative control). A HIGH finding on safe code is a false positive.

This runs with NO LLM and NO external tools — it is the reproducible floor. It also documents,
by design, which classes the deterministic tier CANNOT reach (IDOR / missing authz = V3),
i.e. exactly what the optional LLM backend is for.

Overlaps `eval/harness.py` on recall and is kept anyway, because it asserts something the
harness structurally cannot: **zero HIGH-confidence findings anywhere on the secure fixture**.
The harness only counts a false positive inside a labelled trap region, so a confident hit on
an unlabelled line of safe code would pass there and fail here.

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

def _golden_ids() -> set[str]:
    """The planted classes, read from the golden set rather than hardcoded as a range.

    A literal `range(1, 21)` silently stops covering the corpus the moment someone plants a
    new flaw — the test keeps passing while measuring less, which is the failure mode this
    whole suite exists to prevent."""
    import re
    path = os.path.join(REPO, "tests", "expected-findings.md")
    with open(path, encoding="utf-8") as f:
        return set(re.findall(r"^\|\s*(V\d+)\s*\|", f.read(), re.M))


def _regions() -> list[tuple[str, int, int, str]]:
    """(file, start, end, golden id) for every planted flaw, from the derived ground truth.

    `maps_to` alone is not enough to decide what was found. It is a property of the *detector*,
    so one detector class covers one golden id — but V2 and V22 are the same class (`exec` with
    a shell string) reached two different ways, one directly and one across a function
    boundary. Keyed on `maps_to`, finding both looks identical to finding one, and the
    interprocedural tier this fixture exists to measure would score as a no-op. Region
    matching is what the eval harness already uses; using it here too means the repo has one
    definition of "detected" rather than two that can disagree."""
    import json
    path = os.path.join(REPO, "eval", "ground-truth", "secaudit-fixtures", "ground-truth.json")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return [(l["file"], l["location"]["start_line"], l["location"]["end_line"], l["id"].split(":")[1])
            for l in data["findings"]
            if l["is_vulnerable"] and l.get("corpus") == "vulnerable-app"]


def _found_ids(findings) -> set[str]:
    """Golden ids covered by this run — by the detector's declared target, or by location."""
    found = {f.maps_to for f in findings if f.maps_to}
    for f in findings:
        name = f.file.replace("\\", "/").split("/")[-1]
        for path, start, end, vid in _regions():
            if name == path and start <= f.line <= end:
                found.add(vid)
    return found


ALL_SINKS = _golden_ids()
# Honest, documented exclusion: broken-access-control / IDOR is a logic flaw with no reliable
# static signature — it needs the enrichment tier. The floor target is everything else.
LLM_TIER_ONLY = {"V3"}
RECALL_TARGET = ALL_SINKS - LLM_TIER_ONLY   # the classes the deterministic tier should catch


def test_corroboration_keeps_distinct_bugs() -> list[str]:
    """Two bugs of the same class, a few lines apart, must both survive corroboration.

    Corroboration folds a taint path into the pattern finding for the SAME bug so one bug is
    not reported twice. It matched on file + CWE + proximity, in list order — and proximity is
    not identity. A second SQL injection three lines below the first absorbed the first one's
    path, and that finding then vanished from the report entirely: a false negative produced by
    the deduplication layer, on code the engine had already correctly analysed. Scanned end to
    end rather than by calling `_corroborate` on hand-built findings, because what has to hold
    is what the user gets out of `scan()`.
    """
    import tempfile
    fails: list[str] = []
    code = ("app.get('/a', (req, res) => {\n"
            "  const { name } = req.query;\n"
            "  db.query(`SELECT * FROM u WHERE n = '${name}'`);\n"
            "});\n"
            "app.get('/b', (req, res) => {\n"
            "  db.query('SELECT * FROM u WHERE id = ' + req.query.id);\n"
            "});\n")
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "routes.js"), "w", encoding="utf-8") as f:
            f.write(code)
        findings = engine.scan(tmp, run_deps=False).findings
    lines = sorted(f.line for f in findings if f.cwe == "CWE-89")
    if lines != [3, 6]:
        fails.append(f"corroboration: two distinct SQL injections must both be reported, "
                     f"got CWE-89 findings on lines {lines}")
    return fails


def main() -> int:
    fails: list[str] = []
    fails += test_corroboration_keeps_distinct_bugs()

    # ---- recall on the vulnerable fixture ----
    vres = engine.scan(VULN, run_deps=False)
    found = _found_ids(vres.findings)
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
          f"  ({recall_hits}/{len(ALL_SINKS)} of all planted; "
          f"{'/'.join(sorted(LLM_TIER_ONLY))} is LLM-tier by design)")
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
