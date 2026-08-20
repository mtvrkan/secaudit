#!/usr/bin/env python3
"""Turn the noise-floor scans into `result.json`: findings per 1,000 lines, Tier 0.

Three cuts, because they answer different questions and only the last two are the ones that
cost a reader anything:

  * **all findings** — everything the scan emitted, informational included;
  * **High and Critical** — what a triage queue would actually contain;
  * **HIGH confidence** — the request-rooted paths, which is what the engine claims rather than
    suspects, and the same cut the dogfood gate holds this repository's own source to.

The denominator is physical lines of the source the engine claims — `.py`, the JS/TS family and
the PHP one — counted by `run.py` at scan time. Not `cloc`: a reproducible figure cannot depend on a tool the
reader may not have, and the denominator has to be what was scanned rather than what a language
census would report.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))

_ACTIONABLE = ("Critical", "High")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--run-date", required=True, help="date of the run, YYYY-MM-DD")
    ap.add_argument("--out", default=os.path.join(HERE, "result.json"))
    args = ap.parse_args(argv)

    results = os.path.join(os.path.abspath(args.workdir), "scan-results")
    per_repo, digests = {}, set()
    totals = collections.Counter()
    by_detector = collections.Counter()

    for name in sorted(os.listdir(results)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(results, name), encoding="utf-8") as fh:
            payload = json.load(fh)
        if "lines" not in payload:              # a scan that failed before it was annotated
            continue
        digests.add(payload.get("engine_digest") or "")
        findings = payload["findings"]
        lines = payload["lines"]
        actionable = [f for f in findings if f["severity"] in _ACTIONABLE]
        high_conf = [f for f in findings if f["confidence"] == "high"]
        for f in findings:
            by_detector[f["detector_id"]] += 1
        totals["findings"] += len(findings)
        totals["actionable"] += len(actionable)
        totals["high_confidence"] += len(high_conf)
        totals["lines"] += lines
        per_repo[payload["name"]] = {
            "lang": payload["lang"], "sha": payload["sha"], "lines": lines,
            "findings": len(findings), "actionable": len(actionable),
            "high_confidence": len(high_conf),
            "per_1k_lines": round(len(findings) / (lines / 1000), 2) if lines else 0.0,
            "actionable_per_1k_lines": round(len(actionable) / (lines / 1000), 2) if lines else 0.0,
        }

    if len(digests) > 1:
        # Same refusal as the SecBench scorer, for the same reason: an aggregate over results
        # produced by two engines is a number neither engine produced.
        raise SystemExit(
            "REFUSING TO SCORE — the scans were produced by more than one engine:\n"
            + "\n".join(f"  - {d or '(no digest recorded)'}" for d in sorted(digests)))
    if not per_repo:
        raise SystemExit(f"no scan results under {results} — run eval/noisefloor/run.py first")

    kloc = totals["lines"] / 1000
    result = {
        "note": "Findings per 1,000 lines on twelve maintained projects that are NOT a "
                "vulnerability corpus. This is a NOISE FLOOR — an upper bound on how much a "
                "user is asked to read — and NOT a precision: nobody has adjudicated these "
                "findings and some may be real.",
        "run_date": args.run_date,
        "engine_digest": next(iter(digests), ""),
        "engine_digest_note": "The engine that produced these scans, taken from the scan "
                              "results rather than the working tree. Check 32 holds it against "
                              "this tree so the published figure cannot outlive the code.",
        "tier": "Tier 0 only (no dependency scan, no external scanners, no LLM)",
        "repos_scored": len(per_repo),
        "total_lines": totals["lines"],
        "overall": {
            "findings": totals["findings"],
            "per_1k_lines": round(totals["findings"] / kloc, 2) if kloc else 0.0,
            "actionable": totals["actionable"],
            "actionable_per_1k_lines": round(totals["actionable"] / kloc, 2) if kloc else 0.0,
            "high_confidence": totals["high_confidence"],
            "high_confidence_per_1k_lines": (round(totals["high_confidence"] / kloc, 2)
                                             if kloc else 0.0),
        },
        "by_repo": dict(sorted(per_repo.items(), key=lambda kv: -kv[1]["per_1k_lines"])),
        "loudest_detectors": dict(by_detector.most_common(10)),
    }
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    o = result["overall"]
    print(f"Noise floor — {len(per_repo)} repos, {totals['lines']:,} lines of scanned source.")
    print(f"  all findings        {o['findings']:5}   {o['per_1k_lines']:6.2f} per 1k lines")
    print(f"  High + Critical     {o['actionable']:5}   {o['actionable_per_1k_lines']:6.2f} "
          f"per 1k lines")
    print(f"  HIGH confidence     {o['high_confidence']:5}   "
          f"{o['high_confidence_per_1k_lines']:6.2f} per 1k lines")
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
