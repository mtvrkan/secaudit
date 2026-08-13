#!/usr/bin/env python3
"""Copy the RealVuln scorer's output into `result.json`, preserving the run history.

`result.json` has always been "the benchmark's own scorer output, copied" — and until now the
copying was done by hand. A hand-copied number is a typed number, which is the one category of
claim this repository does not allow anywhere else: check 27 ties every published RealVuln
figure to this file, so a transcription slip here would propagate into the README, the roadmap
and the social card while every gate stayed green.

So the copy is mechanical. Nothing in this script computes a score. It reads
`reports/dashboard.json` and the per-repo `reports/*/scorecard-*.json` that the benchmark's own
`dashboard.py` and `score.py` wrote, and rearranges them into the shape this repo publishes.

    python3 eval/realvuln/collect_result.py --benchmark ../Real-Vuln-Benchmark \\
        --scanner secaudit --run-date 2026-08-13 --label "what changed in this round"

The current `overall`/`by_family` block is pushed onto `previous_runs` before the new one is
written, so the history the README's comparison table reads from is never lost.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RESULT = os.path.join(HERE, "result.json")


def read_dashboard(benchmark: str, scanner: str) -> dict:
    path = os.path.join(benchmark, "reports", "dashboard.json")
    with open(path, encoding="utf-8") as f:
        aggregates = json.load(f)["aggregates"]
    if scanner not in aggregates:
        raise SystemExit(f"{path} has no aggregate for '{scanner}' — scored scanners: "
                         f"{', '.join(sorted(aggregates))}")
    return aggregates[scanner]


def read_scorecards(benchmark: str, scanner: str) -> tuple[dict, dict]:
    """Per-family totals and per-repo scores, summed from the scorer's own per-repo cards.

    Note 3 in this directory's README applies with force here: scoring a second scanner
    overwrites these cards for the same date, so they must be read before the next scanner is
    scored. A card that belongs to another scanner is skipped rather than misattributed.
    """
    families: dict[str, dict] = {}
    repos: dict[str, dict] = {}
    for path in sorted(glob.glob(os.path.join(benchmark, "reports", "*", "scorecard-*.json"))):
        with open(path, encoding="utf-8") as f:
            card = json.load(f)
        entry = (card.get("scanners") or {}).get(scanner)
        if entry is None:
            continue
        repo = card.get("repo_id") or os.path.basename(os.path.dirname(path))
        repos[repo] = {"f3": entry.get("f3_score"), "precision": entry.get("precision"),
                       "recall": entry.get("recall"), "tp": entry.get("tp"),
                       "fp": entry.get("fp"), "fn": entry.get("fn")}
        for name, stats in (entry.get("per_family") or {}).items():
            bucket = families.setdefault(name, {"tp": 0, "total": 0})
            bucket["tp"] += stats.get("tp", 0)
            bucket["total"] += stats.get("total", stats.get("tp", 0) + stats.get("fn", 0))
    ordered = dict(sorted(families.items(), key=lambda kv: -kv[1]["total"]))
    return ordered, dict(sorted(repos.items(), key=lambda kv: -(kv[1]["f3"] or 0)))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--benchmark", required=True, help="path to the scored benchmark checkout")
    ap.add_argument("--scanner", default="secaudit", help="scanner slug that was scored")
    ap.add_argument("--run-date", required=True, help="date of the run, YYYY-MM-DD")
    ap.add_argument("--label", required=True,
                    help="what changed in this round, for the previous_runs history")
    ap.add_argument("--previous-label", required=True,
                    help="how to describe the run being pushed into previous_runs")
    args = ap.parse_args()

    benchmark = os.path.abspath(args.benchmark)
    aggregate = read_dashboard(benchmark, args.scanner)
    families, repos = read_scorecards(benchmark, args.scanner)

    with open(RESULT, encoding="utf-8") as f:
        result = json.load(f)

    result.setdefault("previous_runs", []).insert(0, {
        "run_date": result.get("run_date"),
        "label": args.previous_label,
        "overall": result["overall"],
        "by_family": result["by_family"],
    })

    result["run_date"] = args.run_date
    result["run_label"] = args.label
    result["overall"] = aggregate["micro"]
    result["strict_micro"] = aggregate["strict_micro"]
    result["by_family"] = families
    result["by_repo"] = repos
    result["repos_scored"] = aggregate.get("repos_scored", result.get("repos_scored"))
    result["repos_total"] = aggregate.get("repos_total", result.get("repos_total"))

    with open(RESULT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, indent=1, ensure_ascii=False)
        f.write("\n")

    micro = result["overall"]
    print(f"Copied {args.scanner} @ {args.run_date}: F3 {micro['f3_score']}, "
          f"precision {micro['precision']}, recall {micro['recall']} "
          f"({micro['tp']} TP / {micro['fp']} FP / {micro['fn']} FN) over "
          f"{result['repos_scored']} repos, {len(families)} families.")
    print(f"History now holds {len(result['previous_runs'])} earlier run(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
