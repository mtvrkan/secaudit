#!/usr/bin/env python3
"""Select the 12 repositories worth spending inference on, and print what it would cost.

Measuring the LLM tier across all 62 repositories was declined, and the decision was right: it
needs paid inference on a corpus that is 62 clones deep, and the tier is optional and off by
default. But "no full run" was allowed to become "no number at all", and a repository whose whole
argument is *measured, not asserted* now ships one entire tier with nothing behind it. Its own
`docs/what-we-miss.md` says an unmeasured tier is not coverage.

A subsample is not the full run and does not pretend to be. What it is:

* **Concentrated where the tier is supposed to help.** Tier 0 structurally cannot decide
  `broken_access_control`, `missing_auth`, `sensitive_data_exposure` or most of `other` — they
  are properties of what a handler intends, not of any line in it. Ranking the 62 repositories by
  how many labels in exactly those families Tier 0 currently misses puts 31% of them in 12 repos.
* **Selected by the scorer, not by hand.** The ranking is computed from the committed
  per-repository scorecards, so the subsample is derived and re-derivable rather than chosen.
* **Reported as what it is.** Any figure from this must be published as "Tier 1 on a named
  12-repository subset, N labels", never as a corpus figure. The subset is printed below so the
  claim carries its own denominator.

    python3 eval/realvuln/tier1_subsample.py --benchmark ../Real-Vuln-Benchmark
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

# The families the enrichment tier exists to reach. Tier 0 finds these at 1/76, 4/74, 31/141 and
# 268/831 respectively, and the first two are the ones the roadmap has always said need a pass
# that knows what the application intends.
LOGIC_FAMILIES = ("broken_access_control", "missing_auth", "sensitive_data_exposure", "other")

# From the module docstring of `llmcontext.py`: four calls per scan, 240k characters of context
# across them. Priced per repository rather than per call because that is the unit being chosen.
CALLS_PER_SCAN = 4


def rank(benchmark: str, scanner: str) -> list[tuple[int, str]]:
    rows = []
    for path in glob.glob(os.path.join(benchmark, "reports", "*", "scorecard-*.json")):
        with open(path, encoding="utf-8") as fh:
            card = json.load(fh)
        entry = (card.get("scanners") or {}).get(scanner)
        if entry is None:
            continue
        missed = sum(stats.get("fn", 0)
                     for family, stats in (entry.get("per_family") or {}).items()
                     if family in LOGIC_FAMILIES)
        rows.append((missed, card.get("repo_id") or os.path.basename(os.path.dirname(path))))
    rows.sort(reverse=True)
    return rows


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--benchmark", required=True, help="path to the scored benchmark checkout")
    ap.add_argument("--scanner", default="secaudit")
    ap.add_argument("--size", type=int, default=12, help="how many repositories to select")
    args = ap.parse_args(argv)

    rows = rank(os.path.abspath(args.benchmark), args.scanner)
    if not rows:
        raise SystemExit("no scorecards found — score the benchmark first, see README.md")
    top = rows[:args.size]
    covered, total = sum(n for n, _ in top), sum(n for n, _ in rows)

    print(f"Tier-1 subsample — {len(top)} of {len(rows)} scored repositories.\n")
    print(f"{'repo':54} unreached logic-class labels")
    for missed, repo in top:
        print(f"  {repo[:52]:52} {missed}")
    print(f"\nThese hold {covered} of {total} labels ({covered / total:.0%}) in "
          f"{', '.join(LOGIC_FAMILIES)} that Tier 0 does not reach.")
    print(f"Cost: {len(top)} scans x {CALLS_PER_SCAN} calls = {len(top) * CALLS_PER_SCAN} model "
          f"calls, ~240k characters of context each.\n")

    print("To measure it — a distinct --scanner slug, so it can never be mistaken for the "
          "reproducible Tier-0 figure:\n")
    for _, repo in top:
        print(f"  python3 eval/realvuln/run.py --benchmark {args.benchmark} \\\n"
              f"      --repo {repo} --backend anthropic --scanner secaudit-tier1")
    print("\nThen score and read it as what it is:\n"
          f"  cd {args.benchmark} && for r in {' '.join(r for _, r in top)}; do \\\n"
          "      python3 score.py --repo $r --scanner secaudit-tier1; done\n"
          "  python3 dashboard.py --scanners secaudit-tier1\n")
    print("PUBLISH IT AS: \"Tier 1, 12-repository subset selected by unreached logic-class "
          "labels, N of M labels\" — never as a corpus figure. The Tier-0 numbers in "
          "result.json are over 62 repositories and the two are not comparable.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
