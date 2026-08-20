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

**Those are two files written by two commands, and for one round they disagreed.** The headline
comes from `dashboard.json`; the per-repository table comes from the scorecards. The final
2026-08-16 round published `overall.fp = 271` while its own `by_repo` table in the same file
summed to **273**: `dashboard.py` had not been re-run after that round's `score.py`, so the
headline was the *previous* engine's aggregate and the table was this one's.

The first reading of that was "271 was never produced by any engine", and re-running the two
earlier engines from worktrees says otherwise — they emit 930 findings and 271 false positives,
exactly as published. The round that shipped 271 emits **932**, and the two extra are
`PROTO-JS-WRITE` on one vendored `static/js` file: the `hasOwnProperty` guard that round removed
on purpose. So the defect is not a phantom number, it is **a round that changed the engine and
republished the previous engine's headline**, which is worse, because its own conclusion rested
on that headline — the page argued the change was safe partly because RealVuln's false positives
were "271 before and after". They were 271 before and 273 after. What genuinely did not move is
the labelled trap count, 248 either way, and that is the instrument the argument needed.

`_refuse_if_inconsistent` is the fix at write time and check 42 is the fix at build time. The
generalisation is the part worth keeping: **a file assembled from two sources needs a check that
the two agree, and "they are both the scorer's output" is not that check.** Check 27 tied the
prose to this file and check 32 tied this file to the engine; nothing tied this file to itself.

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
REPO = os.path.dirname(os.path.dirname(HERE))
RESULT = os.path.join(HERE, "result.json")

sys.path.insert(0, os.path.join(REPO, "scripts"))
from engine_digest import engine_digest                                       # noqa: E402


def read_dashboard(benchmark: str, scanner: str) -> dict:
    path = os.path.join(benchmark, "reports", "dashboard.json")
    with open(path, encoding="utf-8") as f:
        aggregates = json.load(f)["aggregates"]
    if scanner not in aggregates:
        raise SystemExit(f"{path} has no aggregate for '{scanner}' — scored scanners: "
                         f"{', '.join(sorted(aggregates))}")
    return aggregates[scanner]


def read_scorecards(benchmark: str, scanner: str, run_date: str) -> tuple[dict, dict]:
    """Per-family totals and per-repo scores, summed from the scorer's own per-repo cards.

    Note 3 in this directory's README applies with force here: scoring a second scanner
    overwrites these cards for the same date, so they must be read before the next scanner is
    scored. A card that belongs to another scanner is skipped rather than misattributed.

    **One card per repository, and picking which one is not a detail.** `score.py` writes
    `scorecard-<date>.json`, so a benchmark checkout that has been scored on two days holds two
    cards per repository, both carrying an entry for this scanner. The first version of this
    function read every card it found: `repos[repo]` was overwritten and stayed right, and
    `families[...] += ...` accumulated, so **every per-family total came out doubled** while the
    per-repository table beside it did not. Check 27 caught it on the first run after a second
    date existed — `open_redirect 74 / 80` where the page says `37 / 40` — but only because the
    prose was already gated; nothing in this script would have noticed, and a family table that
    doubles uniformly still looks like a table.

    So: the card for `run_date` if it exists, otherwise the newest, and never more than one.
    """
    families: dict[str, dict] = {}
    repos: dict[str, dict] = {}
    by_repo_dir: dict[str, list[str]] = {}
    for path in sorted(glob.glob(os.path.join(benchmark, "reports", "*", "scorecard-*.json"))):
        by_repo_dir.setdefault(os.path.dirname(path), []).append(path)
    chosen = [next((p for p in cards if p.endswith(f"scorecard-{run_date}.json")), max(cards))
              for cards in by_repo_dir.values()]

    for path in sorted(chosen):
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


def read_run_digest(benchmark: str, scanner: str) -> str | None:
    """The engine `run.py` recorded when it produced this scanner's results, if it recorded one."""
    path = os.path.join(benchmark, "scan-results", f".secaudit-engine-{scanner}.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh).get("engine_digest")


def refuse_if_inconsistent(overall: dict, repos: dict) -> None:
    """Refuse to write a headline that its own per-repository table contradicts.

    The scorer counts every finding that is not a true positive as a false positive, so the two
    tables are the same numbers grouped differently and they have to add up. When they do not,
    one of the two files was written at a different moment than the other — which is a real
    failure and not a rounding artefact, and the only safe thing to do with it is stop.
    """
    summed = {key: sum(r.get(key) or 0 for r in repos.values()) for key in ("tp", "fp", "fn")}
    stated = {key: overall.get(key) for key in ("tp", "fp", "fn")}
    if not repos or summed == stated:
        return
    raise SystemExit(
        "REFUSING TO COLLECT — reports/dashboard.json and the per-repo scorecards disagree:\n"
        f"  dashboard aggregate: {stated}\n"
        f"  sum of {len(repos)} scorecards: {summed}\n"
        "One of the two was written before the other finished. Re-run `score.py` for every "
        "repository and then `dashboard.py`, in that order, and collect again.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--benchmark", required=True, help="path to the scored benchmark checkout")
    ap.add_argument("--scanner", default="secaudit", help="scanner slug that was scored")
    ap.add_argument("--run-date", required=True, help="date of the run, YYYY-MM-DD")
    ap.add_argument("--label", required=True,
                    help="what changed in this round, for the previous_runs history")
    ap.add_argument("--previous-label",
                    help="how to describe the run being pushed into previous_runs; "
                         "required unless --amend")
    ap.add_argument("--amend", action="store_true",
                    help="replace the current head instead of pushing it into previous_runs — "
                         "for re-measuring a round that has not been committed yet")
    # Correcting a published figure means stamping it with the engine that produced it, which is
    # not the engine in front of you. `git worktree add <dir> <commit>` and point this at its
    # kit/ — the same flag, for the same reason, as `eval/secbenchjs/run.py --engine-kit`.
    ap.add_argument("--engine-kit", default=os.path.join(REPO, "kit"),
                    help="the kit/ whose digest to stamp (default: this checkout's)")
    args = ap.parse_args()
    if not args.amend and not args.previous_label:
        ap.error("--previous-label is required unless --amend is given")
    if args.amend and args.previous_label:
        ap.error("--amend replaces the head, so there is nothing to push into previous_runs "
                 "and no --previous-label to give")

    benchmark = os.path.abspath(args.benchmark)
    aggregate = read_dashboard(benchmark, args.scanner)
    families, repos = read_scorecards(benchmark, args.scanner, args.run_date)
    refuse_if_inconsistent(aggregate["micro"], repos)

    with open(RESULT, encoding="utf-8") as f:
        result = json.load(f)

    # A round is measured more than once — a fix lands, the corpus is re-run, the figures move.
    # Every one of those re-runs used to push the *current* head onto the history under the
    # PREVIOUS round's label, so collecting twice left a save point wearing the wrong name and
    # the history grew a run that never happened. It happened three times before it was named.
    # `--amend` is what that second collection actually wanted: replace the head, keep history.
    if not args.amend:
        result.setdefault("previous_runs", []).insert(0, {
            "run_date": result.get("run_date"),
            "label": args.previous_label,
            "overall": result["overall"],
            "by_family": result["by_family"],
        })

    # Stamped here, by the step that writes the figures, and not left to whoever remembers.
    # `engine_digest_note` says "never the digest alone" and that instruction was the only thing
    # keeping the two together — so the failure mode was a person updating the figures, leaving
    # the digest, and check 32 reporting a mismatch that looks like a stale digest rather than
    # what it is. The digest is a property of the run; the run writes it.
    #
    # **Read from the run, not from the tree.** Hashing the working tree here answers "what is
    # the code now", and the field claims "what produced these figures". Those came apart the
    # first time a docstring was edited between the scan and the collection: the stamp matched
    # the tree, check 32 compares the stamp to the tree, and the run it actually described was
    # two edits old. `run.py` now writes the digest beside the results it wrote, and this reads
    # that. `--engine-kit` remains for a benchmark checkout scanned before that existed.
    digest = read_run_digest(benchmark, args.scanner)
    if digest is None:
        digest, unlisted = engine_digest(os.path.abspath(args.engine_kit))
        if unlisted:
            raise SystemExit(
                "refusing to stamp a digest that does not cover the whole engine — these modules "
                "are in neither list in scripts/engine_digest.py: " + ", ".join(unlisted))
        print(f"  (no engine stamp from run.py for '{args.scanner}'; hashing "
              f"{os.path.abspath(args.engine_kit)} instead)")
    result["engine_digest"] = digest
    result["run_date"] = args.run_date
    result["run_label"] = args.label
    result["overall"] = aggregate["micro"]
    result["strict_micro"] = aggregate["strict_micro"]
    result["by_family"] = families
    result["by_repo"] = repos
    result["repos_scored"] = aggregate.get("repos_scored", result.get("repos_scored"))
    result["repos_total"] = aggregate.get("repos_total", result.get("repos_total"))

    with open(RESULT, "w", encoding="utf-8", newline="\n") as f:
        # indent=2, like `eval/harness.py` and `eval/secbenchjs/score.py` and like the file
        # already committed here. It was 1, which meant every collected run reformatted the
        # whole file and buried a five-line change in a two-thousand-line diff — the reviewer
        # cannot see what moved, which for a measurement file is most of the point of committing
        # it at all.
        json.dump(result, f, indent=2, ensure_ascii=False)
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
