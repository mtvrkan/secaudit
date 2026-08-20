#!/usr/bin/env python3
"""Produce SecAudit results for the RealVuln benchmark, in the shape its scorer ingests.

    git clone https://github.com/kolega-ai/Real-Vuln-Benchmark
    cd Real-Vuln-Benchmark && python3 clone_repos.py && cd -
    python3 eval/realvuln/run.py --benchmark ../Real-Vuln-Benchmark
    cd ../Real-Vuln-Benchmark && python3 score.py --scanner secaudit --all-repos

Why an external benchmark at all: every number in `eval/scorecard.md` is measured against a
corpus written alongside the detectors, which makes it a regression floor and nothing more.
RealVuln is 66 real vulnerable repositories with hand-labelled findings **and false-positive
traps**, scored by code we did not write. Its published baselines are the comparison that
means something — rule-based SAST at F3 17.7, general-purpose LLMs around 51.7, purpose-built
systems at 73.0. Whatever SecAudit scores, that number goes in the README unedited.

This script only writes result files. It deliberately does not compute a score: the benchmark's
own `score.py` is the authority, and a tool that grades itself against someone else's corpus
has reintroduced exactly the problem the corpus was meant to solve.

RealVuln accepts Semgrep-format JSON from any scanner without a custom parser, which is what
`--format semgrep` emits.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KIT = os.path.join(REPO, "kit")
SCANNER_SLUG = "secaudit"

sys.path.insert(0, os.path.join(REPO, "scripts"))
from engine_digest import engine_digest                                       # noqa: E402


def stamp_engine(benchmark: str, scanner: str) -> str:
    """Record which engine produced this run, beside the results it produced.

    `collect_result.py` used to stamp `result.json` with the digest of the working tree at the
    moment of collection, which answers a different question from the one the field claims to
    answer: the tree is what the code is *now*, and the figure describes what scanned. Editing a
    docstring between the run and the collection was enough to make the stamp a fiction that
    check 32 could not see, because the stamp and the tree agreed with each other and neither had
    anything to do with the run. `eval/secbenchjs/run.py` had this right — every result file it
    writes carries the digest of the engine that wrote it — and this side did not.

    The file lives at the root of `scan-results/` and not inside the scanner's directory, because
    the benchmark's own `dashboard.py` reads every `*.json` under a scanner directory as another
    run of that scanner.
    """
    digest, unlisted = engine_digest(KIT)
    if unlisted:
        raise SystemExit("refusing to run with modules in neither list in "
                         "scripts/engine_digest.py: " + ", ".join(unlisted))
    path = os.path.join(benchmark, "scan-results", f".secaudit-engine-{scanner}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"engine_digest": digest, "scanner": scanner}, fh, indent=2)
        fh.write("\n")
    return digest


def repos_in(benchmark: str) -> list[str]:
    """Benchmark repo ids, taken from the ground-truth directory."""
    gt = os.path.join(benchmark, "ground-truth")
    if not os.path.isdir(gt):
        return []
    return sorted(name for name in os.listdir(gt)
                  if os.path.isfile(os.path.join(gt, name, "ground-truth.json")))


def checkout_path(benchmark: str, repo_id: str) -> str | None:
    """Where `clone_repos.py` put the source for a repo id, if it is there."""
    for candidate in (os.path.join(benchmark, "repos", repo_id),
                      os.path.join(benchmark, "targets", repo_id),
                      os.path.join(benchmark, repo_id)):
        if os.path.isdir(candidate):
            return candidate
    return None


def scan(target: str, backend: str = "none") -> dict:
    """Run the CLI as a subprocess rather than importing it.

    The benchmark measures the tool a user installs, not a function called in-process with
    tuned arguments — and a crash on one repo must not take the whole run down with it.

    `backend` selects the tier. The default `none` is the deterministic Tier-0 run every
    published figure describes. Anything else enriches with that LLM backend, which is what
    `--backend` on this script exists for — see `main` for why no such number is published yet.
    """
    env = dict(os.environ, PYTHONPATH=KIT + os.pathsep + os.environ.get("PYTHONPATH", ""),
               PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "secaudit_core.cli", target, "--format", "semgrep",
         "--no-deps", "--no-scanners", "--backend", backend],
        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
        cwd=REPO, timeout=1800)
    if proc.returncode not in (0, 1):      # 1 is the severity gate, not a failure
        raise RuntimeError(proc.stderr.strip()[:400] or f"exit {proc.returncode}")
    return json.loads(proc.stdout)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--benchmark", required=True,
                    help="path to a Real-Vuln-Benchmark checkout with repos already cloned")
    ap.add_argument("--repo", help="score a single repo id instead of all of them")
    # A second slug lets two builds of the engine be scored against the SAME clone of the
    # corpus. Without it, "did this change help?" can only be answered against a number
    # taken months earlier, when the corpus may have moved underneath it.
    ap.add_argument("--scanner", default=SCANNER_SLUG,
                    help="scanner slug the results are written under (default: secaudit)")
    # The Tier-1 switch. Everything this repository publishes about RealVuln is Tier 0, because
    # Tier 0 is the part that reproduces: same corpus, same engine, same number, on any machine
    # with no key. A model run is not that, and the honest way to hold both facts is to make the
    # measurement one command away and say plainly that it has not been run — rather than either
    # quietly omitting the tier or quoting a number nobody can reproduce.
    ap.add_argument("--backend", default="none",
                    choices=("none", "anthropic", "openai", "ollama"),
                    help="LLM backend to enrich with (default: none — the Tier-0 run every "
                         "published figure describes). Anything else measures Tier 1 and needs "
                         "that backend's key in the environment; use a distinct --scanner slug "
                         "so it is never mistaken for the reproducible number.")
    args = ap.parse_args()

    if args.backend != "none" and args.scanner == SCANNER_SLUG:
        print(f"Refusing to write a Tier-1 run under the `{SCANNER_SLUG}` slug: that slug is "
              f"what `result.json` and every published figure mean, and a model run cannot be "
              f"reproduced by the next person. Re-run with --scanner {SCANNER_SLUG}-tier1.")
        return 2
    if args.backend != "none":
        print(f"Tier 1 via `{args.backend}` — NOT reproducible. Two runs on the same corpus can "
              f"disagree, so whatever this scores is a single observation, not a floor.\n")

    benchmark = os.path.abspath(args.benchmark)
    repos = [args.repo] if args.repo else repos_in(benchmark)
    if not repos:
        print(f"No ground-truth directories under {benchmark}/ground-truth — is this a "
              f"Real-Vuln-Benchmark checkout?")
        return 1

    print(f"Engine {stamp_engine(benchmark, args.scanner)}")

    written, skipped, failed = 0, [], []
    for repo_id in repos:
        source = checkout_path(benchmark, repo_id)
        if source is None:
            skipped.append(repo_id)
            continue
        try:
            payload = scan(source, args.backend)
        except Exception as e:
            failed.append(f"{repo_id}: {e}")
            continue
        # Paths must be relative to the repo root for the scorer to line them up with labels.
        for result in payload.get("results", []):
            result["path"] = os.path.relpath(
                os.path.join(source, result["path"]), source).replace("\\", "/")
        out_dir = os.path.join(benchmark, "scan-results", repo_id, args.scanner)
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        written += 1
        print(f"  {repo_id}: {len(payload.get('results', []))} result(s)")

    print(f"\nWrote results for {written}/{len(repos)} repo(s).")
    # Never summarize a partial run as a clean one — a silently skipped repo would show up in
    # the score as a repo with no findings, which reads as a scanner that missed everything.
    if skipped:
        print(f"SKIPPED (not cloned — run `python3 clone_repos.py` first): "
              f"{', '.join(skipped[:10])}{'…' if len(skipped) > 10 else ''}")
    if failed:
        print("FAILED:")
        print("\n".join("  - " + f for f in failed))
    # `score.py` takes one repo at a time; `--all-repos` does not exist. This line printed the
    # flag that does not exist, which is the first thing anyone reproducing the run copies.
    print(f"\nNow score with the benchmark's own scorer, one repo at a time:\n"
          f'  cd {benchmark} && for r in repos/*/; do python3 score.py '
          f'--repo "$(basename "$r")" --scanner {args.scanner}; done\n'
          f"  python3 dashboard.py --scanners {args.scanner}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
