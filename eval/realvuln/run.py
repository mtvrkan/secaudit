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


def scan(target: str) -> dict:
    """Run the CLI as a subprocess rather than importing it.

    The benchmark measures the tool a user installs, not a function called in-process with
    tuned arguments — and a crash on one repo must not take the whole run down with it."""
    env = dict(os.environ, PYTHONPATH=KIT + os.pathsep + os.environ.get("PYTHONPATH", ""),
               PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "secaudit_core.cli", target, "--format", "semgrep",
         "--no-deps", "--no-scanners"],
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
    args = ap.parse_args()

    benchmark = os.path.abspath(args.benchmark)
    repos = [args.repo] if args.repo else repos_in(benchmark)
    if not repos:
        print(f"No ground-truth directories under {benchmark}/ground-truth — is this a "
              f"Real-Vuln-Benchmark checkout?")
        return 1

    written, skipped, failed = 0, [], []
    for repo_id in repos:
        source = checkout_path(benchmark, repo_id)
        if source is None:
            skipped.append(repo_id)
            continue
        try:
            payload = scan(source)
        except Exception as e:
            failed.append(f"{repo_id}: {e}")
            continue
        # Paths must be relative to the repo root for the scorer to line them up with labels.
        for result in payload.get("results", []):
            result["path"] = os.path.relpath(
                os.path.join(source, result["path"]), source).replace("\\", "/")
        out_dir = os.path.join(benchmark, "scan-results", repo_id, SCANNER_SLUG)
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
    print(f"\nNow score with the benchmark's own scorer:\n"
          f"  cd {benchmark} && python3 score.py --scanner {SCANNER_SLUG} --all-repos")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
