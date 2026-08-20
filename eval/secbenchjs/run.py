#!/usr/bin/env python3
"""Scan every fetched SecBench.js package with Tier 0 and write one result file each.

    python3 eval/secbenchjs/run.py --packages ../secbench-pkgs

Tier 0 only, and deliberately: `--no-deps --no-scanners --backend none` is the configuration
every published figure in this repository describes, and a JavaScript number measured with a
different one would not sit beside the Python one. The dependency tier is switched off for a
second reason here — the target *is* a dependency, and asking whether it has vulnerable
dependencies of its own answers a different question than the benchmark poses.

Findings are written as this repository's own JSON rather than Semgrep's, because the scorer is
in this repository too and there is no third tool to agree with — RealVuln's harness emits
Semgrep JSON because RealVuln's scorer reads it.

**One result per package is cached on disk, and the cache is keyed on the engine.** Six hundred
scans is fifteen minutes, so resuming an interrupted run matters; but a cache keyed on the
package alone is worse than no cache, because it serves a scan produced by code that no longer
exists and the harness reports a number for an engine nobody is running. That is not
hypothetical here: the JavaScript ReDoS front end landed, fired on the benchmark's own sink
files when called directly, and moved the published recall by exactly zero — every result came
off disk. Each result now carries `engine_digest`, and a result whose digest is not this tree's
is rescanned rather than reused. `--rescan` forces the whole corpus regardless.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "kit"))
sys.path.insert(0, os.path.join(REPO, "scripts"))

from engine_digest import engine_digest                                       # noqa: E402

WORKER = r"""
import json, os, sys
sys.path.insert(0, sys.argv[3])
from secaudit_core import engine
target, out, digest = sys.argv[1], sys.argv[2], sys.argv[4]
result = engine.scan(target, run_deps=False, use_scanners=False)
payload = {"engine_digest": digest,
           "files_scanned": result.files_scanned,
           "findings": [{"detector_id": f.detector_id, "cwe": f.cwe, "file": f.file,
                         "line": f.line, "severity": f.severity.value,
                         "confidence": f.confidence.value, "source": f.source}
                        for f in result.findings]}
with open(out, "w", encoding="utf-8", newline="\n") as fh:
    json.dump(payload, fh, indent=1, ensure_ascii=False); fh.write("\n")
"""


def _cached_for(out: str, digest: str) -> bool:
    """Whether `out` holds a result this engine produced.

    A result written before the digest was recorded has no `engine_digest` key at all, and is
    treated as stale rather than as trustworthy — the whole point is that an unlabelled result
    is one whose provenance nobody can state.
    """
    try:
        with open(out, encoding="utf-8") as fh:
            return json.load(fh).get("engine_digest") == digest
    except (OSError, ValueError):
        return False


def scan_one(target: str, out: str, timeout: float, digest: str, kit: str):
    """Scan one package in a child process so a slow one can be abandoned.

    In-process was the obvious first version and it does not survive contact with npm: the
    taint tier reads a whole tree before analysing it, and `react-native` is 30 MB across 586
    JavaScript files. A Python loop cannot be interrupted portably from the outside, so the
    bound has to be a process boundary. It also isolates a crash, which on 594 unaudited
    packages is not a hypothetical.
    """
    cmd = [sys.executable, "-c", WORKER, target, out, kit, digest]
    env = dict(os.environ, PYTHONUTF8="1")
    try:
        proc = subprocess.run(cmd, timeout=(timeout or None), capture_output=True, env=env)
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0 or not os.path.exists(out):
        return None
    return out


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--packages", required=True, help="output directory of fetch_packages.py")
    ap.add_argument("--limit", type=int, default=0, help="scan only the first N (for a smoke run)")
    # 300s, not 120s. The corpus has exactly one package near the old limit — react-native at
    # 30 MB — and it finished in under 120s on an idle machine and timed out on a busy one. That
    # makes the *corpus* a function of machine load: three runs scored 593 packages and the next
    # scored 594, and the unmatched-finding count moved by 110 for no reason anyone could read
    # off a diff. A timeout is meant to be a backstop against a runaway scan, not a routine
    # participant in the measurement, so it is set where nothing in this corpus reaches it.
    ap.add_argument("--timeout", type=float, default=300.0,
                    help="seconds per package before the scan is abandoned (0 disables)")
    ap.add_argument("--rescan", action="store_true",
                    help="ignore cached results even when they match this engine")
    # Reproducing a published figure means running the engine that produced it, and that engine
    # is a `git worktree add` away rather than gone. `score.py`'s `blind_run` used to say the
    # opposite — "the engine that produced it is gone", which was true of the working tree and
    # not of the repository — and the cost of believing it was two numbers measured by two
    # different matchers sitting in one table. The digest is computed from whichever kit is
    # scanning, so a result file still records what actually emitted it.
    ap.add_argument("--engine-kit", default=os.path.join(REPO, "kit"),
                    help="the kit/ directory to scan with (default: this checkout's). Point it "
                         "at another worktree to re-measure a historical engine.")
    args = ap.parse_args(argv)

    packages = os.path.abspath(args.packages)
    with open(os.path.join(packages, "entries.json"), encoding="utf-8") as fh:
        entries = json.load(fh)
    if args.limit:
        entries = entries[:args.limit]

    kit = os.path.abspath(args.engine_kit)
    digest, unlisted = engine_digest(kit)
    if unlisted:
        # The digest is only a cache key worth trusting if it covers the whole engine. A module
        # nobody has classified is one this run cannot promise it hashed.
        print("REFUSING TO RUN — these modules are in neither list in scripts/engine_digest.py, "
              "so the engine digest does not describe the whole engine:")
        for rel in unlisted:
            print(f"  - {rel}")
        return 2
    print(f"Engine {digest}")
    if kit != os.path.join(REPO, "kit"):
        print(f"  from {kit} — this is not this checkout's engine")

    started = time.time()
    scanned = empty = reused = 0
    timed_out: list[tuple[str, float]] = []
    for i, entry in enumerate(entries, 1):
        target = os.path.join(packages, entry["class"], entry["dir"])
        if not os.path.isdir(target) or not os.listdir(target):
            empty += 1
            continue
        out = os.path.join(packages, "scan-results", entry["class"], entry["dir"] + ".json")
        if not args.rescan and _cached_for(out, digest):
            scanned += 1
            reused += 1
            continue
        os.makedirs(os.path.dirname(out), exist_ok=True)
        payload = scan_one(target, out, args.timeout, digest, kit)
        if payload is None:
            size = sum(os.path.getsize(os.path.join(r, f))
                       for r, _, fs in os.walk(target) for f in fs) / 1e6
            timed_out.append((f"{entry['class']}/{entry['dir']}", size))
            print(f"  TIMEOUT after {args.timeout:.0f}s — {entry['dir']} ({size:.1f} MB)")
            continue
        scanned += 1
        if i % 50 == 0 or i == len(entries):
            print(f"  {i}/{len(entries)} scanned ({time.time() - started:.0f}s)")

    print(f"\nScanned {scanned} package(s) in {time.time() - started:.0f}s; "
          f"{empty} were not fetched.")
    # Said out loud on every run. A reuse count of 593 next to a claimed engine change is the
    # one thing that makes this measurement meaningless, and it should not need looking for.
    print(f"{reused} result(s) reused from cache (same engine digest), "
          f"{scanned - reused} freshly scanned.")
    if timed_out:
        # Named, not swallowed. A harness that silently drops the inputs it cannot finish
        # reports a recall computed over the easy half of the corpus.
        print(f"{len(timed_out)} package(s) did NOT finish within {args.timeout:.0f}s and are "
              f"counted as misses by the scorer:")
        for name, size in sorted(timed_out, key=lambda x: -x[1]):
            print(f"  - {name} ({size:.1f} MB)")
    print("Now score:  python3 eval/secbenchjs/score.py --packages "
          f"{args.packages} --run-date YYYY-MM-DD")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
