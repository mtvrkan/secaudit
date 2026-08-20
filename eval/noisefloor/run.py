#!/usr/bin/env python3
"""Measure how much a clean checkout is asked to read: findings per 1,000 lines, Tier 0.

Both published numbers answer *does it find the bug*. Neither answers the question anybody
actually asks before adopting a scanner — **how much of my time will this waste?** Precision on
RealVuln is 0.709, but that is precision over a corpus where roughly one line in forty is a
planted flaw. It says nothing about what a healthy repository produces, and a tool that reports
forty things per thousand lines gets switched off in a week whatever its recall.

So: eight widely used, actively maintained projects, pinned by commit SHA, scanned with the same
Tier 0 every other figure here describes.

**A finding here is not automatically a false positive**, and this file will not pretend
otherwise. Nobody has adjudicated them; these are real projects and some findings may be real.
What the number bounds is *volume* — the reading a user is asked to do on code nobody planted
anything in. That is why the headline is a floor and not a precision, in the same way
SecBench.js's unmatched ratio is a lower bound and not a precision.

    python3 eval/noisefloor/run.py --workdir <dir>      # clone at the pinned SHA, then scan
    python3 eval/noisefloor/score.py --workdir <dir> --run-date YYYY-MM-DD
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "scripts"))
from engine_digest import engine_digest                                       # noqa: E402

# The scan runs in a subprocess so one pathological tree cannot take the whole run down with it,
# and so the engine is imported from `kit/` exactly the way the published benchmarks import it.
WORKER = r"""
import json, os, sys
sys.path.insert(0, sys.argv[3])
from secaudit_core import engine
target, out, digest = sys.argv[1], sys.argv[2], sys.argv[4]
result = engine.scan(target, run_deps=False, use_scanners=False)
payload = {"engine_digest": digest,
           "files_scanned": result.files_scanned,
           "findings": [f.to_dict() for f in result.findings]}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(payload, fh)
"""


def clone(name: str, sha: str, dest: str) -> bool:
    """Fetch exactly one commit. Pinned by SHA, so a moved branch cannot change the corpus."""
    if os.path.isdir(os.path.join(dest, ".git")):
        return True
    os.makedirs(dest, exist_ok=True)
    url = f"https://github.com/{name}.git"
    for cmd in (["git", "init", "-q"],
                ["git", "remote", "add", "origin", url],
                ["git", "fetch", "-q", "--depth", "1", "origin", sha],
                ["git", "checkout", "-q", "FETCH_HEAD"]):
        if subprocess.run(cmd, cwd=dest, capture_output=True).returncode:
            return False
    return True


def count_lines(root: str) -> int:
    """Physical lines of the source the engine actually claims, `.git` excluded.

    Deliberately not `cloc`: the denominator has to be reproducible without a tool nobody has,
    and it has to count what was *scanned* rather than what a language census would count.
    """
    # Derived from `langs`, never listed here. This function spelled `(*JSTS_EXTS, ".py")` while
    # the corpus grew four PHP repositories, and the result was a denominator that counted none
    # of their lines and a numerator that counted all of their findings — a per-1k figure over a
    # denominator that did not contain the code it was dividing. The same typed-once-per-consumer
    # shape `langs.py` exists to end, in the one place where getting it wrong changes a published
    # number rather than a finding.
    from secaudit_core.langs import JSTS_EXTS, PHP_EXTS
    exts = (*JSTS_EXTS, *PHP_EXTS, ".py")
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            if not name.lower().endswith(exts):
                continue
            try:
                with open(os.path.join(dirpath, name), "rb") as fh:
                    total += fh.read().count(b"\n") + 1
            except OSError:
                continue
    return total


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workdir", required=True, help="where the pinned checkouts live")
    ap.add_argument("--rescan", action="store_true",
                    help="ignore cached results even when they match this engine")
    args = ap.parse_args(argv)

    sys.path.insert(0, os.path.join(REPO, "kit"))
    with open(os.path.join(HERE, "repos.json"), encoding="utf-8") as fh:
        spec = json.load(fh)

    digest, unlisted = engine_digest()
    if unlisted:
        print("REFUSING TO RUN — these modules are in neither list in scripts/engine_digest.py, "
              "so the engine digest does not describe the whole engine:")
        for rel in unlisted:
            print(f"  - {rel}")
        return 2
    print(f"Engine {digest}")

    workdir = os.path.abspath(args.workdir)
    results = os.path.join(workdir, "scan-results")
    os.makedirs(results, exist_ok=True)
    started = time.time()
    failed = []
    for entry in spec["repos"]:
        slug = entry["name"].replace("/", "__")
        dest = os.path.join(workdir, slug)
        out = os.path.join(results, slug + ".json")
        if not args.rescan and os.path.exists(out):
            with open(out, encoding="utf-8") as fh:
                if json.load(fh).get("engine_digest") == digest:
                    print(f"  {entry['name']}: reused (same engine)")
                    continue
        if not clone(entry["name"], entry["sha"], dest):
            failed.append(entry["name"])
            print(f"  {entry['name']}: CLONE FAILED")
            continue
        cmd = [sys.executable, "-c", WORKER, dest, out, os.path.join(REPO, "kit"), digest]
        if subprocess.run(cmd, capture_output=True).returncode:
            failed.append(entry["name"])
            print(f"  {entry['name']}: SCAN FAILED")
            continue
        with open(out, encoding="utf-8") as fh:
            payload = json.load(fh)
        payload["lines"] = count_lines(dest)
        payload["name"] = entry["name"]
        payload["lang"] = entry["lang"]
        payload["sha"] = entry["sha"]
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        print(f"  {entry['name']}: {len(payload['findings'])} finding(s) "
              f"over {payload['lines']:,} lines")

    print(f"\nDone in {time.time() - started:.0f}s.")
    if failed:
        # Named, never swallowed: a noise floor computed over the repos that happened to clone
        # is a noise floor over an unstated corpus.
        print(f"{len(failed)} repo(s) did NOT produce a result and are excluded from the "
              f"figure: {', '.join(failed)}")
    print("Now score:  python3 eval/noisefloor/score.py --workdir "
          f"{args.workdir} --run-date YYYY-MM-DD")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
