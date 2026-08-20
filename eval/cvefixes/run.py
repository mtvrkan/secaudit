#!/usr/bin/env python3
"""Scan the materialised CVEfixes corpus with Tier 0 and write one result file per CVE.

    python3 eval/cvefixes/run.py --corpus ../corpora/cvefixes

Tier 0 only — `--no-deps --no-scanners --backend none` — which is the configuration every
published figure in this repository describes. The dependency tier is off for the same reason
it is off on SecBench.js: the entry under test *is* somebody's project at a vulnerable commit,
and asking what its dependencies were in 2019 answers a different question than the corpus poses.

**The cache is keyed on the engine, not on the entry.** A cache keyed on the entry alone serves a
scan produced by code that no longer exists, and the harness then reports a number for an engine
nobody is running. This repository has already been bitten by exactly that once, on SecBench.js,
where a new front end moved a published recall by precisely zero because every result came off
disk. Each result carries `engine_digest`; one that does not match this tree is rescanned.

Each CVE is scanned as its own directory, so a finding's path identifies the entry it belongs to
and the scanner's cross-file reasoning stays inside one CVE rather than leaking between two
unrelated projects that happen to be in the same corpus.
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

WORKER = r"""
import json, sys
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
    if not os.path.exists(out):
        return False
    try:
        with open(out, encoding="utf-8") as fh:
            return json.load(fh).get("engine_digest") == digest
    except (OSError, ValueError):
        return False


def scan_one(target: str, out: str, timeout: float, digest: str, kit: str) -> str:
    cmd = [sys.executable, "-c", WORKER, target, out, kit, digest]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "timeout"
    if proc.returncode != 0:
        return "error: " + (proc.stderr or "").strip().splitlines()[-1][:160]
    return "ok"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default=os.path.join(REPO, "..", "corpora", "cvefixes"))
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--rescan", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    corpus = os.path.join(args.corpus, "corpus")
    if not os.path.isdir(corpus):
        print(f"no corpus at {corpus} — run eval/cvefixes/build_corpus.py first", file=sys.stderr)
        return 2

    kit = os.path.join(REPO, "kit")
    digest, unlisted = engine_digest(kit)
    if unlisted:
        # The digest is only a cache key worth trusting if it covers the whole engine.
        print("REFUSING TO RUN — modules in neither list in scripts/engine_digest.py: "
              + ", ".join(unlisted), file=sys.stderr)
        return 2
    print(f"Engine {digest}")

    results = os.path.join(args.corpus, "scan-results")
    os.makedirs(results, exist_ok=True)
    entries = sorted(d for d in os.listdir(corpus) if os.path.isdir(os.path.join(corpus, d)))
    if args.limit:
        entries = entries[:args.limit]

    started, reused, failed = time.time(), 0, {}
    for i, cve in enumerate(entries, 1):
        out = os.path.join(results, f"{cve}.json")
        if not args.rescan and _cached_for(out, digest):
            reused += 1
            continue
        status = scan_one(os.path.join(corpus, cve), out, args.timeout, digest, kit)
        if status != "ok":
            failed[cve] = status
        if i % 50 == 0 or i == len(entries):
            print(f"  {i}/{len(entries)}  reused={reused}  failed={len(failed)}  "
                  f"{time.time() - started:.0f}s", flush=True)

    with open(os.path.join(args.corpus, "run.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"engine_digest": digest, "entries": len(entries),
                   "reused": reused, "failed": failed}, fh, indent=1)
        fh.write("\n")
    print(f"scanned {len(entries)} CVE(s), reused {reused}, failed {len(failed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
