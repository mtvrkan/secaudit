#!/usr/bin/env python3
"""One sha256 over every module that can change what a measured run emits.

This started life inside `check_consistency.py`, whose check 32 refuses to let
`eval/realvuln/result.json` claim figures that were produced by different code. It moved here
the day a second consumer appeared, and the second consumer is the reason the move was not
optional: `eval/secbenchjs/run.py` caches one scan result per package, and a cache keyed on the
package alone will happily serve a scan produced by an engine that no longer exists. That is not
a slow test — it is a measurement that silently does not measure. It was found the honest way:
a new ReDoS front end that fires on the benchmark's own sink files moved the published recall by
exactly zero, because every result was served from disk.

So the digest is the cache key. A run whose engine differs from the one that produced a result
rescans rather than reuses, and a result file carries the digest of the engine that wrote it.

What it covers: every `.py` under `secaudit_core/`, except the modules listed in
`NOT_IN_MEASURED_PATH` — each of which is excluded for a stated reason, because a silent
exclusion here is a way to change the engine without changing the digest. Subpackages go in
wholesale; a new top-level module is reported as unlisted rather than quietly hashed or quietly
skipped, so that adding one forces a decision.
"""
from __future__ import annotations

import hashlib
import os

KIT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "kit")

# Reached by a flag the published run does not pass, so they cannot change its findings.
# Each entry carries why — an unexplained exclusion is indistinguishable from an oversight.
NOT_IN_MEASURED_PATH = {
    "backends.py": "the LLM tier; the published run passes `--backend none`",
    "llmcontext.py": "builds the Tier-1 prompt, which that run never sends",
    "patch.py": "only runs under `--suggest-patches`",
    "diff.py": "only runs under `--since`",
    "gitref.py": "only runs under `--since`",
    "compliance.py": "reached only by `--format cra`",
    "sbom.py": "reached only by `--format cyclonedx`",
    "spdx.py": "reached only by `--format spdx`",
    "exploitation.py": "reached only by `--exploitation`",
    "scanners.py": "the published run passes `--no-scanners`",
    "i18n.py": "translates report chrome; the semgrep renderer emits finding fields, not chrome",
    "monitor.py": "reached only by `--watch`, which diffs exploitation feeds rather than code",
}

# The top-level modules that DO shape the measured run. Subpackages (`structural/`, `taint/`) are
# in wholesale — every file in them exists to decide a finding.
MEASURED_TOP_LEVEL = {"__init__.py", "cli.py", "deps.py", "detectors.py", "engine.py",
                      "langs.py", "redos.py", "report.py", "schema.py"}


def engine_digest(kit: str = KIT) -> tuple[str, list[str]]:
    """`(digest, unlisted)` — the hash, and any top-level module nobody has classified yet."""
    core = os.path.join(kit, "secaudit_core")
    hashed, unlisted = [], []
    for dirpath, dirnames, filenames in os.walk(core):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), core).replace("\\", "/")
            if rel in NOT_IN_MEASURED_PATH:
                continue
            if os.path.dirname(rel) == "" and rel not in MEASURED_TOP_LEVEL:
                unlisted.append(rel)
            hashed.append(rel)
    h = hashlib.sha256()
    for rel in sorted(hashed):
        h.update(rel.encode("utf-8"))
        h.update(b"\n")
        # Normalised to LF: a CRLF checkout is not a different engine, and the benchmark's own
        # ground-truth digest already taught this repository that lesson on Windows.
        with open(os.path.join(core, rel.replace("/", os.sep)), "rb") as fh:
            h.update(fh.read().replace(b"\r\n", b"\n"))
    return "sha256:" + h.hexdigest(), unlisted


if __name__ == "__main__":
    import sys

    # An optional kit/ path, so `python3 scripts/engine_digest.py ../worktree/kit` answers the
    # question this script exists for — *which engine produced that result file* — about an
    # engine other than the one in front of you. It used to take the argument and ignore it,
    # which is the one behaviour a digest tool must not have.
    digest, unlisted = engine_digest(sys.argv[1] if len(sys.argv) > 1 else KIT)
    print(digest)
    for rel in unlisted:
        print(f"  unlisted top-level module: {rel}")
