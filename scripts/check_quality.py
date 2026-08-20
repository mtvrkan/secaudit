#!/usr/bin/env python3
"""Lint, type-check and coverage — the three gates that need a tool this package does not ship.

    python3 scripts/check_quality.py --lint --types              # what run_checks.py runs
    python3 scripts/check_quality.py --lint --types --coverage --require    # what CI runs

Every other gate in this repository runs on the standard library, on purpose: the package has
zero runtime dependencies and the suite keeps the same invariant, so a contributor can reproduce
a red build with nothing installed. ruff, mypy and coverage break that — they are real
dependencies, and requiring them locally would make the common case (`python3
scripts/run_checks.py` on a fresh clone) fail for a reason that has nothing to do with the
change being made.

So they degrade, and `--require` is what stops the degradation from becoming the point:

* Without `--require`, a missing tool prints SKIP and exits 0. That is a convenience.
* With `--require`, a missing tool is a failure. CI passes it, so in CI these gates cannot
  silently not-run — which is the failure mode a skip-on-absence check invites and the reason
  several gates in this repo were found to be quietly passing.

Configuration for all three lives in the repository-root `pyproject.toml`, not in flags here:
one place to read, and the same settings whether the tool is run through this script or
directly.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KIT = os.path.join(REPO, "kit")


def _tool_available(module: str, binary: str) -> bool:
    """Importable as a module or present on PATH — either is enough to run it."""
    if shutil.which(binary):
        return True
    probe = subprocess.run([sys.executable, "-c", f"import {module}"],
                           capture_output=True, cwd=REPO)
    return probe.returncode == 0


def _run(label: str, argv: list[str], module: str, binary: str, require: bool) -> int:
    if not _tool_available(module, binary):
        if require:
            print(f"FAIL  {label} — `{binary}` is not installed and --require was passed. "
                  f"CI must never skip this gate; install it or drop --require deliberately.")
            return 1
        print(f"SKIP  {label} — `{binary}` not installed (pip install {binary})")
        return 0

    env = dict(os.environ, PYTHONPATH=KIT + os.pathsep + os.environ.get("PYTHONPATH", ""))
    done = subprocess.run([sys.executable, "-m", *argv], cwd=REPO, env=env,
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    if done.returncode == 0:
        print(f"PASS  {label}")
        return 0
    print(f"FAIL  {label}")
    print((done.stdout or "") + (done.stderr or ""))
    return 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lint", action="store_true", help="ruff over the whole repository")
    parser.add_argument("--types", action="store_true", help="mypy over the shipped package")
    parser.add_argument("--coverage", action="store_true",
                        help="run the suite under coverage and enforce the floor")
    parser.add_argument("--require", action="store_true",
                        help="a missing tool is a failure, not a skip (CI passes this)")
    args = parser.parse_args(argv)
    if not (args.lint or args.types or args.coverage):
        parser.error("nothing to do — pass at least one of --lint / --types / --coverage")

    failures = 0
    if args.lint:
        failures += _run("lint (ruff)", ["ruff", "check", "."], "ruff", "ruff", args.require)
    if args.types:
        failures += _run("type check (mypy)", ["mypy"], "mypy", "mypy", args.require)
    if args.coverage:
        # Through pytest rather than `run_checks.py`: the suites run in-process there, so the
        # measurement covers the engine directly. `run_checks.py` launches each suite as a
        # subprocess, which coverage would only see with a sitecustomize hook — more moving
        # parts for the same number.
        failures += _run("coverage floor", ["coverage", "run", "-m", "pytest", "kit/tests", "-q"],
                         "coverage", "coverage", args.require)
        if not failures:
            failures += _run("coverage report", ["coverage", "report"],
                             "coverage", "coverage", args.require)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
