#!/usr/bin/env python3
"""One command that runs every gate CI runs.

    python3 scripts/run_checks.py            # everything
    python3 scripts/run_checks.py --fast     # skip the eval suites (structure + consistency only)
    python3 scripts/run_checks.py --list     # show the gates without running them

The point is that a contributor can reproduce a red build locally. Every gate here is also a
step in `.github/workflows/validate.yml`, and that is now checked rather than promised: check 26
in `scripts/check_consistency.py` fails the build if a gate in this list runs in no workflow.
It exists because this docstring used to ask for the two to be kept in sync by hand and they
were not — the advertised-Python-floor gate lived here and nowhere in CI.

Exit code is the number of failed gates (0 = all green), so a shell can branch on it.
"""
from __future__ import annotations

import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KIT = os.path.join(REPO, "kit")

# (label, argv, fast?) — `fast` gates run under --fast; the rest are the measurement suites.
GATES: list[tuple[str, list[str], bool]] = [
    ("repo structure",        ["scripts/check_repo.py"], True),
    ("stated-number consistency", ["scripts/check_consistency.py"], True),
    ("landing page renders from repo facts", ["scripts/gen_site.py", "--check"], True),
    ("social card matches the measured numbers", ["scripts/gen_og_image.py", "--check"], True),
    ("language coverage matrix is current", ["scripts/gen_language_matrix.py", "--check"], True),
    ("what-we-miss page is current", ["scripts/gen_what_we_miss.py", "--check"], False),
    ("authorization hook self-test", ["plugins/secaudit/hooks/active-scan-guard.py", "--selftest"], True),
    ("fixture self-test (sinks + negative control)", ["tests/selftest.py"], False),
    ("report grader self-test",   ["tests/grade-report.py", "--selftest"], False),
    ("reference report coverage", ["tests/grade-report.py", "examples/self-test-report.md",
                                   "--min", "20"], False),
    ("Tier-0 recall / precision", ["kit/tests/test_engine.py"], False),
    ("taint tier (reachability)",  ["kit/tests/test_taint.py"], False),
    ("dependency reachability / VEX", ["kit/tests/test_deps.py"], False),
    ("compliance mapping / SBOM / CRA", ["kit/tests/test_compliance.py"], False),
    ("eval ground truth is current", ["eval/build_ground_truth.py", "--check"], True),
    ("eval scorecard is current",     ["eval/harness.py", "--check"], False),
    ("eval regression gate",          ["eval/harness.py", "--gate"], False),
    ("scanner adapters",          ["kit/tests/test_scanners.py"], False),
    ("detector pack",             ["kit/tests/test_detectors.py"], False),
    ("enrichment plumbing",       ["kit/tests/test_backends.py"], False),
    ("report renderers (SARIF + HTML)", ["kit/tests/test_report.py"], False),
    ("two-tier end-to-end",       ["kit/tests/test_enrich_e2e.py"], False),
    ("dogfood precision (own source)", ["kit/tests/test_dogfood.py"], False),
    ("CLI boundary",              ["kit/tests/test_cli.py"], False),
    ("MCP server (protocol + boundaries)", ["kit/tests/test_mcp.py"], False),
    ("diff mode (--since, real git repos)", ["kit/tests/test_diff.py"], False),
    ("advertised Python floor",    ["scripts/check_python_floor.py"], False),
    ("semgrep rule pack (equivalence + freshness)", ["kit/tests/test_semgrep_pack.py"], False),
    ("exploitation (KEV/EPSS) + SPDX", ["kit/tests/test_exploitation.py"], False),
    ("verified patch suggestion (refusals)", ["kit/tests/test_patch.py"], False),
    ("i18n bundles (complete + consistent)", ["kit/tests/test_i18n.py"], False),
    ("live-LLM smoke (skips without a key)", ["kit/tests/test_live_llm.py"], False),
]


def utf8_stdout() -> None:
    """Reports and gate output carry Unicode. A legacy console codepage must not crash a check."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass


def run(label: str, argv: list[str]) -> bool:
    env = dict(os.environ, PYTHONPATH=KIT + os.pathsep + os.environ.get("PYTHONPATH", ""))
    proc = subprocess.run([sys.executable, *argv], cwd=REPO, env=env,
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    ok = proc.returncode == 0
    print(f"{'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        body = (proc.stdout or "") + (proc.stderr or "")
        print("\n".join("        " + line for line in body.strip().splitlines()))
    return ok


def main(argv: list[str]) -> int:
    utf8_stdout()
    fast = "--fast" in argv
    gates = [(label, cmd) for label, cmd, in_fast in GATES if in_fast or not fast]

    if "--list" in argv:
        for label, cmd in gates:
            print(f"{label}\n    python3 {' '.join(cmd)}")
        return 0

    print(f"SecAudit checks — {len(gates)} gate(s){' (fast subset)' if fast else ''}\n")
    failed = [label for label, cmd in gates if not run(label, cmd)]
    print()
    if failed:
        print(f"{len(failed)} gate(s) failed: " + ", ".join(failed))
        return len(failed)
    print(f"All {len(gates)} gates green.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
