#!/usr/bin/env python3
"""Validate the SARIF renderer produces a GitHub-code-scanning-shaped document."""
from __future__ import annotations

import json
import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(KIT)
sys.path.insert(0, KIT)

from secaudit_core import engine, report              # noqa: E402

VULN = os.path.join(REPO, "tests", "fixtures", "vulnerable-app")


def main() -> int:
    fails: list[str] = []
    res = engine.scan(VULN, run_deps=False, use_scanners=False)
    doc = json.loads(report.to_sarif(res))  # must be valid JSON

    if doc.get("version") != "2.1.0":
        fails.append("SARIF version must be 2.1.0")
    run = (doc.get("runs") or [{}])[0]
    driver = run.get("tool", {}).get("driver", {})
    if driver.get("name") != "SecAudit":
        fails.append("driver.name must be SecAudit")

    rules = driver.get("rules", [])
    results = run.get("results", [])
    if not rules or not results:
        fails.append("expected non-empty rules and results")
    if len(results) != len(res.findings):
        fails.append(f"results ({len(results)}) != findings ({len(res.findings)})")

    rule_ids = {r["id"] for r in rules}
    for r in results:
        if r.get("ruleId") not in rule_ids:
            fails.append(f"result ruleId {r.get('ruleId')} has no matching rule")
        if r.get("level") not in ("error", "warning", "note"):
            fails.append(f"bad SARIF level {r.get('level')}")
        loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
        if not loc.get("artifactLocation", {}).get("uri") or not loc.get("region", {}).get("startLine"):
            fails.append("result missing location uri/startLine")

    # every rule carries a security-severity GitHub can read; a Critical finding => error + 9.0
    for r in rules:
        if "security-severity" not in r.get("properties", {}):
            fails.append(f"rule {r['id']} missing security-severity")
    crit = [f for f in res.findings if f.severity.value == "Critical"]
    if crit:
        cr = next(r for r in results if r["ruleId"] == crit[0].detector_id)
        if cr["level"] != "error":
            fails.append("Critical finding must map to SARIF level 'error'")

    if fails:
        print("SARIF REPORT TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print(f"SARIF REPORT TESTS PASSED — valid 2.1.0 doc, {len(rules)} rules / {len(results)} "
          "results, security-severity set, levels + locations well-formed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
