#!/usr/bin/env python3
"""End-to-end Tier-0 -> Tier-1 -> report, deterministically and with no API key/network.

The ReplayBackend feeds a captured model response through the REAL enrichment path (prompt ->
parse -> merge), then the report is rendered. This proves the two-tier pipeline works whole and,
concretely, that the LLM tier adds the IDOR/V3 finding the deterministic tier cannot reach and
triages Tier-0 leads. (A live model is validated separately by test_live_llm.py when a key is
present; this test is the deterministic CI guarantee.)"""
from __future__ import annotations

import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(KIT)
sys.path.insert(0, KIT)

from secaudit_core import engine, report                # noqa: E402
from secaudit_core.backends import ReplayBackend, get_backend  # noqa: E402
from secaudit_core.schema import Verdict                # noqa: E402

VULN = os.path.join(REPO, "tests", "fixtures", "vulnerable-app")
RESPONSE = os.path.join(KIT, "tests", "fixtures", "llm-response.json")


def main() -> int:
    fails: list[str] = []

    if not isinstance(get_backend("replay"), ReplayBackend):
        fails.append("get_backend('replay') should return a ReplayBackend")

    res = engine.scan(VULN, run_deps=False, use_scanners=False)
    n_tier0 = len(res.findings)
    res = ReplayBackend(RESPONSE).enrich(res)

    if res.backend != "replay":
        fails.append(f"backend not stamped replay ({res.backend})")

    # the LLM tier added the IDOR/V3 logic finding the deterministic tier misses
    idor = [f for f in res.findings if f.detector_id == "LLM-LOGIC" and "IDOR" in f.title]
    if len(idor) != 1:
        fails.append(f"expected exactly 1 LLM-added IDOR finding, got {len(idor)}")
    elif not (idor[0].file == "server.js" and idor[0].line == 23 and idor[0].source == "llm"):
        fails.append(f"IDOR finding malformed: {idor[0].to_dict()}")
    if len(res.findings) != n_tier0 + 1:
        fails.append(f"enrichment should add exactly the 1 logic finding ({n_tier0} -> {len(res.findings)})")

    # triage verdicts were applied to existing Tier-0 findings
    by = {(f.detector_id, f.line): f for f in res.findings}
    sqli = by.get(("SEC-JS-SQLI", 12))
    if not sqli or sqli.verdict != Verdict.CONFIRMED or not sqli.triage_note:
        fails.append("SQLi finding was not confirmed + annotated by the triage step")
    ssrf = by.get(("SEC-JS-SSRF", 44))
    if not ssrf or ssrf.verdict != Verdict.PLAUSIBLE:
        fails.append("SSRF lead was not marked plausible by triage")

    # the final report renders and includes the triage note + the added IDOR finding
    md = report.to_markdown(res)
    if "IDOR" not in md or "Triage:" not in md:
        fails.append("rendered report is missing the IDOR finding or triage annotations")
    # and the SARIF still validates as JSON after enrichment
    import json
    json.loads(report.to_sarif(res))

    if fails:
        print("ENRICHMENT E2E TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print(f"ENRICHMENT E2E TESTS PASSED — Tier-0 ({n_tier0}) -> replayed LLM triage + IDOR/V3 "
          "added -> report/SARIF render. Full two-tier pipeline verified offline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
