#!/usr/bin/env python3
"""Validate the Tier-1 enrichment plumbing without any API key or network: a stub backend
returns a canned model response and we assert the merge is correct. This demonstrates the
two-tier value split — the LLM tier triages Tier-0 findings AND adds the logic bug (IDOR / V3)
the deterministic tier cannot detect."""
from __future__ import annotations

import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KIT)

from secaudit_core.backends import (get_backend, NoneBackend, AnthropicBackend,  # noqa: E402
                                    _HTTPBackend)
from secaudit_core.schema import (Finding, ScanResult, Severity,  # noqa: E402
                                  Confidence, Verdict)

CANNED = """Here is my analysis:
```json
{
  "triage": [
    {"detector_id": "SEC-JS-PROTO", "file": "util.js", "line": 8,
     "verdict": "refuted", "severity": "Low", "note": "guarded by an allowlist upstream"},
    {"detector_id": "SEC-PY-PICKLE", "file": "py_app.py", "line": 35,
     "verdict": "confirmed", "severity": "Critical", "note": "reachable from the session cookie"}
  ],
  "extra": [
    {"title": "IDOR: missing ownership check on /invoice/:id", "file": "server.js",
     "line": 23, "severity": "High", "note": "no owner_id filter — any user reads any invoice"}
  ]
}
```
"""


class StubBackend(_HTTPBackend):
    name = "stub"

    def _call(self, prompt: str) -> str:
        return CANNED


def _sample_result() -> ScanResult:
    r = ScanResult(target="x", backend="none")
    r.findings = [
        Finding("SEC-JS-PROTO", "Prototype pollution", Severity.HIGH, Confidence.MEDIUM,
                "CWE-1321", "A08", "util.js", 8, "merge(...)", "guard keys"),
        Finding("SEC-PY-PICKLE", "Insecure deserialization", Severity.CRITICAL, Confidence.HIGH,
                "CWE-502", "A08", "py_app.py", 35, "pickle.loads(...)", "use json"),
    ]
    return r


def main() -> int:
    fails: list[str] = []

    # --- get_backend name resolution ---
    if not isinstance(get_backend("claude"), AnthropicBackend):
        fails.append("get_backend('claude') should alias to AnthropicBackend")
    if not isinstance(get_backend("bogus"), NoneBackend):
        fails.append("get_backend(unknown) should fall back to NoneBackend")

    # --- _parse_json robustness ---
    b = StubBackend()
    if b._parse_json('{"triage":[],"extra":[]}') != {"triage": [], "extra": []}:
        fails.append("_parse_json failed on raw JSON")
    if b._parse_json(CANNED).get("extra", [{}])[0].get("line") != 23:
        fails.append("_parse_json failed to extract JSON from a fenced block")
    if b._parse_json("no json here") != {}:
        fails.append("_parse_json should return {} on junk, not throw")

    # --- enrich / _apply merge ---
    res = b.enrich(_sample_result())
    by = {(f.detector_id, f.line): f for f in res.findings}
    proto = by.get(("SEC-JS-PROTO", 8))
    pick = by.get(("SEC-PY-PICKLE", 35))
    if not proto or proto.verdict != Verdict.REFUTED or proto.severity != Severity.LOW:
        fails.append("triage did not refute+downgrade the prototype-pollution lead")
    if not pick or pick.verdict != Verdict.CONFIRMED:
        fails.append("triage did not confirm the pickle finding")

    logic = [f for f in res.findings if f.detector_id == "LLM-LOGIC"]
    if len(logic) != 1:
        fails.append(f"expected 1 LLM-added logic finding, got {len(logic)}")
    elif not (logic[0].file == "server.js" and logic[0].line == 23
              and logic[0].source == "llm" and "IDOR" in logic[0].title):
        fails.append(f"LLM logic finding malformed: {logic[0].to_dict() if logic else None}")
    if res.backend != "stub":
        fails.append(f"result.backend not stamped ({res.backend})")

    # --- NoneBackend passthrough (no mutation, adds a note) ---
    n = NoneBackend().enrich(_sample_result())
    if len(n.findings) != 2 or n.backend != "none":
        fails.append("NoneBackend should pass findings through unchanged")

    # --- HTTP backend fails OPEN to Tier-0 on error (no key / no network) ---
    class Boom(_HTTPBackend):
        name = "boom"

        def _call(self, prompt):
            raise RuntimeError("no key")
    boom = Boom().enrich(_sample_result())
    if len(boom.findings) != 2 or "fallback" not in boom.backend:
        fails.append("backend error should fall back to Tier-0 findings, not crash or drop them")

    if fails:
        print("BACKEND TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("BACKEND TESTS PASSED — triage merge, LLM-added IDOR/logic finding (the V3 class Tier-0 "
          "misses), fenced-JSON parsing, name aliases, and fail-open-to-Tier-0 all correct.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
