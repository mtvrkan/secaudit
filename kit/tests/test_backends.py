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


def _test_source_context() -> list[str]:
    """The property the enrichment tier was missing entirely: the model is shown the code.

    Every assertion here is about the payload that actually reaches `_call`, not about the
    context builder's own return value. Asserting on the builder would have passed just as well
    while `_prompt` ignored it, which is the shape of bug this suite already caught twice
    elsewhere (a severity map asserted by reading itself, a privacy claim asserted by grepping
    its own source).
    """
    import shutil                                                           # noqa: PLC0415
    import tempfile                                                         # noqa: PLC0415
    from secaudit_core import llmcontext                                    # noqa: PLC0415

    fails: list[str] = []
    seen: list[str] = []

    class Capture(_HTTPBackend):
        name = "capture"

        def _call(self, prompt: str) -> str:
            seen.append(prompt)
            return ('{"triage":[],"extra":[{"title":"IDOR on /invoice","file":"routes/api.py",'
                    '"line":4,"severity":"High","note":"no owner filter"},'
                    '{"title":"invented","file":"nowhere/ghost.py","line":1,'
                    '"severity":"High","note":"model made this up"}]}')

    root = tempfile.mkdtemp(prefix="secaudit-ctx-")
    try:
        os.makedirs(os.path.join(root, "routes"))
        os.makedirs(os.path.join(root, "secrets"))
        with open(os.path.join(root, "routes", "api.py"), "w", encoding="utf-8") as f:
            f.write("def get_invoice(id):\n    return db.invoice(id)\n" * 4)
        with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as f:
            f.write("import os\n" * 40 + "eval(request.args['x'])\n")
        # Sorts BEFORE `routes/api.py` alphabetically and carries no handler hint, so it is the
        # file that separates "ranked toward handlers" from "whatever the walk returned first".
        with open(os.path.join(root, "aaa_helpers.py"), "w", encoding="utf-8") as f:
            f.write("def slugify(s):\n    return s.lower()\n")
        # Credential material, in three shapes the exclusion list has to catch separately.
        with open(os.path.join(root, ".env"), "w", encoding="utf-8") as f:
            f.write("AWS_SECRET_ACCESS_KEY=" + "x" * 40 + "\n")
        with open(os.path.join(root, "server.pem"), "w", encoding="utf-8") as f:
            f.write("-----BEGIN PRIVATE KEY-----\n")
        with open(os.path.join(root, "secrets", "prod.py"), "w", encoding="utf-8") as f:
            f.write("DB_PASSWORD = 'hunter2'\n")

        res = ScanResult(target=root, backend="none")
        res.findings = [Finding("SEC-PY-EVAL", "eval on request data", Severity.CRITICAL,
                                Confidence.HIGH, "CWE-95", "A03", "app.py", 41,
                                "eval(request.args['x'])", "do not eval")]
        out = Capture().enrich(res)

        if not seen:
            return ["source context: backend was never called"]
        prompt = "\n".join(seen)

        # 1. The bug this whole change exists for: source must be in the payload.
        if "eval(request.args['x'])" not in prompt or "FILE app.py" not in prompt:
            fails.append("source context: the flagged file's code never reached the prompt")
        if "   41 |" not in prompt:
            fails.append("source context: excerpt lines are not line-numbered, so a model's "
                         "reported line cannot be checked against them")

        # 2. Discovery needs files Tier 0 said nothing about.
        if "FILE routes/api.py" not in prompt:
            fails.append("source context: an unflagged handler file was not sent, so the model "
                         "cannot report anything the pattern scan missed")

        # 3. Credential material must never be shipped, in any of its three shapes.
        for marker, what in (("AWS_SECRET_ACCESS_KEY", ".env"),
                             ("BEGIN PRIVATE KEY", "*.pem"),
                             ("hunter2", "secrets/ directory")):
            if marker in prompt:
                fails.append(f"source context: {what} content was sent to the backend")

        # 4. A discovered flaw in a file the model was shown is kept; one in a file it was not
        #    shown is refused and counted.
        logic = [f for f in out.findings if f.detector_id == "LLM-LOGIC"]
        if len(logic) != 1 or logic[0].file != "routes/api.py":
            fails.append(f"source context: expected exactly the grounded logic finding, "
                         f"got {[f.file for f in logic]}")
        if not any("not in the context sent" in n for n in out.notes):
            fails.append("source context: an ungrounded model finding was dropped without "
                         "saying so — a silent filter is the failure mode, not the fix")

        # 5. The result must state what the model actually saw.
        if not any("of 3 source files" in n for n in out.notes):
            fails.append(f"source context: coverage was not reported in the notes ({out.notes})")

        # 5b. Discovery budget goes to handlers first. Without the ranking these two files come
        #     back in plain alphabetical order, which spends the budget on a slug helper before
        #     the route file where the undetectable classes actually live.
        if prompt.find("FILE routes/api.py") > prompt.find("FILE aaa_helpers.py"):
            fails.append("source context: discovery order is not ranked toward handlers")

        # 6. Determinism — the same tree must produce a byte-identical payload.
        seen.clear()
        Capture().enrich(_fresh(root))
        second = "\n".join(seen)
        if second != prompt:
            fails.append("source context: two runs over one tree produced different payloads")

        # 7. No source (a live-URL target) must not silently invite discovery.
        seen.clear()
        url = ScanResult(target="https://example.com", backend="none")
        url.findings = [Finding("SEC-HDR", "missing header", Severity.LOW, Confidence.HIGH,
                                "CWE-693", "A05", "-", 1, "-", "add it")]
        Capture().enrich(url)
        if not seen or "No source code is available" not in seen[0]:
            fails.append("source context: a target with no source did not say so in the prompt")

        # 8. The budget is a real ceiling, not documentation.
        if llmcontext.MAX_CHUNKS < 1 or llmcontext.CHUNK_BUDGET_CHARS < 1000:
            fails.append("source context: implausible budget constants")
        big = llmcontext.build(_fresh(root))
        if any(len(c) > llmcontext.CHUNK_BUDGET_CHARS * 1.05 for c in big.chunks):
            fails.append("source context: a chunk exceeded the character budget")
        if len(big.chunks) > llmcontext.MAX_CHUNKS:
            fails.append("source context: more chunks than MAX_CHUNKS — the cost ceiling leaks")

        # 9. Truncation: the branch that BOUNDS the payload, exercised rather than assumed.
        #    A budget nobody has watched overflow is a budget nobody knows the shape of, and
        #    "what was not sent is reported" is a published claim, so it gets a failing case.
        #    Ten handler files against a budget that fits about one forces the cap.
        for i in range(10):
            with open(os.path.join(root, f"route_{i}.py"), "w", encoding="utf-8") as f:
                f.write(f"# handler {i}\ndef view_{i}(request):\n    return db.get(request.args)\n"
                        * 200)
        budget, chunks_cap = llmcontext.CHUNK_BUDGET_CHARS, llmcontext.MAX_CHUNKS
        llmcontext.CHUNK_BUDGET_CHARS, llmcontext.MAX_CHUNKS = 4_000, 2
        try:
            tight = llmcontext.build(_fresh(root))
            if not tight.truncated:
                fails.append("source context: a tree far over budget did not report truncation")
            if len(tight.chunks) > 2:
                fails.append(f"source context: MAX_CHUNKS=2 produced {len(tight.chunks)} chunks")
            if "budget ran out" not in tight.note() or "cannot be ruled out" not in tight.note():
                fails.append(f"source context: truncation is not stated in the note "
                             f"({tight.note()!r})")
            # The ordering guarantee that makes truncation survivable: excerpts are packed
            # first, so the code behind a finding is never what gets dropped.
            if "app.py" not in tight.excerpt_files:
                fails.append("source context: truncation dropped the excerpt behind a finding — "
                             "the one thing the packing order exists to protect")
        finally:
            llmcontext.CHUNK_BUDGET_CHARS, llmcontext.MAX_CHUNKS = budget, chunks_cap
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return fails


def _fresh(root: str) -> ScanResult:
    r = ScanResult(target=root, backend="none")
    r.findings = [Finding("SEC-PY-EVAL", "eval on request data", Severity.CRITICAL,
                          Confidence.HIGH, "CWE-95", "A03", "app.py", 41,
                          "eval(request.args['x'])", "do not eval")]
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

    fails += _test_source_context()

    if fails:
        print("BACKEND TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("BACKEND TESTS PASSED — triage merge, LLM-added IDOR/logic finding (the V3 class Tier-0 "
          "misses), fenced-JSON parsing, name aliases, and fail-open-to-Tier-0 all correct.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
