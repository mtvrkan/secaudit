#!/usr/bin/env python3
"""OPTIONAL live-backend smoke test. Runs a REAL LLM enrichment call when a backend is
configured, and SKIPS cleanly otherwise (so CI, which has no key, always passes).

Backend auto-selected from the environment:
  ANTHROPIC_API_KEY -> anthropic   |   OPENAI_API_KEY -> openai   |   Ollama up -> ollama

Run it yourself to validate the live Tier-1 path end-to-end:
    ANTHROPIC_API_KEY=…  python kit/tests/test_live_llm.py
    OLLAMA_HOST=http://localhost:11434 python kit/tests/test_live_llm.py

It sends one tiny finding and asserts the model returns a usable, well-formed triage (valid
JSON, a recognized verdict, no crash). Exit 0 = passed or skipped; 1 = a configured backend
misbehaved."""
from __future__ import annotations

import os
import sys
import urllib.request

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KIT)

from secaudit_core.backends import get_backend           # noqa: E402
from secaudit_core.schema import (Finding, ScanResult, Severity, Confidence, Verdict)  # noqa: E402


def _ollama_up() -> bool:
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    try:
        urllib.request.urlopen(host + "/api/tags", timeout=2)
        return True
    except Exception:
        return False


def _pick_backend() -> str | None:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if _ollama_up():
        return "ollama"
    return None


def main() -> int:
    name = _pick_backend()
    if not name:
        print("LIVE LLM TEST SKIPPED — no backend configured "
              "(set ANTHROPIC_API_KEY / OPENAI_API_KEY, or start Ollama). CI-safe.")
        return 0

    print(f"Live backend: {name} (model={os.environ.get('SECAUDIT_MODEL', 'default')})")
    res = ScanResult(target="live-smoke", backend="none")
    res.findings = [Finding(
        "SEC-PY-PICKLE", "Insecure deserialization (pickle.loads on untrusted data)",
        Severity.CRITICAL, Confidence.HIGH, "CWE-502", "A08", "app.py", 10,
        "data = pickle.loads(request.cookies['s'])", "Use JSON; never unpickle untrusted bytes.")]

    enriched = get_backend(name).enrich(res)

    if "fallback" in enriched.backend:
        print(f"LIVE LLM TEST FAILED — backend errored: {[n for n in enriched.notes if name in n]}")
        return 1
    f = enriched.findings[0]
    if f.verdict not in (Verdict.CONFIRMED, Verdict.PLAUSIBLE, Verdict.REFUTED):
        print(f"LIVE LLM TEST FAILED — no usable verdict returned ({f.verdict}).")
        return 1
    print(f"LIVE LLM TEST PASSED — {name} returned verdict={f.verdict.value}"
          + (f', note=\"{f.triage_note[:80]}…\"' if f.triage_note else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
