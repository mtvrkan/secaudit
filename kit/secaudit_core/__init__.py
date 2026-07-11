"""secaudit_core — the self-running, provider-agnostic core of SecAudit.

Tier 0 (this package, no LLM required): deterministic detectors + scanner integration
that always run and always produce a report.
Tier 1 (optional, pluggable): an LLM backend enriches the Tier-0 findings — triage,
logic/unknown-vuln discovery, narrative — with the model of your choice (Claude, OpenAI,
a local Ollama model, or `none`). Claude is the best default; it is not required.
"""
__all__ = ["schema", "detectors", "engine", "backends", "report"]
__version__ = "1.0.0"
