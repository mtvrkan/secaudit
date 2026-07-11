"""Pluggable enrichment backends (Tier 1). The Tier-0 engine runs without any of these;
a backend, when configured, triages each finding (confirm / refute / adjust severity) and can
surface logic bugs the deterministic pack cannot (e.g. IDOR / missing authorization).

Backends are provider-agnostic and dependency-free — each talks to its API over urllib, so no
vendor SDK is required:
  * none      — passthrough (pure Tier 0). Always available.
  * anthropic — Claude Messages API (ANTHROPIC_API_KEY). Best default quality.
  * openai    — OpenAI Chat Completions (OPENAI_API_KEY).
  * ollama    — a LOCAL model via http://localhost:11434 (no key, code never leaves the host).

The LLM backends are wired end-to-end but are not exercised in CI (no keys / no local model
there); `none` is fully covered by the test suite.
"""
from __future__ import annotations

import json
import os
import urllib.request

from .schema import ScanResult, Severity, Verdict

_TRIAGE_SYS = (
    "You are an adversarial application-security verifier. For each candidate finding decide if "
    "it is real and reachable from untrusted input in THIS code. Default to skeptical. Also report "
    "any logic/authorization flaws (e.g. IDOR, missing ownership checks) the pattern scan missed. "
    "Reply ONLY with JSON: {\"triage\":[{\"detector_id\":str,\"file\":str,\"line\":int,"
    "\"verdict\":\"confirmed|plausible|refuted\",\"severity\":\"Critical|High|Medium|Low|Informational\","
    "\"note\":str}],\"extra\":[{\"title\":str,\"file\":str,\"line\":int,\"severity\":str,\"note\":str}]}"
)


def get_backend(name: str):
    name = (name or "none").lower()
    return {
        "none": NoneBackend, "anthropic": AnthropicBackend, "claude": AnthropicBackend,
        "openai": OpenAIBackend, "ollama": OllamaBackend, "replay": ReplayBackend,
    }.get(name, NoneBackend)()


class Backend:
    name = "none"

    def enrich(self, result: ScanResult) -> ScanResult:
        raise NotImplementedError

    # -- shared helpers --------------------------------------------------
    def _prompt(self, result: ScanResult) -> str:
        items = [{"detector_id": f.detector_id, "title": f.title, "file": f.file,
                  "line": f.line, "severity": f.severity.value, "evidence": f.evidence}
                 for f in result.findings]
        return ("Target: " + result.target + "\nCandidate findings (JSON):\n"
                + json.dumps(items, indent=2))

    def _apply(self, result: ScanResult, data: dict) -> ScanResult:
        by_key = {(f.detector_id, f.file, f.line): f for f in result.findings}
        for t in data.get("triage", []):
            f = by_key.get((t.get("detector_id"), t.get("file"), t.get("line")))
            if not f:
                continue
            try:
                f.verdict = Verdict(str(t.get("verdict", "plausible")).lower())
            except ValueError:
                f.verdict = Verdict.PLAUSIBLE
            f.triage_note = str(t.get("note", ""))[:500]
            try:
                f.severity = Severity(str(t.get("severity", f.severity.value)))
            except ValueError:
                pass
        from .schema import Finding, Confidence
        for e in data.get("extra", []):
            try:
                sev = Severity(str(e.get("severity", "Medium")))
            except ValueError:
                sev = Severity.MEDIUM
            result.findings.append(Finding(
                detector_id="LLM-LOGIC", title=str(e.get("title", "Logic flaw"))[:200],
                severity=sev, confidence=Confidence.MEDIUM, cwe="CWE-284", owasp="A01",
                file=str(e.get("file", "?")), line=int(e.get("line", 1) or 1),
                evidence="(model-identified)", fix="See triage note.",
                source="llm", verdict=Verdict.PLAUSIBLE, triage_note=str(e.get("note", ""))[:500]))
        result.backend = self.name
        return result

    def _parse_json(self, text: str) -> dict:
        # Grab the outermost {...} object, tolerating markdown fences or prose around it.
        # find('{')/rfind('}') already skip any ```json language tag and surrounding text, so
        # no separate (and fragile) fence-stripping pass is needed.
        start, end = text.find("{"), text.rfind("}")
        return json.loads(text[start:end + 1]) if 0 <= start < end else {}


class NoneBackend(Backend):
    name = "none"

    def enrich(self, result: ScanResult) -> ScanResult:
        result.backend = "none"
        result.notes.append("No LLM backend: findings are Tier-0, unverified. "
                            "Add --backend anthropic|openai|ollama for triage + logic-bug discovery.")
        return result


class _HTTPBackend(Backend):
    def _post(self, url: str, payload: dict, headers: dict, timeout: int = 90) -> dict:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                    headers={"Content-Type": "application/json", **headers})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())

    def enrich(self, result: ScanResult) -> ScanResult:
        if not result.findings:
            result.backend = self.name
            return result
        try:
            text = self._call(self._prompt(result))
            return self._apply(result, self._parse_json(text))
        except Exception as e:
            result.notes.append(f"{self.name} backend unavailable ({e}); returned Tier-0 findings.")
            result.backend = f"{self.name} (fallback: none)"
            return result

    def _call(self, prompt: str) -> str:
        raise NotImplementedError


class AnthropicBackend(_HTTPBackend):
    name = "anthropic"

    def _call(self, prompt: str) -> str:
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        model = os.environ.get("SECAUDIT_MODEL", "claude-opus-4-8")
        data = self._post("https://api.anthropic.com/v1/messages", {
            "model": model, "max_tokens": 4096, "system": _TRIAGE_SYS,
            "messages": [{"role": "user", "content": prompt}],
        }, {"x-api-key": key, "anthropic-version": "2023-06-01"})
        return "".join(b.get("text", "") for b in data.get("content", []))


class OpenAIBackend(_HTTPBackend):
    name = "openai"

    def _call(self, prompt: str) -> str:
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            raise RuntimeError("OPENAI_API_KEY not set")
        model = os.environ.get("SECAUDIT_MODEL", "gpt-4o")
        data = self._post("https://api.openai.com/v1/chat/completions", {
            "model": model, "temperature": 0,
            "messages": [{"role": "system", "content": _TRIAGE_SYS},
                         {"role": "user", "content": prompt}],
        }, {"Authorization": f"Bearer {key}"})
        return data["choices"][0]["message"]["content"]


class ReplayBackend(_HTTPBackend):
    """Replays a captured model response from a file instead of calling an API — so the full
    enrichment pipeline (prompt -> response -> parse -> merge) is exercised deterministically in
    CI with no key/network. Path comes from the constructor or SECAUDIT_REPLAY."""
    name = "replay"

    def __init__(self, path: str | None = None):
        self._path = path or os.environ.get("SECAUDIT_REPLAY", "")

    def _call(self, prompt: str) -> str:
        with open(self._path, encoding="utf-8") as f:
            return f.read()


class OllamaBackend(_HTTPBackend):
    name = "ollama"

    def _call(self, prompt: str) -> str:
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        model = os.environ.get("SECAUDIT_MODEL", "qwen2.5-coder")
        data = self._post(f"{host}/api/generate", {
            "model": model, "system": _TRIAGE_SYS, "prompt": prompt,
            "stream": False, "format": "json",
        }, {})
        return data.get("response", "")
