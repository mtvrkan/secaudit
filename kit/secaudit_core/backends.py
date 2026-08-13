"""Pluggable enrichment backends (Tier 1). The Tier-0 engine runs without any of these;
a backend, when configured, triages each finding (confirm / refute / adjust severity) and can
surface logic bugs the deterministic pack cannot (e.g. IDOR / missing authorization).

Backends are provider-agnostic and dependency-free — each talks to its API over urllib, so no
vendor SDK is required:
  * none      — passthrough (pure Tier 0). Always available.
  * anthropic — Claude Messages API (ANTHROPIC_API_KEY). Best default quality.
  * openai    — OpenAI Chat Completions (OPENAI_API_KEY).
  * ollama    — a LOCAL model via http://localhost:11434 (no key, code never leaves the host).

**These backends send your source code.** `llmcontext` builds the payload and the reasoning is
there; the consequence belongs here, next to the API calls that make it true. A remote backend
receives excerpts around every finding plus whole files it has not been shown a reason to skip,
which is what makes triage and logic-bug discovery possible at all — and which makes `ollama`
the choice to reach for when the code may not leave the machine, rather than merely the cheap
one. Files matching credential patterns are withheld from every backend, local included.

The LLM backends are wired end-to-end but are not exercised in CI (no keys / no local model
there); `none` and the full prompt/parse/merge path are covered by stub and replay backends.
"""
from __future__ import annotations

import json
import os
import urllib.request

from . import llmcontext
from .schema import ScanResult, Severity, Verdict

_TRIAGE_SYS = (
    "You are an adversarial application-security verifier. You are given candidate findings from "
    "a pattern scanner AND the source code they refer to, line-numbered. "
    "For each candidate finding decide, FROM THE SOURCE SHOWN, whether it is real and reachable "
    "from untrusted input. Default to skeptical: refute anything the code shows is guarded, "
    "parameterized, or unreachable. "
    "Then report logic and authorization flaws the pattern scan cannot detect — missing ownership "
    "checks (IDOR), endpoints with no authentication, broken access control, business-logic flaws "
    "— using ONLY the files shown to you. "
    "Every `file` you cite must be one that appears in the source above and every `line` must be "
    "a line number printed in it. Do not report a flaw in a file you were not shown, and do not "
    "speculate about code that is not present: an unshown file is unknown, not clean. "
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
    def _prompt(self, result: ScanResult, source: str = "") -> str:
        items = [{"detector_id": f.detector_id, "title": f.title, "file": f.file,
                  "line": f.line, "severity": f.severity.value, "evidence": f.evidence}
                 for f in result.findings]
        head = ("Target: " + result.target + "\nCandidate findings (JSON):\n"
                + json.dumps(items, indent=2))
        if not source:
            # No readable tree (a live-URL scan, or a target that vanished). Say so in the
            # prompt itself: a model given a bare finding list and no statement about why will
            # answer the discovery question anyway, out of nothing.
            return (head + "\n\nNo source code is available for this target. Triage from the "
                           "evidence lines only, and return an EMPTY `extra` list — you cannot "
                           "discover a flaw in code you have not been shown.")
        return head + "\n\nSource code (line-numbered):\n" + source

    def _apply(self, result: ScanResult, data: dict, shown: set[str] | None = None) -> ScanResult:
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
        ungrounded = 0
        for e in data.get("extra", []):
            # A discovered flaw must point at a file the model was actually shown. `shown` is
            # None only where no context was built at all (nothing to check against); where it
            # exists, a citation outside it is not a finding — it is the model answering the
            # question from prior knowledge of what web apps usually get wrong. Counted and
            # reported rather than dropped in silence, because a filtered register is not
            # evidence anywhere else in this codebase either.
            cited = str(e.get("file", "?")).replace("\\", "/")
            if shown is not None and cited not in shown:
                ungrounded += 1
                continue
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
        if ungrounded:
            result.notes.append(
                f"{ungrounded} model-reported finding(s) cited a file that was not in the "
                f"context sent, so they were not merged — a citation the reader cannot open is "
                f"not a finding.")
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

    def complete(self, prompt: str) -> str:
        """No model configured. Declines rather than returning an empty diff, which would read
        as "the model had nothing to suggest"."""
        return "[no backend configured: patch suggestion needs --backend]"

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
        """Triage + discovery over the repository's source, in at most `MAX_CHUNKS` calls.

        A scan with zero Tier-0 findings is no longer an early return. That was defensible while
        the payload was the finding list itself — an empty list is nothing to send — but a clean
        Tier-0 result on a repository full of handlers is exactly the case where discovery is
        worth the most, and skipping it made "no findings" self-confirming.
        """
        ctx = llmcontext.build(result)
        chunks = ctx.chunks or [""]
        if not result.findings and not ctx.chunks:
            result.backend = self.name
            return result
        shown = set(ctx.excerpt_files) | set(ctx.discovery_files) if ctx.chunks else None
        completed = 0
        try:
            for chunk in chunks:
                text = self._call(self._prompt(result, chunk))
                self._apply(result, self._parse_json(text), shown)
                completed += 1
        except Exception as e:                       # noqa: BLE001 - reported, not swallowed
            # A failure on chunk 3 of 4 leaves real triage already merged from chunks 1 and 2.
            # Discarding it would be wasteful; keeping it silently would be worse — the report
            # would look like a full Tier-1 pass over a partial one.
            if completed:
                result.notes.append(
                    f"{self.name} backend failed after {completed} of {len(chunks)} context "
                    f"chunk(s) ({e}); the triage below covers only what was sent before the "
                    f"failure and the rest of the tree is unexamined, not clean.")
                result.backend = f"{self.name} (partial: {completed}/{len(chunks)})"
            else:
                result.notes.append(
                    f"{self.name} backend unavailable ({e}); returned Tier-0 findings.")
                result.backend = f"{self.name} (fallback: none)"
            return result
        if ctx.chunks:
            result.notes.append(ctx.note())
        result.backend = self.name
        return result

    def _call(self, prompt: str) -> str:
        raise NotImplementedError

    def complete(self, prompt: str) -> str:
        """One prompt, one raw reply — no JSON contract, no merging into a ScanResult.

        Patch authoring and patch review need a plain completion, and they need failures to be
        visible rather than absorbed: `enrich` deliberately swallows backend errors so a scan
        still produces a Tier-0 report, but a patch step that silently returns "" on a network
        error would report `no_patch` and look like the model declined. Returning the error
        text makes it show up in the rejection reason instead.
        """
        try:
            return self._call(prompt)
        except Exception as e:
            return f"[backend error: {e.__class__.__name__}: {e}]"



class AnthropicBackend(_HTTPBackend):
    name = "anthropic"

    def _call(self, prompt: str) -> str:
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        model = os.environ.get("SECAUDIT_MODEL", "claude-opus-5")
        # `max_tokens` bounds thinking AND response text together, and this model thinks by
        # default — the 4096 that was ample when the default model did not think can now
        # truncate the triage JSON mid-object, which the parser would report as a malformed
        # response rather than as a cut-off one. 16000 is the ceiling that stays inside the
        # HTTP timeout for a non-streaming call.
        #
        # Note there is no `temperature` here and there must not be: it is rejected outright
        # by this model family. Raw HTTP rather than the official SDK is deliberate — the
        # shipped package declares zero runtime dependencies and `assert_no_runtime_deps.py`
        # gates it, so adding `anthropic` would fail the build, not merely enlarge it.
        data = self._post("https://api.anthropic.com/v1/messages", {
            "model": model, "max_tokens": 16000, "system": _TRIAGE_SYS,
            "messages": [{"role": "user", "content": prompt}],
        }, {"x-api-key": key, "anthropic-version": "2023-06-01"})
        # Only text blocks carry the triage JSON; thinking blocks have no "text" key and are
        # skipped by the .get("text", "") rather than concatenated into the payload.
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
