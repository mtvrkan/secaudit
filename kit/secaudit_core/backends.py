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
from dataclasses import dataclass

from . import llmcontext
from .schema import ScanResult, Severity, Verdict


class UnreadableReply(ValueError):
    """A model reply that carried no JSON object at all.

    Distinct from a JSON error, because the two want different handling. A reply that starts an
    object and gets it wrong is a broken call; a reply with no object in it is usually a refusal,
    a truncated stream or an error page in the response body — one bad chunk out of several, and
    the rest of the run is still worth having. So this one is counted and carried on from, and
    the count reaches the report rather than the exit code.
    """

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

# The business-logic classes this pass will accept, and what each one *is* in the report. The
# table is the single source of truth: consistency check 24 reads the CWEs out of it, so a class
# added here without an ASVS chapter fails the build rather than shipping unmapped.
#
# Four classes, not five. `race_window` (CWE-367) was left out deliberately: whether a
# read-then-write is exploitable depends on transaction isolation the extract does not carry, so
# asking about it is asking the model to guess, and a guess in a channel whose whole defence is
# narrowness is the one thing that would sink it.
@dataclass(frozen=True)
class LogicClass:
    detector_id: str
    cwe: str
    owasp: str
    title: str
    # Tier-0 weaknesses this class would be RESTATING if one already sits in the same handler.
    # Keyed on a family rather than on equality with `cwe`, because the deterministic rules and
    # this pass name the same bug with different ids — `AUTHZ-PY-IDOR` files broken access
    # control under CWE-284 and `AUTHZ-PY-NOAUTH` files missing authentication under CWE-306,
    # while the logic classes use the narrower CWE-639 and CWE-862. An equality check looked
    # exactly like a working suppression and would have fired on nothing at all.
    restates: tuple


LOGIC_CLASSES: dict[str, LogicClass] = {
    "missing_ownership": LogicClass(
        "LOGIC-IDOR", "CWE-639", "A01",
        "Object accessed by a caller-supplied id with no ownership check",
        ("CWE-639", "CWE-284", "CWE-285")),
    "missing_authorization": LogicClass(
        "LOGIC-AUTHZ", "CWE-862", "A01",
        "Endpoint performs a privileged action with no authorization",
        ("CWE-862", "CWE-306")),
    "workflow_skip": LogicClass(
        "LOGIC-WORKFLOW", "CWE-841", "A04",
        "Workflow state advanced without the preceding step",
        ("CWE-841",)),
    "trusted_client_value": LogicClass(
        "LOGIC-CLIENTTRUST", "CWE-602", "A04",
        "Server trusts a value the client chose",
        ("CWE-602", "CWE-915")),
}

_LOGIC_SYS = (
    "You are an application-security reviewer adjudicating a SHORTLIST. You are given a handler "
    "map — deterministic facts extracted from the source about each mounted request handler — and "
    "the source code itself, line-numbered. "
    "Do NOT hunt for vulnerabilities across the repository. For each handler in the map, decide "
    "whether the facts plus the source show one of exactly four business-logic flaws:\n"
    "  missing_ownership     — a caller-supplied identifier selects a record and no principal "
    "narrows it (look at `request_ids`, `ops[].constrained_by_principal`, `principals`).\n"
    "  missing_authorization — a state-changing, non-public handler performs a privileged action "
    "with nothing establishing the caller (`auth_evidence`, `state_changing`, `public_by_design`).\n"
    "  workflow_skip         — a state field is written with no check of the state it came from "
    "(`state_writes` without a corresponding `state_checks`).\n"
    "  trusted_client_value  — a price, amount or quantity is taken from the request and used "
    "without server-side revalidation (`money_from_request`).\n"
    "The map is an EXTRACT, not the code. Confirm every candidate against the source before "
    "reporting it, and stay silent when the source shows the check the map did not see — "
    "`auth_evidence` is followed only through functions defined in the same module, so a gate "
    "imported from elsewhere is absent from the map and present in the code. Reporting a handler "
    "that is correct is worse than missing one that is not. "
    "Cite the `handler` name exactly as the map spells it, and a `line` inside that handler's "
    "`line`..`end_line` span. A flaw you cannot tie to a handler in the map is out of scope: do "
    "not report it. "
    "Reply ONLY with JSON: {\"logic\":[{\"class\":\"missing_ownership|missing_authorization|"
    "workflow_skip|trusted_client_value\",\"handler\":str,\"file\":str,\"line\":int,\"title\":str,"
    "\"severity\":\"Critical|High|Medium|Low|Informational\",\"note\":str}]}"
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

    def _logic_prompt(self, result: ScanResult, handler_map: str, source: str = "") -> str:
        """The business-logic call: a shortlist to adjudicate, not a repository to search.

        Kept separate from `_prompt` rather than bolted onto it as a third channel. The triage
        prompt tells the model to be adversarial about a scanner's claims; this one tells it to
        be conservative about its own. One message asking for both produces a model that applies
        whichever posture it read last, and the posture is the entire precision argument here.
        """
        head = ("Target: " + result.target + "\nHandler map (JSON lines):\n" + handler_map)
        if not source:
            return (head + "\n\nNo source code accompanies this map. Return an EMPTY `logic` "
                           "list: the map is an extract and confirming a flaw against it alone "
                           "is guessing.")
        return head + "\n\nSource code (line-numbered):\n" + source

    def _apply_logic(self, result: ScanResult, data: dict, shown: set[str] | None,
                     handlers: list) -> ScanResult:
        """Merge the business-logic channel, refusing everything it cannot tie to a handler.

        Four refusals, each counted and reported rather than dropped quietly:

        * a class outside `LOGIC_CLASSES` — no fallback CWE, because stamping one weakness id on
          whatever the model happened to say is how a compliance section ends up describing a
          flaw nobody found;
        * a file the model was not shown;
        * a line outside every handler span in that file — naming a file it was shown and a line
          in some other function is not a finding;
        * a handler where Tier 0 already reported the same weakness, which is a restatement.

        Dedup is keyed on the handler rather than the line, so one flaw reported at two lines of
        one handler — the shape a repeated call produces — lands once.
        """
        from .schema import Confidence, Finding
        by_file: dict[str, list] = {}
        for fact in handlers:
            by_file.setdefault(fact.file, []).append(fact)
        allowed = set(shown) | set(by_file) if shown is not None else None

        unknown = ungrounded = outside = restated = 0
        for item in data.get("logic", []):
            spec = LOGIC_CLASSES.get(str(item.get("class", "")))
            if spec is None:
                unknown += 1
                continue
            cited = str(item.get("file", "?")).replace("\\", "/")
            if allowed is not None and cited not in allowed:
                ungrounded += 1
                continue
            line = int(item.get("line", 0) or 0)
            name = str(item.get("handler", ""))
            fact = next((f for f in by_file.get(cited, [])
                         if f.contains(line) and (not name or f.name == name)), None)
            if fact is None:
                outside += 1
                continue
            # Tier 0 got there first: `AUTHZ-PY-IDOR` and `LOGIC-IDOR` are the same sentence about
            # the same handler, and a report that prints both has inflated its own finding count.
            prior = next((f for f in result.findings
                          if f.file == cited and fact.contains(f.line)
                          and (f.cwe in spec.restates or f.detector_id == spec.detector_id)), None)
            if prior is not None:
                # Two different things collide here and only one of them is a refusal. A prior
                # finding from another tier means this pass is restating a bug that was already
                # reported, and the reader is owed that count. A prior finding from THIS pass
                # means the same flaw came back from a second model call — a duplicate, merged
                # once, worth no sentence. Counting the second as the first would inflate the
                # refusal figure with the pass's own repetitions and make it unreadable.
                if prior.source != "llm-logic":
                    restated += 1
                continue
            try:
                sev = Severity(str(item.get("severity", "Medium")))
            except ValueError:
                sev = Severity.MEDIUM
            # An unverified model claim must not outrank a proven Tier-0 Critical in the same
            # report, however confidently it was phrased.
            if sev.rank > Severity.HIGH.rank:
                sev = Severity.HIGH
            result.findings.append(Finding(
                detector_id=spec.detector_id, title=str(item.get("title") or spec.title)[:200],
                severity=sev, confidence=Confidence.MEDIUM, cwe=spec.cwe, owasp=spec.owasp,
                file=cited, line=line or fact.line, evidence=f"(business-logic pass: {fact.name})",
                fix="See triage note.", source="llm-logic", verdict=Verdict.PLAUSIBLE,
                triage_note=str(item.get("note", ""))[:500]))

        refusals = [(unknown, "named a class the pass does not define"),
                    (ungrounded, "cited a file that was not in the context sent"),
                    (outside, "cited a line outside every handler in the map"),
                    (restated, "restated a weakness Tier 0 had already reported in that handler")]
        for count, reason in refusals:
            if count:
                result.notes.append(f"{count} business-logic finding(s) {reason}, so they were "
                                    f"not merged.")
        return result

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
            # One scan sends up to `MAX_CHUNKS` calls and a repository-wide logic flaw is visible
            # from more than one of them, so the same finding arrived up to four times and the
            # report counted it four times. Nothing here was deduplicating a channel that appends.
            line_no = int(e.get("line", 1) or 1)
            if any(f.detector_id == "LLM-LOGIC" and f.file == cited and f.line == line_no
                   for f in result.findings):
                continue
            try:
                sev = Severity(str(e.get("severity", "Medium")))
            except ValueError:
                sev = Severity.MEDIUM
            result.findings.append(Finding(
                detector_id="LLM-LOGIC", title=str(e.get("title", "Logic flaw"))[:200],
                severity=sev, confidence=Confidence.MEDIUM, cwe="CWE-284", owasp="A01",
                file=cited, line=line_no,
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
        #
        # A reply with no object in it raises. It used to return `{}`, on the reasoning that junk
        # must not crash the scan — but the caller never crashed on it either: it catches, keeps
        # whatever merged, and labels the backend `(fallback: none)` or `(partial: n/m)`. What
        # `{}` actually bought was a *false success*. A model that returns prose, a refusal, a
        # truncated stream or an error page merged nothing and the header still said the tier
        # had run, so "the model confirmed none of these findings" and "the model said something
        # we could not read" rendered identically. For a tier whose whole output is verdicts,
        # those are the two answers that must never look alike.
        start, end = text.find("{"), text.rfind("}")
        if not 0 <= start < end:
            raise UnreadableReply(
                f"the model returned {len(text)} character(s) with no JSON object in them")
        return json.loads(text[start:end + 1])


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
        # The business-logic call is one of the `MAX_CHUNKS`, not an extra on top of it — the
        # reservation happens in `llmcontext.build`, which is why `total` can be counted here.
        total = len(chunks) + (1 if ctx.handlers else 0)
        completed = 0
        # Replies that carried no JSON object. Counted rather than raised on, so one refusal or
        # one truncated stream does not throw away the chunks that did come back — and reported,
        # so the run cannot pass as a full pass.
        unreadable = 0
        try:
            for chunk in chunks:
                text = self._call(self._prompt(result, chunk))
                try:
                    self._apply(result, self._parse_json(text), shown)
                except UnreadableReply:
                    unreadable += 1
                completed += 1
            if ctx.handlers:
                text = self._call(self._logic_prompt(result, ctx.handler_map, ctx.logic_source))
                # Grounded on the files whose source went WITH the map, not on everything the
                # scan sent: this call is stateless and knows nothing about the triage calls, so
                # a citation into a file only they carried is a citation into code this model
                # never saw.
                try:
                    self._apply_logic(result, self._parse_json(text), set(ctx.logic_files),
                                      ctx.handlers)
                except UnreadableReply:
                    unreadable += 1
                completed += 1
        except Exception as e:                       # noqa: BLE001 - reported, not swallowed
            # A failure on chunk 3 of 4 leaves real triage already merged from chunks 1 and 2.
            # Discarding it would be wasteful; keeping it silently would be worse — the report
            # would look like a full Tier-1 pass over a partial one.
            if completed:
                result.notes.append(
                    f"{self.name} backend failed after {completed} of {total} model call(s) "
                    f"({e}); the triage below covers only what was sent before the "
                    f"failure and the rest of the tree is unexamined, not clean.")
                result.backend = f"{self.name} (partial: {completed}/{total})"
            else:
                result.notes.append(
                    f"{self.name} backend unavailable ({e}); returned Tier-0 findings.")
                result.backend = f"{self.name} (fallback: none)"
            return result
        if ctx.chunks:
            result.notes.append(ctx.note())
        if unreadable:
            # Every call was made and every call came back — with nothing in it this tier could
            # read. Reported here rather than left to the verdict counts, because "no finding
            # was confirmed" is what an unenriched report looks like either way.
            result.notes.append(
                f"{unreadable} of {total} model call(s) returned a reply with no JSON object in "
                f"it, so the findings they covered were never triaged. Those findings are "
                f"Tier-0 and unverified, not cleared.")
            result.backend = (f"{self.name} (fallback: none)" if unreadable == total
                              else f"{self.name} (unreadable: {unreadable}/{total})")
            return result
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
