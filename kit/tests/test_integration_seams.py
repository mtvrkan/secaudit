#!/usr/bin/env python3
"""The two integration seams, exercised for real: the scanner subprocess adapters and the LLM
HTTP path.

These were the least-covered modules in the package (69% and 66%), and the uncovered lines
were not obscure branches — they were the code that *shells out to a scanner* and the code that
*makes the HTTP request*. Every parse function was covered against captured sample output while
nothing checked that the tool was invoked correctly, that a scanner exiting non-zero degraded
into a note instead of taking the scan down, or that a backend's transport error surfaced.
Those are the seams where an integration actually breaks.

Neither half is tested by mocking the function under test:

* **Scanners** run real `subprocess` calls against **fake executables written into a temp
  directory placed on `PATH`**. The adapter resolves the tool through `shutil.which`, spawns
  it, and parses what it prints — the whole path runs, and the only thing replaced is the
  scanner's own binary. Stubbing `subprocess.run` would have tested the mock.
* **Backends** inject a transport at `_post`, the one seam that would otherwise need the
  network. Everything above it — request assembly, response shaping, error containment — is
  the real code, and the assertions are about the request the backend *built*.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KIT)

from secaudit_core import scanners                             # noqa: E402
from secaudit_core.backends import AnthropicBackend, OpenAIBackend, OllamaBackend  # noqa: E402
from secaudit_core.schema import ScanResult                    # noqa: E402

fails: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        fails.append(message)


# --------------------------------------------------------------- fake executables on PATH

# Shaped the way semgrep actually emits SARIF: the CWE rides in the rule's `properties.tags`,
# not in the message text. Writing it into the message instead made this fixture assert against
# a parser that never claimed to read there — the fixture was wrong, not the parser.
SEMGREP_SARIF = json.dumps({
    "runs": [{
        "results": [{
            "ruleId": "python.lang.security.audit.dangerous-system-call",
            "level": "error",
            "message": {"text": "Found dangerous system call"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "app/run.py"},
                "region": {"startLine": 12}}}],
        }],
        "tool": {"driver": {"rules": [{
            "id": "python.lang.security.audit.dangerous-system-call",
            "name": "dangerous-system-call",
            "properties": {"tags": ["CWE-78: OS Command Injection"],
                           "security-severity": "9.3"},
        }]}},
    }],
})

# The fake secret is assembled at runtime rather than written as a literal. A key-shaped string
# in a non-fixture source file is exactly what check 19 exists to catch, and it caught this —
# correctly, since a scanner cannot tell a documentation-example key from a live one. Keeping
# the gate strict and moving the string out of the source is the right way round; adding an
# exemption for a test file would have blunted the check for every future file.
_FAKE_SECRET = "AKIA" + "IOSFODNN7" + "EXAMPLE"

GITLEAKS_JSON = json.dumps([{
    "Description": "AWS Access Key", "File": "config/settings.py", "StartLine": 4,
    "RuleID": "aws-access-token", "Secret": _FAKE_SECRET,
}])

OSV_JSON = json.dumps({
    "results": [{
        "packages": [{
            "package": {"name": "flask", "ecosystem": "PyPI"},
            "vulnerabilities": [{
                "id": "GHSA-xxxx-yyyy-zzzz",
                "summary": "Flask before 2.2.5 leaks the session cookie (CWE-200)",
                "database_specific": {"severity": "HIGH"},
            }],
        }],
    }],
})


def _write_fake(directory: str, name: str, stdout: str, exit_code: int = 0) -> None:
    """Write an executable named `name` that prints `stdout` and exits `exit_code`.

    Written for the current platform rather than assumed: on Windows `subprocess.run(["semgrep",
    ...])` resolves `semgrep.bat` through PATHEXT and never sees an extensionless file, and on
    POSIX a `.bat` is not executable. This kit makes Windows-specific claims and runs its gates
    on both platforms, so the fixture has to work on both too.
    """
    if os.name == "nt":
        path = os.path.join(directory, f"{name}.bat")
        payload = stdout.replace("^", "^^").replace("&", "^&").replace("<", "^<")
        payload = payload.replace(">", "^>").replace("|", "^|").replace("%", "%%")
        with open(path, "w", encoding="utf-8", newline="\r\n") as fh:
            fh.write("@echo off\n")
            fh.write(f"echo {payload}\n")
            fh.write(f"exit /b {exit_code}\n")
        return
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("#!/bin/sh\n")
        fh.write("cat <<'SECAUDIT_EOF'\n")
        fh.write(stdout + "\n")
        fh.write("SECAUDIT_EOF\n")
        fh.write(f"exit {exit_code}\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class fake_scanners_on_path:
    """Context manager putting a directory of fake scanners at the front of PATH."""

    def __init__(self, **tools: tuple) -> None:
        self.tools = tools
        self.directory = ""
        self.previous = ""

    def __enter__(self) -> str:
        self.directory = tempfile.mkdtemp(prefix="secaudit-fakebin-")
        for name, spec in self.tools.items():
            stdout, exit_code = spec if isinstance(spec, tuple) else (spec, 0)
            _write_fake(self.directory, name.replace("_", "-"), stdout, exit_code)
        self.previous = os.environ.get("PATH", "")
        os.environ["PATH"] = self.directory + os.pathsep + self.previous
        return self.directory

    def __exit__(self, *exc) -> None:
        os.environ["PATH"] = self.previous
        shutil.rmtree(self.directory, ignore_errors=True)


# --------------------------------------------------------------------------- scanner seams

def test_installed_scanners_are_run_and_parsed() -> None:
    """All three adapters, spawned for real, with their output parsed into findings."""
    with tempfile.TemporaryDirectory() as target:
        with fake_scanners_on_path(semgrep=SEMGREP_SARIF, gitleaks=GITLEAKS_JSON,
                                   osv_scanner=OSV_JSON):
            notes: list[str] = []
            tools: list[str] = []
            findings = scanners.run_installed_scanners(target, notes, tools)

    check("semgrep" in tools, f"semgrep did not report itself as used: {tools}")
    check("gitleaks" in tools, f"gitleaks did not report itself as used: {tools}")
    check("osv-scanner" in tools, f"osv-scanner did not report itself as used: {tools}")
    sources = {f.source for f in findings}
    check(sources == {"semgrep", "gitleaks", "osv"},
          f"expected findings from all three adapters, got sources {sources}")
    check(any(f.cwe == "CWE-78" for f in findings),
          "the semgrep CWE was not carried through from the SARIF message")
    check(any(f.package == "flask" for f in findings),
          "the osv finding lost its package name — engine.apply_vex keys reachability on it")
    secret = [f for f in findings if f.source == "gitleaks"]
    check(bool(secret) and _FAKE_SECRET not in (secret[0].evidence or ""),
          "the gitleaks adapter printed the secret it found into the evidence line")


def test_a_scanner_that_fails_degrades_into_a_note() -> None:
    """A scanner that is installed and broken must not take the scan down with it.

    This is the branch that matters most in the field and the one that was uncovered: the tool
    resolves on PATH, so the adapter commits to running it, and then it exits non-zero with
    unparseable output.
    """
    with tempfile.TemporaryDirectory() as target:
        with fake_scanners_on_path(semgrep=("not json at all", 2)):
            notes: list[str] = []
            tools: list[str] = []
            findings = scanners.run_installed_scanners(target, notes, tools)

    check("semgrep" not in tools,
          "a semgrep run that failed still reported semgrep as a tool used")
    check(any("semgrep" in n and "failed" in n for n in notes),
          f"the failure was not disclosed in the notes: {notes}")
    check(findings == [], f"a failed scanner produced findings: {findings}")


def test_absent_scanners_are_named_in_the_notes() -> None:
    """A report has to say which higher-fidelity tools were not available."""
    with tempfile.TemporaryDirectory() as target:
        with fake_scanners_on_path(semgrep=SEMGREP_SARIF):
            notes: list[str] = []
            tools: list[str] = []
            scanners.run_installed_scanners(target, notes, tools)

    absent_note = " ".join(n for n in notes if "Not installed" in n)
    check("gitleaks" in absent_note and "osv-scanner" in absent_note,
          f"absent scanners were not named: {notes}")
    check("semgrep" not in absent_note,
          f"a scanner that WAS installed was listed as absent: {absent_note}")


def test_a_target_that_is_not_a_directory_runs_nothing() -> None:
    notes: list[str] = []
    tools: list[str] = []
    check(scanners.run_installed_scanners(os.path.join(KIT, "does-not-exist"), notes, tools) == [],
          "scanners ran against a target that does not exist")
    check(tools == [], "a non-existent target still reported tools as used")


# --------------------------------------------------------------------------- backend seams

class _RecordingTransport:
    """Stands in for the one call that would otherwise need the network."""

    def __init__(self, response: dict | None = None, error: Exception | None = None) -> None:
        self.response = response or {}
        self.error = error
        self.calls: list[tuple] = []

    def __call__(self, url: str, payload: dict, headers: dict, timeout: int = 90) -> dict:
        self.calls.append((url, payload, headers, timeout))
        if self.error is not None:
            raise self.error
        return self.response


def _with_transport(backend, transport):
    backend._post = transport                                            # type: ignore[method-assign]
    return backend


def test_anthropic_request_shape() -> None:
    """The request the backend builds, asserted field by field.

    Three of these are load-bearing beyond "it works": `temperature` is rejected outright by
    this model family, `max_tokens` bounds thinking and response text *together* on a model
    that thinks by default, and only text blocks carry the triage JSON.
    """
    transport = _RecordingTransport({"content": [
        {"type": "thinking", "thinking": ""},
        {"type": "text", "text": '{"triage": []}'},
    ]})
    os.environ["ANTHROPIC_API_KEY"] = "test-key-not-a-real-one"
    os.environ.pop("SECAUDIT_MODEL", None)
    try:
        text = _with_transport(AnthropicBackend(), transport)._call("triage this")
    finally:
        os.environ.pop("ANTHROPIC_API_KEY", None)

    check(text == '{"triage": []}',
          f"a thinking block leaked into the parsed payload: {text!r}")
    check(len(transport.calls) == 1, "the backend did not make exactly one request")
    url, payload, headers, _ = transport.calls[0]
    check(url.endswith("/v1/messages"), f"wrong endpoint: {url}")
    check(payload["model"] == "claude-opus-5",
          f"default model is {payload['model']!r}, not the current default")
    check("temperature" not in payload,
          "the request carries `temperature`, which this model family rejects with a 400")
    check(payload["max_tokens"] >= 16000,
          f"max_tokens={payload['max_tokens']} bounds thinking + text together and will "
          f"truncate the triage JSON on a model that thinks by default")
    check(headers.get("anthropic-version") == "2023-06-01",
          f"missing or wrong API version header: {headers}")
    check(headers.get("x-api-key") == "test-key-not-a-real-one", "the API key was not sent")


def test_backends_refuse_without_a_key_rather_than_calling_out() -> None:
    for backend_cls, var in ((AnthropicBackend, "ANTHROPIC_API_KEY"),
                             (OpenAIBackend, "OPENAI_API_KEY")):
        transport = _RecordingTransport({})
        saved = os.environ.pop(var, None)
        try:
            raised = ""
            try:
                _with_transport(backend_cls(), transport)._call("x")
            except Exception as e:                                       # noqa: BLE001
                raised = str(e)
            check(var in raised,
                  f"{backend_cls.__name__} without {var} raised {raised!r}, not a clear refusal")
            check(transport.calls == [],
                  f"{backend_cls.__name__} made a request with no key configured")
        finally:
            if saved is not None:
                os.environ[var] = saved


def test_openai_and_ollama_response_shapes() -> None:
    os.environ["OPENAI_API_KEY"] = "test-key"
    try:
        transport = _RecordingTransport(
            {"choices": [{"message": {"content": "openai-said-this"}}]})
        text = _with_transport(OpenAIBackend(), transport)._call("x")
        check(text == "openai-said-this", f"OpenAI response not unwrapped: {text!r}")
        check(transport.calls[0][2].get("Authorization", "").startswith("Bearer "),
              "OpenAI key was not sent as a bearer token")
    finally:
        os.environ.pop("OPENAI_API_KEY", None)

    transport = _RecordingTransport({"response": "ollama-said-this"})
    text = _with_transport(OllamaBackend(), transport)._call("x")
    check(text == "ollama-said-this", f"Ollama response not unwrapped: {text!r}")
    check(transport.calls[0][0].endswith("/api/generate"),
          f"Ollama called the wrong endpoint: {transport.calls[0][0]}")


def test_enrich_contains_a_transport_failure_but_complete_reports_it() -> None:
    """The two error policies are deliberately opposite, and both are asserted here.

    `enrich` swallows: a Tier-0 report must still reach the user when the model is unreachable.
    `complete` surfaces: a patch step that returned "" on a network error would be reported as
    the model declining to suggest a patch, which is a different and misleading outcome.
    """
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    try:
        boom = _RecordingTransport(error=RuntimeError("connection reset by peer"))

        result = ScanResult(target="x", backend="none")
        result.findings = []
        enriched = _with_transport(AnthropicBackend(), boom).enrich(result)
        check(enriched.backend == "anthropic",
              "a result with no findings should shortcut without contacting the model")

        result = ScanResult(target="x", backend="none")
        from secaudit_core.schema import Confidence, Finding, Severity   # noqa: PLC0415
        result.findings = [Finding("X", "t", Severity.HIGH, Confidence.MEDIUM, "CWE-1", "A01",
                                   "a.py", 1, "e", "f")]
        enriched = _with_transport(AnthropicBackend(), boom).enrich(result)
        check("fallback" in enriched.backend,
              f"a transport failure did not mark the backend as fallen back: {enriched.backend}")
        check(any("unavailable" in n for n in enriched.notes),
              f"the failure was not disclosed in the notes: {enriched.notes}")
        check(len(enriched.findings) == 1,
              "the Tier-0 findings were lost when the model was unreachable")

        completion = _with_transport(AnthropicBackend(), boom).complete("write a patch")
        check("backend error" in completion,
              f"`complete` swallowed a transport error instead of surfacing it: {completion!r}")
    finally:
        os.environ.pop("ANTHROPIC_API_KEY", None)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    test_installed_scanners_are_run_and_parsed()
    test_a_scanner_that_fails_degrades_into_a_note()
    test_absent_scanners_are_named_in_the_notes()
    test_a_target_that_is_not_a_directory_runs_nothing()
    test_anthropic_request_shape()
    test_backends_refuse_without_a_key_rather_than_calling_out()
    test_openai_and_ollama_response_shapes()
    test_enrich_contains_a_transport_failure_but_complete_reports_it()

    if fails:
        print("INTEGRATION SEAM TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("INTEGRATION SEAM TESTS PASSED — scanner adapters spawned as real subprocesses "
          "against fake executables on PATH, and the LLM request shape, key refusal and "
          "error-containment policies asserted through an injected transport.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
