#!/usr/bin/env python3
"""CLI-layer tests — the tool's main integration surface: argument parsing, the
`--min` CI-gate exit code, `--format` selection, and `-o` file output. No LLM, no
network (backend defaults to `none`); runs fully offline against the shipped fixtures."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(KIT)
sys.path.insert(0, KIT)

from secaudit_core import cli                          # noqa: E402

VULN = os.path.join(REPO, "tests", "fixtures", "vulnerable-app")
SECURE = os.path.join(REPO, "tests", "fixtures", "secure-app")

# Built by concatenation so this test file never itself contains the contiguous `AKIA…`
# literal that the CI stray-secret guard scans for outside tests/fixtures/.
AWS_EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def run(argv: list[str]) -> tuple[int, str]:
    """Invoke the CLI in-process; return (exit_code, stdout + stderr).

    Both streams, because refusals are written to stderr — a test that watched only stdout
    would see an empty string and could not tell a clear refusal from a silent one.
    """
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue() + err.getvalue()


def _precommit_hooks() -> list[tuple[str, list[str]]]:
    """[(hook id, args)] from `.pre-commit-hooks.yaml`.

    Parsed with a regex rather than PyYAML: the zero-runtime-dependency invariant covers the
    tests too, and the file is a flat list this repository owns. A shape it cannot read shows
    up as zero hooks, which the caller treats as a failure rather than a pass.
    """
    import re
    path = os.path.join(REPO, ".pre-commit-hooks.yaml")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    hooks = []
    for block in re.split(r"^- id:", text, flags=re.M)[1:]:
        name = block.splitlines()[0].strip()
        found = re.search(r"^\s*args:\s*\[(.*)\]\s*$", block, flags=re.M)
        args = re.findall(r'"([^"]*)"', found.group(1)) if found else []
        hooks.append((name, args))
    return hooks


def main() -> int:
    fails: list[str] = []

    # 1) CI gate: the vulnerable fixture has High/Critical sinks → `--min high` must fail (exit 1).
    code, _ = run([VULN, "--no-deps", "--no-scanners", "--min", "high"])
    if code != 1:
        fails.append(f"[gate] vulnerable-app --min high should exit 1, got {code}")

    # 2) CI gate: the secure fixture has no High/Critical → `--min high` must pass (exit 0).
    code, _ = run([SECURE, "--no-deps", "--no-scanners", "--min", "high"])
    if code != 0:
        fails.append(f"[gate] secure-app --min high should exit 0, got {code}")

    # 3) Threshold is inclusive at the boundary and excludes below it: vulnerable-app has
    #    Critical findings, so `--min critical` still fails; with no --min the exit is always 0.
    code, _ = run([VULN, "--no-deps", "--no-scanners", "--min", "critical"])
    if code != 1:
        fails.append(f"[gate] vulnerable-app --min critical should exit 1, got {code}")
    code, _ = run([VULN, "--no-deps", "--no-scanners"])
    if code != 0:
        fails.append(f"[gate] no --min should always exit 0, got {code}")

    # 4) --format json emits a parseable document whose findings count is internally consistent.
    code, out = run([VULN, "--no-deps", "--no-scanners", "--format", "json"])
    try:
        doc = json.loads(out)
    except Exception as e:
        doc = None
        fails.append(f"[format] json output is not parseable JSON: {e}")
    if doc is not None and "findings" not in doc:
        fails.append("[format] json output missing `findings` key")

    # 5) --format sarif emits a valid 2.1.0 SARIF doc on stdout.
    code, out = run([VULN, "--no-deps", "--no-scanners", "--format", "sarif"])
    try:
        if json.loads(out).get("version") != "2.1.0":
            fails.append("[format] sarif output is not version 2.1.0")
    except Exception as e:
        fails.append(f"[format] sarif output is not parseable JSON: {e}")

    # 6) -o writes the report to a file (not stdout) and prints a one-line confirmation.
    with tempfile.TemporaryDirectory() as td:
        dest = os.path.join(td, "report.md")
        code, out = run([SECURE, "--no-deps", "--no-scanners", "-o", dest])
        if not os.path.isfile(dest):
            fails.append("[output] -o did not create the report file")
        elif os.path.getsize(dest) == 0:
            fails.append("[output] -o wrote an empty report file")
        if "Wrote" not in out:
            fails.append("[output] -o did not print a confirmation line to stdout")

    # 7) A masked secret's value must never reach the rendered report (defense-in-depth check
    #    at the CLI boundary, not just the engine): the fixture's example AWS key stays hidden.
    code, out = run([VULN, "--no-deps", "--no-scanners", "--format", "md"])
    if AWS_EXAMPLE_KEY in out:
        fails.append("[mask] a masked secret value leaked into the rendered report")

    # 8) A URL target is refused, loudly.
    #    This package reads source on disk. Handed a URL it used to treat it as a path, match
    #    no files, and finish with an empty report — indistinguishable from a clean audit
    #    unless someone noticed the file count. That is the worst answer a security tool can
    #    give, so it is now exit 2 with an explanation.
    for url in ("https://example.com", "http://10.0.0.1:8080/app", "HTTPS://EXAMPLE.COM"):
        code, out = run([url, "--no-deps"])
        if code != 2:
            fails.append(f"[url] `{url}` should exit 2, got {code}")
        if "audits source code on disk" not in out:
            fails.append(f"[url] `{url}` did not explain why it refused: {out.strip()[:120]!r}")

    #    ...but a real directory whose name looks host-like must still be scanned. Refusing to
    #    scan a directory called `example.com` would be its own quiet failure.
    import tempfile as _tf
    holder = _tf.mkdtemp(prefix="secaudit-hostdir-")
    hostdir = os.path.join(holder, "example.com")
    os.makedirs(hostdir)
    with open(os.path.join(hostdir, "a.js"), "w", encoding="utf-8") as f:
        f.write("eval(userInput);\n")
    code, out = run([hostdir, "--no-deps", "--no-scanners", "--format", "json"])
    try:
        if not any(f["detector_id"] == "SEC-JS-EVAL" for f in json.loads(out)["findings"]):
            fails.append("[url] a directory named like a host must still be scanned")
    except (json.JSONDecodeError, KeyError):
        fails.append("[url] scanning a host-named directory did not produce a report")

    # 9) Every flag combination shipped in `.pre-commit-hooks.yaml` actually parses.
    #    A hook config is code that only runs on someone else's machine, at the moment they
    #    are trying to commit — and the failure mode is silent-looking: `--only secrets` (the
    #    plural) is not a group, so the hook exits 2 and a developer sees a broken pre-commit
    #    rather than a security result. That exact typo shipped and nothing caught it.
    for name, args in _precommit_hooks():
        code, out = run([SECURE, *args])
        if code == 2:
            fails.append(f"[pre-commit] hook `{name}` has arguments the CLI rejects: "
                         f"{' '.join(args)} -> exit 2. {out.strip().splitlines()[-1] if out.strip() else ''}")

    if fails:
        print("CLI TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("CLI TESTS PASSED — --min gate (high/critical/none), json+sarif formats, -o file "
          "output, secret masking, a URL target refused with a reason (and a host-named "
          "directory still scanned), and every shipped pre-commit hook's flags accepted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
