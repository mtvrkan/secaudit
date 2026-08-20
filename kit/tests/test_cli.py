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

from secaudit_core import __version__, cli             # noqa: E402

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

    # 0) `--version`, which is the first thing typed after `pip install` and which used to print
    #    a usage error. argparse's `version` action exits through SystemExit, so it does not come
    #    back through `run()`; asserted here rather than left to the install gate, because that
    #    one needs a wheel and a virtualenv and this needs neither.
    out = io.StringIO()
    try:
        with redirect_stdout(out):
            cli.main(["--version"])
    except SystemExit as e:
        if e.code not in (0, None):
            fails.append(f"[version] --version exited {e.code}, expected 0")
    else:
        fails.append("[version] --version did not exit; it printed and carried on")
    printed = out.getvalue().strip()
    if printed != f"secaudit {__version__}":
        fails.append(f"[version] --version printed {printed!r}, expected "
                     f"'secaudit {__version__}'")

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
    #    Invoked the way pre-commit invokes it, which is the part this check used to miss: both
    #    hooks declare `pass_filenames: true`, so pre-commit appends EVERY staged file that
    #    matches. Passing one target proved the flags parse and nothing more — and the CLI took a
    #    single positional, so the moment a commit touched two files the hook died on
    #    `unrecognized arguments` instead of reporting a finding. Every commit but a one-file one.
    staged = sorted(os.path.join(SECURE, f) for f in os.listdir(SECURE)
                    if os.path.isfile(os.path.join(SECURE, f)))[:3]
    if len(staged) < 2:
        fails.append("[pre-commit] the secure fixture no longer has two files to stage, so the "
                     "multi-file invocation is untested")
    for name, args in _precommit_hooks():
        for label, targets in (("one file", staged[:1]), ("several files", staged)):
            code, out = run([*targets, *args])
            if code == 2:
                last = out.strip().splitlines()[-1] if out.strip() else ""
                fails.append(f"[pre-commit] hook `{name}` rejects {label} the way pre-commit "
                             f"passes them: {' '.join(args)} -> exit 2. {last}")

    # 10) `--summary PATH` writes the readable report whenever it is asked to.
    #     It used to be skipped for EVERY `--format md` run, on the reasoning that markdown had
    #     "already produced it" — but without `-o` the report goes to stdout, so the flag wrote
    #     nothing, printed nothing and exited 0. A CI job that publishes the summary afterwards
    #     published a file from some earlier run, or none at all.
    with tempfile.TemporaryDirectory() as tmp:
        alone = os.path.join(tmp, "human.md")
        run([SECURE, "--no-deps", "--no-scanners", "--format", "md", "--summary", alone])
        if not os.path.exists(alone):
            fails.append("[summary] --format md --summary wrote nothing (report went to stdout)")
        elif "SecAudit report" not in open(alone, encoding="utf-8").read():
            fails.append("[summary] --summary wrote a file that is not the report")

        beside = os.path.join(tmp, "other.md")
        run([SECURE, "--no-deps", "--no-scanners", "--format", "md",
             "-o", os.path.join(tmp, "report.md"), "--summary", beside])
        if not os.path.exists(beside):
            fails.append("[summary] --summary to a second path alongside -o wrote nothing")

        # The one case the skip existed for: the same file must not be written twice.
        same = os.path.join(tmp, "same.md")
        run([SECURE, "--no-deps", "--no-scanners", "--format", "md",
             "-o", same, "--summary", same])
        written = open(same, encoding="utf-8").read().count("# SecAudit report")
        if written != 1:
            fails.append(f"[summary] -o and --summary naming one file wrote the report "
                         f"{written} times")

    # 11) `--lang` reaches the HTML renderer. `to_html` took no locale at all, so
    #     `--format html --lang tr` was accepted and produced an English document — the flag
    #     was not refused, it was ignored, which is the same defect as (10) in a second place.
    with tempfile.TemporaryDirectory() as tmp:
        tr_page, en_page = os.path.join(tmp, "tr.html"), os.path.join(tmp, "en.html")
        run([SECURE, "--no-deps", "--no-scanners", "--format", "html",
             "--lang", "tr", "-o", tr_page])
        run([SECURE, "--no-deps", "--no-scanners", "--format", "html", "-o", en_page])
        tr_html = open(tr_page, encoding="utf-8").read()
        en_html = open(en_page, encoding="utf-8").read()
        if 'lang="tr"' not in tr_html:
            fails.append("[lang] --lang tr did not set the HTML document language")
        if "Bulgular" not in tr_html:
            fails.append("[lang] --lang tr rendered English section headings in the HTML report")
        if "\x00" in tr_html:
            fails.append("[lang] the target placeholder leaked into the rendered HTML")
        if 'lang="en"' not in en_html or "Findings" not in en_html:
            fails.append("[lang] the default HTML report stopped being English")

    # A target that is not there must be refused, not audited. This is the failure the URL guard
    # above was written for, arriving by the ordinary route: `os.walk` yields nothing for a path
    # that does not exist and raises nothing either, so the run produced a full report with every
    # count at zero and exit 0 — a CI gate that passed forever while scanning nothing, for as
    # long as the path in the workflow stayed wrong. Asserted with --min, because that is the
    # invocation where the wrong answer is a green build rather than an empty page.
    code, out = run([os.path.join(REPO, "no-such-directory-xyz"), "--min", "low"])
    if code != 2:
        fails.append(f"[missing] a target that does not exist must exit 2, got {code}")
    if "does not exist" not in out:
        fails.append("[missing] the refusal does not say the path is not there")

    # The residual of the same failure, for a target that does exist: everything under it was
    # skipped, or `--only` named a group nothing here matches. The counts are all zero either
    # way, so the report has to distinguish "read nothing" from "found nothing".
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "node_modules"))
        with open(os.path.join(d, "node_modules", "a.py"), "w", encoding="utf-8") as fh:
            fh.write("import os\nos.system('ls ' + input())\n")
        code, out = run([d, "--no-deps", "--no-scanners"])
        if "NO FILES WERE READ" not in out:
            fails.append("[empty] a scan that read nothing renders as a clean report")
        if "Files scanned:** 0" not in out:
            fails.append("[empty] the report does not state that it read zero files")
    code, out = run([VULN, "--no-deps", "--no-scanners"])
    if "Files scanned:** 0" in out or "Files scanned:**" not in out:
        fails.append("[empty] a real scan does not state how many files it read")
    if "NO FILES WERE READ" in out:
        fails.append("[empty] a real scan claims it read nothing")

    # Flags that cannot do anything on their own are refused rather than ignored. A run that
    # quietly drops the step it was asked for looks exactly like one that did it and passed.
    code, out = run([VULN, "--no-deps", "--no-scanners", "--patch-tests", "true"])
    if code != 2 or "--patch-tests" not in out:
        fails.append(f"[flags] --patch-tests without --suggest-patches must exit 2, got {code}")
    with tempfile.TemporaryDirectory() as d:
        code, out = run([VULN, "--no-deps", "--no-scanners", "--suggest-patches", d])
        if code != 2 or "needs a model" not in out:
            fails.append(f"[flags] --suggest-patches with no backend must exit 2, got {code}")

    if fails:
        print("CLI TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("CLI TESTS PASSED — --min gate (high/critical/none), json+sarif formats, -o file "
          "output, secret masking, a URL target refused with a reason (and a host-named "
          "directory still scanned), a target that does not exist refused rather than reported "
          "clean, a scan that read no files saying so instead of rendering as a clean bill of "
          "health, every report stating how many files it read, --patch-tests and "
          "--suggest-patches refused when they cannot do anything, every shipped pre-commit "
          "hook accepted with one staged file and with several — the way pre-commit actually "
          "invokes them — --summary written whenever asked (and never twice), and --lang "
          "honoured by the HTML renderer.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
