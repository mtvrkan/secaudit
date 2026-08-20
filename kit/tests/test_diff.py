"""Diff mode (`--since REF`) — against a real git repository, not a mocked one.

The value of this feature is entirely in whether it says the right thing about a change, and
almost all of the ways it can say the wrong thing live in the plumbing: resolving a ref,
materialising a tree, agreeing on path names between two scans rooted in different directories.
A test that stubs git out would pass while every one of those was broken, so each case here
builds an actual repository in a temp dir and runs the actual CLI.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secaudit_core import cli, diff                                   # noqa: E402
from secaudit_core.schema import Confidence, Finding, Severity        # noqa: E402

fails: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        fails.append(message)


VULNERABLE = """\
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));
});
"""

SAFE = """\
const { execFile } = require('child_process');
const HOST = /^[a-z0-9.-]{1,253}$/i;
app.get('/ping', (req, res) => {
  const host = String(req.query.host || '');
  if (!HOST.test(host)) return res.status(400).send('bad host');
  execFile('ping', ['-c', '1', '--', host], (e, out) => res.send(out));
});
"""


class Repo:
    """A throwaway git repository. Commits are made with an explicit identity so the test does
    not depend on whatever `user.email` the machine running it happens to have configured."""

    def __init__(self) -> None:
        self.path = tempfile.mkdtemp(prefix="secaudit-difftest-")
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "SecAudit Test")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args: str) -> str:
        done = subprocess.run(["git", *args], cwd=self.path,
                              capture_output=True, text=True, check=False)
        if done.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)}: {done.stderr.strip()}")
        return done.stdout.strip()

    def write(self, name: str, text: str) -> None:
        full = os.path.join(self.path, name)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(text)

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def run(self, *extra: str) -> tuple[int, str]:
        """The CLI, exactly as a user runs it, with stdout captured."""
        import io
        from contextlib import redirect_stdout, redirect_stderr
        buffer, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buffer), redirect_stderr(err):
            code = cli.main([self.path, "--no-deps", "--no-scanners", *extra])
        return code, buffer.getvalue() + err.getvalue()

    def close(self) -> None:
        shutil.rmtree(self.path, ignore_errors=True)


def test_introduced_and_resolved() -> None:
    repo = Repo()
    try:
        repo.write("server.js", "// nothing here yet\n")
        base = repo.commit("empty")

        repo.write("server.js", VULNERABLE)
        code, out = repo.run("--since", base, "--min", "high")
        check("## Introduced" in out, "the report must have an Introduced section")
        check("SEC-JS-CMDI" in out.split("## Resolved")[0],
              "a command injection added by the change belongs under Introduced")
        check(code == 1, f"--min high must fail when the change introduced a Critical (got {code})")

        # Now fix it. The same rule that failed the gate must move to Resolved, and the gate
        # must pass — a gate that cannot be satisfied by fixing the code is not a gate.
        repo.write("server.js", SAFE)
        code, out = repo.run("--since", base, "--min", "high")
        introduced = out.split("## Resolved")[0]
        check("SEC-JS-CMDI" not in introduced,
              "the fixed finding must not still be reported as introduced")
        check(code == 0, f"--min high must pass once the introduced finding is fixed (got {code})")
    finally:
        repo.close()


def test_preexisting_findings_do_not_fail_the_gate() -> None:
    """The whole reason diff mode exists. If untouched debt fails the build, the gate is
    switched off within a week and stops catching new Criticals too."""
    repo = Repo()
    try:
        repo.write("server.js", VULNERABLE)
        base = repo.commit("with a pre-existing bug")

        repo.write("README.md", "# docs\n")           # a change that touches nothing risky
        code, out = repo.run("--since", base, "--min", "high")
        check(code == 0,
              f"an unrelated change must not fail on a finding it did not introduce (got {code})")
        check("Nothing new" in out, "the report should say plainly that nothing was introduced")
        check("Pre-existing" in out and "SEC-JS-CMDI" not in out.split("## Resolved")[0],
              "the untouched finding must still be surfaced, under Pre-existing")
    finally:
        repo.close()


def test_line_drift_is_not_a_change() -> None:
    """Adding an import at the top of a file moves every finding below it. A line-keyed diff
    reports all of them as resolved AND introduced at once, on a commit that changed nothing
    about them — and a diff that cries wolf is a diff people stop reading."""
    repo = Repo()
    try:
        repo.write("server.js", VULNERABLE)
        base = repo.commit("baseline")

        repo.write("server.js", "const os = require('os');\nconst path = require('path');\n"
                                + VULNERABLE)
        code, out = repo.run("--since", base, "--format", "json")
        import json
        result = json.loads(out)
        check(result["counts"]["introduced"] == 0,
              f"pushing every line down must introduce nothing "
              f"(got {result['counts']['introduced']}: "
              f"{[f['detector_id'] for f in result['introduced']]})")
        check(result["counts"]["resolved"] == 0,
              f"...and resolve nothing (got {result['counts']['resolved']})")
        check(result["counts"]["unchanged"] > 0,
              "...while still reporting the finding as open")
    finally:
        repo.close()


def test_repeated_identical_lines_stay_distinct() -> None:
    """Two identical dangerous lines in one file are two findings. If the fingerprint collapses
    them, fixing one reads as fixing both — the diff would say the file is clean while a live
    command injection is still in it."""
    seen: dict[tuple, int] = {}
    make = lambda line: Finding(                                          # noqa: E731
        detector_id="SEC-JS-EVAL", title="eval", severity=Severity.HIGH,
        confidence=Confidence.HIGH, cwe="CWE-95", owasp="A03", file="a.js",
        line=line, evidence="eval(input);", fix="")
    first = diff.fingerprint(make(10), seen)
    second = diff.fingerprint(make(40), seen)
    check(first != second,
          "two identical evidence lines in one file must not share a fingerprint")


def test_missing_ref_and_non_repo_explain_themselves() -> None:
    repo = Repo()
    try:
        repo.write("server.js", VULNERABLE)
        repo.commit("baseline")
        code, out = repo.run("--since", "no-such-branch")
        check(code == 2, f"an unknown ref is a usage error, not a scan failure (got {code})")
        check("no-such-branch" in out and "does not fetch" in out,
              f"the message must name the ref and say we do not fetch it — got: {out.strip()!r}")
    finally:
        repo.close()

    outside = tempfile.mkdtemp(prefix="secaudit-nogit-")
    try:
        with open(os.path.join(outside, "server.js"), "w", encoding="utf-8") as f:
            f.write(VULNERABLE)
        import io
        from contextlib import redirect_stdout, redirect_stderr
        buffer, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buffer), redirect_stderr(err):
            code = cli.main([outside, "--no-deps", "--no-scanners", "--since", "HEAD"])
        message = buffer.getvalue() + err.getvalue()
        check(code == 2 and "git repositor" in message,
              f"a target outside a git repo must say so, not traceback — got: {message.strip()!r}")
    finally:
        shutil.rmtree(outside, ignore_errors=True)


def test_incompatible_format_is_refused() -> None:
    repo = Repo()
    try:
        repo.write("server.js", VULNERABLE)
        base = repo.commit("baseline")
        code, out = repo.run("--since", base, "--format", "sarif")
        check(code == 2 and "not a comparison" in out,
              f"a single-scan format must be refused rather than silently ignoring --since "
              f"— got exit {code}: {out.strip()!r}")
    finally:
        repo.close()


def test_since_reaches_the_patch_step() -> None:
    """`--since` used to return before `--suggest-patches` was ever consulted.

    So the combination that most obviously belongs together — gate a pull request on what it
    introduced, then offer a fix for it — wrote no patches, printed no refusals and exited 0.
    Asserted through the `--backend none` refusal because that message is proof the patch step
    ran at all: before the fix nothing was printed, because nothing was reached.
    """
    repo = Repo()
    try:
        repo.write("server.js", "// nothing here yet\n")
        base = repo.commit("empty")
        repo.write("server.js", VULNERABLE)
        out_dir = os.path.join(repo.path, "patches")
        _, out = repo.run("--since", base, "--suggest-patches", out_dir, "--backend", "none")
        check("--suggest-patches needs a model" in out,
              f"--since must still reach --suggest-patches; got {out.strip()[:200]!r}")
    finally:
        repo.close()


def test_since_states_that_the_diff_is_not_translated() -> None:
    """`--lang tr --since` rendered an English diff without saying so.

    The diff report's vocabulary is not in the locale bundles, so there is nothing for `--lang`
    to select — which is a bound worth stating rather than a flag worth ignoring.
    """
    repo = Repo()
    try:
        repo.write("server.js", VULNERABLE)
        base = repo.commit("baseline")
        code, out = repo.run("--since", base, "--lang", "tr")
        check(code == 0 and "not translated" in out,
              f"--lang with --since must say the diff is not translated; got exit {code}: "
              f"{out.strip()[:200]!r}")
    finally:
        repo.close()


def _alias_of(path: str) -> str | None:
    """A second, different spelling of `path`, or None if this platform cannot produce one.

    The bug this exists for needs two spellings of one directory, which is the ordinary state of
    affairs and not an exotic one: on a GitHub Windows runner `TEMP` is the 8.3 short name
    `C:\\Users\\RUNNER~1\\...` while git answers with `runneradmin`. So the alias is built the
    way each platform actually produces one — `GetShortPathNameW` on Windows (no privileges, no
    subprocess, and the exact condition CI hit), a symlink on POSIX.
    """
    if os.name == "nt":
        import ctypes                                                    # noqa: PLC0415
        buf = ctypes.create_unicode_buffer(1024)
        n = ctypes.windll.kernel32.GetShortPathNameW(path, buf, 1024)    # type: ignore[attr-defined]
        short = buf.value if n else ""
        # Returns the long path unchanged when 8.3 is disabled on the volume — that is not an
        # alias, and pretending it is would make this test assert nothing.
        return short if short and os.path.normcase(short) != os.path.normcase(path) else None
    link = tempfile.mkdtemp(prefix="secaudit-alias-") + "-link"
    try:
        os.symlink(path, link, target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError):
        return None
    return link


def test_an_aliased_target_never_scans_the_working_tree_as_its_own_baseline() -> None:
    """The regression that CI caught and this machine did not.

    `gitref` compared `abspath(target)` against git's `--show-toplevel`. Those are two spellings
    of the same directory whenever the caller's path is a short name, a junction or a symlink,
    and `relpath` between them produced `..\\..\\<repo>` — a path climbing out of the extracted
    baseline and landing on the live working tree. `os.path.exists` agreed, so the baseline was
    the current code, every finding compared equal to itself, and a change introducing a
    Critical was reported as introducing nothing. Green build, silent miss.

    Asserted through the CLI rather than through `relpath`, because the assertion that matters
    is "a new Critical is still reported as new when the path is spelled differently".
    """
    repo = Repo()
    try:
        alias = _alias_of(repo.path)
        if alias is None:
            if os.environ.get("CI"):
                fails.append("[alias] no second spelling of a directory could be produced and "
                             "this is CI — the aliased-path regression is not being covered")
            else:
                print("  note: this platform produced no path alias (8.3 disabled, or symlinks "
                      "unavailable) — the aliased-target case was NOT exercised.")
            return

        repo.write("server.js", "// nothing here yet\n")
        base = repo.commit("empty")
        repo.write("server.js", VULNERABLE)

        import io                                                        # noqa: PLC0415
        from contextlib import redirect_stderr, redirect_stdout          # noqa: PLC0415
        buffer, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buffer), redirect_stderr(err):
            code = cli.main([alias, "--no-deps", "--no-scanners", "--since", base, "--min", "high"])
        out = buffer.getvalue() + err.getvalue()

        check("SEC-JS-CMDI" in out.split("## Resolved")[0],
              f"a Critical introduced through an aliased path ({alias!r}) must still be reported "
              f"as introduced — the baseline must come from the archive, never from the working "
              f"tree")
        check(code == 1,
              f"--min high must fail for a Critical introduced through an aliased path (got {code})")
    finally:
        repo.close()


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    if shutil.which("git") is None:
        print("DIFF TESTS SKIPPED — git is not on PATH.")
        return 0

    test_introduced_and_resolved()
    test_preexisting_findings_do_not_fail_the_gate()
    test_line_drift_is_not_a_change()
    test_repeated_identical_lines_stay_distinct()
    test_missing_ref_and_non_repo_explain_themselves()
    test_incompatible_format_is_refused()
    test_since_reaches_the_patch_step()
    test_since_states_that_the_diff_is_not_translated()
    test_an_aliased_target_never_scans_the_working_tree_as_its_own_baseline()

    if fails:
        print("DIFF TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("DIFF TESTS PASSED — introduced/resolved classification, pre-existing debt does not "
          "fail the gate, line drift is not a change, identical lines stay distinct, bad "
          "refs / non-repos / single-scan formats explain themselves, and --since reaches "
          "--suggest-patches instead of silently dropping it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
