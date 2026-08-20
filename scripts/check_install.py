#!/usr/bin/env python3
"""Install the built wheel into an empty virtualenv and use it the way a reader would.

    python3 scripts/check_install.py

Everything else in this repository tests the code where it lives — on `sys.path`, next to its
own fixtures, with the repository root as the working directory. None of that is how anybody
receives this package. `scripts/assert_no_runtime_deps.py` reads the wheel's metadata at release
time and `scripts/check_packaging.py` reads the manifest, and between them they still cannot
answer the only question a new user has: does `pip install` produce something that runs.

It did not have an answer until somebody typed the commands by hand, and that is the wrong way
to learn it. What the manual run found was not a broken install — the wheel builds, both entry
points resolve and a scan from an unrelated directory works — but it did find the README's
first line telling a reader to type `/plugin install secaudit` while the walkthrough forty lines
below said `/plugin install secaudit@secaudit-kit`. Check 36 in `check_consistency.py` now holds
those together; this file holds the other half, which is that the thing they install works.

**Offline by construction.** The wheel is built with `--no-build-isolation` and installed with
`--no-index`, so the gate needs no network and cannot be made green or red by a registry. That
is only possible because the package declares zero runtime dependencies — the gate is therefore
also a second, independent statement of that claim: if a dependency ever appears, this install
fails outright rather than quietly resolving it.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KIT = os.path.join(REPO, "kit")

# A file that must produce a finding, and one that must not. Both are written here rather than
# pointed at a fixture in the tree: the point of this gate is to run the installed package
# against a directory that has nothing to do with this repository.
PROBE_VULNERABLE = """\
import sqlite3
from flask import Flask, request
app = Flask(__name__)

@app.route("/u")
def lookup():
    name = request.args.get("name")
    con = sqlite3.connect("app.db")
    return con.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall()
"""
PROBE_CLEAN = """\
def add(a, b):
    return a + b
"""


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    """Run a command in an environment that cannot reach this checkout.

    `run_checks.py` puts `kit/` on `PYTHONPATH` for every gate it launches, which is right for
    the gates that import the package under test and catastrophic for this one: the child
    virtualenv would import `secaudit_core` from the repository and the gate would pass while
    proving nothing about the wheel. It did exactly that — the standalone run was green and the
    same gate failed under `run_checks.py`, which is the useful direction for that discrepancy to
    point. `VIRTUAL_ENV` and `PYTHONHOME` go with it for the same reason.
    """
    env = {k: v for k, v in os.environ.items()
           if k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV")}
    env["PYTHONUTF8"] = "1"
    return subprocess.run(cmd, capture_output=True, text=True, env=env, **kw)


def venv_python(root: str) -> str:
    for rel in (os.path.join("Scripts", "python.exe"), os.path.join("bin", "python")):
        path = os.path.join(root, rel)
        if os.path.exists(path):
            return path
    raise FileNotFoundError(f"no interpreter in the virtualenv at {root}")


def venv_script(root: str, name: str) -> str:
    for rel in (os.path.join("Scripts", name + ".exe"), os.path.join("bin", name)):
        path = os.path.join(root, rel)
        if os.path.exists(path):
            return path
    return ""


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    # `--no-build-isolation` uses the ambient setuptools instead of downloading one. Without it
    # the gate needs a registry, and a gate that needs a registry is one that goes red for
    # reasons that have nothing to do with this package.
    probe = run([sys.executable, "-c", "import setuptools, wheel"])
    if probe.returncode != 0:
        print("SKIP  install gate — setuptools/wheel are not importable in this interpreter, "
              "so the wheel cannot be built without downloading a build environment. "
              "`pip install setuptools wheel` to run it.")
        return 0

    fails: list[str] = []
    work = tempfile.mkdtemp(prefix="secaudit-install-")
    # `--no-build-isolation` runs setuptools in place, and setuptools writes `kit/build/` and an
    # egg-info directory next to the source. A gate that leaves untracked directories in the
    # working tree is a gate that shows up in the next `git status` as if somebody had done it
    # by hand — and on the first run of this one, it did.
    litter = [os.path.join(KIT, "build"), os.path.join(KIT, "secaudit_kit.egg-info")]
    pre_existing = {path for path in litter if os.path.exists(path)}
    try:
        wheelhouse = os.path.join(work, "wheelhouse")
        built = run([sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
                     "--wheel-dir", wheelhouse, KIT])
        if built.returncode != 0:
            print("FAIL  install gate — the wheel did not build:")
            print(built.stdout[-2000:] or built.stderr[-2000:])
            return 1
        wheels = [f for f in os.listdir(wheelhouse) if f.endswith(".whl")]
        if len(wheels) != 1:
            print(f"FAIL  install gate — expected exactly one wheel, built {wheels}")
            return 1
        wheel = os.path.join(wheelhouse, wheels[0])

        env_dir = os.path.join(work, "venv")
        made = run([sys.executable, "-m", "venv", env_dir])
        if made.returncode != 0:
            print("FAIL  install gate — could not create a virtualenv:")
            print(made.stderr[-2000:])
            return 1
        py = venv_python(env_dir)

        # `--no-index`: nothing may be fetched. A package with zero runtime dependencies must
        # install from one local file and nothing else, and this is where that gets proven.
        installed = run([py, "-m", "pip", "install", "--no-index", wheel])
        if installed.returncode != 0:
            fails.append("`pip install --no-index <wheel>` failed, which means the package "
                         "needs something from a registry:\n" + installed.stdout[-1500:])
            print("FAIL  install gate")
            print("\n".join("  - " + f for f in fails))
            return 1

        target = os.path.join(work, "project", "src")
        os.makedirs(target)
        with open(os.path.join(target, "app.py"), "w", encoding="utf-8") as fh:
            fh.write(PROBE_VULNERABLE)
        with open(os.path.join(target, "util.py"), "w", encoding="utf-8") as fh:
            fh.write(PROBE_CLEAN)
        project = os.path.dirname(target)

        # 1. The console script the README tells people to type.
        cli = venv_script(env_dir, "secaudit")
        if not cli:
            fails.append("the `secaudit` console script is not on the virtualenv's PATH, so "
                         "`pip install secaudit-kit && secaudit .` — the README's second line "
                         "— does not work")
        else:
            version = run([cli, "--version"], cwd=project)
            if version.returncode != 0 or not version.stdout.strip().startswith("secaudit "):
                fails.append(f"`secaudit --version` exited {version.returncode} printing "
                             f"{version.stdout.strip()!r} — it is the first thing anybody types "
                             f"after installing, and the only way to say which build produced a "
                             f"report")
            scan = run([cli, "."], cwd=project)
            if scan.returncode not in (0, 1):
                fails.append(f"`secaudit .` exited {scan.returncode} on an ordinary "
                             f"directory:\n{scan.stderr[-1000:]}")
            elif "CWE-89" not in scan.stdout:
                fails.append("`secaudit .` did not report the SQL injection in the probe — the "
                             "installed package runs but does not detect:\n"
                             + scan.stdout[-1000:])

        # 2. The module form, which is what every documented CI snippet uses.
        module = run([py, "-m", "secaudit_core.cli", ".", "--format", "json"], cwd=project)
        if module.returncode not in (0, 1) or '"findings"' not in module.stdout:
            fails.append("`python -m secaudit_core.cli . --format json` did not produce a JSON "
                         f"report from the installed package:\n{module.stderr[-1000:]}")

        # 3. The MCP server, which is a separate entry point and a separate way to be broken.
        mcp = run([py, "-m", "secaudit_mcp", "--tools"], cwd=project)
        if mcp.returncode != 0 or '"tools"' not in mcp.stdout:
            fails.append("`python -m secaudit_mcp --tools` did not print a tool manifest from "
                         f"the installed package:\n{mcp.stderr[-1000:]}")

        # 4. Nothing may be imported from the repository. A gate that accidentally reads the
        #    checkout is a gate that would pass on a machine where the wheel ships nothing.
        where = run([py, "-c", "import secaudit_core, os; print(os.path.dirname("
                              "secaudit_core.__file__))"], cwd=project)
        resolved = where.stdout.strip()
        if not resolved:
            fails.append("the installed package could not be imported at all")
        elif os.path.normcase(REPO) in os.path.normcase(resolved):
            fails.append(f"the installed `secaudit_core` resolved to {resolved}, inside this "
                         f"repository — the gate was reading the checkout, not the wheel")
    finally:
        shutil.rmtree(work, ignore_errors=True)
        for path in litter:
            if path not in pre_existing:
                shutil.rmtree(path, ignore_errors=True)

    if fails:
        print("INSTALL GATE FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("INSTALL GATE PASSED — the wheel builds with no build isolation, installs into an "
          "empty virtualenv with no index, and the console script, the module entry point and "
          "the MCP server all run from it against a directory outside this repository.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
