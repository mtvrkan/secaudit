#!/usr/bin/env python3
"""The package manifest must parse, resolve its entry points, and declare no runtime dependency.

    python3 scripts/check_packaging.py

This was an inline heredoc in `.github/workflows/validate.yml`. It moved here for the reason
every other check moved here: a gate written inside a workflow cannot be run locally, so the
only way to find out it fails is to push. It is also the half of the zero-dependency claim that
`scripts/assert_no_runtime_deps.py` does not cover — that one reads a built wheel and runs at
release, this one reads the source manifest and runs on every change.

Both are needed. A dependency added to `kit/pyproject.toml` should fail the pull request that
adds it, not the release three weeks later.
"""
from __future__ import annotations

import importlib
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(REPO, "kit", "pyproject.toml")


def _load(path: str) -> dict:
    # `tomllib` is 3.11+; the package floor is 3.9. CI runs a modern interpreter, and this gate
    # asking for one is fine — but it must say so rather than crash with an ImportError that
    # reads like the manifest is broken.
    try:
        import tomllib
    except ModuleNotFoundError:
        print("SKIP — this check needs tomllib (Python 3.11+); the interpreter running it "
              f"is {sys.version.split()[0]}.")
        raise SystemExit(0) from None
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def main() -> int:
    data = _load(MANIFEST)
    project = data["project"]
    fails: list[str] = []

    if project.get("dependencies") != []:
        fails.append(f"kit must stay zero-runtime-dep; manifest declares "
                     f"{project.get('dependencies')!r}")

    sys.path.insert(0, os.path.join(REPO, "kit"))
    for name, target in sorted(project.get("scripts", {}).items()):
        module_name, _, attribute = target.partition(":")
        try:
            module = importlib.import_module(module_name)
        except ImportError as e:
            fails.append(f"console script `{name}` points at `{target}`, which does not "
                         f"import: {e}")
            continue
        if not hasattr(module, attribute):
            fails.append(f"console script `{name}` points at `{target}`, but "
                         f"`{module_name}` has no `{attribute}`")

    # Every importable subpackage must be listed. `packages` is an explicit list, not `find:`,
    # so a new subdirectory with an `__init__.py` is simply absent from the wheel — the
    # installed package then fails at the import that needs it, while every test in a source
    # checkout passes, because a checkout has the directory whether the manifest mentions it or
    # not. This fired for real when `taint.py` became `taint/`.
    declared = set(data.get("tool", {}).get("setuptools", {}).get("packages", []))
    root = os.path.join(REPO, "kit")
    on_disk = set()
    for top in sorted(declared):
        base = os.path.join(root, *top.split("."))
        if not os.path.isdir(base):
            fails.append(f"manifest lists package `{top}`, which is not a directory under kit/")
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            if "__init__.py" in filenames:
                on_disk.add(os.path.relpath(dirpath, root).replace(os.sep, "."))
    for missing in sorted(on_disk - declared):
        fails.append(f"`{missing}` is an importable package on disk but is not in "
                     f"`[tool.setuptools] packages` — it would be missing from the wheel")

    # The locale bundles are data the renderer reads at runtime. Without a package-data entry
    # they exist in a checkout and not in the wheel, and `--lang tr` renders English on every
    # installed copy — indistinguishable from a translation nobody wrote.
    package_data = data.get("tool", {}).get("setuptools", {}).get("package-data", {})
    if "locales/*.json" not in package_data.get("secaudit_core", []):
        fails.append("secaudit_core package-data no longer ships `locales/*.json` — an "
                     "installed copy would silently render English for every --lang")

    if fails:
        print("PACKAGING CHECK FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    entry_points = ", ".join(sorted(project.get("scripts", {})))
    print(f"Packaging OK — manifest parses, zero runtime deps, entry points resolve "
          f"({entry_points}), locale bundles ship.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
