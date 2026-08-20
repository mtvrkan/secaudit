#!/usr/bin/env python3
"""Fail if a built wheel declares any runtime dependency.

    python3 scripts/assert_no_runtime_deps.py dist/

"Zero runtime dependencies" is the load-bearing claim of this package: it is why it installs
into an air-gapped environment, why it cannot be the weak link in your supply chain, and half
the reason to choose it over a scanner that pulls in forty transitive packages. A claim like
that decays through a single careless `install_requires`, and the people who would discover it
are users, at install time, on a machine that has no network.

Checked against the *built artefact* rather than `pyproject.toml`, because the artefact is what
gets installed: a build backend, a plugin, or a `setup.py` shim can add requirements that never
appear in the source manifest.
"""
from __future__ import annotations

import glob
import os
import sys
import zipfile


def dependencies(wheel: str) -> list[str]:
    with zipfile.ZipFile(wheel) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        text = archive.read(name).decode("utf-8", "replace")
    # `Requires-Dist: x; extra == "dev"` is an optional extra, not something a plain install
    # pulls in. Counting those would make the check fire on a legitimate dev extra and get it
    # switched off, which costs more than the narrow case it would catch.
    return [line.split(":", 1)[1].strip() for line in text.splitlines()
            if line.startswith("Requires-Dist:") and "extra ==" not in line]


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    where = argv[0] if argv else "dist"
    wheels = sorted(glob.glob(os.path.join(where, "*.whl")))
    if not wheels:
        print(f"FAIL — no wheel found in {where}/. Build one first: python3 -m build kit")
        return 1

    failed = False
    for wheel in wheels:
        found = dependencies(wheel)
        if found:
            print(f"FAIL — {os.path.basename(wheel)} declares runtime dependencies:")
            print("\n".join("  - " + d for d in found))
            print("The zero-dependency invariant is why this installs anywhere. Move the "
                  "requirement behind an optional extra, or vendor it.")
            failed = True
        else:
            print(f"OK — {os.path.basename(wheel)} declares no runtime dependencies.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
