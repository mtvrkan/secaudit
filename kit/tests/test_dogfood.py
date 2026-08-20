#!/usr/bin/env python3
"""Real-code precision signal: run the engine on the kit's OWN production source — a real
~8.5k-line Python codebase, not a tuned fixture — and hold it to what it actually achieves.

This is the honest complement to the fixture numbers: those measure recall against planted
sinks, this measures false positives against real, non-planted code.

It used to gate on High/Critical only, while its own docstring said "require it to stay quiet".
It was not quiet — thirteen Medium findings sat under that gate and could have become thirty
without a single build going red. Three gates now, in increasing order of what they permit:

  1. **No High/Critical severity.** Unchanged; this is the original contract.
  2. **No HIGH-confidence finding.** On this engine, HIGH confidence on a taint path means the
     path is rooted in a *framework request* rather than in a function parameter — untrusted by
     construction rather than untrusted only if some caller made it so. There is no request in
     this codebase: it is a CLI and a library. So a HIGH-confidence finding here is not a
     debatable lead, it is the analysis having invented a source, and it fails the build at any
     severity.
  3. **A per-detector ceiling on everything else, pinned to the measured count.** Set to what is
     measured, never to a round number above it — the same rule `pyproject.toml` states for the
     coverage floor and `eval/thresholds.json` for the detection floors, for the same reason: a
     ceiling above what is measured is permission to regress silently.

The thirteen are all parameter-rooted paths into `open()` and `urlopen()` — a tool that opens
the file and fetches the feed it was asked to. The analysis reports them at MEDIUM precisely
because whether a parameter is untrusted is caller knowledge it does not have (see
`taint/__init__.py`, "Function parameters are a weak source"). They are false positives on this
codebase and they are not a bug in the tier; what would be a bug is more of them appearing
without anyone noticing, which is what the ceiling is for.

Lowering an entry when a detector is narrowed is the good direction and needs no ceremony.
Raising one needs a written reason in the pull request, because that edit is the visible part.
"""
from __future__ import annotations

import os
import sys
from collections import Counter

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KIT)

from secaudit_core import engine                         # noqa: E402
from secaudit_core.schema import Severity, Confidence    # noqa: E402

SRC = os.path.join(KIT, "secaudit_core")

# detector id -> (ceiling, why these are false positives on this codebase)
# Measured 2026-08-14 over kit/secaudit_core.
CEILING: dict[str, tuple[int, str]] = {
    # 11 → 12 on 2026-08-16: `engine._published_build_dirs` reads `package.json` out of a
    # directory `os.walk` produced, which is the identical shape to `sbom.py:106` already inside
    # this count — a constant filename joined to a directory the operator pointed the tool at.
    # Raised rather than narrowed, and the distinction matters: the previous time this gate fired
    # the rule was matching its own definition, which is a rule bug and was fixed by narrowing.
    # This one is the rule working correctly on the shape the ceiling exists to excuse. Narrowing
    # "the last component is a literal" out of path traversal would be wrong in general —
    # `open(os.path.join(tainted_dir, "index.html"))` in a web app is still the attacker choosing
    # the directory.
    # Raised 12 -> 13 on 2026-08-18 for `engine._is_own_release`, which joins "package.json" to
    # a directory walked up from a path it was handed. That is the same shape as
    # `_published_build_dirs` two functions below it, already inside this count: a constant
    # filename joined to a directory the operator pointed the tool at. A second manifest reader
    # is not a new risk, and narrowing the rule so it stops seeing either would be wrong in
    # general — `open(os.path.join(tainted_dir, "index.html"))` in a web application is still the
    # attacker choosing the directory.
    "TAINT-PY-PATH": (13, "a scanner opens the paths it is handed — argv, a config path, a "
                          "walked file; every one is parameter-rooted, none is request-rooted"),
    "TAINT-PY-SSRF": (2, "the two feed fetchers (KEV/EPSS enrichment and the LLM backend), "
                         "each reaching urlopen with a URL its own caller chose"),
    # 0 -> 1 on 2026-08-19, and this is the oldest joke in the repository told once more: the
    # rule that reports a login answering "no such account" and "wrong password" differently now
    # fires on `structural/js.py`, which is the file that DESCRIBES those two messages in order
    # to find them. Every string it matched is a fix sentence or a vocabulary constant of the
    # JavaScript port of the same rule. Raised rather than narrowed for the reason the path
    # ceiling above gives: the rule is working, on a file whose subject happens to be itself.
    "ENUM-PY-RESPONSE": (1, "the JavaScript port of the account-enumeration rule, whose fix "
                            "text and vocabulary lists are the two messages it looks for"),
    # The REDOS-PY ceiling of 13 that used to live here is GONE, and the reason it is worth a
    # comment is that it is the outcome a ceiling is supposed to have. Thirteen of this engine's
    # own JS/TS matchers were genuinely quadratic — found by its own new criterion, on the day
    # that criterion landed — and were capped rather than excused, with the rewrite scheduled in
    # `.claude/TECH-DEBT.md`. All thirteen are now linear. Each rewrite was checked
    # match-for-match against 7 MB of real JavaScript before it landed, because the whole risk of
    # touching a matcher inside the measured path is changing what it matches; the language is
    # identical and the published figures were re-measured anyway, since the engine digest moved.
}


def main() -> int:
    res = engine.scan(SRC, run_deps=False, use_scanners=False)
    rel = os.path.relpath(SRC, os.path.dirname(KIT))

    high_sev = [f for f in res.findings if f.severity.rank >= Severity.HIGH.rank]
    high_conf = [f for f in res.findings if f.confidence == Confidence.HIGH]
    counts = Counter(f.detector_id for f in res.findings)

    print(f"Dogfood scan of real production code ({rel}): {len(res.findings)} finding(s), "
          f"{len(high_sev)} High/Critical, {len(high_conf)} HIGH-confidence.")
    for det, n in sorted(counts.items()):
        cap = CEILING.get(det, (0, ""))[0]
        print(f"  {det}: {n} (ceiling {cap})")

    fails: list[str] = []
    for f in high_sev:
        fails.append(f"High/Critical on own source: [{f.severity.value}] {f.detector_id} "
                     f"{f.file}:{f.line} — {f.evidence[:80]}")
    for f in high_conf:
        fails.append(f"HIGH-confidence on own source (a request-rooted path in a codebase with "
                     f"no requests): {f.detector_id} {f.file}:{f.line} — {f.evidence[:80]}")
    for det, n in sorted(counts.items()):
        if det not in CEILING:
            fails.append(f"{det} fires {n}x on own source and has no entry in CEILING — add one "
                         f"with the reason it is a false positive here, or narrow the detector")
        elif n > CEILING[det][0]:
            fails.append(f"{det} fires {n}x on own source, ceiling is {CEILING[det][0]} — "
                         f"a precision regression; narrow the detector or justify the raise")

    if fails:
        print("\nDOGFOOD FAILED:")
        for line in fails:
            print(f"  - {line}")
        return 1

    total_cap = sum(c for c, _ in CEILING.values())
    print(f"DOGFOOD PASSED — 0 High/Critical, 0 HIGH-confidence, "
          f"{len(res.findings)}/{total_cap} against the pinned ceiling.")
    return 0


def test_dogfood() -> None:
    """pytest bridge — see conftest.py; the suite's verdict is main()'s exit code."""
    assert main() == 0


if __name__ == "__main__":
    sys.exit(main())
