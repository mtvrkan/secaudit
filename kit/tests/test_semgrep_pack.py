"""The exported Semgrep pack must find exactly what the detectors it came from find.

A rule pack is a claim about behaviour, and "I translated it and it looked right" is not a
check. Semgrep is not installed in this suite (and adding it would put a heavyweight dependency
in the path of every contributor), so this does not test Semgrep — it tests the part that is
ours: that each exported pattern, applied to the shipped fixtures, produces the identical set of
`(file, line, span)` hits as the detector it was generated from. Spans rather than lines alone,
because a translation that shifts where a match begins and ends is a different rule even when
it lands on the same line.

The bound on that, stated because it is easy to read more into a green run than is there: this
compares behaviour **on the shipped fixtures**, so it catches a translation error the corpus
exercises, not every conceivable one. A regex widened in a way the fixtures do not distinguish
(`{16}` to `{4,}` against a key of exactly 16 characters, matched greedily) produces identical
spans and passes here. What makes that unshippable is the separate byte-for-byte staleness
check against the generator: the pack is generated, so any divergence from what the detectors
currently produce fails regardless of whether a fixture would notice.

That leaves exactly one thing unverified here — whether Semgrep accepts the YAML envelope —
and that is checked in CI by running `semgrep --validate` against the pack. The split is
deliberate: the semantics are verified everywhere, the schema where the tool exists.
"""
from __future__ import annotations

import os
import re
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(KIT)
sys.path.insert(0, KIT)
sys.path.insert(0, os.path.join(REPO, "scripts"))

from secaudit_core.detectors import DETECTORS                            # noqa: E402
from secaudit_core import taint                                          # noqa: E402
import gen_semgrep_pack as pack                                          # noqa: E402

RULES = os.path.join(REPO, "rules", "secaudit")
CORPORA = [os.path.join(REPO, "tests", "fixtures", "vulnerable-app"),
           os.path.join(REPO, "tests", "fixtures", "secure-app")]

fails: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        fails.append(message)


def parsed_rules() -> dict[str, dict]:
    """{secaudit id: {regex, severity, paths}} read back off disk.

    Line-oriented rather than via PyYAML: this repository's suite runs with the standard
    library only, the same invariant the package itself keeps. It reads what was written, so a
    generator that emits an unreadable shape fails here rather than in someone's CI.
    """
    out: dict[str, dict] = {}
    for name in sorted(os.listdir(RULES)):
        if not name.endswith(".yaml"):
            continue
        current: dict | None = None
        in_paths = False
        with open(os.path.join(RULES, name), encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("- id: secaudit."):
                    current = {"regex": "", "severity": "", "paths": [], "file": name}
                    in_paths = False
                elif current is None:
                    continue
                elif stripped.startswith("- pattern-regex: "):
                    current["regex"] = _unquote(stripped[len("- pattern-regex: "):])
                elif stripped.startswith("severity: "):
                    current["severity"] = stripped[len("severity: "):]
                elif stripped == "include:":
                    in_paths = True
                elif in_paths and stripped.startswith("- "):
                    current["paths"].append(_unquote(stripped[2:]))
                elif stripped.startswith("secaudit-id: "):
                    in_paths = False
                    out[_unquote(stripped[len("secaudit-id: "):])] = current
    return out


def _unquote(value: str) -> str:
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    return value


def _files() -> list[tuple[str, str]]:
    found = []
    for corpus in CORPORA:
        for root, dirs, names in os.walk(corpus):
            dirs[:] = [d for d in dirs if d != "node_modules"]
            for name in names:
                path = os.path.join(root, name)
                try:
                    with open(path, encoding="utf-8", errors="ignore") as f:
                        found.append((os.path.relpath(path, REPO).replace("\\", "/"), f.read()))
                except OSError:
                    pass
    return sorted(found)


def _applies(globs: list[str], filename: str) -> bool:
    base = os.path.basename(filename)
    ext = os.path.splitext(base)[1].lower()
    return any(g == base or (g.startswith("*.") and g[1:].lower() == ext) for g in globs)


def _hits(pattern: re.Pattern, globs: list[str], corpus: list) -> set:
    out = set()
    for name, text in corpus:
        if not _applies(globs, name):
            continue
        for match in pattern.finditer(text):
            out.add((name, text[:match.start()].count("\n") + 1, match.start(), match.end()))
    return out


def test_every_exportable_detector_is_exported() -> None:
    expected = {d.id for d in DETECTORS if not pack.withheld_reason(d)}
    actual = set(parsed_rules())
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    check(not missing, f"detectors that should be exported but are not in the pack: {missing}")
    check(not extra,
          f"rules in the pack with no matching exportable detector: {extra} — a withheld "
          f"detector that leaks into the pack ships a rule we said we would not ship")


def test_withheld_detectors_stay_withheld() -> None:
    """The reason each one is held back is a property of the detector, so a detector that
    changes shape should change side — and be noticed, not silently exported."""
    exported = set(parsed_rules())
    for d in DETECTORS:
        reason = pack.withheld_reason(d)
        if reason and d.id in exported:
            check(False, f"{d.id} is exported but cannot be reproduced faithfully: {reason}")


def test_exported_patterns_match_identically() -> None:
    """pytest's view of the comparison below. The count it returns is for `main`'s summary
    line; a test function that returns a value is one pytest cannot read a verdict from.

    It asserts rather than only calling: without this the function was collected by pytest,
    reported as passed, and could not go red whatever the comparison found — the failures land
    in `fails`, which only `main` reads. That is the same vacuous-pytest shape this repository
    fixed once already, left behind in the wrapper that exists to prevent it."""
    before = len(fails)
    compare_exported_patterns()
    assert fails[before:] == [], "\n".join(fails[before:])


def compare_exported_patterns() -> int:
    """The claim the pack makes: same regex, same hits. Checked, not asserted."""
    corpus = _files()
    check(len(corpus) > 5, f"the fixture corpus is too small to be evidence ({len(corpus)} files)")

    rules = parsed_rules()
    by_id = {d.id: d for d in DETECTORS}
    compared = 0

    for detector_id, rule in sorted(rules.items()):
        detector = by_id[detector_id]

        try:
            exported = re.compile(rule["regex"])
        except re.error as e:
            check(False, f"{detector_id}: the exported regex does not compile: {e}")
            continue

        # The detector's own view of each file — code-shape rules would use the blanked view,
        # but none of those are exported, so this is the raw text for every rule here.
        native_hits = set()
        for name, text in corpus:
            if not _applies(rule["paths"], name):
                continue
            scanned = text if detector.literal else (taint.code_view(text, name) or text)
            for match in detector.regex().finditer(scanned):
                native_hits.add((name, scanned[:match.start()].count("\n") + 1,
                                 match.start(), match.end()))

        exported_hits = _hits(exported, rule["paths"], corpus)

        if native_hits != exported_hits:
            only_native = sorted(native_hits - exported_hits)
            only_exported = sorted(exported_hits - native_hits)
            check(False,
                  f"{detector_id}: the exported rule and the detector disagree. "
                  f"Only the detector finds {only_native or 'nothing'}; "
                  f"only the exported rule finds {only_exported or 'nothing'}")
        compared += 1

    check(compared > 0, "no rules were compared — the pack parsed as empty")
    return compared


def test_flags_survive_the_translation() -> None:
    """A dropped `(?i)` silently narrows a rule; a wrongly added one silently widens a
    case-sensitive secret pattern into false positives. Both are invisible in a diff."""
    rules = parsed_rules()
    by_id = {d.id: d for d in DETECTORS}
    for detector_id, rule in rules.items():
        detector = by_id[detector_id]
        wanted = "(?m)" if detector.case_sensitive else "(?im)"
        check(rule["regex"].startswith(wanted),
              f"{detector_id}: expected the exported pattern to start with {wanted} "
              f"(case_sensitive={detector.case_sensitive}), got {rule['regex'][:8]!r}")


def test_generator_check_mode_agrees_with_disk() -> None:
    check(pack.main(["--check"]) == 0,
          "the committed pack is stale — run: python3 scripts/gen_semgrep_pack.py")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    if not os.path.isdir(RULES):
        print("SEMGREP PACK TESTS FAILED: rules/secaudit/ does not exist. "
              "Run: python3 scripts/gen_semgrep_pack.py")
        return 1

    test_every_exportable_detector_is_exported()
    test_withheld_detectors_stay_withheld()
    compared = compare_exported_patterns()
    test_flags_survive_the_translation()
    test_generator_check_mode_agrees_with_disk()

    if fails:
        print("SEMGREP PACK TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    withheld = sum(1 for d in DETECTORS if pack.withheld_reason(d))
    print(f"SEMGREP PACK TESTS PASSED — {compared} exported rule(s) produce the identical "
          f"(file, line, span) hits as their detectors on the fixtures; {withheld} detector(s) "
          f"correctly withheld; flags preserved; committed pack is current.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
