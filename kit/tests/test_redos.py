#!/usr/bin/env python3
"""ReDoS analysis tests — the structural criteria, and the regexes that must stay quiet.

A ReDoS rule earns its place by what it does NOT report. Every real codebase is full of
regular expressions, so a criterion that fires on ordinary ones would bury the report; the
negative cases below are therefore the load-bearing half of this file. The bounded-quantifier
and disjoint-alternation cases in particular are the two that separate a structural criterion
from "contains a plus sign".
"""
from __future__ import annotations

import os
import re
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KIT)

from secaudit_core import redos                              # noqa: E402

fails: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        fails.append(message)


def expect_pattern(pattern: str, catastrophic: bool, label: str) -> None:
    reason = redos.catastrophic_reason(pattern)
    if bool(reason) != catastrophic:
        fails.append(f"[{label}] {pattern!r}: expected "
                     f"{'a reason' if catastrophic else 'no reason'}, got {reason!r}")
    # Whatever the verdict, the pattern must be one Python itself accepts — otherwise the test
    # is asserting against a regex nobody could have written.
    try:
        re.compile(pattern)
    except re.error as e:
        fails.append(f"[{label}] {pattern!r} is not a valid regex: {e}")


def test_nested_quantifiers_are_catastrophic() -> None:
    for pattern in (r"((a)+)+", r"(a+)+", r"(a*)*", r"(\w+\s?)*", r"(.*)*", r"(\d+)*",
                    r"^(([a-z])+.)+[A-Z]([a-z])+$"):
        expect_pattern(pattern, True, "nested")


def test_overlapping_alternation_under_a_quantifier_is_catastrophic() -> None:
    for pattern in (r"(a|a)+", r"(a|ab)*", r"(foo|foobar)+"):
        expect_pattern(pattern, True, "alternation")


def test_ordinary_regexes_are_left_alone() -> None:
    """The precision half. Every one of these is a pattern a normal project ships."""
    for pattern in (
        r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$",     # an email check
        r"^\d{4}-\d{2}-\d{2}$",                          # a date
        r"https?://[^\s]+",                              # a URL
        r"^[A-Za-z_][A-Za-z0-9_]*$",                     # an identifier
        r"\b(GET|POST|PUT|DELETE)\b",                    # disjoint alternation
        r"[0-9a-f]{40}",                                 # a git sha
        r"^\s*#",                                        # a comment line
    ):
        expect_pattern(pattern, False, "ordinary")


def test_a_bounded_repeat_is_not_catastrophic() -> None:
    """`{2,5}` bounds the work. Treating every `{` as unbounded would report half of everything."""
    expect_pattern(r"(a+){2,5}", False, "bounded")
    expect_pattern(r"(a+){2,}", True, "unbounded-lower-only")


def test_findings_are_produced_at_the_call_site() -> None:
    """The pattern is usually a module constant and the call is elsewhere — the finding has to
    land where the regex is *run*, because that is the line an operator can reason about."""
    code = (
        'import re\n'
        'PATTERN = r"((a)+)+"\n'
        '\n'
        'def check(user_input):\n'
        '    return re.search(PATTERN, user_input)\n'
    )
    findings = redos.analyze_file("app/validate.py", code)
    check(len(findings) == 1, f"expected one finding for a constant-bound pattern, got {len(findings)}")
    if findings:
        f = findings[0]
        check(f.line == 5, f"finding landed on line {f.line}, expected the call on line 5")
        check(f.cwe == "CWE-1333", f"wrong CWE {f.cwe} — the label set accepts CWE-1333")
        check("re.search" in f.evidence, f"evidence does not show the call: {f.evidence!r}")


def test_a_safe_pattern_produces_nothing() -> None:
    code = 'import re\nEMAIL = r"^[a-z]+@[a-z]+\\.[a-z]{2,4}$"\nre.match(EMAIL, x)\n'
    check(redos.analyze_file("app/v.py", code) == [], "an ordinary email regex was reported")


def test_runtime_built_patterns_are_not_guessed_at() -> None:
    """A pattern this analysis cannot read is one it says nothing about — not one it assumes
    is safe, and not one it assumes is dangerous. `limitations()` states this."""
    code = 'import re\ndef f(part):\n    return re.compile("(" + part + "+)+")\n'
    check(redos.analyze_file("app/v.py", code) == [], "a runtime-built pattern was judged")
    check(any("runtime" in line for line in redos.limitations()),
          "limitations do not disclose that runtime-built patterns are unanalysed")


def test_malformed_patterns_do_not_crash_the_parser() -> None:
    for pattern in ("(", ")", "[", "a{", "(?P<", "\\", "((((((((((a", "(?:", "[]"):
        try:
            redos.catastrophic_reason(pattern)
        except Exception as e:                                          # noqa: BLE001
            fails.append(f"the parser raised {type(e).__name__} on {pattern!r}")


def test_unparseable_and_non_python_files_say_nothing() -> None:
    check(redos.analyze_file("app/v.py", "def broken(:\n") == [],
          "a file that does not parse produced findings")
    check(redos.analyze_file("app/v.js", "re.search(/((a)+)+/, x)") == [],
          "a non-Python file was analysed")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    test_nested_quantifiers_are_catastrophic()
    test_overlapping_alternation_under_a_quantifier_is_catastrophic()
    test_ordinary_regexes_are_left_alone()
    test_a_bounded_repeat_is_not_catastrophic()
    test_findings_are_produced_at_the_call_site()
    test_a_safe_pattern_produces_nothing()
    test_runtime_built_patterns_are_not_guessed_at()
    test_malformed_patterns_do_not_crash_the_parser()
    test_unparseable_and_non_python_files_say_nothing()

    if fails:
        print("REDOS TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("REDOS TESTS PASSED — star height and alternation overlap asserted in both "
          "directions, with ordinary project regexes held silent and a malformed-pattern "
          "fuzz over the parser.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
