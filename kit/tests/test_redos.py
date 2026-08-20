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


def expect_pattern(pattern: str, catastrophic: bool, label: str, degree: str = "") -> None:
    verdict = redos.backtracking_reason(pattern)
    if bool(verdict) != catastrophic:
        fails.append(f"[{label}] {pattern!r}: expected "
                     f"{'a reason' if catastrophic else 'no reason'}, got {verdict!r}")
    if degree and verdict and verdict[0] != degree:
        fails.append(f"[{label}] {pattern!r}: expected {degree}, got {verdict[0]}")
    # Whatever the verdict, the pattern must be one Python itself accepts — otherwise the test
    # is asserting against a regex nobody could have written.
    try:
        re.compile(pattern)
    except re.error as e:
        fails.append(f"[{label}] {pattern!r} is not a valid regex: {e}")


def test_nested_quantifiers_are_catastrophic() -> None:
    for pattern in (r"((a)+)+", r"(a+)+", r"(a*)*", r"(\w+\s?)*", r"(.*)*", r"(\d+)*",
                    r"^(([a-z])+.)+[A-Z]([a-z])+$"):
        expect_pattern(pattern, True, "nested", "exponential")


def test_overlapping_alternation_under_a_quantifier_is_catastrophic() -> None:
    for pattern in (r"(a|a)+", r"(a|ab)*", r"(foo|foobar)+"):
        expect_pattern(pattern, True, "alternation")


def test_overlapping_adjacent_repeats_are_quadratic() -> None:
    """The polynomial half. Every pattern here is a published ReDoS advisory's own regex, or the
    shape of one: two unbounded repeats whose boundary can slide because their character sets
    overlap. SecBench.js scored the exponential criteria at 8 of 87 labels, and this is what the
    other 79 mostly look like."""
    for pattern in (
        r"^\S+@\S+$",                                   # email-existence: `@` is itself an \S
        r".+\@.+\..+",                                  # is-email: `.` matches everything between
        r"^((?:\d+)?\.?\d+) *(ms|s)?$",                 # ms: an optional integer part
        r"\/\*\s*# sourceMappingURL=(.*)\s*\*\/",       # postcss: `.*` then `\s*`
        r"^hwb\(\s*([+-]?\d*[\.]?\d+)(?:deg)?\s*\)$",   # color-string: `\d*` then `\d+`
        r"^([a-z0-9-]+)[ \t]+([a-zA-Z0-9+\/ \t\n]+[=]*)(.*)$",   # sshpk
    ):
        expect_pattern(pattern, True, "quadratic", "quadratic")


def test_a_pinned_boundary_is_not_quadratic() -> None:
    """The load-bearing negative for the quadratic criterion, and the reason it is not simply
    "two quantifiers in a row" — which describes most regular expressions ever written.

    In each of these the text between the two repeats can only be matched one way, so there is
    exactly one place the boundary can fall and nothing to backtrack through."""
    for pattern in (
        r"\d+\.\d+",            # a version number: `\.` is not a digit
        r"[a-z]+[0-9]*",        # disjoint sets
        r"[^;]+;",              # a single repeat, terminated by what it cannot match
        r"^\w+/\w+$",           # a two-part path
        r"^\s+|\s+$",           # trim: one repeat per branch
    ):
        expect_pattern(pattern, False, "pinned")


def test_ambiguity_with_nothing_to_reject_it_is_not_quadratic() -> None:
    """The second half of the quadratic criterion, and the half that was almost shipped untested.

    Two overlapping repeats are only expensive if something *after* them can refuse the split the
    engine tries first. `^(#{1,6})\\s+(.*)$` can divide its whitespace between `\\s+` and `(.*)`
    in as many ways as there are spaces, and never does, because `.*$` accepts whatever it is
    handed. Without this condition the criterion reported 28 regular expressions in this
    repository's own source and would report a comparable share of any codebase.

    Every case here is ambiguous by the first half of the criterion. None of them can fail."""
    for pattern in (
        r"^(#{1,6})\s+(.*)$",     # a markdown heading: `.*$` cannot reject anything
        r"\d*[.]?\d+",            # ambiguous, and the pattern simply ends
        r"^\s*(.*)$",             # the same shape with the repeats adjacent
    ):
        expect_pattern(pattern, False, "no-failure")


def test_the_two_degrees_are_reported_at_different_severities() -> None:
    """Exponential hangs on a few dozen characters; quadratic needs a large subject. Reporting
    both at High would say those are the same emergency."""
    exponential = redos.analyze_file("app/v.js", "const re = /(a+)+/;\n")
    quadratic = redos.analyze_file("app/v.js", "const re = /^\\S+@\\S+$/;\n")
    check([f.severity.value for f in exponential] == ["High"],
          f"exponential should be High, got {[f.severity.value for f in exponential]}")
    check([f.severity.value for f in quadratic] == ["Medium"],
          f"quadratic should be Medium, got {[f.severity.value for f in quadratic]}")
    check(all(f.cwe == "CWE-1333" for f in exponential + quadratic),
          "both degrees are still CWE-1333")


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
            redos.backtracking_reason(pattern)
        except Exception as e:                                          # noqa: BLE001
            fails.append(f"the parser raised {type(e).__name__} on {pattern!r}")


def test_unparseable_and_unclaimed_files_say_nothing() -> None:
    check(redos.analyze_file("app/v.py", "def broken(:\n") == [],
          "a file that does not parse produced findings")
    # A language with no front end, asserted with a file that would fire if one existed.
    check(redos.analyze_file("app/v.go", "var re = regexp.MustCompile(`((a)+)+`)") == [],
          "a language with no ReDoS front end was analysed anyway")


# ------------------------------------------------------------ JavaScript / TypeScript front end
#
# The Python front end needs a call site; this one does not, and the whole cost of that is the
# ambiguity of `/`. Every negative case below is a slash that must NOT be read as a regex, and
# they are the load-bearing half for the same reason the safe-pattern cases are.

def js(source: str) -> list[int]:
    return [f.line for f in redos.analyze_file("app/v.js", source)]


def test_a_catastrophic_regex_literal_is_reported_where_it_is_written() -> None:
    check(js("const re = /(a+)+$/;\n") == [1],
          "a catastrophic regex literal was not reported")
    check(js("\n\nconst re = /^(?:x|xy)+$/g;\n") == [3],
          "an overlapping alternation in a literal was not reported, or the line was wrong")


def test_a_safe_regex_literal_is_left_alone() -> None:
    check(js("const slug = /^[a-z0-9_-]+$/i;\n") == [],
          "an ordinary regex literal was reported")


def test_division_is_not_read_as_a_regex() -> None:
    for source, label in (
            ("const ratio = total / count / 2;\n", "chained division"),
            ("const x = obj.value / 2;\n", "division after a property"),
            ("const y = (a + b) / (c - d);\n", "division after a closing paren"),
            ("let z = arr[0] / n;\n", "division after a subscript"),
            ("total /= count;\n", "divide-and-assign")):
        found = redos._js_patterns(source)
        check(found == [], f"{label} was read as a regex literal: {found!r}")


def test_regexes_inside_strings_and_comments_are_not_read() -> None:
    for source, label in (
            ('const s = "/(a+)+/";\n', "double-quoted string"),
            ("const s = '/(a+)+/';\n", "single-quoted string"),
            ("const s = `/(a+)+/`;\n", "template literal"),
            ("// /(a+)+/ is the bad one\n", "line comment"),
            ("/* see /(a+)+/ below */\n", "block comment")):
        check(js(source) == [], f"a regex written inside a {label} was analysed")


def test_a_slash_inside_a_character_class_does_not_end_the_literal() -> None:
    # `/[/\\]/` — the first inner slash is class content, not the terminator. Getting this
    # wrong truncates the pattern and changes the verdict on the regex that follows it.
    check(redos._js_patterns("const cls = str.split(/[/\\\\]/);\n") == [(1, "[/\\\\]", "")],
          "a slash inside a character class was treated as the end of the literal")


def test_new_regexp_takes_one_layer_of_escaping_off() -> None:
    # In JavaScript the string "(\\w+\\s?)*" IS the pattern (\w+\s?)* — and "(\d+)+" is the
    # pattern (d+)+, because the string ate the backslash. Both are catastrophic; reading the
    # escaping the other way would report the first as `(\\w...` and never match the parser.
    check(redos._js_patterns('const r = new RegExp("(\\\\w+\\\\s?)*");\n')
          == [(1, "(\\w+\\s?)*", "r")], "new RegExp escaping was not unwound")
    check(js('const r = new RegExp("(\\\\d+)+");\n') == [1],
          "a catastrophic pattern passed to new RegExp was not reported")


def test_typescript_is_read_too() -> None:
    check([f.line for f in redos.analyze_file("app/v.ts", "const re: RegExp = /(a+)+/;\n")] == [1],
          "a TypeScript file was not analysed")


def test_a_constant_pattern_is_reported_where_it_is_run() -> None:
    """The mirror of `test_findings_are_produced_at_the_call_site`, which asserted this for
    Python from the day the module was written. A JavaScript pattern is a regex where it is
    declared, so this front end used to report only that line — and in this corpus the
    declaration and the match are routinely a hundred lines apart, which leaves the reader to
    find the exposure themselves."""
    source = (
        "const TOKEN_RE = /^\\S+@\\S+$/;\n"
        "function parse(input) {\n"
        "  return TOKEN_RE.test(input);\n"
        "}\n"
        "const other = input.replace(TOKEN_RE, '');\n"
    )
    check(js(source) == [1, 3, 5],
          f"expected the declaration and both call sites, got {js(source)}")


def test_a_use_site_needs_the_pattern_to_actually_run() -> None:
    """A name is not a match. Mentioning the constant — exporting it, passing it on, testing it
    for null — is not where a subject meets the pattern, and reporting those lines would turn one
    defect into as many findings as the file has references to it."""
    source = (
        "const TOKEN_RE = /^\\S+@\\S+$/;\n"
        "if (!TOKEN_RE) throw new Error('missing');\n"
        "module.exports = { TOKEN_RE };\n"
    )
    check(js(source) == [1], f"a mention was reported as a use site: {js(source)}")


def test_a_safe_constant_has_no_use_sites_reported() -> None:
    check(js("const SLUG = /^[a-z0-9-]+$/;\nconst ok = SLUG.test(name);\n") == [],
          "an ordinary pattern's call site was reported")


def test_the_javascript_front_end_reports_its_own_detector_id() -> None:
    ids = {f.detector_id for f in redos.analyze_file("app/v.js", "const re = /(a+)+/;\n")}
    check(ids == {"REDOS-JS"}, f"expected REDOS-JS, got {ids!r}")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    test_nested_quantifiers_are_catastrophic()
    test_overlapping_alternation_under_a_quantifier_is_catastrophic()
    test_overlapping_adjacent_repeats_are_quadratic()
    test_a_pinned_boundary_is_not_quadratic()
    test_ambiguity_with_nothing_to_reject_it_is_not_quadratic()
    test_the_two_degrees_are_reported_at_different_severities()
    test_ordinary_regexes_are_left_alone()
    test_a_bounded_repeat_is_not_catastrophic()
    test_findings_are_produced_at_the_call_site()
    test_a_safe_pattern_produces_nothing()
    test_runtime_built_patterns_are_not_guessed_at()
    test_malformed_patterns_do_not_crash_the_parser()
    test_unparseable_and_unclaimed_files_say_nothing()
    test_a_catastrophic_regex_literal_is_reported_where_it_is_written()
    test_a_safe_regex_literal_is_left_alone()
    test_division_is_not_read_as_a_regex()
    test_regexes_inside_strings_and_comments_are_not_read()
    test_a_slash_inside_a_character_class_does_not_end_the_literal()
    test_new_regexp_takes_one_layer_of_escaping_off()
    test_typescript_is_read_too()
    test_a_constant_pattern_is_reported_where_it_is_run()
    test_a_use_site_needs_the_pattern_to_actually_run()
    test_a_safe_constant_has_no_use_sites_reported()
    test_the_javascript_front_end_reports_its_own_detector_id()

    if fails:
        print("REDOS TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("REDOS TESTS PASSED — star height, alternation overlap and adjacent-repeat ambiguity "
          "asserted in both directions, with ordinary project regexes and pinned boundaries held "
          "silent, use sites reported only where a subject actually meets the pattern, and a "
          "malformed-pattern fuzz over the parser.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
