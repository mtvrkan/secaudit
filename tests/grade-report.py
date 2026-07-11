#!/usr/bin/env python3
"""SecAudit report grader — score a produced audit report against the golden set.

`selftest.py` proves the *fixture* still contains every planted sink. This script
proves an *audit report* actually surfaced them: it reads the golden set from
`expected-findings.md` (the single source of truth — no second copy to drift) and
checks, for each planted finding V1–V20, whether the report cites it — by its CWE
id or by a distinctive location token (a route / function name unique to that one
finding). It also checks the dependency and secret sections are populated.

Two ways to use it:

  * CI regression gate on the committed reference report — fails if anyone edits
    the report and drops a finding below full coverage:
      python3 tests/grade-report.py examples/self-test-report.md --min 20

  * Grade a fresh run you saved after auditing the fixture:
      /secaudit-code tests/fixtures/vulnerable-app     (save the report to a file)
      python3 tests/grade-report.py my-report.md

Matching is intentionally lenient on *format* (a real report needn't use "V1"
labels) but strict on *substance*: a finding counts as covered only if its CWE or
a signal token unique to it appears. Exit 0 = coverage >= --min (default 16) and
the dependency + secret sections are populated; non-zero = a regression, with the
misses listed so you can see exactly what the report failed to surface.
"""
from __future__ import annotations
import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(ROOT, "expected-findings.md")

# A markdown data row for a planted finding, e.g. "| V1 | SQL injection | A05 / CWE-89 | ... |"
ROW_RE = re.compile(r"^\|\s*(V\d+)\s*\|(.+)$")
# A CWE reference, tolerating a non-breaking hyphen and grouped lists like "CWE-502/94".
CWE_GROUP_RE = re.compile(r"CWE[-\s]?([\d/,]+)", re.I)
BACKTICK_RE = re.compile(r"`([^`]+)`")

# Location tokens that are structural noise (shared by many findings), never a
# unique per-finding signal. Filtered out of token matching below.
GENERIC_TOKENS = {"server.js", "auth.js", "util.js", "chat.js", "py_app.py",
                  "Dockerfile", "package.json"}

# The dependency / secret sections are "populated" if any of these appear, OR if
# the report explicitly says the relevant tooling was unavailable (a legitimate
# fallback-mode outcome the golden set permits). Bare common words ("send", "qs")
# are deliberately excluded — they matched ordinary prose and gave a false PASS.
DEP_NEEDLES = ["lodash", "minimist", "marked", "express",
               "path-to-regexp", "serve-static", "npm audit"]
SECRET_NEEDLES = ["aws access key", "aws secret", "api token", "api_token",
                  "hardcoded secret", "hardcoded credential", "hardcoded aws"]
UNAVAILABLE_RE = re.compile(
    r"(unavailable|not installed|no lockfile|lookup unavailable|tool[^.\n]*(missing|absent))",
    re.I)


def norm(text: str) -> str:
    """Normalise the non-breaking hyphen so 'CWE‑089' == 'CWE-89'."""
    return text.replace("‑", "-")


def has_token(text: str, token: str) -> bool:
    """Case-insensitive, boundary-aware containment.

    Substring matching gave false credit: a short token like `eval`/`merge`/`send`
    matched inside 'evaluation'/'merged'/'sender'. Require the token not to be
    flanked by word characters so it only matches as a whole identifier/path.
    """
    return re.search(r"(?<!\w)" + re.escape(token) + r"(?!\w)", text, re.I) is not None


def cwe_list(text: str) -> list[str]:
    """CWE numbers in `text`, in order, expanding grouped lists (CWE-502/94 -> 502, 94)."""
    out: list[str] = []
    for grp in CWE_GROUP_RE.findall(norm(text)):
        out += re.findall(r"\d+", grp)
    return out


def load_golden() -> list[dict]:
    """Parse the V1–V16 code-findings table from expected-findings.md."""
    findings: list[dict] = []
    with open(GOLDEN, encoding="utf-8") as f:
        for line in f:
            m = ROW_RE.match(line.strip())
            if not m:
                continue
            cols = [c.strip() for c in m.group(2).split("|")]
            if len(cols) < 3:
                continue
            klass, owasp_cwe, location = cols[0], cols[1], cols[2]
            cwes = cwe_list(owasp_cwe)
            findings.append({
                "id": m.group(1),
                "class": klass,
                "primary_cwe": cwes[0] if cwes else None,
                "tokens": set(BACKTICK_RE.findall(location)),
            })
    return findings


def distinctive_tokens(findings: list[dict]) -> set[str]:
    """Tokens that identify exactly one finding (and aren't generic file names)."""
    freq: dict[str, int] = {}
    for f in findings:
        for t in f["tokens"]:
            freq[t] = freq.get(t, 0) + 1
    return {t for t, n in freq.items() if n == 1 and t not in GENERIC_TOKENS}


def grade(report_text: str, findings: list[dict]) -> list[tuple[str, str | None]]:
    """Return (finding_id, matched_signal_or_None) for each golden finding."""
    report = norm(report_text)
    report_cwes = set(cwe_list(report))
    uniq = distinctive_tokens(findings)
    results = []
    for f in findings:
        signal = None
        if f["primary_cwe"] and f["primary_cwe"] in report_cwes:
            signal = f"CWE-{f['primary_cwe']}"
        else:
            for t in sorted(f["tokens"] & uniq):
                if has_token(report, t):
                    signal = f"token `{t}`"
                    break
        results.append((f["id"], signal))
    return results


def section_ok(report: str, needles: list[str]) -> bool:
    return (any(has_token(report, n) for n in needles)
            or bool(UNAVAILABLE_RE.search(report)))


def selftest() -> int:
    """Verify the grader's own gates — that it credits a complete report and, just as
    importantly, does NOT credit prose that merely brushes past finding keywords."""
    findings = load_golden()
    if len(findings) != 20:
        print(f"[selftest] FAIL: parsed {len(findings)} golden findings, expected 20")
        return 1
    n = len(findings)
    ok = True

    # Positive: a report that cites every primary CWE + a dependency + a secret must PASS.
    pos = ("Findings: " + " ".join(f"CWE-{f['primary_cwe']}" for f in findings)
           + " lodash 4.17.15 is vulnerable. AWS access key found hardcoded (masked).")
    covered = sum(1 for _, s in grade(pos, findings) if s)
    if covered != n:
        print(f"[selftest] FAIL positive: {covered}/{n} covered"); ok = False
    if not (section_ok(pos, DEP_NEEDLES) and section_ok(pos, SECRET_NEEDLES)):
        print("[selftest] FAIL positive: dep/secret section not detected"); ok = False

    # Negative: prose with near-miss words (send/qs/evaluation/merged/rendered/execute)
    # but no real finding must score 0 and leave both sections empty.
    neg = ("We send a quick response and add qs support. The evaluation merged and "
           "rendered the newest execute path successfully.")
    falsely = [vid for vid, s in grade(neg, findings) if s]
    if falsely:
        print(f"[selftest] FAIL negative: falsely credited {falsely}"); ok = False
    if section_ok(neg, DEP_NEEDLES):
        print("[selftest] FAIL negative: dependency section falsely populated"); ok = False
    if section_ok(neg, SECRET_NEEDLES):
        print("[selftest] FAIL negative: secret section falsely populated"); ok = False

    print("[selftest] PASS — grader gates behave correctly." if ok else "[selftest] FAILED")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Grade a SecAudit report against the golden set.")
    ap.add_argument("report", nargs="?", help="path to the audit report markdown to grade")
    ap.add_argument("--min", type=int, default=20,
                    help="minimum code findings that must be covered to pass (default: 20)")
    ap.add_argument("--selftest", action="store_true",
                    help="run the grader's built-in gate checks and exit (no report needed)")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.report:
        ap.error("a report path is required (or pass --selftest)")

    if not os.path.isfile(args.report):
        print(f"error: report not found: {args.report}", file=sys.stderr)
        return 2

    report = open(args.report, encoding="utf-8").read()
    findings = load_golden()
    if not findings:
        print("error: could not parse the golden set from expected-findings.md", file=sys.stderr)
        return 2

    results = grade(report, findings)
    covered = [(vid, sig) for vid, sig in results if sig]
    missed = [vid for vid, sig in results if not sig]

    print(f"Grading {os.path.relpath(args.report, os.path.dirname(ROOT))} "
          f"against {len(findings)} golden findings\n")
    for vid, sig in results:
        mark = "OK  " if sig else "MISS"
        print(f"  [{mark}] {vid:<4} {'via ' + sig if sig else 'NOT FOUND'}")

    dep_ok = section_ok(report, DEP_NEEDLES)
    secret_ok = section_ok(report, SECRET_NEEDLES)
    print(f"\n  Dependency section populated: {'yes' if dep_ok else 'NO'}")
    print(f"  Secret section populated:     {'yes' if secret_ok else 'NO'}")

    print(f"\nCoverage: {len(covered)}/{len(findings)} code findings "
          f"(threshold {args.min}).")

    fails = []
    if len(covered) < args.min:
        fails.append(f"coverage {len(covered)} < required {args.min}; missing: {', '.join(missed)}")
    if not dep_ok:
        fails.append("dependency section not populated (and not marked unavailable)")
    if not secret_ok:
        fails.append("secret section not populated (and not marked unavailable)")

    if fails:
        print("\nGRADE: FAIL")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("\nGRADE: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
