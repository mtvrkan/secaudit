#!/usr/bin/env python3
"""Validate the report renderers: SARIF shape, and the self-contained HTML report."""
from __future__ import annotations

import json
import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(KIT)
sys.path.insert(0, KIT)

from secaudit_core import engine, i18n, report        # noqa: E402
from secaudit_core.schema import Finding, ScanResult, Severity, Confidence   # noqa: E402

VULN = os.path.join(REPO, "tests", "fixtures", "vulnerable-app")


def check_html(res, fails: list[str]) -> str:
    """The HTML report has to survive being emailed, so `self-contained` is an assertion, not
    an aspiration — and it renders attacker-influenced strings, so escaping is one too."""
    from html.parser import HTMLParser
    import re

    doc = report.to_html(res)

    class Balance(HTMLParser):
        def __init__(self):
            super().__init__()
            self.stack, self.bad = [], []

        def handle_starttag(self, tag, attrs):
            if tag not in ("meta", "br", "link", "img", "hr", "input"):
                self.stack.append(tag)

        def handle_endtag(self, tag):
            if self.stack and self.stack[-1] == tag:
                self.stack.pop()
            else:
                self.bad.append(tag)

    parser = Balance()
    parser.feed(doc)
    if parser.stack or parser.bad:
        fails.append(f"HTML is not well-formed: unclosed {parser.stack}, mismatched {parser.bad}")

    external = re.findall(r'(?:src|href)="(?!#)[^"]+"', doc)
    if external:
        fails.append(f"HTML report must be self-contained; it references {external}")
    if "<script" in doc.lower():
        fails.append("HTML report must carry no script")
    if doc.count('class="finding"') != len(res.findings):
        fails.append(f"HTML rendered {doc.count(chr(34) + 'class=' + chr(34))} findings, "
                     f"expected {len(res.findings)}")
    if "@media print" not in doc:
        fails.append("HTML report must carry print rules — it is also the PDF path")
    # The "an empty report is not a clean bill" disclaimer must be present — in whatever
    # language the report is rendered in. Asserted against the locale bundle rather than
    # against a hardcoded English sentence: the renderer gained a `locale` argument, and a test
    # that pins the English wording would pass only until someone ran `--lang tr`, which is the
    # supported case it exists to protect.
    for locale in i18n.available():
        rendered = report.to_html(res, locale)
        disclaimer = i18n.Strings(locale)("clean.meaning")
        if disclaimer not in rendered:
            fails.append(f"HTML report in '{locale}' must say what an empty result does not "
                         f"mean; the {locale} disclaimer is missing")
        if f'lang="{locale}"' not in rendered:
            fails.append(f"HTML report in '{locale}' must declare that language on <html>")

    # Non-vacuous escaping check: a finding whose evidence is markup must not become markup.
    hostile = ScanResult(target="<b>t</b>", backend="none")
    hostile.findings.append(Finding(
        detector_id="X<i>", title="<script>alert(1)</script>", severity=Severity.HIGH,
        confidence=Confidence.HIGH, cwe="CWE-79", owasp="A03", file="a<b>.js", line=1,
        evidence="<img src=x onerror=alert(1)>", fix="<em>fix</em>"))
    poisoned = report.to_html(hostile)
    for raw in ("<script>alert(1)</script>", "<img src=x", "<em>fix</em>"):
        if raw in poisoned:
            fails.append(f"HTML report did not escape {raw!r} — a scanner that renders its own "
                         f"evidence unescaped plants the bug it was hired to find")
    if "&lt;script&gt;alert(1)&lt;/script&gt;" not in poisoned:
        fails.append("HTML report dropped the hostile title instead of escaping it")
    return doc


def check_semgrep_json(res, fails: list[str]) -> dict:
    """The Semgrep-JSON renderer, which is the one the external number is computed through.

    RealVuln's scorer reads this shape and nothing else, so a silent change here does not break
    a test — it moves the published F3 and looks like a detection regression. That is the worst
    failure mode a renderer can have, and it was the only renderer with no test.
    """
    doc = json.loads(report.to_semgrep_json(res))

    if doc.get("errors") != [] or "paths" not in doc:
        fails.append("semgrep JSON must carry the `errors` and `paths` keys the scorer reads")
    scanned = doc.get("paths", {}).get("scanned", [])
    if scanned != sorted({f.file for f in res.findings}):
        fails.append("semgrep JSON `paths.scanned` must be the deduplicated, sorted file set")

    results = doc.get("results", [])
    if len(results) != len(res.findings):
        fails.append(f"semgrep JSON emitted {len(results)} results for {len(res.findings)} "
                     f"findings — the scorer counts rows, so a dropped row is a lost TP")

    by_id = {f.detector_id for f in res.findings}
    for r in results:
        if r.get("check_id") not in by_id:
            fails.append(f"semgrep result check_id {r.get('check_id')!r} is not a detector id")
        start, end = r.get("start", {}), r.get("end", {})
        if start.get("line", 0) < 1 or end.get("line", 0) < 1:
            fails.append(f"semgrep result {r.get('check_id')} has a line below 1 — a 0 line is "
                         f"unscoreable and silently drops the finding")
        extra = r.get("extra", {})
        if extra.get("severity") not in ("ERROR", "WARNING", "INFO"):
            fails.append(f"bad semgrep severity {extra.get('severity')!r}")
        for key in ("cwe", "owasp", "confidence"):
            if key not in extra.get("metadata", {}):
                fails.append(f"semgrep metadata for {r.get('check_id')} is missing {key}")

    # Severity mapping, stated here independently rather than read from the renderer's own
    # table. Reading `report._SEMGREP_SEVERITY` looked like the tighter test and is in fact no
    # test at all: it moves with the bug, and a mutation run proved it — flipping Medium to
    # ERROR passed. What this asserts is the meaning the consumer acts on: ERROR is the level a
    # CI gate blocks a merge on, so a Medium promoted into it turns advisory findings into
    # build breaks, and a High demoted out of it lets a real one through unnoticed.
    expect_level = {"Critical": "ERROR", "High": "ERROR", "Medium": "WARNING",
                    "Low": "INFO", "Informational": "INFO"}
    for finding in res.findings:
        row = next((r for r in results if r["check_id"] == finding.detector_id
                    and r["path"] == finding.file and r["start"]["line"] == max(1, finding.line)),
                   None)
        if row is None:
            fails.append(f"semgrep JSON lost {finding.detector_id} at {finding.file}:{finding.line}")
        elif row["extra"]["severity"] != expect_level[finding.severity.value]:
            fails.append(f"{finding.severity.value} mapped to {row['extra']['severity']}, "
                         f"expected {expect_level[finding.severity.value]}")
    # Every severity the schema defines must be exercised by the fixture corpus or stated here,
    # or a mapping could rot in a severity nothing produces.
    for sev in Severity:
        if sev.value not in expect_level:
            fails.append(f"severity {sev.value} has no expected Semgrep level in this test")
        elif report._SEMGREP_SEVERITY.get(sev.value) != expect_level[sev.value]:
            fails.append(f"renderer maps {sev.value} to "
                         f"{report._SEMGREP_SEVERITY.get(sev.value)!r}, "
                         f"expected {expect_level[sev.value]!r}")

    # The optional metadata blocks, and the line floor. A finding on line 0 (a file-level flaw:
    # a missing header, a whole-file misconfiguration) must land on line 1, because the scorer
    # matches on line numbers and 0 matches nothing.
    rich = ScanResult(target="t", backend="none")
    rich.findings.append(Finding(
        detector_id="D1", title="t", severity=Severity.CRITICAL, confidence=Confidence.HIGH,
        cwe="CWE-89", owasp="A03", file="a.py", line=0, evidence="e", fix="f",
        taint_path="L1: req.args (request) -> L2: sink", vex_status="affected",
        vex_justification="reachable", exploitation="KEV"))
    one = json.loads(report.to_semgrep_json(rich))["results"][0]
    if one["start"]["line"] != 1 or one["end"]["line"] != 1:
        fails.append("a line-0 finding must be clamped to line 1, not emitted as 0")
    meta = one["extra"]["metadata"]
    for key, want in (("taint_path", "L1: req.args (request) -> L2: sink"),
                      ("vex_status", "affected"), ("vex_justification", "reachable"),
                      ("exploitation", "KEV")):
        if meta.get(key) != want:
            fails.append(f"semgrep metadata dropped {key} (got {meta.get(key)!r})")

    # ...and they must be ABSENT rather than null when unset — a scorer reading `vex_status`
    # as present-but-empty is a different claim from "not assessed".
    plain = ScanResult(target="t", backend="none")
    plain.findings.append(Finding(
        detector_id="D2", title="t", severity=Severity.LOW, confidence=Confidence.MEDIUM,
        cwe="CWE-1", owasp="A01", file="b.py", line=4, evidence="e", fix="f"))
    bare = json.loads(report.to_semgrep_json(plain))["results"][0]["extra"]["metadata"]
    for key in ("taint_path", "vex_status", "vex_justification", "exploitation"):
        if key in bare:
            fails.append(f"unset {key} must be omitted from semgrep metadata, not emitted empty")
    if bare.get("confidence") != "MEDIUM":
        fails.append("semgrep metadata confidence must be the upper-cased confidence value")
    return doc


def check_alert_tracking_survives_a_line_shift(fails: list[str]) -> None:
    """A code-scanning alert must keep its identity when the code above it moves.

    This is the half of "SARIF works" that a shape assertion cannot see. GitHub tracks an alert
    by `partialFingerprints`; if the fingerprint moves, the old alert is closed and a new one
    opened, and the dismissal, the assignee and the review comments go with it. The fingerprint
    used to be `detector:file:line`, so *any* insertion earlier in the file reset every alert
    below it — the exact failure the field exists to prevent.

    Tested by scanning the same file twice with a blank line prepended, which is the smallest
    edit that moves every line and changes no finding.
    """
    import tempfile   # noqa: PLC0415

    # The last two lines are byte-identical on purpose. Content-only fingerprints collide on
    # them, GitHub merges the two alerts into one, and the second finding silently disappears
    # from the UI — so the fixture has to contain the case, or the uniqueness half of this
    # check is decoration. It found a real collision: 3 of 100 on this repository's own source.
    source = ("const express = require('express');\n"
              "app.get('/a', (req, res) => { db.query('SELECT * FROM t WHERE id=' + req.query.id); });\n"
              "app.get('/b', (req, res) => { res.send(eval(req.query.x)); });\n"
              "function one() {\n"
              "  res.send(eval(req.query.x));\n"
              "}\n"
              "function two() {\n"
              "  res.send(eval(req.query.x));\n"
              "}\n")

    def fingerprints(text: str) -> list[str]:
        # A LIST, not a set or a dict: collisions are the second thing being tested here, and a
        # container keyed on the fingerprint silently deduplicates exactly the bug. (It did —
        # this check passed against a deliberately colliding fixture until the container changed.)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "server.js")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            res = engine.scan(tmp, run_deps=False, use_scanners=False)
            doc = json.loads(report.to_sarif(res))
            out = []
            for r in doc["runs"][0]["results"]:
                fp = r.get("partialFingerprints", {}).get("secauditId")
                if fp is None:
                    fails.append("every SARIF result must carry a partialFingerprint — without "
                                 "one GitHub falls back to location and every edit re-creates "
                                 "the alert")
                    continue
                out.append(fp)
            return out

    before = fingerprints(source)
    after = fingerprints("\n// a comment added at the top\n" + source)

    if not before:
        fails.append("the fingerprint fixture produced no findings — it is not testing anything")
        return
    lost = set(before) - set(after)
    if lost:
        fails.append(f"{len(lost)} alert fingerprint(s) changed when a line was inserted above "
                     f"them; GitHub would close those alerts and open new ones, losing every "
                     f"dismissal. Fingerprints must not encode position.")
    if len(set(before)) != len(before):
        fails.append("two findings share a fingerprint — GitHub would merge them into one alert")


def main() -> int:
    fails: list[str] = []
    res = engine.scan(VULN, run_deps=False, use_scanners=False)
    doc = json.loads(report.to_sarif(res))  # must be valid JSON

    if doc.get("version") != "2.1.0":
        fails.append("SARIF version must be 2.1.0")
    run = (doc.get("runs") or [{}])[0]
    driver = run.get("tool", {}).get("driver", {})
    if driver.get("name") != "SecAudit":
        fails.append("driver.name must be SecAudit")

    rules = driver.get("rules", [])
    results = run.get("results", [])
    if not rules or not results:
        fails.append("expected non-empty rules and results")
    if len(results) != len(res.findings):
        fails.append(f"results ({len(results)}) != findings ({len(res.findings)})")

    rule_ids = {r["id"] for r in rules}
    for r in results:
        if r.get("ruleId") not in rule_ids:
            fails.append(f"result ruleId {r.get('ruleId')} has no matching rule")
        if r.get("level") not in ("error", "warning", "note"):
            fails.append(f"bad SARIF level {r.get('level')}")
        loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
        if not loc.get("artifactLocation", {}).get("uri") or not loc.get("region", {}).get("startLine"):
            fails.append("result missing location uri/startLine")

    # every rule carries a security-severity GitHub can read; a Critical finding => error + 9.0
    for r in rules:
        if "security-severity" not in r.get("properties", {}):
            fails.append(f"rule {r['id']} missing security-severity")
    crit = [f for f in res.findings if f.severity.value == "Critical"]
    if crit:
        cr = next(r for r in results if r["ruleId"] == crit[0].detector_id)
        if cr["level"] != "error":
            fails.append("Critical finding must map to SARIF level 'error'")

    check_alert_tracking_survives_a_line_shift(fails)

    html = check_html(res, fails)
    sg = check_semgrep_json(res, fails)

    if fails:
        print("REPORT TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print(f"REPORT TESTS PASSED — valid SARIF 2.1.0 doc, {len(rules)} rules / "
          f"{len(results)} results; HTML report {len(html):,} bytes, self-contained, "
          f"well-formed, escaping verified against hostile input; Semgrep JSON "
          f"{len(sg['results'])} results, the shape the external score is computed from.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
