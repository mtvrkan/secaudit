#!/usr/bin/env python3
"""Validate the report renderers: SARIF shape, and the self-contained HTML report."""
from __future__ import annotations

import json
import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(KIT)
sys.path.insert(0, KIT)

from secaudit_core import engine, report              # noqa: E402
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
    if "not a statement that the code is safe" not in doc:
        fails.append("HTML report must say what an empty result does not mean")

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

    html = check_html(res, fails)

    if fails:
        print("REPORT TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print(f"REPORT TESTS PASSED — valid SARIF 2.1.0 doc, {len(rules)} rules / "
          f"{len(results)} results; HTML report {len(html):,} bytes, self-contained, "
          f"well-formed, escaping verified against hostile input.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
