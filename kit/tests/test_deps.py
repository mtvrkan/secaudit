#!/usr/bin/env python3
"""Dependency reachability + OpenVEX classification tests.

The failure mode this suite exists to prevent is a **false all-clear**: a package we cannot
see being imported is not the same as a package that is not used. Every branch of `classify`
is asserted, and the transitive and unindexable cases are asserted to stay
`under_investigation` rather than drift into `not_affected` — those two are the ones where a
wrong answer reads as "you are fine".

Runs entirely offline. `npm audit` needs a network and a registry; the classification layer it
feeds does not, so it is tested on its own against the shipped fixture.
"""
from __future__ import annotations

import json
import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(KIT)
sys.path.insert(0, KIT)

from secaudit_core import deps, engine, report                # noqa: E402
from secaudit_core.schema import (Confidence, Finding, ScanResult,  # noqa: E402
                                  Severity, Verdict)

VULN = os.path.join(REPO, "tests", "fixtures", "vulnerable-app")

fails: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        fails.append(message)


# --------------------------------------------------------------------------- specifiers

def test_package_of() -> None:
    cases = {
        "express": "express",
        "lodash/merge": "lodash",
        "@scope/pkg": "@scope/pkg",
        "@scope/pkg/sub": "@scope/pkg",
        "./local": None,
        "../up": None,
        "/abs": None,
        "node:fs": None,
        "": None,
        "@broken": None,
    }
    for spec, want in cases.items():
        got = deps.js_package_of(spec)
        check(got == want, f"js_package_of({spec!r}) -> {got!r}, expected {want!r}")


# --------------------------------------------------------------------------- import index

def test_import_index() -> None:
    index = deps.build_import_index(VULN)
    check("express" in index and "server.js" in index["express"],
          "import index missed `require('express')` in server.js")
    check("marked" in index and "chat.js" in index["marked"],
          "import index missed `require('marked')` in chat.js")
    check("requests" in index and "py_app.py" in index["requests"],
          "import index missed a Python `import requests`")
    check("lodash" not in index,
          "import index invented an import of lodash (it is declared but never required)")

    runtime, dev = deps.read_manifest(VULN)
    check({"express", "lodash", "marked", "minimist"} <= runtime,
          f"manifest read missed a runtime dependency: {sorted(runtime)}")


def test_import_forms() -> None:
    """Each import syntax must land in the index — a missed form is a false `not_affected`."""
    import tempfile
    forms = {
        "a.js": "const x = require('alpha');",
        "b.mjs": "import y from 'bravo';",
        "c.ts": "import { z } from 'charlie';",
        "d.js": "export { q } from 'delta';",
        "e.js": "const m = await import('echo');",
        "f.js": "import 'foxtrot';",
        "g.py": "import golf\nfrom hotel import thing\nfrom . import local\n",
    }
    with tempfile.TemporaryDirectory() as tmp:
        for name, body in forms.items():
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as f:
                f.write(body)
        index = deps.build_import_index(tmp)
    for pkg in ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"):
        check(pkg in index, f"import index missed the form that imports `{pkg}`")
    check("local" not in index and "" not in index,
          "import index treated a relative Python import as a package")


# --------------------------------------------------------------------------- classification

def test_classify() -> None:
    index = {"express": {"server.js"}, "jest": {"tests/unit.test.js"},
             "webpack": {"scripts/build.js"}, "supertest": {"tests/api.test.js"}}
    runtime = {"express", "lodash", "supertest"}
    dev = {"jest", "webpack"}

    v = deps.classify("express", index, runtime, dev)
    check(v.status == deps.STATUS_AFFECTED, "an imported runtime package must be `affected`")
    check("server.js" in v.note, "the `affected` note must name the importing file")

    v = deps.classify("lodash", index, runtime, dev)
    check(v.status == deps.STATUS_NOT_AFFECTED
          and v.justification == deps.JUSTIFICATION_CODE_NOT_PRESENT,
          "a declared-but-never-imported package must be `not_affected/code_not_present`")

    v = deps.classify("jest", index, runtime, dev)
    check(v.status == deps.STATUS_NOT_AFFECTED
          and v.justification == deps.JUSTIFICATION_COMPONENT_NOT_PRESENT,
          "a dev dependency imported only from tests must be `not_affected/component_not_present`")

    v = deps.classify("supertest", index, runtime, dev)
    check(v.status == deps.STATUS_UNDER_INVESTIGATION,
          "a RUNTIME dependency imported only from tests is ambiguous, not cleared — it may ship")

    # The two false-all-clear traps.
    v = deps.classify("some-transitive", index, runtime, dev)
    check(v.status == deps.STATUS_UNDER_INVESTIGATION,
          "an undeclared (transitive) package must stay `under_investigation`: a missing "
          "first-party import says nothing about whether a direct dependency loads it")

    v = deps.classify("express", {}, set(), set(), indexable=False)
    check(v.status == deps.STATUS_UNDER_INVESTIGATION,
          "with no indexable source, every advisory must stay `under_investigation` rather "
          "than be assumed unreachable")

    check(deps.classify("express", index, runtime, dev).reachable, "`affected` must be reachable")
    check(not deps.classify("lodash", index, runtime, dev).reachable,
          "`not_affected` must not be reachable")


# --------------------------------------------------------------------------- engine wiring

def _dep_finding(package: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(detector_id="DEP-NPM", title=f"Vulnerable dependency: {package}",
                   severity=severity, confidence=Confidence.HIGH, cwe="CWE-1395", owasp="A06",
                   file="package.json", line=1, evidence=f"{package}: high severity",
                   fix="Upgrade.", source="npm-audit", verdict=Verdict.CONFIRMED,
                   package=package)


def test_apply_vex() -> None:
    notes: list[str] = []
    findings = [_dep_finding("express"), _dep_finding("lodash"),
                _dep_finding("some-transitive"), _dep_finding("marked", Severity.CRITICAL)]
    engine.apply_vex(VULN, findings, notes)
    by = {f.package: f for f in findings}

    check(by["express"].vex_status == deps.STATUS_AFFECTED, "express should classify as affected")
    check(by["express"].severity == Severity.HIGH,
          "an `affected` advisory must keep its original severity")
    check(by["express"].verdict == Verdict.CONFIRMED,
          "an `affected` advisory must stay CONFIRMED")

    check(by["lodash"].vex_status == deps.STATUS_NOT_AFFECTED,
          "lodash is declared but never required in the fixture — it should be not_affected")
    check(by["lodash"].severity == Severity.LOW,
          f"a `not_affected` High must drop two rungs (High→Medium→Low), "
          f"got {by['lodash'].severity.value}")
    check(by["lodash"].verdict == Verdict.PLAUSIBLE,
          "a `not_affected` advisory must not remain CONFIRMED — a reader filtering on "
          "CONFIRMED would act on an advisory we ruled out")
    check(by["lodash"].triage_note, "the VEX call must carry its evidence into the report")

    check(by["some-transitive"].vex_status == deps.STATUS_UNDER_INVESTIGATION,
          "an undeclared transitive package must stay under_investigation")
    check(by["some-transitive"].severity == Severity.HIGH,
          "under_investigation must not downgrade severity")

    check(any("OpenVEX" in n for n in notes), "apply_vex must summarize the classification")

    # A finding with no package (a code finding) must be left completely alone.
    code_finding = Finding(detector_id="SEC-JS-EVAL", title="eval", severity=Severity.CRITICAL,
                           confidence=Confidence.HIGH, cwe="CWE-95", owasp="A03", file="a.js",
                           line=1, evidence="eval(x)", fix="Do not.")
    engine.apply_vex(VULN, [code_finding], [])
    check(code_finding.vex_status == "" and code_finding.severity == Severity.CRITICAL,
          "apply_vex must not touch a finding that names no package")


def test_openvex_document() -> None:
    findings = [_dep_finding("express"), _dep_finding("lodash")]
    engine.apply_vex(VULN, findings, [])
    result = ScanResult(target=VULN, findings=findings)
    doc = json.loads(report.to_openvex(result))

    check(doc["@context"].startswith("https://openvex.dev/ns/"),
          "OpenVEX document must declare the OpenVEX context")
    check(len(doc["statements"]) == 2,
          f"expected one statement per classified advisory, got {len(doc['statements'])}")
    by_status = {s["status"]: s for s in doc["statements"]}
    check(deps.STATUS_NOT_AFFECTED in by_status, "OpenVEX document lost the not_affected call")
    check("justification" in by_status[deps.STATUS_NOT_AFFECTED],
          "a not_affected statement without a justification is not valid OpenVEX")
    check("justification" not in by_status.get(deps.STATUS_AFFECTED, {"justification": 1}),
          "an `affected` statement must not carry a not_affected justification")
    check(all(s["status_notes"] for s in doc["statements"]),
          "every statement must carry the evidence for its call")


def main() -> int:
    test_package_of()
    test_import_index()
    test_import_forms()
    test_classify()
    test_apply_vex()
    test_openvex_document()

    if fails:
        print("DEPENDENCY / VEX TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("DEPENDENCY / VEX TESTS PASSED — import forms indexed, every classify branch "
          "asserted, transitive and unindexable cases stay under_investigation, engine wiring "
          "and OpenVEX output verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
