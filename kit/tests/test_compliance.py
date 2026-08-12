#!/usr/bin/env python3
"""Compliance mapping, SBOM and CRA evidence-pack tests.

The failure this suite guards against is **a document that looks authoritative and is not**.
A wrong CWE→ASVS chapter is a footnote; an SBOM with an invented version, or a CRA pack that
implies compliance, is something a person files with a regulator. So the assertions here are
weighted toward the claims, not the plumbing: that unresolved versions are flagged rather than
guessed, that an unsupported ecosystem produces "no SBOM" rather than an empty component list,
and that the disclaimer says what it has to say.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(KIT)
sys.path.insert(0, KIT)

from secaudit_core import compliance, engine, report, sbom      # noqa: E402
from secaudit_core.schema import (Confidence, Finding, ScanResult,   # noqa: E402
                                  Severity, Verdict)

VULN = os.path.join(REPO, "tests", "fixtures", "vulnerable-app")

fails: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        fails.append(message)


# --------------------------------------------------------------------------- mapping

def test_asvs_mapping() -> None:
    check(len(compliance.ASVS_CHAPTERS) == 17,
          f"ASVS 5.0 has 17 chapters, the table has {len(compliance.ASVS_CHAPTERS)}")
    check(compliance.ASVS_CHAPTERS.get("V1") == "Encoding and Sanitization",
          "chapter V1 title drifted from ASVS 5.0")

    for cwe, chapter in compliance.CWE_TO_ASVS.items():
        if chapter not in compliance.ASVS_CHAPTERS:
            fails.append(f"{cwe} maps to `{chapter}`, which is not an ASVS chapter")
        if not cwe.startswith("CWE-"):
            fails.append(f"malformed CWE key `{cwe}` in CWE_TO_ASVS")

    check(compliance.asvs_for("CWE-89") == ("V1", "Encoding and Sanitization"),
          "SQL injection should map to the encoding/sanitization chapter")
    check(compliance.asvs_for("CWE-639")[0] == "V8",
          "IDOR should map to the authorization chapter")
    check(compliance.asvs_for("CWE-99999") is None,
          "an unknown CWE must return None, not a default chapter — a wrong chapter in a "
          "compliance report is worse than an absent one")


def test_cra_mapping() -> None:
    check(compliance.CRA_REPORTING_STARTS == "2026-09-11",
          "the CRA vulnerability-handling application date drifted")
    check("2024/2847" in compliance.CRA_REGULATION,
          "the CRA regulation reference must name the regulation number")

    code = compliance.cra_clauses_for("CWE-89", is_dependency=False, actively_exploited=False)
    check("Annex I Part I (2)(a)" in code,
          "every finding bears on the no-known-exploitable-vulnerabilities clause")
    check("Annex I Part II (1)" not in code,
          "a code finding must not claim the SBOM/component-identification clause")

    dep = compliance.cra_clauses_for("CWE-1395", is_dependency=True, actively_exploited=False)
    check("Annex I Part II (1)" in dep,
          "a dependency advisory bears on the SBOM/component-identification clause")

    exploited = compliance.cra_clauses_for("CWE-89", is_dependency=False,
                                           actively_exploited=True)
    check(any("Article 14" in c for c in exploited),
          "an actively exploited vulnerability must surface the Article 14 reporting duty — "
          "that is the clause with a 24-hour clock on it")

    check(all(c in compliance.CRA_CLAUSES for c in code + dep if "Article" not in c),
          "cra_clauses_for returned a clause with no text in CRA_CLAUSES")

    check(set(compliance.summary()["not_mapped"]) == {"PCI DSS", "SOC 2", "ISO 27001"},
          "the summary must keep stating which standards are NOT mapped; silently dropping "
          "that line is how an unmapped standard reads as a covered one")


# --------------------------------------------------------------------------- SBOM

def test_sbom() -> None:
    doc = sbom.build(VULN)
    check(doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6",
          "SBOM must declare CycloneDX 1.6")
    check(doc.get("$schema", "").endswith("bom-1.6.schema.json"),
          "SBOM must reference the CycloneDX 1.6 schema")

    names = {c["name"] for c in doc["components"]}
    check({"express", "lodash", "marked", "minimist"} <= names,
          f"SBOM missed a declared dependency: {sorted(names)}")
    for component in doc["components"]:
        check(component["purl"].startswith("pkg:npm/"),
              f"component {component['name']} has a malformed purl")
        check(component["bom-ref"] == component["purl"],
              "bom-ref must be stable and match the purl")
    check(all(c["version"] for c in doc["components"]),
          "every fixture dependency is in the lockfile, so every version must resolve")

    # Determinism: same tree, byte-identical document. A clock in here would make two SBOMs
    # of the same product diff, which defeats using the diff to spot dependency changes.
    check(sbom.to_json(VULN) == sbom.to_json(VULN), "SBOM generation is not deterministic")

    # An unresolvable version must be FLAGGED, never guessed from the range.
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "package.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "x", "dependencies": {"left-pad": "^1.3.0"}}, f)
        doc = sbom.build(tmp)
        component = doc["components"][0]
        check(component["version"] == "",
              f"a package with no lockfile entry must have an empty version, not a guess "
              f"(got {component['version']!r})")
        props = {p["name"] for p in component.get("properties", [])}
        check("secaudit:version-unresolved" in props,
              "an unresolved version must be flagged in the document a consumer reads")

    with tempfile.TemporaryDirectory() as tmp:
        check(not sbom.is_supported(tmp),
              "a tree with no npm manifest must report SBOM as unsupported, so the caller can "
              "say 'unsupported ecosystem' rather than emit zero components")


# --------------------------------------------------------------------------- CRA pack

def test_cra_pack() -> None:
    scan = engine.scan(VULN, run_deps=False, use_scanners=False)
    pack = json.loads(report.to_cra_pack(scan))

    check(pack["artifact"] == "secaudit-cra-evidence-pack", "pack lost its artifact marker")
    check(pack["vulnerability_handling_obligations_apply_from"] == "2026-09-11",
          "pack must state when the obligations start")
    check(pack["sbom"] and pack["sbom"]["bomFormat"] == "CycloneDX",
          "the pack must embed the SBOM — Annex I Part II (1) is the reason it exists")
    check(len(pack["vulnerability_register"]) == len(scan.findings),
          "every finding must appear in the register; a filtered register is not evidence")

    for entry in pack["vulnerability_register"]:
        check(entry["cra_clauses"], f"{entry['id']} has no CRA clause mapping")
        check(entry["remediation"], f"{entry['id']} has no remediation text")
        check(entry["actively_exploited"] is None,
              "exploitation status must be null (not checked), never false — the difference "
              "decides whether an Article 14 clock has started")

    check(pack["clause_coverage"], "the pack must state which clauses it bears on")
    check(any("Part II (3)" in c for c in pack["clause_coverage"]),
          "running the scan is evidence toward the regular-security-testing clause")

    disclaimer = pack["disclaimer"]
    for phrase in ("not evidence of compliance", "no conformity assessment",
                   "Exploitation status is not determined"):
        check(phrase in disclaimer,
              f"the disclaimer must say '{phrase}' — a pack that reads as a compliance "
              f"certificate is the one way this feature does real harm")

    check(pack["limitations"], "the pack must carry the scan's stated limitations")

    # An unsupported ecosystem says so instead of implying a dependency-free product.
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "a.py"), "w", encoding="utf-8") as f:
            f.write("import os\ndef f(x):\n    os.system(x)\n")
        empty = json.loads(report.to_cra_pack(
            engine.scan(tmp, run_deps=False, use_scanners=False)))
        check(empty["sbom"] is None and empty["sbom_note"],
              "with no npm manifest the pack must state why there is no SBOM")


def main() -> int:
    test_asvs_mapping()
    test_cra_mapping()
    test_sbom()
    test_cra_pack()

    if fails:
        print("COMPLIANCE TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print(f"COMPLIANCE TESTS PASSED — {len(compliance.ASVS_CHAPTERS)} ASVS chapters, "
          f"{len(compliance.CWE_TO_ASVS)} mapped CWEs, {len(compliance.CRA_CLAUSES)} CRA "
          f"clauses; CycloneDX 1.6 determinism, unresolved-version flagging and the "
          f"evidence pack's disclaimer verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
