"""Render a ScanResult as Markdown or JSON."""
from __future__ import annotations

import json

from .schema import ScanResult, Severity


_SARIF_SCORE = {"Critical": "9.0", "High": "7.5", "Medium": "5.0",
                "Low": "3.0", "Informational": "1.0"}
_SARIF_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning",
                "Low": "note", "Informational": "note"}


def to_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0 for GitHub code scanning. `security-severity` on each rule drives the
    severity GitHub shows; `level` drives the annotation style."""
    rules, rule_index = [], {}
    for f in result.by_severity():
        if f.detector_id in rule_index:
            continue
        rule_index[f.detector_id] = len(rules)
        rules.append({
            "id": f.detector_id,
            "name": f.detector_id.replace(":", "_"),
            "shortDescription": {"text": f.title[:120]},
            "helpUri": "https://github.com/mtvrkan/secaudit",
            "properties": {"tags": [f.cwe, f"OWASP-{f.owasp}", "security"],
                          "security-severity": _SARIF_SCORE.get(f.severity.value, "5.0")},
        })
    results = []
    for f in result.by_severity():
        results.append({
            "ruleId": f.detector_id,
            "ruleIndex": rule_index[f.detector_id],
            "level": _SARIF_LEVEL.get(f.severity.value, "warning"),
            "message": {"text": f"{f.title} ({f.cwe}, OWASP {f.owasp}). Fix: {f.fix}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": max(1, f.line)}}}],
            "partialFingerprints": {"secauditId": f"{f.detector_id}:{f.file}:{f.line}"},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SecAudit", "version": "1.0.0",
                "informationUri": "https://github.com/mtvrkan/secaudit",
                "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def to_json(result: ScanResult) -> str:
    return json.dumps({
        "target": result.target, "backend": result.backend,
        "tools_used": result.tools_used, "counts": result.counts(),
        "notes": result.notes,
        "findings": [f.to_dict() for f in result.by_severity()],
    }, indent=2)


def to_markdown(result: ScanResult) -> str:
    counts = result.counts()
    lines = [
        f"# SecAudit report — `{result.target}`", "",
        f"**Backend:** {result.backend}  ·  **Tools:** {', '.join(result.tools_used)}", "",
        "## Summary", "",
        "| Severity | Count |", "|---|---|",
    ]
    for s in Severity:
        lines.append(f"| {s.value} | {counts[s.value]} |")
    lines += ["", f"**Total findings:** {len(result.findings)}", "", "## Findings", ""]

    if not result.findings:
        lines.append("_No findings from the deterministic tier._")
    for f in result.by_severity():
        verdict = f.verdict.value
        conf = f.confidence.value
        lines += [
            f"### [{f.severity.value}] {f.title}",
            f"- **Location:** `{f.file}:{f.line}`",
            f"- **Class:** {f.cwe} · OWASP {f.owasp}  ·  **Detector:** `{f.detector_id}` "
            f"({f.source}, confidence {conf}, verdict {verdict})",
            f"- **Evidence:** `{f.evidence}`",
        ]
        if f.triage_note:
            lines.append(f"- **Triage:** {f.triage_note}")
        lines += [f"- **Fix:** {f.fix}", ""]

    if result.notes:
        lines += ["## Notes & limitations", ""]
        lines += [f"- {n}" for n in result.notes]
    lines += ["", "> Best-effort assessment, not a guarantee. The deterministic tier is a "
              "reproducible floor; detection quality with an LLM backend depends on the model."]
    return "\n".join(lines)
