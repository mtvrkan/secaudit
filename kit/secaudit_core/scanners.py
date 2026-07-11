"""Installed-scanner integration (Tier 0, still LLM-free). When a real scanner is present it
is higher-fidelity than the built-in regex pack, so the engine prefers it and falls back to the
pack otherwise. Each adapter: detect the tool, run it, parse its native output into Findings.
Gracefully skipped (with a note) when the tool is absent or errors.

The parse_* functions are pure (text -> findings) so they are unit-tested against captured
sample outputs without needing the tools installed."""
from __future__ import annotations

import json
import os
import shutil
import subprocess

from .schema import Finding, Severity, Confidence, Verdict


def _has(tool: str) -> bool:
    return shutil.which(tool) is not None


def _num_to_sev(score) -> Severity:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return Severity.MEDIUM
    if s >= 9.0:
        return Severity.CRITICAL
    if s >= 7.0:
        return Severity.HIGH
    if s >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


_LEVEL_SEV = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "note": Severity.LOW,
              "none": Severity.INFO}
_WORD_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "moderate": Severity.MEDIUM,
             "medium": Severity.MEDIUM, "low": Severity.LOW}


def _first_cwe(*texts) -> str:
    import re
    for t in texts:
        if not t:
            continue
        m = re.search(r"CWE[-\s]?(\d+)", str(t), re.I)
        if m:
            return f"CWE-{m.group(1)}"
    return "CWE-Other"


# --------------------------------------------------------------------------- semgrep (SARIF)
def parse_semgrep_sarif(text: str) -> list[Finding]:
    data = json.loads(text)
    findings: list[Finding] = []
    for run in data.get("runs", []):
        # rule metadata (for cwe / severity) keyed by id
        rules = {}
        for r in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules[r.get("id")] = r
        for res in run.get("results", []):
            rid = res.get("ruleId", "semgrep-rule")
            rule = rules.get(rid, {})
            props = {**rule.get("properties", {}), **res.get("properties", {})}
            sev = (_num_to_sev(props.get("security-severity"))
                   if props.get("security-severity") is not None
                   else _LEVEL_SEV.get(str(res.get("level", "warning")).lower(), Severity.MEDIUM))
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "?")
            line = loc.get("region", {}).get("startLine", 1)
            tags = props.get("tags", []) or props.get("cwe", [])
            findings.append(Finding(
                detector_id=f"semgrep:{rid}", title=res.get("message", {}).get("text", rid)[:200],
                severity=sev, confidence=Confidence.HIGH,
                cwe=_first_cwe(rule.get("name"), " ".join(map(str, tags)), rid),
                owasp="A03", file=str(uri).replace("\\", "/"), line=int(line or 1),
                evidence=res.get("message", {}).get("text", "")[:200],
                fix="See the semgrep rule guidance; remediate the flagged sink.",
                source="semgrep", verdict=Verdict.UNVERIFIED))
    return findings


# --------------------------------------------------------------------------- gitleaks (JSON)
def _mask(secret: str) -> str:
    secret = str(secret or "")
    return (secret[:4] + "*" * max(0, len(secret) - 4)) if secret else "****"


def parse_gitleaks_json(text: str) -> list[Finding]:
    data = json.loads(text) or []
    findings: list[Finding] = []
    for it in data:
        findings.append(Finding(
            detector_id=f"gitleaks:{it.get('RuleID', 'secret')}",
            title=f"Hardcoded secret: {it.get('Description', it.get('RuleID', 'secret'))}"[:200],
            severity=Severity.HIGH, confidence=Confidence.HIGH, cwe="CWE-798", owasp="A07",
            file=str(it.get("File", "?")).replace("\\", "/"), line=int(it.get("StartLine", 1) or 1),
            evidence=f"{it.get('RuleID', 'secret')} (masked: {_mask(it.get('Secret') or it.get('Match'))})",
            fix="Remove the secret from source, rotate it, purge git history, use a secret manager.",
            source="gitleaks", verdict=Verdict.CONFIRMED))
    return findings


# --------------------------------------------------------------------------- osv-scanner (JSON)
def parse_osv_json(text: str) -> list[Finding]:
    data = json.loads(text)
    findings: list[Finding] = []
    for res in data.get("results", []):
        src = res.get("source", {}).get("path", "dependencies")
        for pkg in res.get("packages", []):
            p = pkg.get("package", {})
            name, ver = p.get("name", "?"), p.get("version", "?")
            for v in pkg.get("vulnerabilities", []):
                sev_word = str(v.get("database_specific", {}).get("severity", "")).lower()
                sev = _WORD_SEV.get(sev_word, Severity.MEDIUM)
                vid = v.get("id", "OSV")
                findings.append(Finding(
                    detector_id=f"osv:{vid}", title=f"Vulnerable dependency: {name}@{ver} ({vid})"[:200],
                    severity=sev, confidence=Confidence.HIGH,
                    cwe=_first_cwe(v.get("summary")), owasp="A06",
                    file=str(src).replace("\\", "/"), line=1,
                    evidence=(v.get("summary") or vid)[:200],
                    fix=f"Upgrade `{name}` beyond the affected range ({vid}).",
                    source="osv", verdict=Verdict.CONFIRMED))
    return findings


# --------------------------------------------------------------------------- live runners
def run_semgrep(root: str, notes: list[str], tools: list[str]) -> list[Finding]:
    if not _has("semgrep"):
        return []
    try:
        out = subprocess.run(["semgrep", "--sarif", "--config", "auto", "--quiet", root],
                             capture_output=True, text=True, timeout=600)
        findings = parse_semgrep_sarif(out.stdout)
        tools.append("semgrep")
        return findings
    except Exception as e:
        notes.append(f"semgrep present but failed ({e}); used the built-in pack instead.")
        return []


def run_gitleaks(root: str, notes: list[str], tools: list[str]) -> list[Finding]:
    if not _has("gitleaks"):
        return []
    try:
        out = subprocess.run(["gitleaks", "detect", "--no-banner", "--report-format", "json",
                             "--report-path", "-", "--source", root],
                             capture_output=True, text=True, timeout=300)
        findings = parse_gitleaks_json(out.stdout or "[]")
        tools.append("gitleaks")
        return findings
    except Exception as e:
        notes.append(f"gitleaks present but failed ({e}); secret scan limited to the built-in pack.")
        return []


def run_osv(root: str, notes: list[str], tools: list[str]) -> list[Finding]:
    if not _has("osv-scanner"):
        return []
    try:
        out = subprocess.run(["osv-scanner", "--format", "json", "-r", root],
                             capture_output=True, text=True, timeout=300)
        findings = parse_osv_json(out.stdout or "{}")
        tools.append("osv-scanner")
        return findings
    except Exception as e:
        notes.append(f"osv-scanner present but failed ({e}); dependency scan fell back to npm audit.")
        return []


def run_installed_scanners(root: str, notes: list[str], tools: list[str]) -> list[Finding]:
    """Run whichever real scanners are on PATH; return their normalized findings."""
    if not os.path.isdir(root):
        return []
    findings: list[Finding] = []
    findings += run_semgrep(root, notes, tools)
    findings += run_gitleaks(root, notes, tools)
    findings += run_osv(root, notes, tools)
    absent = [t for t in ("semgrep", "gitleaks", "osv-scanner") if not _has(t)]
    if absent:
        notes.append("Not installed: " + ", ".join(absent)
                    + " — used the built-in detector pack for those. Install them for higher fidelity.")
    return findings
