"""Tier-0 engine — walk a source target, run the built-in detectors (and installed scanners
when present), and return a deduped ScanResult. No LLM involved; always runnable."""
from __future__ import annotations

import json
import os
import subprocess

from .detectors import detectors_for
from .schema import Finding, ScanResult, Severity, Confidence, Verdict
from . import scanners

# Higher-fidelity sources win when two findings collide at the same file/line/class.
_SOURCE_RANK = {"semgrep": 4, "osv": 4, "gitleaks": 4, "npm-audit": 3, "llm": 2, "builtin": 1}

SKIP_DIRS = {".git", "node_modules", "__pycache__", "dist", ".next", "venv", ".venv", "build"}
MAX_BYTES = 1_000_000  # skip files larger than 1 MB (assets, minified bundles)


def _iter_files(root: str):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield os.path.join(dirpath, name)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _evidence(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    line = text[start: end if end != -1 else len(text)].strip()
    return line[:200]


def scan_code(root: str) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_files(root):
        dets = detectors_for(path)
        if not dets:
            continue
        try:
            if os.path.getsize(path) > MAX_BYTES:
                continue
            text = open(path, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        rel = os.path.relpath(path, root if os.path.isdir(root) else os.path.dirname(root))
        for det in dets:
            sup = det.suppressor()
            if sup and sup.search(text):
                continue  # a control marker is present → cleared
            for m in det.regex().finditer(text):
                # Secret detectors must never print the value — redact the evidence line.
                evidence = ("[redacted] possible secret detected here (value not shown)"
                            if det.mask else _evidence(text, m.start()))
                findings.append(Finding(
                    detector_id=det.id, title=det.title, severity=det.severity,
                    confidence=det.confidence, cwe=det.cwe, owasp=det.owasp,
                    file=rel.replace("\\", "/"), line=_line_of(text, m.start()),
                    evidence=evidence, fix=det.fix,
                    source="builtin", verdict=Verdict.UNVERIFIED, maps_to=det.maps_to,
                ))
    return findings


def scan_dependencies(root: str, notes: list[str], tools: list[str]) -> list[Finding]:
    """Best-effort Claude-free dependency audit: run `npm audit --json` if a package.json and
    npm are present. Gracefully skipped otherwise. (Extension point for osv-scanner/pip-audit.)"""
    if not os.path.isdir(root) or not os.path.isfile(os.path.join(root, "package.json")):
        return []
    npm = any(os.access(os.path.join(p, exe), os.X_OK)
              for p in os.environ.get("PATH", "").split(os.pathsep)
              for exe in ("npm", "npm.cmd"))
    if not npm:
        notes.append("npm not found — dependency audit skipped (Tier-0 code scan still ran).")
        return []
    try:
        out = subprocess.run(["npm", "audit", "--json"], cwd=root, capture_output=True,
                             text=True, timeout=120, shell=(os.name == "nt"))
        data = json.loads(out.stdout)
    except Exception as e:  # offline / no lockfile / registry error
        notes.append(f"npm audit could not run ({e}) — dependency findings skipped.")
        return []
    tools.append("npm-audit")
    findings: list[Finding] = []
    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
               "moderate": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
    for name, v in (data.get("vulnerabilities") or {}).items():
        sev = sev_map.get(str(v.get("severity", "moderate")).lower(), Severity.MEDIUM)
        findings.append(Finding(
            detector_id="DEP-NPM", title=f"Vulnerable dependency: {name}",
            severity=sev, confidence=Confidence.HIGH, cwe="CWE-1395", owasp="A06",
            file="package.json", line=1,
            evidence=f"{name}: {v.get('severity', '?')} severity (npm audit)",
            fix=f"Upgrade `{name}` to a fixed version (`npm audit fix` / bump the pin).",
            source="npm-audit", verdict=Verdict.CONFIRMED,
        ))
    return findings


def _dedupe(findings: list[Finding]) -> list[Finding]:
    # 1) exact same rule + location.
    seen, primary = set(), []
    for f in findings:
        if f.key() in seen:
            continue
        seen.add(f.key())
        primary.append(f)
    # 2) collapse *cross-tool* duplicates — the same class at the same spot reported by more
    #    than one source. Group by (file, line, cwe); within a group keep only the findings
    #    from the highest-fidelity source present (a real scanner over the built-in regex lead).
    #    Findings that share the top source are distinct detectors the tool emitted on purpose,
    #    so they are ALL kept — keying on the source-max instead of overwriting one-per-key
    #    avoids silently dropping two genuinely different findings that share a CWE at one line.
    groups: dict[tuple, list[Finding]] = {}
    for f in primary:
        groups.setdefault((f.file, f.line, f.cwe), []).append(f)
    out: list[Finding] = []
    for group in groups.values():
        top = max(_SOURCE_RANK.get(f.source, 0) for f in group)
        out.extend(f for f in group if _SOURCE_RANK.get(f.source, 0) == top)
    return out


def scan(target: str, run_deps: bool = True, use_scanners: bool = True) -> ScanResult:
    result = ScanResult(target=target, backend="none")
    result.tools_used.append("builtin-detectors")
    result.findings.extend(scan_code(target))
    if use_scanners:
        result.findings.extend(scanners.run_installed_scanners(target, result.notes, result.tools_used))
    if run_deps:
        result.findings.extend(scan_dependencies(target, result.notes, result.tools_used))
    result.findings = _dedupe(result.findings)
    result.notes.append(
        "Tier-0 (deterministic, no LLM). IDOR / broken-access-control and other logic flaws "
        "are not reliably detectable without the enrichment tier; run with an LLM backend for triage "
        "+ logic-bug discovery.")
    return result
