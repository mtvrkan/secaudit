"""Tier-0 engine — walk a source target, run the built-in detectors (and installed scanners
when present), and return a deduped ScanResult. No LLM involved; always runnable."""
from __future__ import annotations

import json
import os
import subprocess

from .detectors import detectors_for, group_of
from .schema import Finding, ScanResult, Severity, Confidence, Verdict
from . import authz, deps, exploitation, redos, scanners, taint

# Higher-fidelity sources win when two findings collide at the same file/line/class.
# `taint` outranks `builtin` because a proven source→sink path is strictly more evidence than
# a pattern match at the same spot, and sits below the real scanners, which carry their own
# dataflow engines. It never *replaces* a corroborated finding, though — see `_corroborate`.
_SOURCE_RANK = {"semgrep": 4, "osv": 4, "gitleaks": 4, "npm-audit": 3, "taint": 3,
                "authz": 3, "redos": 3, "llm": 2, "builtin": 1}

# How far apart a pattern match and a taint path may be and still describe the same bug.
# The regex usually fires where the dangerous string is built and the taint path where it is
# consumed, which in real code is a line or two later.
_CORROBORATION_WINDOW = 3

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


def scan_code(root: str, only: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_files(root):
        dets = detectors_for(path)
        if only is not None:
            dets = [d for d in dets if group_of(d.id) in only]
        if not dets:
            continue
        try:
            if os.path.getsize(path) > MAX_BYTES:
                continue
            with open(path, encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        rel = os.path.relpath(path, root if os.path.isdir(root) else os.path.dirname(root))
        # Two views of the file. Code-shape rules match the view with comments and string
        # contents blanked, so a rule catalog mentioning `eval(` in a literal is not read as a
        # call to eval; literal rules (secrets, SQL fragments, quoted header names) match the
        # raw text. Offsets are identical in both, so evidence always comes from the original.
        view = taint.code_view(text, path)
        for det in dets:
            scanned = text if (det.literal or view is None) else view
            sup = det.suppressor()
            if sup and sup.search(scanned):
                continue  # a control marker is present → cleared
            for m in det.regex().finditer(scanned):
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


def _read_sources(root: str, exts: tuple[str, ...]) -> dict[str, str]:
    """Every analysable file under `root`, keyed by the forward-slash relative path every
    finding, SARIF location and golden-set id is keyed on."""
    files: dict[str, str] = {}
    for path in _iter_files(root):
        if not path.lower().endswith(exts):
            continue
        try:
            if os.path.getsize(path) > MAX_BYTES:
                continue
            with open(path, encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        rel = os.path.relpath(path, root if os.path.isdir(root) else os.path.dirname(root))
        files[rel.replace("\\", "/")] = text
    return files


def scan_authz(root: str) -> list[Finding]:
    """Run the authorization analysis — the two classes the pattern pack cannot decide.

    Separate from `scan_taint` because it asks a different question. Taint asks where a value
    came from; this asks whether the handler that used the value knew who was calling. A value
    can be perfectly clean and the handler still hand it to the wrong person."""
    return authz.analyze_files(_read_sources(root, authz.AUTHZ_EXTS))


def scan_redos(root: str) -> list[Finding]:
    """Run the catastrophic-backtracking analysis over every analysable file."""
    return redos.analyze_files(_read_sources(root, redos.REDOS_EXTS))


def scan_taint(root: str) -> list[Finding]:
    """Run the taint tier over every analyzable file and return one Finding per path.

    These are the findings the pattern pack structurally cannot produce: the source and the
    sink are usually on different lines, and the argument position matters (a value bound as
    a query parameter is the fix, not the bug). Confidence comes from the path's root — see
    `taint.TaintPath.confidence`."""
    # Read the whole analysable set first, then analyse it together. Per-file analysis cannot
    # see an import edge, and the import edge is where most real handler→helper flows live:
    # the route that reads the request and the module that does the dangerous thing are
    # almost never the same file.
    files = _read_sources(root, (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"))

    findings: list[Finding] = []
    for tp in taint.analyze_files(files):
        # A cross-module path is reported where the untrusted value enters, because that is
        # the route someone has to recognise — but the fix belongs in the callee, so the
        # callee's location is stated rather than left to be inferred from the path string.
        fix = (tp.sink.fix if tp.sink_file == tp.file
               else f"{tp.sink.fix} The dangerous call is in `{tp.sink_file}:{tp.sink_line}`; "
                    f"fix it there, and check the other callers of that function.")
        findings.append(Finding(
            detector_id=tp.sink.id, title=tp.sink.title,
            severity=_severity_for(tp.sink.severity, tp.confidence),
            confidence=tp.confidence, cwe=tp.sink.cwe, owasp=tp.sink.owasp,
            file=tp.file, line=tp.line, evidence=tp.evidence, fix=fix,
            source="taint", verdict=Verdict.UNVERIFIED, maps_to=tp.sink.maps_to,
            taint_path=tp.describe()))
    return findings


_SEVERITY_LADDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _severity_for(sink_severity: Severity, confidence: Confidence) -> Severity:
    """Severity is impact; confidence is certainty — but a report that ranks an unproven lead
    at Critical trains people to ignore Critical.

    A parameter-rooted path is a MEDIUM-confidence lead: whether the parameter carries
    untrusted data depends on callers we did not analyze. So it is reported one rung below the
    sink's inherent severity. Nothing is lost — where the pattern pack independently found the
    same sink, `_corroborate` keeps that finding at its full severity and merely attaches the
    path as evidence. This only caps findings the taint tier raised on its own.
    """
    if confidence == Confidence.HIGH:
        return sink_severity
    return _SEVERITY_LADDER[max(0, _SEVERITY_LADDER.index(sink_severity) - 1)]


def _corroborate(findings: list[Finding]) -> list[Finding]:
    """Fold taint evidence into the pattern findings it confirms, instead of double-reporting.

    A pattern hit and a taint path at the same spot are one bug seen twice. Reporting both
    inflates the count and makes the report look padded; dropping one throws away evidence.
    So the pattern finding absorbs the path — and, when the path is rooted in a framework
    request object, its confidence too, because reachability from untrusted input is exactly
    what "high confidence" is supposed to mean. Uncorroborated taint paths stay as their own
    findings; they are the ones the pattern pack could not see at all.

    Pairing is **nearest-first and one-to-one**, which is the part that has to be right. The
    window exists because a path is reported at the line the untrusted value entered while the
    pattern matched the line of the dangerous call, so the two are close but rarely equal. What
    the window does NOT establish is identity: two SQL injections a few lines apart in one file
    are the same file and the same CWE, and pairing in list order let the second one's pattern
    finding absorb the first one's path — deleting a real bug from the report while keeping the
    count plausible. Matching the closest pair first, and letting each finding be used once,
    means an exactly-coincident pair always wins and a genuinely separate bug is never consumed
    by its neighbour."""
    patterns = [f for f in findings if f.source != "taint"]
    paths = [f for f in findings if f.source == "taint"]

    candidates = sorted(
        (abs(path.line - pattern.line), pi, qi)
        for pi, pattern in enumerate(patterns)
        for qi, path in enumerate(paths)
        if path.file == pattern.file and path.cwe == pattern.cwe
        and abs(path.line - pattern.line) <= _CORROBORATION_WINDOW)

    paired_patterns: set[int] = set()
    absorbed: set[int] = set()
    for _, pi, qi in candidates:                  # ties break on index, so this is deterministic
        if pi in paired_patterns or qi in absorbed:
            continue
        pattern, path = patterns[pi], paths[qi]
        pattern.taint_path = path.taint_path
        if path.confidence == Confidence.HIGH:
            pattern.confidence = Confidence.HIGH
        paired_patterns.add(pi)
        absorbed.add(qi)

    return patterns + [p for i, p in enumerate(paths) if i not in absorbed]


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
            source="npm-audit", verdict=Verdict.CONFIRMED, package=name,
        ))
    return findings


def apply_vex(root: str, findings: list[Finding], notes: list[str]) -> list[Finding]:
    """Classify every dependency advisory by import reachability, in one place.

    Runs over any finding that names a package, whichever adapter produced it — npm audit,
    osv-scanner, or a future one. Doing this per adapter is how one of them silently ships
    without reachability, which is worse than not having it at all: the register would then
    look triaged while part of it was not."""
    packaged = [f for f in findings if f.package]
    if not packaged:
        return findings

    index = deps.build_import_index(root)
    runtime_deps, dev_deps = deps.read_manifest(root)
    indexable = deps.indexed_languages(root)
    if not indexable:
        notes.append("No JavaScript/TypeScript or Python source could be indexed — dependency "
                     "advisories are left `under_investigation` rather than assumed unreachable.")

    counts: dict[str, int] = {}
    for f in packaged:
        vex = deps.classify(f.package, index, runtime_deps, dev_deps, indexable)
        f.vex_status, f.vex_justification = vex.status, vex.justification
        f.triage_note = vex.note
        if not vex.reachable:
            # `not_affected` is a triage result, not a confirmation. A reader filtering on
            # CONFIRMED must not act on an advisory we ruled out.
            f.verdict = Verdict.PLAUSIBLE
            f.severity = _severity_for_vex(f.severity)
        counts[vex.status] = counts.get(vex.status, 0) + 1

    if counts:
        summary = ", ".join(f"{n} {status}" for status, n in sorted(counts.items()))
        notes.append(f"Dependency reachability (OpenVEX): {summary}. Import-level, not "
                     f"symbol-level — see the VEX status on each advisory for the evidence.")
    return findings


def _severity_for_vex(advisory_severity: Severity) -> Severity:
    """An advisory we have shown the product does not load is not a High.

    Two rungs down, because the gap between "your app is exploitable" and "a package you never
    import has a CVE" is wider than one step, and CI gates run on severity. The advisory stays
    in the register with its original severity in the evidence line — nothing is hidden, it is
    ranked honestly instead."""
    i = _SEVERITY_LADDER.index(advisory_severity)
    return _SEVERITY_LADDER[max(0, i - 2)]


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


def scan(target: str, run_deps: bool = True, use_scanners: bool = True,
         use_taint: bool = True, only: set[str] | None = None,
         check_exploitation: bool = False, use_authz: bool = True,
         use_redos: bool = True) -> ScanResult:
    result = ScanResult(target=target, backend="none")
    result.tools_used.append("builtin-detectors")
    result.findings.extend(scan_code(target, only))
    if use_taint:
        result.tools_used.append("taint")
        result.findings.extend(scan_taint(target))
    if use_authz:
        result.tools_used.append("authz")
        result.findings.extend(scan_authz(target))
    if use_redos:
        result.tools_used.append("redos")
        result.findings.extend(scan_redos(target))
    if use_scanners:
        result.findings.extend(scanners.run_installed_scanners(target, result.notes, result.tools_used))
    if run_deps:
        result.findings.extend(scan_dependencies(target, result.notes, result.tools_used))
    # After every dependency source has reported, so one pass classifies them all.
    apply_vex(target, result.findings, result.notes)
    # Corroborate BEFORE dedupe, not after. Dedupe collapses same-location findings by source
    # rank, and `taint` outranks `builtin` — running it first would delete the pattern finding
    # that corroboration exists to enrich, losing its detector id, its severity and the LLM
    # tier's triage key along with it.
    result.findings = _dedupe(_corroborate(result.findings))
    if check_exploitation:
        # After dedupe: the same advisory can arrive from npm audit and osv, and asking two
        # feeds about the same CVE twice is a slower way to get the same answer.
        cves = [f.detector_id for f in result.findings]
        catalog = exploitation.fetch(list(cves))
        exploitation.apply(result.findings, catalog, result.notes)
        result.tools_used.append("cisa-kev+first-epss")

    result.notes.append(
        "Tier-0 (deterministic, no LLM). Business-logic flaws — the rules being broken are the "
        "product's, and they are not written down anywhere the analyzer can read — remain "
        "outside this tier; run with an LLM backend for triage + logic-bug discovery.")
    if use_taint:
        result.notes.extend(taint.limitations())
    if use_authz:
        result.notes.extend(authz.limitations())
    if use_redos:
        result.notes.extend(redos.limitations())
    return result
