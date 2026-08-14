"""Render a ScanResult as Markdown or JSON."""
from __future__ import annotations

import hashlib
import json

from . import i18n
from .schema import ScanResult, Severity


_SARIF_SCORE = {"Critical": "9.0", "High": "7.5", "Medium": "5.0",
                "Low": "3.0", "Informational": "1.0"}
_SARIF_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning",
                "Low": "note", "Informational": "note"}


def _fingerprints(findings: list) -> dict[int, str]:
    """A stable identity per finding, for GitHub code scanning's alert tracking.

    Two properties are needed and they pull against each other. The fingerprint must **survive a
    line shift**, or an edit anywhere above an alert closes it and opens a new one, taking the
    dismissal and the review comments with it. And it must be **unique**, or code scanning merges
    two findings into one alert and the second disappears from the UI.

    Content alone gives the first and not the second: on this repository's own source, hashing
    (detector, file, CWE, evidence) collided on 3 of 100 findings — the same literal matched on
    two lines. So identical-content findings are additionally ordered by line and numbered. The
    ordinal is what keeps them distinct, and ordering by line is what keeps it stable: inserting
    a line above shifts every line and changes no relative order. Inserting a *new identical
    finding* between two others does renumber the ones after it, which is the residual case and
    is rarer than the edit this exists to survive.
    """
    keyed: dict[str, list] = {}
    for f in findings:
        evidence = " ".join((f.evidence or "").split())
        keyed.setdefault(f"{f.detector_id}\n{f.file}\n{f.cwe}\n{evidence}", []).append(f)

    out: dict[int, str] = {}
    for seed, group in keyed.items():
        for ordinal, f in enumerate(sorted(group, key=lambda g: g.line)):
            digest = hashlib.sha256(f"{seed}\n#{ordinal}".encode()).hexdigest()
            out[id(f)] = digest[:32]
    return out


def to_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0 for GitHub code scanning. `security-severity` on each rule drives the
    severity GitHub shows; `level` drives the annotation style."""
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
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
    fingerprint = _fingerprints(result.findings)
    for f in result.by_severity():
        # GitHub code scanning shows the message inline on the diff, where the reachability
        # path is the difference between "a reviewer dismisses this" and "a reviewer fixes it".
        reach = f" Reachability: {f.taint_path}." if f.taint_path else ""
        results.append({
            "ruleId": f.detector_id,
            "ruleIndex": rule_index[f.detector_id],
            "level": _SARIF_LEVEL.get(f.severity.value, "warning"),
            "message": {"text": f"{f.title} ({f.cwe}, OWASP {f.owasp}).{reach} Fix: {f.fix}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": max(1, f.line)}}}],
            # Deliberately NOT keyed on the line number, which is what this used to be
            # (`detector:file:line`). A fingerprint exists so GitHub can recognise the same
            # alert after the code moves; one containing the line changes whenever anything
            # above it does, so code scanning closed the alert and opened a new one on every
            # unrelated edit — losing the dismissal, the assignee and the comments with it.
            # Keyed on the matched evidence instead: stable under line shifts, and distinct
            # between two hits of one rule in one file.
            "partialFingerprints": {"secauditId": fingerprint[id(f)]},
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


_SEMGREP_SEVERITY = {"Critical": "ERROR", "High": "ERROR", "Medium": "WARNING",
                     "Low": "INFO", "Informational": "INFO"}


def to_semgrep_json(result: ScanResult) -> str:
    """Semgrep CLI JSON — the de-facto interchange format for SAST results.

    Worth carrying even though SARIF exists, because a lot of tooling ingests Semgrep JSON
    directly and does not speak SARIF. Concretely: the
    [RealVuln benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark) scores any scanner
    that emits this shape without needing a bespoke parser, which is how SecAudit gets an
    externally computed number instead of one it grades itself.

    Only the fields consumers actually read are emitted. `col`/`offset` are stated as 1/0
    rather than invented: the engine works line-granular, and a fabricated column would be a
    precise-looking lie in a file whose whole purpose is being compared against ground truth.
    """
    results = []
    for f in result.by_severity():
        line = max(1, f.line)
        metadata = {
            "cwe": [f.cwe],
            "owasp": [f"OWASP {f.owasp}"],
            "confidence": f.confidence.value.upper(),
            "source": f.source,
            "references": ["https://github.com/mtvrkan/secaudit"],
        }
        if f.taint_path:
            metadata["taint_path"] = f.taint_path
        if f.vex_status:
            metadata["vex_status"] = f.vex_status
            if f.vex_justification:
                metadata["vex_justification"] = f.vex_justification
        if f.exploitation:
            metadata["exploitation"] = f.exploitation
        results.append({
            "check_id": f.detector_id,
            "path": f.file,
            "start": {"line": line, "col": 1, "offset": 0},
            "end": {"line": line, "col": 1, "offset": 0},
            "extra": {
                "message": f"{f.title} ({f.cwe}, OWASP {f.owasp}). Fix: {f.fix}",
                "metadata": metadata,
                "severity": _SEMGREP_SEVERITY.get(f.severity.value, "WARNING"),
                "lines": f.evidence,
                "fingerprint": f"{f.detector_id}:{f.file}:{f.line}",
                "is_ignored": False,
            },
        })
    return json.dumps({
        "version": "secaudit-1.0.0",
        "results": results,
        "errors": [],
        "paths": {"scanned": sorted({f.file for f in result.findings})},
    }, indent=2)


def to_cra_pack(result: ScanResult) -> str:
    """The CRA evidence pack: SBOM + vulnerability register + VEX + clause mapping, in one file.

    Not a compliance certificate, and it says so in its own `disclaimer` field. It is the set
    of artefacts the Cyber Resilience Act's vulnerability-handling obligations (Annex I Part
    II, applying from 2026-09-11) expect a manufacturer to be able to produce on request, in
    the machine-readable shape the regulation asks for — assembled from one scan instead of
    from four tools and a spreadsheet.

    The honest framing matters more here than anywhere else in the tool: producing this
    document does not make a product compliant, and a report that implied otherwise would be
    worse than useless to the person relying on it."""
    from . import compliance, sbom

    register: list[dict] = []
    for f in result.by_severity():
        # `actively_exploited` is not something the deterministic tier can know yet — KEV/EPSS
        # enrichment is a separate, network-bound step. Emitting the field as an explicit null
        # rather than `false` keeps the difference between "checked, not exploited" and "not
        # checked" visible to whoever files the Article 14 notification.
        register.append({
            "id": f.detector_id,
            "title": f.title,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "cwe": f.cwe,
            "owasp": f.owasp,
            "asvs_chapter": (compliance.asvs_for(f.cwe) or (None, None))[0],
            # `null` here means this project refuses to name a requirement for this weakness,
            # not that none applies — `compliance.PCI_NOT_ASSERTABLE` carries the reason per
            # CWE, and `pci_scope_note()` states the two limits that produce most of them.
            "pci_dss_requirement": (compliance.pci_for(f.cwe) or (None, None))[0],
            "location": f"{f.file}:{f.line}",
            "component": f.package or None,
            "vex_status": f.vex_status or None,
            "vex_justification": f.vex_justification or None,
            # The CRA's 24-hour early-warning obligation triggers on ACTIVELY EXPLOITED
            # vulnerabilities, not on every CVE. This field is the one a regulator's question
            # lands on, so it is in the register even when the feeds were not consulted —
            # `null` there means "not checked", which is a different answer from "listed".
            "exploitation": f.exploitation or None,
            "exploitation_evidence": f.exploitation_note or None,
            "reachability": f.taint_path or None,
            "actively_exploited": None,
            "cra_clauses": compliance.cra_clauses_for(
                f.cwe, is_dependency=bool(f.package), actively_exploited=False),
            "remediation": f.fix,
        })

    pack = {
        "artifact": "secaudit-cra-evidence-pack",
        "regulation": compliance.CRA_REGULATION,
        "vulnerability_handling_obligations_apply_from": compliance.CRA_REPORTING_STARTS,
        "target": result.target,
        "tools_used": result.tools_used,
        "backend": result.backend,
        "sbom": (sbom.build(result.target) if sbom.is_supported(result.target) else None),
        "sbom_note": (None if sbom.is_supported(result.target) else
                      "No npm manifest found; no SBOM produced. SecAudit generates CycloneDX "
                      "for npm projects only today — an absent SBOM here means unsupported "
                      "ecosystem, not a product without dependencies."),
        "vulnerability_register": register,
        "clause_coverage": {
            clause: compliance.CRA_CLAUSES[clause]
            for clause in sorted({c for entry in register for c in entry["cra_clauses"]
                                  if c in compliance.CRA_CLAUSES}
                                 | set(compliance.scan_evidences()))
        },
        "evidence_of_testing": {
            "clause": compliance.scan_evidences(),
            "note": "This scan is one dated, reproducible security review. Annex I Part II (3) "
                    "expects them to be regular and to continue through the support period; a "
                    "single run is evidence of one review, not of a programme.",
        },
        "limitations": result.notes,
        # Carried alongside the CRA pack because a register that names PCI requirement ids and
        # not their bounds is the half of the mapping that gets quoted.
        "pci_dss": {
            "version": compliance.PCI_VERSION,
            "requirements_referenced": {
                req: compliance.PCI_REQUIREMENTS[req]
                for req in sorted({entry["pci_dss_requirement"] for entry in register
                                   if entry["pci_dss_requirement"]})
            },
            "scope_note": compliance.pci_scope_note(),
            "not_asserted": compliance.PCI_NOT_ASSERTABLE,
        },
        "disclaimer": (
            "This pack is INPUT to a compliance process, not evidence of compliance. It "
            "contains no conformity assessment, no risk assessment under Article 13, and no "
            "legal opinion. Findings are best-effort and bounded by scope, tooling and the "
            "limitations listed above. Exploitation status is not determined — the Article 14 "
            "reporting duty is triggered by ACTIVE exploitation, which requires threat "
            "intelligence this tool does not consult. Have qualified counsel and your "
            "conformity assessment body review anything filed."
        ),
    }
    return json.dumps(pack, indent=2, ensure_ascii=False)


def to_openvex(result: ScanResult) -> str:
    """OpenVEX document for the classified dependency advisories.

    Separate from the report on purpose: this is the machine-readable answer to "which of
    these advisories affect the product", which is the question the EU CRA's reporting duty
    (from 2026-09-11) actually asks. Consumers ingest it; humans read the report."""
    from . import deps
    statements = [deps.vex_statement(f.package, f.detector_id,
                                     deps.Verdict(f.vex_status, f.vex_justification,
                                                  f.triage_note))
                  for f in result.by_severity() if f.package and f.vex_status]
    return deps.to_openvex(result.target, statements)


def to_json(result: ScanResult) -> str:
    return json.dumps({
        "target": result.target, "backend": result.backend,
        "tools_used": result.tools_used, "counts": result.counts(),
        "notes": result.notes,
        "findings": [f.to_dict() for f in result.by_severity()],
    }, indent=2)


_SEVERITY_COLOR = {"Critical": "#b3261e", "High": "#b34a1f", "Medium": "#8a5a00",
                   "Low": "#4a5a6a", "Informational": "#5f5c53"}


def _esc(text: str) -> str:
    """HTML-escape. A security report renders attacker-influenced strings — file paths,
    evidence lines, triage notes written by a model — so escaping is not cosmetic here: an
    unescaped evidence line is a scanner that plants XSS in its own findings page."""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def to_html(result: ScanResult, locale: str = i18n.DEFAULT) -> str:
    """A self-contained, printable HTML report — and the PDF path, via the browser's own
    print-to-PDF rather than a rendering dependency the kit would have to ship and pin.

    Self-contained means exactly that: no external stylesheet, script, font or image, so the
    file can be attached to a ticket, mailed to an auditor, or opened on a machine with no
    network and render identically. Executive summary and technical body are separate sections
    because they have different readers, and the print rules keep a finding from splitting
    across a page break.

    `locale` selects the same bundle `to_markdown` uses, and localizes the same layer: the
    report's own furniture, never a finding's title, evidence or fix. This renderer took no
    locale at all until it was noticed that `--lang tr --format html` was accepted and produced
    an English document — the flag was not refused, it was ignored, which is the failure mode the
    CLI's `--summary` and `--suggest-patches` handling had in the same pass."""
    t = i18n.Strings(locale)
    counts = result.counts()
    total = len(result.findings)
    top = [f for f in result.by_severity() if f.severity.rank >= Severity.HIGH.rank]

    cards = "".join(
        f'<div class="card" style="--c:{_SEVERITY_COLOR[s.value]}">'
        f'<b>{counts[s.value]}</b><span>{_esc(t.severity(s.value))}</span></div>'
        for s in Severity)

    blocks = []
    for f in result.by_severity():
        # Built before the f-string, not inside it: an expression spanning lines within `{}` is
        # a syntax error until 3.12 and this package advertises a lower floor (check 32).
        meta = t("field.detector_meta", source=f.source, confidence=f.confidence.value,
                 verdict=f.verdict.value)
        rows = [(t("field.location"), f"<code>{_esc(f.file)}:{f.line}</code>"),
                (t("field.class"), f"{_esc(f.cwe)} · OWASP {_esc(f.owasp)}"),
                (t("field.detector"),
                 f"<code>{_esc(f.detector_id)}</code> ({_esc(meta)})"),
                (t("field.evidence"), f"<pre>{_esc(f.evidence)}</pre>")]
        if f.taint_path:
            rows.append((t("field.reachability"), f"<pre>{_esc(f.taint_path)}</pre>"))
        if f.vex_status:
            just = f" ({_esc(f.vex_justification)})" if f.vex_justification else ""
            rows.append((t("field.vex"), f"<code>{_esc(f.vex_status)}</code>{just}"))
        if f.exploitation:
            note = f" {_esc(f.exploitation_note)}" if f.exploitation_note else ""
            rows.append((t("field.exploitation"), f"<code>{_esc(f.exploitation)}</code>{note}"))
        if f.triage_note:
            rows.append((t("field.triage"), _esc(f.triage_note)))
        rows.append((t("field.fix"), _esc(f.fix)))
        body = "".join(f"<tr><th>{_esc(label)}</th><td>{value}</td></tr>"
                       for label, value in rows)
        blocks.append(
            f'<article class="finding" style="--c:{_SEVERITY_COLOR[f.severity.value]}">'
            f'<h3><span class="sev">{_esc(f.severity.value)}</span> {_esc(f.title)}</h3>'
            f"<table>{body}</table></article>")

    target_html = f"<code>{_esc(result.target)}</code>"
    if total:
        breakdown = ", ".join(f"{counts[s.value]} {t.severity(s.value).lower()}"
                              for s in Severity if counts[s.value])
        lede = _esc(t("html.lede", n=total, target="\x00", breakdown=breakdown))
    else:
        lede = _esc(t("html.lede_none", target="\x00"))
    # The target is substituted AFTER escaping so its `<code>` markup survives while everything
    # the bundle contributed is still escaped. A NUL placeholder cannot occur in a locale string.
    lede = lede.replace("\x00", target_html)

    notes = "".join(f"<li>{_esc(n)}</li>" for n in result.notes)

    return f"""<!doctype html>
<html lang="{_esc(t.locale)}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(t("html.title"))} — {_esc(result.target)}</title>
<style>
:root{{--bg:#fbfbfa;--panel:#fff;--ink:#16150f;--muted:#5f5c53;--line:#e5e2dc;--code:#f3f1ec}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{
  --bg:#131311;--panel:#1a1a17;--ink:#f2f0ea;--muted:#a09c92;--line:#2e2d28;--code:#211f1b}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);
 font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}}
.wrap{{max-width:60rem;margin:0 auto;padding:2.5rem 1.25rem 4rem}}
h1{{font-size:1.7rem;margin:0 0 .35rem;letter-spacing:-.02em}}
.meta{{color:var(--muted);font-size:.9rem;margin:0 0 2rem}}
h2{{font-size:1.15rem;margin:2.5rem 0 .75rem;padding-bottom:.4rem;border-bottom:1px solid var(--line)}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(7rem,1fr));gap:.6rem}}
.card{{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--c);
 border-radius:8px;padding:.75rem}}
.card b{{display:block;font-size:1.5rem;line-height:1.1}}
.card span{{color:var(--muted);font-size:.78rem}}
.finding{{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--c);
 border-radius:8px;padding:1rem 1.1rem;margin:0 0 .9rem;break-inside:avoid}}
.finding h3{{margin:0 0 .6rem;font-size:1rem}}
.sev{{color:var(--c);font-weight:700;text-transform:uppercase;font-size:.72rem;
 letter-spacing:.07em;margin-right:.5rem}}
table{{width:100%;border-collapse:collapse;font-size:.9rem}}
th{{text-align:left;vertical-align:top;color:var(--muted);font-weight:600;width:9rem;
 padding:.25rem .75rem .25rem 0;white-space:nowrap}}
td{{padding:.25rem 0;vertical-align:top}}
code{{background:var(--code);padding:.1em .35em;border-radius:4px;
 font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.88em}}
pre{{background:var(--code);border:1px solid var(--line);border-radius:6px;margin:.15rem 0;
 padding:.5rem .6rem;overflow-x:auto;white-space:pre-wrap;word-break:break-word;
 font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.85em}}
ul{{margin:.5rem 0;padding-left:1.2rem;color:var(--muted);font-size:.9rem}}
footer{{margin-top:2.5rem;padding-top:1rem;border-top:1px solid var(--line);
 color:var(--muted);font-size:.85rem}}
@media print{{
  :root{{--bg:#fff;--panel:#fff;--ink:#000;--muted:#444;--line:#ccc;--code:#f4f4f4}}
  .wrap{{max-width:none;padding:0}}
  h2{{break-after:avoid}}
}}
</style></head><body><div class="wrap">
<h1>{_esc(t("html.title"))}</h1>
<p class="meta"><code>{_esc(result.target)}</code> ·
 {_esc(t("html.meta", backend=result.backend, tools=', '.join(result.tools_used)))}</p>

<h2>{_esc(t("report.summary"))}</h2>
<p>{lede}</p>
<div class="cards">{cards}</div>
{'<p>' + _esc(t("html.top", n=len(top))) + '</p>' if top else ''}

<h2>{_esc(t("report.findings"))}</h2>
{''.join(blocks) or '<p>' + _esc(t("html.none")) + '</p>'}

<h2>{_esc(t("html.notes"))}</h2>
<ul>{notes or '<li>' + _esc(t("html.notes_none")) + '</li>'}</ul>

<footer>{_esc(t("html.footer"))} {_esc(t("clean.meaning"))}
{_esc(t("lang.note")) if t.locale != i18n.DEFAULT else ''}</footer>
</div></body></html>
"""


def to_markdown(result: ScanResult, locale: str = i18n.DEFAULT) -> str:
    """The human-readable report. `locale` selects the bundle under `i18n/`.

    Only the report's own furniture is localized. Finding titles, evidence and fix text come
    from the detector definitions and stay in English — see `i18n.py` for why translating them
    would make the tool less safe rather than more accessible.
    """
    t = i18n.Strings(locale)
    counts = result.counts()
    lines = [
        "# " + t("report.title", target=result.target), "",
        t("report.meta", backend=result.backend, tools=", ".join(result.tools_used)), "",
        "## " + t("report.summary"), "",
        f"| {t('report.severity')} | {t('report.count')} |", "|---|---|",
    ]
    for s in Severity:
        lines.append(f"| {t.severity(s.value)} | {counts[s.value]} |")
    lines += ["", t("report.total", n=len(result.findings)), "",
              "## " + t("report.findings"), ""]

    if not result.findings:
        lines.append(t("report.none"))
    for f in result.by_severity():
        lines += [
            f"### [{t.severity(f.severity.value)}] {f.title}",
            f"- **{t('field.location')}:** `{f.file}:{f.line}`",
            f"- **{t('field.class')}:** {f.cwe} · OWASP {f.owasp}  ·  "
            f"**{t('field.detector')}:** `{f.detector_id}` "
            f"({t('field.detector_meta', source=f.source, confidence=f.confidence.value, verdict=f.verdict.value)})",
            f"- **{t('field.evidence')}:** `{f.evidence}`",
        ]
        # The path is the argument. A reviewer who disagrees with a finding needs the hops to
        # point at, not a verdict to accept — so it is rendered in full, never summarized.
        if f.taint_path:
            lines.append(f"- **{t('field.reachability')}:** `{f.taint_path}`")
        if f.vex_status:
            just = f" ({f.vex_justification})" if f.vex_justification else ""
            lines.append(f"- **{t('field.vex')}:** `{f.vex_status}`{just}")
        if f.exploitation:
            note = f" {f.exploitation_note}" if f.exploitation_note else ""
            lines.append(f"- **{t('field.exploitation')}:** `{f.exploitation}`{note}")
        if f.triage_note:
            lines.append(f"- **{t('field.triage')}:** {f.triage_note}")
        lines += [f"- **{t('field.fix')}:** {f.fix}", ""]

    if result.notes:
        lines += ["## " + t("report.notes"), ""]
        lines += [f"- {n}" for n in result.notes]
    lines += ["", "> " + t("clean.meaning")]
    if locale != i18n.DEFAULT:
        lines += ["", "> " + t("lang.note")]
    return "\n".join(lines)
