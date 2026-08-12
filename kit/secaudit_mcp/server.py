"""MCP stdio server for SecAudit. Standard library only, like the rest of the kit.

    python3 -m secaudit_mcp            # speak MCP over stdin/stdout
    python3 -m secaudit_mcp --tools    # print the tool manifest and exit (used by the gate)

Protocol: JSON-RPC 2.0, one message per line, over stdio — the transport every MCP client
implements. The three methods a client actually needs are `initialize`, `tools/list` and
`tools/call`; notifications (`notifications/*`) get no response, which is what makes them
notifications and what a naive implementation gets wrong.

Two design decisions worth stating, because both cost features on purpose:

**No active-scan tools.** No tool here probes a system. `scan_source` reads files the
caller already has; `scan_dependencies` and `compliance_pack` may query an advisory database
through an installed scanner (`npm audit`, `osv-scanner`), which is a network call about
package names, not a request aimed at anyone's host. The distinction is the whole point, so it
is stated rather than rounded to "offline": the plugin's live mode exists and stays behind its
`scope.yaml` authorization gate, because an MCP `tools/call` carries no evidence that anyone
consented to have a system probed, and a tool that scans a URL on request is a tool that scans
whatever a prompt injection puts in front of it.

**`coverage` is a first-class tool, not documentation.** An MCP client that gets findings but
cannot get the bounds will report "no issues found" as "this is secure". So the same
generated limitations the reports carry are callable, and the description of every scanning
tool points at it.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secaudit_core import compliance, engine, report, sbom, taint      # noqa: E402
from secaudit_core.detectors import DETECTORS                          # noqa: E402

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "secaudit"
SERVER_VERSION = "1.0.0"

# JSON-RPC error codes we can actually produce (the spec's reserved range).
PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS = -32700, -32600, -32601, -32602

_BOUNDS = ("Call `coverage` for what this engine cannot see. A clean result means these rules "
           "did not fire — it is not a statement that the code is safe.")

_PATH = {"type": "string", "description": "File or directory to analyse, on this machine."}

TOOLS: list[dict] = [
    {
        "name": "scan_source",
        "description": ("Run SecAudit's deterministic Tier-0 audit over source you already "
                        "have: pattern detectors plus source→sink taint analysis. No "
                        "network, no LLM, no target is contacted. " + _BOUNDS),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": _PATH,
                "min_severity": {"type": "string",
                                 "enum": ["informational", "low", "medium", "high", "critical"],
                                 "description": "Omit findings below this severity."},
                "format": {"type": "string", "enum": ["markdown", "json", "sarif"],
                           "description": "Report format. Default markdown."},
                "taint": {"type": "boolean",
                          "description": "Run the taint tier. Default true; false is pattern "
                                         "matching only and loses every proven path."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "scan_dependencies",
        "description": ("Audit declared dependencies and classify each advisory by whether the "
                        "code actually imports the package — OpenVEX `affected` / "
                        "`not_affected` / `under_investigation`, with the evidence for the "
                        "call. Import-level, not symbol-level. Queries an advisory database "
                        "via an installed scanner, so it needs a network — but it contacts no "
                        "target. " + _BOUNDS),
        "inputSchema": {
            "type": "object",
            "properties": {"path": _PATH},
            "required": ["path"],
        },
    },
    {
        "name": "generate_sbom",
        "description": ("Emit a CycloneDX 1.6 SBOM for the target. Versions that cannot be "
                        "resolved from a lockfile are flagged, never guessed from a range."),
        "inputSchema": {
            "type": "object",
            "properties": {"path": _PATH},
            "required": ["path"],
        },
    },
    {
        "name": "compliance_pack",
        "description": ("Emit the EU Cyber Resilience Act evidence pack: SBOM + vulnerability "
                        "register with reachability + ASVS chapter mapping + clause coverage. "
                        "Input to a compliance process, not a certificate."),
        "inputSchema": {
            "type": "object",
            "properties": {"path": _PATH},
            "required": ["path"],
        },
    },
    {
        "name": "explain_finding",
        "description": ("Explain one detector or taint sink by id (e.g. `SEC-JS-SQLI`, "
                        "`TAINT-PY-SQLI`): what it matches, its CWE and ASVS chapter, the fix, "
                        "and how confident the rule is by construction."),
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string",
                                  "description": "Detector or taint sink id, as reported in a "
                                                 "finding."}},
            "required": ["id"],
        },
    },
    {
        "name": "coverage",
        "description": ("What this engine can and cannot see: analysis depth per language, the "
                        "taint tier's documented bounds, and the vulnerability classes with no "
                        "deterministic coverage. Call this before reporting that code is clean."),
        "inputSchema": {"type": "object", "properties": {}},
    },
]

_TOOL_NAMES = {t["name"] for t in TOOLS}
_SEVERITY_RANK = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


# --------------------------------------------------------------------------- tool bodies

def _require_path(args: dict) -> str:
    path = args.get("path")
    if not isinstance(path, str) or not path:
        raise ValueError("`path` is required and must be a string.")
    if not os.path.exists(path):
        raise ValueError(f"No such file or directory: {path}")
    return path


def _scan_source(args: dict) -> str:
    path = _require_path(args)
    result = engine.scan(path, run_deps=False, use_taint=args.get("taint", True) is not False)

    floor = _SEVERITY_RANK.get(str(args.get("min_severity", "")).lower(), 0)
    if floor:
        result.findings = [f for f in result.findings if f.severity.rank >= floor]

    fmt = args.get("format", "markdown")
    if fmt == "json":
        return report.to_json(result)
    if fmt == "sarif":
        return report.to_sarif(result)
    return report.to_markdown(result)


def _scan_dependencies(args: dict) -> str:
    path = _require_path(args)
    result = engine.scan(path, run_deps=True, use_scanners=True, use_taint=False)
    result.findings = [f for f in result.findings if f.package]
    if not result.findings:
        note = "; ".join(result.notes) or "no manifest found"
        return (f"No dependency advisories were produced for `{path}` ({note}).\n\n"
                f"This is not an all-clear: with no advisory source reachable, nothing was "
                f"checked. Install `osv-scanner` or make `npm audit` runnable and re-run.")
    return report.to_markdown(result) + "\n\n" + report.to_openvex(result)


def _generate_sbom(args: dict) -> str:
    return sbom.to_json(_require_path(args))


def _compliance_pack(args: dict) -> str:
    path = _require_path(args)
    return report.to_cra_pack(engine.scan(path, run_deps=True))


def _explain_finding(args: dict) -> str:
    wanted = str(args.get("id", "")).strip()
    if not wanted:
        raise ValueError("`id` is required.")

    for d in DETECTORS:
        if d.id == wanted:
            chapter = compliance.asvs_for(d.cwe)
            return "\n".join([
                f"# {d.id} — {d.title}",
                "",
                f"- **Class:** {d.cwe} · OWASP {d.owasp}"
                + (f" · ASVS {chapter[0]} ({chapter[1]})" if chapter else ""),
                f"- **Severity / confidence:** {d.severity.value} / {d.confidence.value}",
                f"- **Applies to:** {', '.join(d.exts)}",
                f"- **Matches:** `{d.pattern}`",
                f"- **Matched against:** "
                + ("raw file text" if d.literal else
                   "a view with comments and string-literal contents blanked"),
                (f"- **Cleared when the file contains:** `{d.suppress_if}`"
                 if d.suppress_if else "- **No suppressor:** this rule has no safe-pattern escape."),
                f"- **Fix:** {d.fix}",
                "",
                "This is a pattern rule. It states that a shape is present, not that untrusted "
                "input reaches it — that claim only comes with a taint path.",
            ])

    sinks = {s.id: s for s in list(taint.PY_SINKS.values())
             + [s for _, s in taint.JS_SINKS] + [s for _, s in taint.JS_ASSIGN_SINKS]}
    sink = sinks.get(wanted)
    if sink:
        chapter = compliance.asvs_for(sink.cwe)
        args_note = (f"argument position(s) {', '.join(str(a) for a in sink.taint_args)}"
                     if sink.taint_args else "any argument")
        return "\n".join([
            f"# {sink.id} — {sink.title}",
            "",
            f"- **Class:** {sink.cwe} · OWASP {sink.owasp}"
            + (f" · ASVS {chapter[0]} ({chapter[1]})" if chapter else ""),
            f"- **Severity when the path is request-rooted:** {sink.severity.value}",
            f"- **Dangerous in:** {args_note}"
            + (f", and only when `{sink.requires_kwarg}` is set" if sink.requires_kwarg else ""),
            f"- **Fix:** {sink.fix}",
            "",
            "This is a taint sink. A finding carrying it names the untrusted source and every "
            "hop to this call, so it can be followed and refuted. A path rooted in a function "
            "parameter rather than a framework request object is reported one severity rung "
            "lower, because whether that parameter carries untrusted data is caller knowledge "
            "the analysis only has when the caller is in the scanned set too.",
        ])

    known = sorted({d.id for d in DETECTORS} | set(sinks))
    return (f"Unknown id `{wanted}`. Ids are reported on every finding. "
            f"{len(known)} are defined; the first few are: {', '.join(known[:8])}.")


def _coverage(_args: dict) -> str:
    lines = ["# SecAudit coverage and bounds", "",
             "## Analysis depth by language", ""]
    for name, spec in taint.TAINT_DEPTH.items():
        # Scope is read out of the dispatch table, not spelled out here: a capability sentence
        # typed into the describing code is the one that goes stale without failing anything.
        scope = ["intraprocedural"]
        if spec.get("interprocedural"):
            scope.append("interprocedural")
        if spec.get("cross_module"):
            scope.append("cross-module (import edges, any depth, scanned files only)")
        lines.append(f"- **{name}** — taint (source→sink dataflow): {spec['frontend']}, "
                     f"{', '.join(scope)}.")

    lexical = sorted({ext for ext in taint._EXT_GROUP} - set(taint._TAINT_EXTS))
    covered_exts = {e for d in DETECTORS for e in d.exts}
    pattern_only = sorted(covered_exts - set(taint._TAINT_EXTS))
    lines += [
        f"- **Pattern rules only** ({len(pattern_only)} file types): "
        f"{', '.join(pattern_only)}. Located matches, no proven source.",
        f"- Of those, {len(lexical)} have a lexical model, so their code-shape rules do not "
        f"match inside comments or string literals: {', '.join(lexical)}.",
        "",
        "## Documented false-negative sources",
        "",
    ]
    lines += [f"- {line}" for line in taint.limitations()]
    lines += [
        "",
        "## Classes with no deterministic coverage",
        "",
        "- Broken access control / IDOR — whether a handler checks ownership is a question "
        "about intent, not shape.",
        "- Business-logic flaws — the rules being broken are the product's, and are not "
        "written down anywhere the analyzer can read.",
        "- Race conditions / TOCTOU — needs an interleaving model.",
        "- Second-order injection — the two ends are in different files and usually different "
        "services.",
        "",
        "## Not exposed over MCP",
        "",
        "- **Live-target checks.** They exist in the Claude Code plugin behind an explicit "
        "authorization gate (`scope.yaml`). A tool call carries no evidence of consent to "
        "probe a running system, so this server does not offer one. `scan_dependencies` and "
        "`compliance_pack` do reach the network to look up advisories by package name; that "
        "is a query about a package, not a request aimed at a host.",
        "",
        "## What a clean result means",
        "",
        "That these rules did not fire, in these languages, across the files that were "
        "scanned. Not that the code is safe.",
    ]
    return "\n".join(lines)


_HANDLERS = {
    "scan_source": _scan_source,
    "scan_dependencies": _scan_dependencies,
    "generate_sbom": _generate_sbom,
    "compliance_pack": _compliance_pack,
    "explain_finding": _explain_finding,
    "coverage": _coverage,
}


# --------------------------------------------------------------------------- protocol

def _result(request_id, payload: dict) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def _error(request_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def handle(message: dict) -> dict | None:
    """One JSON-RPC message in, one response out — or None for a notification.

    Returning None rather than an empty response is the whole contract for notifications: a
    client that receives a response to `notifications/initialized` is entitled to treat the
    server as broken, and several do."""
    if message.get("jsonrpc") != "2.0":
        return _error(message.get("id"), INVALID_REQUEST, "Expected JSON-RPC 2.0.")

    method = message.get("method", "")
    request_id = message.get("id")
    if request_id is None:
        return None                       # a notification: acknowledged by silence

    if method == "initialize":
        return _result(request_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": (
                "SecAudit runs a deterministic security audit over local source. Call "
                "`coverage` before summarising a result: a scan with no findings means these "
                "rules did not fire, not that the code is safe. No tool here probes a system; "
                "dependency tools look advisories up by package name."),
        })

    if method == "ping":
        return _result(request_id, {})

    if method == "tools/list":
        return _result(request_id, {"tools": TOOLS})

    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        if name not in _TOOL_NAMES:
            return _error(request_id, INVALID_PARAMS, f"Unknown tool: {name}")
        try:
            text = _HANDLERS[name](params.get("arguments") or {})
        except ValueError as e:
            # A bad argument is the model's mistake to correct, so it comes back as tool
            # content with isError set rather than a protocol error the model never sees.
            return _result(request_id, {"content": [{"type": "text", "text": str(e)}],
                                        "isError": True})
        except Exception as e:                                    # noqa: BLE001
            return _result(request_id, {
                "content": [{"type": "text",
                             "text": f"{name} failed: {type(e).__name__}: {e}"}],
                "isError": True})
        return _result(request_id, {"content": [{"type": "text", "text": text}],
                                    "isError": False})

    return _error(request_id, METHOD_NOT_FOUND, f"Unknown method: {method}")


def serve(stdin=None, stdout=None) -> int:
    """Read newline-delimited JSON-RPC from stdin, write responses to stdout."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            response = _error(None, PARSE_ERROR, "Invalid JSON.")
        else:
            if not isinstance(message, dict):
                response = _error(None, INVALID_REQUEST, "Expected a JSON-RPC object.")
            else:
                response = handle(message)
        if response is not None:
            stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            stdout.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    if "--tools" in argv:
        print(json.dumps({"tools": TOOLS}, indent=2, ensure_ascii=False))
        return 0
    return serve()


if __name__ == "__main__":
    sys.exit(main())
