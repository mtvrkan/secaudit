#!/usr/bin/env python3
"""MCP server tests — protocol conformance and the boundaries the server is supposed to hold.

Two things are being checked, and the second matters more than the first:

  1. **Protocol.** initialize / tools/list / tools/call round-trip, notifications get no
     response, unknown methods and bad arguments fail in the shape a client can handle.
  2. **Boundaries.** No tool reaches a network target; a bad path is refused rather than
     stack-tracing; a scan that produced nothing says so instead of implying an all-clear.

The second set exists because an MCP tool is called by a model, not a person. Anything the
server leaves ambiguous gets resolved by whatever the model assumed, and "no findings" is the
ambiguity with the worst failure mode.
"""
from __future__ import annotations

import io
import json
import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(KIT)
sys.path.insert(0, KIT)

from secaudit_mcp import server                              # noqa: E402

VULN = os.path.join(REPO, "tests", "fixtures", "vulnerable-app")

fails: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        fails.append(message)


def call(method: str, params: dict | None = None, request_id: int | None = 1):
    message = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        message["id"] = request_id
    if params is not None:
        message["params"] = params
    return server.handle(message)


def tool(name: str, arguments: dict | None = None) -> dict:
    response = call("tools/call", {"name": name, "arguments": arguments or {}})
    return response["result"]


# --------------------------------------------------------------------------- 1. protocol

def test_initialize() -> None:
    result = call("initialize", {"protocolVersion": "2025-06-18"})["result"]
    check(result["protocolVersion"] == server.PROTOCOL_VERSION,
          "initialize must echo the protocol version the server implements")
    check("tools" in result["capabilities"], "initialize must advertise the tools capability")
    check(result["serverInfo"]["name"] == "secaudit", "serverInfo.name")
    check("not that the code is safe" in result["instructions"],
          "initialize instructions must tell the client what a clean result does not mean")


def test_notifications_get_no_response() -> None:
    check(call("notifications/initialized", {}, request_id=None) is None,
          "a notification must produce no response at all — a client that gets one is "
          "entitled to treat the server as broken")


def test_tools_list() -> None:
    tools = call("tools/list")["result"]["tools"]
    names = {t["name"] for t in tools}
    check(names == {"scan_source", "scan_dependencies", "generate_sbom", "compliance_pack",
                    "explain_finding", "coverage"},
          f"unexpected tool set: {sorted(names)}")
    for t in tools:
        check(bool(t.get("description")), f"{t['name']} has no description")
        schema = t.get("inputSchema") or {}
        check(schema.get("type") == "object", f"{t['name']} inputSchema must be an object")
        for required in schema.get("required", []):
            check(required in schema.get("properties", {}),
                  f"{t['name']} requires `{required}` but does not declare it")


def test_errors() -> None:
    err = call("no/such/method")["error"]
    check(err["code"] == server.METHOD_NOT_FOUND, "unknown method must be -32601")

    err = call("tools/call", {"name": "definitely_not_a_tool"})["error"]
    check(err["code"] == server.INVALID_PARAMS, "unknown tool must be -32602")

    # A bad ARGUMENT is the model's to fix, so it comes back as tool content with isError —
    # a protocol error would never reach the model that has to correct it.
    result = tool("scan_source", {"path": os.path.join(REPO, "does-not-exist")})
    check(result["isError"] is True, "a missing path must set isError")
    check("No such file" in result["content"][0]["text"],
          "a missing path must say so in the tool content, not raise")

    result = tool("scan_source", {})
    check(result["isError"] is True, "a missing required argument must set isError")


def test_serve_loop() -> None:
    """The transport itself: newline-delimited JSON in, newline-delimited JSON out."""
    stdin = io.StringIO('{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'
                        '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
                        'not json\n'
                        '{"jsonrpc":"2.0","id":2,"method":"ping"}\n')
    stdout = io.StringIO()
    server.serve(stdin, stdout)
    lines = [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]
    check(len(lines) == 3,
          f"expected 3 responses (list, parse error, ping) — the notification must not "
          f"produce one (got {len(lines)})")
    check(lines[1]["error"]["code"] == server.PARSE_ERROR,
          "malformed JSON must produce a parse error, not kill the loop")
    check(lines[2]["id"] == 2, "the loop must keep serving after a parse error")


# --------------------------------------------------------------------------- 2. boundaries

def test_scan_source() -> None:
    result = tool("scan_source", {"path": VULN})
    check(result["isError"] is False, "a scan of the vulnerable fixture must succeed")
    text = result["content"][0]["text"]
    check("SQL injection" in text, "the markdown report must contain the planted SQLi")

    as_json = json.loads(tool("scan_source", {"path": VULN, "format": "json"})
                         ["content"][0]["text"])
    findings = as_json["findings"]
    check(len(findings) > 10, f"json format must carry the findings (got {len(findings)})")

    criticals = json.loads(tool("scan_source", {"path": VULN, "format": "json",
                                                "min_severity": "critical"})
                           ["content"][0]["text"])["findings"]
    check(0 < len(criticals) < len(findings),
          "min_severity must filter, and must not filter everything away")
    check(all(f["severity"] == "Critical" for f in criticals),
          "min_severity=critical must leave only criticals")

    untainted = json.loads(tool("scan_source", {"path": VULN, "format": "json", "taint": False})
                           ["content"][0]["text"])["findings"]
    check(not any(f["taint_path"] for f in untainted),
          "taint=false must produce no taint paths")
    check(any(f["taint_path"] for f in findings),
          "the default must produce taint paths — otherwise the tier is silently off")


def test_no_network_tools() -> None:
    """The boundary that matters most: nothing here scans a live target.

    Asserted against the manifest rather than trusted from the implementation, because the
    manifest is what a client reads to decide what it is allowed to ask for."""
    # Property NAMES, not a substring of the serialized schema: "Report format" contains
    # "port", and a test that fails on its own prose teaches people to delete it.
    forbidden = {"url", "host", "hostname", "port", "endpoint", "domain", "target_url"}
    for t in server.TOOLS:
        declared = set((t.get("inputSchema") or {}).get("properties", {}))
        overlap = declared & forbidden
        check(not overlap,
              f"{t['name']} accepts {sorted(overlap)} — live-target scanning stays behind the "
              f"plugin's authorization gate, not behind an MCP argument")


def test_coverage_tool() -> None:
    text = tool("coverage")["content"][0]["text"]
    for expected in ("Python", "JavaScript", "false-negative", "IDOR",
                     "Not exposed over MCP", "Not that the code is safe"):
        check(expected in text, f"coverage output must mention {expected!r}")


def test_explain_finding() -> None:
    text = tool("explain_finding", {"id": "SEC-JS-SQLI"})["content"][0]["text"]
    check("CWE-89" in text and "ASVS" in text,
          "explaining a detector must give its CWE and ASVS chapter")
    check("not that untrusted input reaches it" in text,
          "a pattern rule must be described as a shape match, not as proof")

    text = tool("explain_finding", {"id": "TAINT-PY-SQLI"})["content"][0]["text"]
    check("taint sink" in text, "explaining a taint sink must say it is one")
    check("argument position" in text, "a taint sink's dangerous argument must be stated")

    text = tool("explain_finding", {"id": "NOPE-1"})["content"][0]["text"]
    check("Unknown id" in text, "an unknown id must be answered, not raised")


def test_empty_dependency_scan_is_not_an_all_clear() -> None:
    """A directory with no manifest must not read as 'dependencies are fine'."""
    text = tool("scan_dependencies", {"path": os.path.join(REPO, "docs")})["content"][0]["text"]
    check("not an all-clear" in text,
          "a dependency scan that found no advisory source must say nothing was checked")


def test_sbom_and_cra() -> None:
    doc = json.loads(tool("generate_sbom", {"path": VULN})["content"][0]["text"])
    check(doc.get("bomFormat") == "CycloneDX", "generate_sbom must emit CycloneDX")
    pack = json.loads(tool("compliance_pack", {"path": VULN})["content"][0]["text"])
    check("sbom" in pack and "regulation" in json.dumps(pack).lower(),
          "the CRA pack must carry both the SBOM and the regulation reference")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    test_initialize()
    test_notifications_get_no_response()
    test_tools_list()
    test_errors()
    test_serve_loop()
    test_scan_source()
    test_no_network_tools()
    test_coverage_tool()
    test_explain_finding()
    test_empty_dependency_scan_is_not_an_all_clear()
    test_sbom_and_cra()

    if fails:
        print("MCP TESTS FAILED:")
        print("\n".join("  - " + f for f in fails if f))
        return 1
    print(f"MCP TESTS PASSED — {len(server.TOOLS)} tools, protocol round-trip, notification "
          f"silence, error shapes, and the no-live-target boundary verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
