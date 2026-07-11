#!/usr/bin/env python3
"""SecAudit active-scan guard — PreToolUse hook (defense-in-depth).

Makes the skill's *passive-by-default* posture a deterministic, harness-level
gate instead of relying only on model discipline. It blocks the two clearly
ACTIVE Bash patterns before they run, unless the operator has asserted
authorization:

  1. Offensive/active security scanners (nuclei, nmap, sqlmap, ZAP, hydra,
     ffuf, nikto, wpscan, ...) — these send crafted probes/attacks.
  2. State-changing / payload-bearing HTTP requests (curl/wget/httpie with
     -X POST|PUT|DELETE|PATCH, a request body, or a file upload).
  3. Read-only GET/HEAD requests that nonetheless carry a crafted injection/probe
     payload in the URL or query string (SQLi canary, path-traversal to a system
     file, cloud-metadata SSRF, XSS/SSTI marker, CRLF/null-byte, ...) — a probe,
     not passive recon.

Authorization is asserted by EITHER:
  * a `scope.yaml` in the working directory containing `i_am_authorized: true`, OR
  * the environment variable  SECAUDIT_ACTIVE=1  for the session.

What is NEVER blocked: passive recon (read-only GET/HEAD, TLS/cert inspection,
tech fingerprinting) and all local static analysis (SAST / dependency / secret
scanners on files you already have). Those need no gate.

Coverage note (honest bound, not a bug): pattern 3 gates the *common* probe canaries
(the OWASP-style markers most audits use), chosen for high precision so benign passive
recon is never gated — it deliberately ignores ambiguous tokens like a bare `../` or
`$(` that also appear in legitimate shell usage. A sufficiently obfuscated/encoded
payload, or one delivered via the `WebFetch` tool (not a shell command, so not visible
to this Bash hook), still relies on the skill's own authorization discipline. This guard
covers the unambiguous and the common active patterns deterministically; it is a
defense-in-depth layer, not a complete WAF.

Protocol: reads the PreToolUse payload as JSON on stdin. To ALLOW, it exits 0 with
no output. To BLOCK, it prints a PreToolUse "deny" decision as JSON on stdout and
still exits 0 — deliberately. hooks.json invokes the guard through an interpreter
fallback chain (`python3 … || python … || py …`) so it runs wherever Python lives
(Windows python.org ships `python`/`py` but not `python3`). If a block used a
non-zero exit, the `||` chain would treat it as failure and re-run the guard on an
already-consumed stdin — the re-run would read empty input and fail open, silently
dropping the block. Exiting 0 on both allow and block means the fallback fires only
when an interpreter is genuinely absent (stdin still intact). The deny payload emits
both the modern `permissionDecision: deny` and the legacy `decision: block` fields
for compatibility. Fails OPEN on any parse error so a malformed payload can never
wedge the session.
"""
from __future__ import annotations
import json
import os
import re
import sys

# Offensive/active scanners — never appropriate against a live target without authorization.
ACTIVE_TOOLS = re.compile(
    r"\b(nuclei|nmap|masscan|zaproxy|zap-cli|zap-baseline|zap-full-scan|sqlmap|"
    r"hydra|medusa|patator|ncrack|gobuster|dirb|dirbuster|feroxbuster|ffuf|wfuzz|"
    r"nikto|wpscan|joomscan|arjun|dalfox|xsstrike|commix|tplmap|crackmapexec|"
    r"netexec|responder|whatweb|wafw00f)\b",
    re.I,
)

# curl / wget / httpie invocations that SEND a state-changing or payload-bearing request.
# A plain read-only GET/HEAD has none of these flags and is left alone.
CURL_ACTIVE = re.compile(
    r"\b(?:curl|wget|http|https|xh)\b[^\n|;&]*?"
    r"(?:-X\s*(?:POST|PUT|DELETE|PATCH)|--request[=\s]*(?:POST|PUT|DELETE|PATCH)|"
    r"--data\b|--data-[a-z]+|--form\b|--upload-file\b|--post-data\b|--post-file\b|"
    r"(?<!\w)-d[=\s]|(?<!\w)-F[=\s]|(?<!\w)-T[=\s])",
    re.I,
)

# curl / wget / httpie GET requests that carry a crafted probe/injection payload in the URL
# or query string. A plain read-only GET of a real resource has none of these markers; their
# presence means the request is an ACTIVE probe, not passive recon. The marker set is chosen
# for HIGH PRECISION (common OWASP canaries) and deliberately excludes ambiguous tokens like a
# bare `../` or `$(` that also appear in benign shell usage, to avoid false-gating passive
# commands. The span after the fetch verb is not operator-bounded, so a payload in any query
# parameter (including after `&`) is seen.
_GET_PROBE_MARKERS = "|".join([
    r"union\s+select", r"['\"]\s*or\s+['\"0-9]", r"\bor\s+1\s*=\s*1\b",
    r"sleep\s*\(", r"pg_sleep", r"waitfor\s+delay", r"benchmark\s*\(",   # SQLi
    r"%27\s*(?:or|and|union)", r"%22\s*(?:or|and|union)",                # SQLi (URL-encoded quote)
    r"/etc/passwd", r"/etc/shadow", r"boot\.ini", r"win\.ini",           # path-traversal targets
    r"\.\.%2f", r"%2e%2e%2f", r"\.\.%5c", r"%2e%2e%5c",                  # path traversal (encoded)
    r"169\.254\.169\.254", r"metadata\.google", r"metadata\.internal",   # SSRF (cloud metadata)
    r"\bfile://", r"\bgopher://", r"\bdict://",                          # SSRF (dangerous schemes)
    r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
    r"<svg[\s/>]", r"<img\s", r"alert\s*\(",                             # XSS
    r"\{\{\s*[0-9'\"]", r"<%=", r"#\{\s*[0-9]",                          # SSTI
    r"%00", r"%0a", r"%0d%0a",                                           # null-byte / CRLF injection
])
GET_PROBE = re.compile(
    r"\b(?:curl|wget|http|https|xh)\b[^\n]*?(?:" + _GET_PROBE_MARKERS + r")",
    re.I,
)


def authorized() -> bool:
    if os.environ.get("SECAUDIT_ACTIVE") == "1":
        return True
    try:
        with open("scope.yaml", encoding="utf-8") as f:
            txt = f.read()
    except OSError:
        return False
    return re.search(r"^\s*i_am_authorized:\s*true\b", txt, re.I | re.M) is not None


def active_reason(cmd: str) -> str | None:
    m = ACTIVE_TOOLS.search(cmd)
    if m:
        return f"active-scanning tool `{m.group(1)}`"
    if CURL_ACTIVE.search(cmd):
        return "a state-changing / payload-bearing HTTP request"
    if GET_PROBE.search(cmd):
        return "a crafted injection/probe payload in an HTTP request"
    return None


def decide(payload: dict) -> int:
    """Core decision (no I/O) for a PreToolUse payload: 0 = allow, 2 = block.
    This is the internal decision signal (asserted by the self-test); the process
    itself always exits 0 and signals a block via a JSON deny decision — see `main`."""
    if payload.get("tool_name") != "Bash":
        return 0
    cmd = (payload.get("tool_input") or {}).get("command", "") or ""
    if not active_reason(cmd):
        return 0
    return 0 if authorized() else 2


def _bash(cmd: str) -> dict:
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


def selftest() -> int:
    """Deterministic gate checks — used by CI. Asserts active patterns block and
    passive/local ones pass while unauthorized. Must run with SECAUDIT_ACTIVE unset."""
    os.environ.pop("SECAUDIT_ACTIVE", None)
    block = [
        "nuclei -u https://x.com", "nmap -sV x.com", "sqlmap -u https://x.com?id=1",
        "zaproxy -quickurl https://x.com", "ffuf -u https://x.com/FUZZ -w w.txt",
        "nikto -h x.com", "hydra -l a -P p.txt x.com ssh",
        "curl -sS -X POST https://x.com/login -d user=a",
        "curl -sS https://x.com --data foo=1", "wget --post-data=a=1 https://x.com",
        "curl -sS -F file=@x https://x.com/upload",
        # GET requests carrying a crafted probe payload (pattern 3).
        "curl -sS \"https://x.com/?id=1' OR '1'='1\"",
        "curl -sS 'https://x.com/?file=../../../../etc/passwd'",
        "curl -sS 'https://x.com/?url=http://169.254.169.254/latest/meta-data/'",
        "curl -sS 'https://x.com/?q=<script>alert(1)</script>'",
        "wget 'https://x.com/?tpl={{7*7}}'",
        "curl -sS 'https://x.com/?next=file:///etc/passwd'",
        "curl -sS 'https://x.com/?page=1&path=..%2f..%2fetc%2fpasswd'",
    ]
    allow = [
        "curl -sS https://x.com/", "curl -I https://x.com/",
        "curl -sS https://x.com/robots.txt", "semgrep --config auto .",
        "npm audit --json", "osv-scanner -r .", "gitleaks detect --no-git",
        "dig x.com", "testssl.sh https://x.com",
        # Benign GETs / local commands that superficially resemble a probe but are not.
        "curl -sS 'https://api.x.com/v1/users?id=123&page=2'",
        "curl -sS https://x.com/.well-known/security.txt",
        "curl -sS https://x.com/ -o ../../out.html",
    ]
    fails = []
    for c in block:
        if decide(_bash(c)) != 2:
            fails.append(f"[should BLOCK] {c}")
    for c in allow:
        if decide(_bash(c)) != 0:
            fails.append(f"[should ALLOW] {c}")
    if decide({"tool_name": "Read", "tool_input": {"file_path": "x"}}) != 0:
        fails.append("[should ALLOW] non-Bash tool")
    # Authorized env must let an active command through.
    os.environ["SECAUDIT_ACTIVE"] = "1"
    if decide(_bash("nuclei -u https://x.com")) != 0:
        fails.append("[auth] SECAUDIT_ACTIVE=1 did not allow active command")
    os.environ.pop("SECAUDIT_ACTIVE", None)

    # The deny decision must be well-formed JSON carrying both the modern and legacy
    # block fields (this is the actual block signal now, not the exit code).
    d = deny_payload("active-scanning tool `nuclei`")
    if d.get("decision") != "block":
        fails.append("[deny] legacy `decision: block` field missing")
    if d.get("hookSpecificOutput", {}).get("permissionDecision") != "deny":
        fails.append("[deny] modern `permissionDecision: deny` field missing")
    try:
        json.loads(json.dumps(d))
    except Exception:
        fails.append("[deny] payload is not JSON-serializable")

    if fails:
        print("HOOK SELF-TEST FAILED:")
        print("\n".join("  " + f for f in fails))
        return 1
    print(f"HOOK SELF-TEST PASSED — {len(block)} active blocked, {len(allow)} passive allowed.")
    return 0


def block_message(reason: str) -> str:
    return (
        f"SecAudit authorization gate: blocked {reason}.\n"
        "This is ACTIVE testing and is gated. Allow it only after asserting authorization:\n"
        "  - create scope.yaml with `i_am_authorized: true` "
        "(see templates/scope.example.yaml), or\n"
        "  - set SECAUDIT_ACTIVE=1 for this session.\n"
        "Passive recon (read-only GET/HEAD) and local source/dependency/secret scans need no gate.\n"
        "Even when authorized, never run DoS, brute-force, or data exfiltration. "
        "See docs/authorization.md."
    )


def deny_payload(reason: str) -> dict:
    """The PreToolUse deny decision. Emits both the modern and legacy field shapes so
    any Claude Code version honors the block."""
    msg = block_message(reason)
    return {
        "decision": "block",            # legacy PreToolUse block field
        "reason": msg,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",   # modern PreToolUse decision field
            "permissionDecisionReason": msg,
        },
    }


def emit_deny(reason: str) -> None:
    """Print the deny decision to stdout (exit stays 0 — see module docstring)."""
    print(json.dumps(deny_payload(reason)))


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # can't parse -> never interfere
    if payload.get("tool_name") != "Bash":
        return 0
    cmd = (payload.get("tool_input") or {}).get("command", "") or ""
    reason = active_reason(cmd)
    if not reason:
        return 0            # passive / non-matching -> allow
    if authorized():
        return 0            # authorization asserted -> allow active testing
    emit_deny(reason)       # block via JSON deny decision on stdout
    return 0                # exit 0 so the hooks.json `||` fallback never re-runs on empty stdin


if __name__ == "__main__":
    sys.exit(main())
