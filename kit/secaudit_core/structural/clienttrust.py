"""An access decision made from a value the caller sends — CWE-807.

30 labels, none found. The shape is one line of reading and one line of deciding:

    cookie = request.cookies.get('env')
    if cookie and cookie == 'graphiql:enable':      # → the developer console
        return next(root, info, **kwargs)

    badge = request.COOKIES.get("ops_badge") or request.headers.get("x-ops-badge", "")
    if badge == "lead":                              # → payroll, casework, everything
        return JsonResponse({"lane": "elevated", "payroll": "full"})

A cookie and a header are *sent by the client*. Nothing signs them, nothing checks them against
the session, and the value is one line in a browser's dev tools. So the branch is not an
authorization check at all — it is the caller telling the server which branch to take, and the
server agreeing.

The rule is that relation: **a value read from the request's own headers or cookies is compared
against a literal, and the comparison decides a branch.** It is not "a header was read" (every
handler reads headers) and not "a comparison happened" (every handler compares things); it is a
comparison of an unauthenticated input against a constant, used as a gate.

**Transport headers are excluded by name**, because the same shape is correct for them: content
negotiation, `X-Requested-With`, a `Referer` check and a webhook's declared content type are all
comparisons of a client-sent header to a constant, and none of them is an access decision. That
exclusion is where this rule's precision lives, and it is a list of *what the header is for*
rather than a guess about the branch.

**A verified value is not a trusted one.** When the module compares with `hmac.compare_digest`,
verifies a signature, or decodes a token, the header has been authenticated and the handler is
left alone — the same "evidence is followed through the module" discipline the rest of this
package uses.

What it does not decide is whether the branch is privileged. `if request.headers.get("x-debug")
== "1"` guarding a log line reads the same as one guarding payroll, and both are reported: an
unauthenticated switch on caller-supplied state is worth one line of a report either way.
"""
from __future__ import annotations

import ast

from ..schema import Confidence, Finding, Severity, Verdict
from .routes import AnyFunc, _dotted, _evidence, EXTS, module_functions

# Where a caller-controlled name comes from. `request.META` is Django's header dictionary.
_CLIENT_SOURCES = ("request.cookies", "request.headers", "request.meta", "self.request.cookies",
                   "self.request.headers", "request.get_signed_cookie", "req.cookies",
                   "req.headers", "request.environ", "headers.get", "cookies.get")

# Headers whose whole purpose is for the client to declare something about the request. Comparing
# one of these to a constant is correct code, not a gate.
_TRANSPORT_HEADERS = (
    "content-type", "content_type", "accept", "accept-encoding", "accept-language",
    "user-agent", "user_agent", "x-requested-with", "referer", "referrer", "origin", "host",
    "connection", "cache-control", "if-none-match", "if-modified-since", "range",
    "content-length", "content_length", "upgrade", "sec-fetch", "dnt", "te", "expect",
)

# Evidence that the value was authenticated before it was believed.
_VERIFICATION_MARKERS = ("compare_digest", "verify", "signature", "hmac", "jwt", "decode_token",
                         "unsign", "check_signature", "validate_token", "itsdangerous")


def _client_reads(func: AnyFunc) -> tuple[set[str], list[ast.Call]]:
    """Names bound from a client-sent header or cookie, and the inline reads themselves."""
    names: set[str] = set()
    reads: list[ast.Call] = []

    def is_client_read(node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            dotted = _dotted(node.func).lower()
            if any(s in dotted for s in _CLIENT_SOURCES):
                key = node.args[0] if node.args else None
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    if any(h in key.value.lower() for h in _TRANSPORT_HEADERS):
                        return False
                return True
        if isinstance(node, ast.Subscript):
            dotted = _dotted(node.value).lower()
            if any(s in dotted for s in _CLIENT_SOURCES):
                key = node.slice
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    if any(h in key.value.lower() for h in _TRANSPORT_HEADERS):
                        return False
                return True
        return False

    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            # `badge = request.COOKIES.get(...) or request.headers.get(...)` — either side.
            if any(is_client_read(child) for child in ast.walk(node.value)):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
        if is_client_read(node):
            reads.append(node)                                            # type: ignore[arg-type]
    return names, reads


def _verified(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Name, ast.Attribute)):
            dotted = _dotted(node).lower()
            if any(m in dotted for m in _VERIFICATION_MARKERS):
                return True
    return False


def _gate_comparisons(func: AnyFunc, names: set[str]) -> list[ast.Compare]:
    """Comparisons of a client-sent value against a literal that decide a branch."""
    out: list[ast.Compare] = []
    for node in ast.walk(func):
        if not isinstance(node, (ast.If, ast.IfExp)):
            continue
        for test in ast.walk(node.test):
            if not isinstance(test, ast.Compare):
                continue
            operands = [test.left, *test.comparators]
            mentions_client = any(
                (isinstance(o, ast.Name) and o.id in names)
                or any(isinstance(c, ast.Name) and c.id in names for c in ast.walk(o))
                for o in operands)
            literal = any(isinstance(o, ast.Constant) and isinstance(o.value, str)
                          for o in operands)
            if mentions_client and literal:
                out.append(test)
    return out


def analyze_file(rel: str, text: str) -> list[Finding]:
    if not rel.lower().endswith(EXTS):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    if _verified(tree):
        return []

    lines = text.splitlines()
    findings: list[Finding] = []
    for func in sorted(module_functions(tree).values(), key=lambda f: f.lineno):
        names, _ = _client_reads(func)
        if not names:
            continue
        gates = _gate_comparisons(func, names)
        if not gates:
            continue
        line = min(g.lineno for g in gates)
        findings.append(Finding(
            detector_id="TRUST-PY-CLIENT-DECISION",
            title="Access decided by a value the caller sent — a cookie or header compared "
                  "against a constant",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            cwe="CWE-807", owasp="A01",
            file=rel, line=line,
            evidence=_evidence(lines, line),
            fix=f"`{func.name}` branches on a header or cookie the caller controls, compared "
                f"against a fixed value, and nothing signs or verifies it — the caller can set "
                f"it in one line. Decide from the authenticated session or a signed token, and "
                f"if the value must travel in a header, verify a signature over it with "
                f"`hmac.compare_digest` before believing it.",
            source="structural", verdict=Verdict.UNVERIFIED))
    return findings


def limitations() -> list[str]:
    return [
        "Client-trust analysis reports a header or cookie compared against a literal where the "
        "comparison decides a branch. Transport headers are excluded by name (content type, "
        "accept, user agent, X-Requested-With, referer, origin, host), and the whole file is "
        "left alone when anything in it verifies a signature — so a module that authenticates "
        "one header and trusts another is not reported for the second.",
    ]
