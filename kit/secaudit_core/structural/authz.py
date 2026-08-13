"""Authorization analysis — the two structural questions a pattern cannot decide.

`broken_access_control` and `missing_authentication` were the two largest zeroes in the external
measurement, and `docs/what-we-miss.md` said of them: *"whether a handler checks that the caller
owns the row it returns is a question about intent, not shape. There is no token sequence that
distinguishes a correct lookup from a missing ownership predicate."*

That is right about **tokens** and wrong about **structure**. What decides these two is a
relation between three things in one handler — who the caller is, which identifier the request
supplied, and what the data operation filtered on — and a parser sees all three at once.

* **IDOR / broken access control.** The handler *has* an authenticated principal, so
  authentication was clearly intended. A request-supplied identifier then reaches a data
  operation and the principal is never used to constrain it.
* **Missing authentication.** The inverse: a state-changing handler that acts on what the caller
  sent with no authorization evidence anywhere — no decorator, no principal, no gate, no 401/403.

**What stops the second one firing.** The benchmark carries 42 deliberate traps for exactly this
rule, all one shape: a handler with no auth *decorator* that reaches a small local helper
comparing a header to an environment token. A decorator-based rule reports all 42. Authorization
evidence is therefore resolved through module-local calls *and references* — the FastAPI variant
injects the same gate as a parameter default and never calls it — which is why `routes.py` builds
a function table for the module before anything in it is judged.

Bounds, stated because a rule about intent that overstates its reach is worse than no rule:

* Python only. Derived from `LANGS` in `routes.py`, so it cannot drift out of the docs.
* Evidence is followed through functions **defined in the same module**. A gate imported from
  elsewhere is not followed, and the handler is left unreported rather than assumed open.
* Ownership is judged by whether the principal constrains the query at all, never by whether it
  constrains it *correctly*. A handler filtering on the wrong identity is outside what this
  decides.
"""
from __future__ import annotations

import ast

from ..schema import Confidence, Finding, Severity, Verdict
from .routes import (AnyFunc, Route, _STATE_CHANGING, _auth_evidence, _data_operations,
                     _evidence, _mentions, _principal_constrains,
                     _principal_names_in_scope, _reads_request, _reads_request_inline,
                     _request_id_names, _route_of, EXTS)

# --------------------------------------------------------------------------- the analysis

def analyze_file(rel: str, text: str) -> list[Finding]:
    """Every authorization finding in one Python source file."""
    if not rel.lower().endswith(EXTS):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []          # a file we cannot parse is a file we say nothing about

    lines = text.splitlines()
    functions: dict[str, AnyFunc] = {
        node.name: node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route = _route_of(node)
        if route is None:
            continue
        findings += _judge(route, rel, lines, functions)
    return findings


def _judge(route: Route, rel: str, lines: list[str],
           functions: dict[str, AnyFunc]) -> list[Finding]:
    func = route.func
    principals = _principal_names_in_scope(func)
    authed = _auth_evidence(func, route.decorators, functions)
    operations = _data_operations(func)

    # ---- IDOR: authentication was intended, and then not used to constrain the lookup.
    # Needs an actual data operation: without a row to fetch there is no object to own.
    if operations and authed and principals:
        request_ids = _request_id_names(route)
        for call in operations:
            # The identifier is either bound to a local first — the usual shape — or read
            # inline and handed straight to the query: `Order.query.get(request.args["id"])`.
            # Only the first was recognised, which meant the tersest form of the bug, the one
            # with no intervening variable to name, was the one form that went unreported.
            if not _mentions(call, request_ids) and not _reads_request_inline(call):
                continue
            if _principal_constrains(call, principals, func, functions):
                continue
            return [Finding(
                detector_id="AUTHZ-PY-IDOR",
                title="Broken access control — object looked up by a caller-supplied id "
                      "without an ownership check",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                cwe="CWE-284", owasp="A01",
                file=rel, line=call.lineno,
                evidence=_evidence(lines, call.lineno),
                fix=f"`{func.name}` knows who is calling ("
                    f"`{sorted(principals)[0]}`) but selects the row with an identifier the "
                    f"caller supplied. Constrain the query by the principal — e.g. add "
                    f"`user_id={sorted(principals)[0]}.id` to the filter — or compare "
                    f"ownership and reject with 403 before returning.",
                source="authz", verdict=Verdict.UNVERIFIED)]

    # ---- Missing authentication: a state-changing handler with no authorization at all.
    # The bar is that the handler *acts on what the caller sent*, not that it reaches a
    # database. Requiring a data operation here found nothing at all (0 true positives against
    # 7 false ones): the unauthenticated endpoints that get labelled are the ones that evaluate
    # an expression, shell out, or parse XML from the request body, and none of those touches a
    # row. What they share is an anonymous caller reaching an operation with a side effect.
    if (not authed and not principals and route.state_changing
            and not route.public_by_design and (operations or _reads_request(func))):
        return [Finding(
            detector_id="AUTHZ-PY-NOAUTH",
            title="Missing authentication on a state-changing endpoint",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            cwe="CWE-306", owasp="A01",
            file=rel, line=route.line,
            evidence=_evidence(lines, route.line),
            fix=f"`{func.name}` handles "
                f"{'/'.join(sorted(m.upper() for m in route.methods & _STATE_CHANGING))} and "
                f"reaches persistent state, but nothing in it — no decorator, no principal, no "
                f"gate helper, no 401/403 — establishes who is calling. Require an "
                f"authenticated identity before the write.",
            source="authz", verdict=Verdict.UNVERIFIED)]

    return []


def analyze_files(files: dict[str, str]) -> list[Finding]:
    return [f for rel, text in sorted(files.items()) for f in analyze_file(rel, text)]


def limitations() -> list[str]:
    return [
        "Ownership is judged by whether the principal constrains the query at all, never by "
        "whether it constrains it correctly — a handler that filters on the wrong identity is "
        "outside what this decides. Any call that receives the principal is treated as a check "
        "delegated, which is deliberately generous: the stricter reading was measured against "
        "the corpus and recovered no true positives while adding false ones.",
    ]
