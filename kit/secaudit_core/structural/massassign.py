"""Mass assignment — a request body unpacked straight into a model.

36 labels, none found, and all of them one of a handful of spellings:

    User.objects.filter(pk=pk).update(**update)   # every column the caller named
    user.__dict__.update(payload)
    setattr(obj, key, value) for key, value in data.items()
    Model(**request.json)

The vulnerability is CWE-915: the caller decides *which fields* get written, so a body carrying
`is_admin` or `balance` writes those too. What makes it decidable is that the danger is visible
in the syntax — a `**` unpack, a `__dict__` update, or a `setattr` loop, whose source is request
data and whose target is a persistent object.

**The field allowlist is the check this looks for.** A handler that names the fields it accepts
— by picking them out of the body, by validating against a schema or serializer with declared
fields, or by passing an explicit `fields=`/`only=`/`exclude=` — has made the decision the
vulnerability is about, and is not reported. That is why a Pydantic or DRF handler which does
exactly this every day does not light up: the schema *is* the allowlist.
"""
from __future__ import annotations

import ast

from ..schema import Confidence, Finding, Severity, Verdict
from .routes import (AnyFunc, _dotted, _evidence, _is_request_read, EXTS, module_functions)

# Calls that write a set of fields chosen by whoever supplied the mapping.
_ASSIGN_CALLS = ("update", "create", "save", "insert", "update_one", "update_many",
                 "find_one_and_update", "bulk_update", "modify", "set")

# A schema or serializer that declares its fields IS the allowlist — do not report through one.
_ALLOWLIST_MARKERS = (
    "fields", "only", "exclude", "allowed", "allowlist", "whitelist", "permitted",
    "schema", "serializer", "basemodel", "dataclass", "form", "validator", "validate",
    "pick", "subset", "safe_fields", "editable",
)


def _names_in(node: ast.AST) -> list[str]:
    out = []
    for child in ast.walk(node):
        if isinstance(child, (ast.Name, ast.Attribute)):
            dotted = _dotted(child)
            if dotted:
                out.append(dotted.lower())
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            out.append(child.value.lower())
    return out


def _request_bound_names(func: AnyFunc) -> set[str]:
    """Locals holding a whole request body — the mapping a `**` unpack would spread.

    Deliberately *not* the id-shaped subset `routes._request_id_names` collects: there the key
    matters because one field is being used as an identifier, here the point is that the caller
    supplied the entire mapping and no key was singled out at all.
    """
    names: set[str] = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        reads = False
        if isinstance(value, ast.Call) and _is_request_read(value):
            reads = True
        elif isinstance(value, ast.Attribute) and _is_request_read(value):
            reads = True
        elif isinstance(value, ast.Subscript) and _is_request_read(value.value):
            reads = True
        # `data = dict(request.json)` / `payload = {**request.json}` keep the whole mapping.
        elif isinstance(value, (ast.Dict, ast.DictComp, ast.Call)) and any(
                _is_request_read(n) for n in ast.walk(value) if isinstance(n, (ast.Call, ast.Attribute))):
            reads = True
        if reads:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def _spreads_request(node: ast.AST, request_names: set[str]) -> bool:
    """A `**mapping` whose mapping is request-derived, anywhere under `node`."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            for kw in child.keywords:
                if kw.arg is not None:            # a named kwarg is a chosen field, not a spread
                    continue
                value = kw.value
                if isinstance(value, ast.Name) and value.id in request_names:
                    return True
                if _is_request_read(value):
                    return True
    return False


def _has_allowlist(func: AnyFunc, functions: dict[str, AnyFunc],
                   seen: set[str] | None = None) -> bool:
    # `seen` accumulates across the whole traversal rather than down each branch. This asks
    # whether an allowlist is reachable, and arriving at a helper a second time cannot change
    # that answer — but a per-path visited set enumerates every distinct path through the call
    # graph, which is exponential rather than linear. See `structural/js.py:_resolved` for the
    # measurement that found this: the same shape there took one file from 0.12s to over ten
    # minutes for 250 more lines of input.
    if seen is None:
        seen = set()
    if any(any(m in n for m in _ALLOWLIST_MARKERS) for n in _names_in(func)):
        return True
    for arg in list(func.args.args) + list(func.args.kwonlyargs):
        annotation = _dotted(arg.annotation).lower() if arg.annotation is not None else ""
        if annotation and annotation not in ("str", "int", "float", "bool", "dict", "list"):
            return True                            # a typed body is a declared field set
    for node in ast.walk(func):
        name = ""
        if isinstance(node, ast.Call):
            name = _dotted(node.func).rsplit(".", 1)[-1]
        elif isinstance(node, ast.Name):
            name = node.id
        callee = functions.get(name)
        if callee is None or name in seen or callee is func:
            continue
        seen.add(name)
        if _has_allowlist(callee, functions, seen):
            return True
    return False


def _dangerous_writes(func: AnyFunc, request_names: set[str]) -> list[ast.stmt | ast.expr]:
    """The three spellings, in one pass."""
    out: list[ast.stmt | ast.expr] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            dotted = _dotted(node.func)
            tail = dotted.rsplit(".", 1)[-1].lower()
            # `Model.objects.filter(...).update(**data)` and `Model(**data)`.
            if (tail in _ASSIGN_CALLS or dotted[:1].isupper()) and _spreads_request(node, request_names):
                out.append(node)
            # `user.__dict__.update(payload)` — the mapping is positional here, not a spread.
            if "__dict__" in dotted and tail == "update":
                for arg in node.args:
                    if (isinstance(arg, ast.Name) and arg.id in request_names) or _is_request_read(arg):
                        out.append(node)
        # `for key, value in data.items(): setattr(obj, key, value)`
        if isinstance(node, ast.For):
            iterated = node.iter
            src = iterated.func.value if isinstance(iterated, ast.Call) and \
                isinstance(iterated.func, ast.Attribute) else iterated
            named = isinstance(src, ast.Name) and src.id in request_names
            if (named or _is_request_read(src)) and any(
                    isinstance(c, ast.Call) and _dotted(c.func).rsplit(".", 1)[-1] == "setattr"
                    for c in ast.walk(node)):
                out.append(node)
    return out


def analyze_file(rel: str, text: str) -> list[Finding]:
    if not rel.lower().endswith(EXTS):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []

    lines = text.splitlines()
    functions = module_functions(tree)
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for func in functions.values():
        request_names = _request_bound_names(func)
        if not request_names:
            continue
        writes = _dangerous_writes(func, request_names)
        if not writes:
            continue
        if _has_allowlist(func, functions):
            continue
        line = writes[0].lineno
        if line in seen_lines:
            continue
        seen_lines.add(line)
        findings.append(Finding(
            detector_id="MASSASSIGN-PY",
            title="Mass assignment — the caller chooses which fields are written",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            cwe="CWE-915", owasp="A08",
            file=rel, line=line,
            evidence=_evidence(lines, line),
            fix=f"`{func.name}` spreads a request-supplied mapping into a persisted object, so "
                f"a body carrying `is_admin`, `role` or `balance` writes those too. Name the "
                f"fields the endpoint accepts — pick them out explicitly, or bind the body to a "
                f"schema that declares them — rather than passing the mapping through.",
            source="structural", verdict=Verdict.UNVERIFIED))
    return findings


def limitations() -> list[str]:
    return [
        "Mass-assignment analysis reports a request-supplied mapping spread into a persisted "
        "object with no field allowlist. A schema, serializer or typed body counts as the "
        "allowlist, so a handler that binds the body to a declared field set is never reported "
        "— including one whose schema declares a field it should not accept.",
    ]
