"""Work sized by the caller — CWE-400, uncontrolled resource consumption.

43 labels, 16 of them already reached through other rules and 27 missed outright. The shape of
the 27 is a number the request supplied, used as *how much to do*, with nothing between the two:

    async def spool_fan(count: int = 500, ref: str = "batch", …):
        rows = [{"idx": idx, "ref": ref} for idx in range(count)]

    "<br>".join("#" * int(params["size"]) for _ in range(int(params["size"])))

One request with `count=100000000` is a memory exhaustion, and it costs the caller a single HTTP
request — which is what separates this from ordinary slowness. The endpoint is not
under-provisioned; it is taking instructions.

The rule is the relation and both halves are needed. **A request-derived integer** — a typed
handler parameter, or an `int()` around a query value — reaching **an allocation whose size is
that integer**: a `range`, a sequence repeat, a buffer, a sleep. A request that says which *page*
to fetch is the same syntax with a bound around it, so the third element is that **nothing clamps
it**: no `min()`, no comparison against a constant, no framework-level `le=`/`max_value=`, no
`if count > LIMIT`.

Clamp evidence is read generously and function-wide, for the reason the whole package states: a
rule reporting the absence of a control must be sure of the absence. Any comparison of the value
against a literal counts, even one that rejects rather than clamps — `if count > 1000: raise` is
the fix written the other way round.

What it does not decide is what the number costs. `range(count)` building ten small dicts is
reported the same as one allocating a megabyte each; a static reading cannot price the loop body,
and the fix — bound the input where it enters — does not depend on the price.
"""
from __future__ import annotations

import ast

from ..schema import Confidence, Finding, Severity, Verdict
from .routes import (AnyFunc, _dotted, _evidence, _is_request_read, EXTS,
                     is_web_module, module_functions, _route_of)

# Calls whose cost is their argument.
_ALLOCATORS = ("range", "bytearray", "bytes", "zeros", "empty", "repeat", "sleep", "randbytes",
               "urandom", "token_bytes", "token_hex", "product", "permutations", "combinations")

# Framework spellings that bound a parameter before the handler sees it.
_DECLARED_BOUNDS = ("le", "lt", "max_value", "max_length", "max_digits", "ge", "gt", "max_items")

_CLAMPS = ("min", "max", "clamp", "cap", "bound", "limit", "islice", "paginate", "truncate")


def _int_parameters(func: AnyFunc) -> set[str]:
    """Handler parameters the caller fills with a number, minus the ones already bounded."""
    names: set[str] = set()
    args = list(func.args.args) + list(func.args.kwonlyargs)
    defaults = ([None] * (len(func.args.args) - len(func.args.defaults))) + list(func.args.defaults)
    by_arg = dict(zip(func.args.args, defaults))
    by_arg.update(dict(zip(func.args.kwonlyargs, func.args.kw_defaults)))
    for arg in args:
        annotation = _dotted(arg.annotation).lower() if arg.annotation is not None else ""
        if annotation not in ("int", "float"):
            continue
        default = by_arg.get(arg)
        if isinstance(default, ast.Call):
            declared = {kw.arg for kw in default.keywords if kw.arg}
            if declared & set(_DECLARED_BOUNDS):
                continue                       # `count: int = Query(500, le=1000)` is bounded
            if _dotted(default.func).rsplit(".", 1)[-1] in ("Depends", "Security", "Provide"):
                continue
        names.add(arg.arg)
    return names


def _int_of_request(func: AnyFunc) -> tuple[set[str], list[ast.Call]]:
    """Locals bound to `int(<something the caller sent>)`, and the inline conversions."""
    names: set[str] = set()
    inline: list[ast.Call] = []

    def is_int_of_request(node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        if _dotted(node.func).rsplit(".", 1)[-1] not in ("int", "float"):
            return False
        return any(_is_request_read(child)
                   for child in ast.walk(node)
                   if isinstance(child, (ast.Call, ast.Attribute)))

    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and is_int_of_request(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        if is_int_of_request(node):
            inline.append(node)                                           # type: ignore[arg-type]
    return names, inline


def _clamped(func: AnyFunc, names: set[str]) -> bool:
    """Whether anything in the function bounds one of these values."""
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            tail = _dotted(node.func).rsplit(".", 1)[-1].lower()
            if tail in _CLAMPS and any(
                    isinstance(a, ast.Name) and a.id in names for a in node.args):
                return True
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            mentions = any(isinstance(o, ast.Name) and o.id in names for o in operands)
            literal = any(isinstance(o, ast.Constant) and isinstance(o.value, (int, float))
                          for o in operands)
            if mentions and literal:
                return True
    return False


def _unbounded_allocations(func: AnyFunc, names: set[str],
                           inline: list[ast.Call]) -> list[ast.expr]:
    # `ast.expr`, not `ast.AST`: the caller reports the first of these and needs a line number,
    # which only an expression or a statement carries.
    out: list[ast.expr] = []

    def sized_by_caller(node: ast.AST) -> bool:
        if isinstance(node, ast.Name) and node.id in names:
            return True
        return any(child is c for c in inline for child in [node])

    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            tail = _dotted(node.func).rsplit(".", 1)[-1].lower()
            if tail in _ALLOCATORS and any(sized_by_caller(a) for a in node.args):
                out.append(node)
        # `"#" * size` and `[0] * size` — a repeat is an allocation with no call to name it.
        # One side has to be a sequence: without that test this matched `price * quantity`,
        # which is arithmetic on two numbers and allocates nothing.
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            sides = (node.left, node.right)
            sequence = any(isinstance(s, (ast.List, ast.Tuple)) or
                           (isinstance(s, ast.Constant) and isinstance(s.value, (str, bytes)))
                           for s in sides)
            if sequence and any(sized_by_caller(s) for s in sides):
                out.append(node)
    return out


def analyze_file(rel: str, text: str) -> list[Finding]:
    if not rel.lower().endswith(EXTS):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    if not is_web_module(tree, text):
        return []

    lines = text.splitlines()
    findings: list[Finding] = []
    for func in sorted(module_functions(tree).values(), key=lambda f: f.lineno):
        converted, inline = _int_of_request(func)
        # A typed `int` parameter is only caller-supplied on a mounted handler — FastAPI binds
        # it from the query string, an internal helper is handed it by other code in the file.
        # Dogfooding found the difference: `range(start, len(lines) + 1)` inside this engine's
        # own scanner is not a request choosing how much work to do.
        names = converted | (_int_parameters(func) if _route_of(func) is not None else set())
        if not names and not inline:
            continue
        if _clamped(func, names):
            continue
        allocations = _unbounded_allocations(func, names, inline)
        if not allocations:
            continue
        line = min(a.lineno for a in allocations)
        findings.append(Finding(
            detector_id="RESOURCE-PY-UNBOUNDED",
            title="Amount of work allocated from a number the caller supplied",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            cwe="CWE-400", owasp="A04",
            file=rel, line=line,
            evidence=_evidence(lines, line),
            fix=f"`{func.name}` sizes an allocation from a value the request supplies and "
                f"nothing bounds it, so one request chooses how much memory and time the "
                f"process spends. Clamp the value where it enters — a framework bound "
                f"(`Query(..., le=100)`), a `min(value, MAX)`, or a rejection above a documented "
                f"ceiling — and paginate rather than sizing a response from a parameter.",
            source="structural", verdict=Verdict.UNVERIFIED))
    return findings


def limitations() -> list[str]:
    return [
        "Resource analysis reports a request-supplied number reaching an allocation — a range, a "
        "repeat, a buffer, a sleep — where nothing in the function bounds it. It cannot price "
        "the work: a loop building ten small dicts reads the same as one allocating a megabyte "
        "each. Any comparison of the value against a numeric literal counts as a bound, "
        "including one that rejects rather than clamps.",
    ]
