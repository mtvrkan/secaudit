"""The handler map — what a model needs to know before it can be asked about business logic.

The four structural rules in this package each answer one fixed question and emit a finding.
This module answers none of them. It extracts the *facts* those rules are built out of — who the
handler thinks its caller is, which identifiers the request chose, which rows are read or written
and whether the principal narrowed them, which money- and state-shaped values come from the
caller — and hands them to something that can reason about intent, which no rule here can.

Why it is a separate module rather than a fifth rule:

* **It emits no `Finding` and is not in `_RULES`.** Tier 0 produces the published RealVuln
  figure; a module that cannot add or remove a finding cannot move that number, which is what
  makes this shippable without a re-measurement.
* **Its vocabulary is its own.** `_MONEY_HINTS`, `_STATE_HINTS` and `_MUTATING` live here and
  never in `routes.py`, because a word added there changes what four measured rules see.

Everything about *what a handler is* still comes from `routes.py` — the same `_route_of`, the
same authorization evidence, the same request-reading helpers. That is the whole point of the
shared model: the map and the rules must not disagree about which functions are handlers.

**The map states its own blind spots, because they become the reader's blind spots.** Django and
class-based views mount without a literal path, so `path` is empty for them; authorization
evidence is followed only through functions defined in the same module, so an imported gate is
invisible and reads as absent; and there is no map at all for a non-Python source. A consumer
that does not say so out loud will present silence as coverage.
"""
from __future__ import annotations

import ast
import json
from dataclasses import dataclass

from .routes import (AnyFunc, EXTS, Route, _auth_evidence, _data_operations, _dotted,
                     _is_request_read, _principal_constrains, _principal_names_in_scope,
                     _reads_request, _request_id_names, is_production_source, module_functions,
                     routes_in)

__all__ = ["DataOp", "HandlerFact", "HandlerMap", "Rendered", "build", "of_file", "rank", "render"]

# Data-operation method names that write. Read/write matters to every question below it: a
# workflow skipped or a price trusted is only a vulnerability when something is persisted.
_MUTATING = ("save", "update", "delete", "insert", "create", "add", "set", "execute", "commit",
             "bulk_create", "update_one", "insert_one", "delete_one", "put_item")

# Value names that carry money or amounts. A handler that reads one of these FROM THE REQUEST is
# the client-trust shape; a handler that computes it server-side never appears here at all, which
# is exactly the distinction a safe twin needs to be visibly different from its vulnerable one.
_MONEY_HINTS = ("price", "amount", "total", "subtotal", "cost", "qty", "quantity", "discount",
                "balance", "credit", "fee", "rate", "currency", "points")

# Value names that carry workflow position. Split into what the handler WRITES and what it
# CHECKS on purpose: "sets status" is the transition, "compares status" is the guard in front of
# it, and a map that merged them would render the correct implementation and the bug identically.
_STATE_HINTS = ("status", "state", "stage", "step", "phase", "approved", "paid", "shipped",
                "verified", "published", "confirmed", "completed", "active", "enabled", "role")


@dataclass(frozen=True)
class DataOp:
    """One call that reads or writes persistent state, and whether the caller was narrowed."""

    line: int
    callee: str
    mutating: bool
    constrained_by_principal: bool

    def to_dict(self) -> dict:
        return {"line": self.line, "callee": self.callee, "mutating": self.mutating,
                "constrained_by_principal": self.constrained_by_principal}


@dataclass(frozen=True)
class HandlerFact:
    """Everything extracted about one mounted handler.

    `end_line` is not decoration: it is the span a citation has to land inside for the finding
    to be about this handler at all. A model that names a file it was shown and a line in some
    other function has not found anything, and without the span there is no way to tell.
    """

    file: str
    line: int
    end_line: int
    name: str
    path: str
    methods: tuple
    decorators: tuple
    state_changing: bool
    public_by_design: bool
    auth_evidence: bool
    principals: tuple
    request_ids: tuple
    reads_request: bool
    ops: tuple
    money_from_request: tuple
    state_writes: tuple
    state_checks: tuple
    helpers_reached: tuple

    @property
    def key(self) -> str:
        return f"{self.file}:{self.line}:{self.name}"

    def contains(self, line: int) -> bool:
        return self.line <= line <= self.end_line

    def to_dict(self) -> dict:
        return {
            "handler": self.name, "file": self.file, "line": self.line, "end_line": self.end_line,
            "path": self.path, "methods": list(self.methods), "decorators": list(self.decorators),
            "state_changing": self.state_changing, "public_by_design": self.public_by_design,
            "auth_evidence": self.auth_evidence, "principals": list(self.principals),
            "request_ids": list(self.request_ids), "reads_request": self.reads_request,
            "ops": [op.to_dict() for op in self.ops],
            "money_from_request": list(self.money_from_request),
            "state_writes": list(self.state_writes), "state_checks": list(self.state_checks),
            "helpers_reached": list(self.helpers_reached),
        }


@dataclass(frozen=True)
class HandlerMap:
    """Every handler found, plus what was not looked at — the second half being the honest half."""

    handlers: tuple
    files_scanned: int
    files_unparsed: tuple

    def to_dict(self) -> dict:
        return {"handlers": [h.to_dict() for h in self.handlers],
                "files_scanned": self.files_scanned,
                "files_unparsed": list(self.files_unparsed)}


@dataclass(frozen=True)
class Rendered:
    """A map rendered for a prompt, and how much of it did not fit.

    Truncation is a property of rendering under a budget, not of the extraction, so it is
    reported here rather than stored on `HandlerMap` — the same map rendered twice under two
    budgets is the same map. What matters is that the omission is *counted*: a payload that
    silently dropped half its handlers reads to the model exactly like a codebase that has none.
    """

    text: str
    included: int
    omitted: int
    # The facts that actually made it into `text`. Carried rather than recomputed because they
    # are what a citation is later checked against: a line the model reports has to fall inside
    # a handler the model was *shown*, and a span re-derived from a different subset would quietly
    # accept a citation in a handler that was truncated away.
    facts: tuple = ()


def of_file(rel: str, text: str) -> list:
    """Every handler fact in one Python source file. Empty for anything else."""
    if not rel.lower().endswith(EXTS) or not is_production_source(rel):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []          # a file we cannot parse is a file we say nothing about

    functions = module_functions(tree)
    return [_fact(route, rel, functions) for route, _ in routes_in(tree)]


def build(files: dict) -> HandlerMap:
    """The map over a whole source tree.

    Iterates in sorted order and reports the files it could not parse, because a handler missing
    from this map is indistinguishable from a handler that does not exist unless the gap is named.
    """
    handlers: list = []
    unparsed: list = []
    scanned = 0
    for rel in sorted(files):
        if not rel.lower().endswith(EXTS) or not is_production_source(rel):
            continue
        scanned += 1
        text = files[rel]
        try:
            ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            unparsed.append(rel)
            continue
        handlers.extend(of_file(rel, text))
    handlers.sort(key=lambda h: (h.file, h.line))
    return HandlerMap(tuple(handlers), scanned, tuple(unparsed))


def rank(fact: HandlerFact) -> tuple:
    """Sort key for which handlers are worth a model's attention first.

    Deliberately not a score: the two leading terms are the two shapes the pass exists to find —
    a state-changing handler with no authorization evidence, and a lookup by a caller-chosen id
    that no principal narrows. Everything after them is a tie-break, and the last two terms are
    the file and line so the ordering is total and the rendered payload is byte-identical across
    runs.
    """
    unguarded = fact.state_changing and not fact.auth_evidence and not fact.public_by_design
    idor_shape = (bool(fact.request_ids) and bool(fact.ops)
                  and not any(op.constrained_by_principal for op in fact.ops))
    interesting = bool(fact.money_from_request) or bool(fact.state_writes)
    return (0 if (unguarded or idor_shape) else 1,
            0 if interesting else 1,
            fact.file, fact.line)


def render(handler_map: HandlerMap, budget: int) -> Rendered:
    """The map as JSON lines under a character budget, most interesting handler first.

    One object per line rather than one document: a truncated JSON document is unparseable and a
    truncated line list is simply shorter, and this payload is truncated by construction whenever
    a repository is large enough to matter.
    """
    header = json.dumps({
        "note": "Extracted facts about each mounted handler. Python sources only; a handler in "
                "another language is not listed and is not thereby absent. Authorization "
                "evidence is followed only through functions defined in the same module, so an "
                "imported gate reads as absent. Django and class-based views mount without a "
                "literal path, so `path` is empty for them.",
        "files_scanned": handler_map.files_scanned,
        "files_unparsed": list(handler_map.files_unparsed),
        "handlers_found": len(handler_map.handlers),
    }, sort_keys=True)

    lines = [header]
    used = len(header)
    included: list = []
    for fact in sorted(handler_map.handlers, key=rank):
        line = json.dumps(fact.to_dict(), sort_keys=True)
        if used + 1 + len(line) > budget:
            break
        lines.append(line)
        used += 1 + len(line)
        included.append(fact)
    return Rendered("\n".join(lines), len(included),
                    len(handler_map.handlers) - len(included), tuple(included))


# ------------------------------------------------------------------------------- extraction

def _fact(route: Route, rel: str, functions: dict) -> HandlerFact:
    func = route.func
    principals = _principal_names_in_scope(func)
    ops = tuple(DataOp(line=call.lineno,
                       callee=_dotted(call.func),
                       mutating=_dotted(call.func).rsplit(".", 1)[-1].lower() in _MUTATING,
                       constrained_by_principal=_principal_constrains(call, principals, func,
                                                                      functions))
                for call in _data_operations(func))
    request_keys = _request_keys(func)
    return HandlerFact(
        file=rel,
        line=route.line,
        end_line=getattr(func, "end_lineno", None) or route.line,
        name=func.name,
        path=route.path,
        methods=tuple(sorted(route.methods)),
        decorators=tuple(route.decorators),
        state_changing=route.state_changing,
        public_by_design=route.public_by_design,
        auth_evidence=_auth_evidence(func, route.decorators, functions),
        principals=tuple(sorted(principals)),
        request_ids=tuple(sorted(_request_id_names(route))),
        reads_request=_reads_request(func),
        ops=tuple(sorted(ops, key=lambda op: (op.line, op.callee))),
        money_from_request=tuple(sorted(_matching(request_keys, _MONEY_HINTS))),
        state_writes=tuple(sorted(_matching(_written_attrs(func) | request_keys, _STATE_HINTS))),
        state_checks=tuple(sorted(_matching(_compared_attrs(func), _STATE_HINTS))),
        helpers_reached=tuple(sorted(_helpers_reached(func, functions))),
    )


def _matching(names: set, hints: tuple) -> set:
    return {n for n in names if any(hint in n.lower() for hint in hints)}


def _request_aliases(func: AnyFunc) -> set:
    """Locals bound to the request payload — `body = request.get_json()`.

    Without these the extraction sees `request.get_json()` and then loses the trail one line
    later, which is the shape every real handler is written in: bind the body once, read keys
    off it. `routes.py` already tracks the same aliasing for id-shaped keys; this is the same
    fact asked for a different set of key names.
    """
    out = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and _is_request_read(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out.add(target.id)
    return out


def _request_keys(func: AnyFunc) -> set:
    """String keys this handler reads out of the request, directly or through an alias.

    `request.json.get("price")`, `request.form["price"]` and `body["price"]` two lines after
    `body = request.get_json()` are the same fact and all three are read. Keyed on the literal,
    which `code_view` would have blanked — this module works on the AST, where a constant is
    still a constant.
    """
    aliases = _request_aliases(func)
    keys = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and _reads_payload(node, aliases):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    keys.add(arg.value)
        elif isinstance(node, ast.Subscript) and _reads_payload(node.value, aliases):
            key = node.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                keys.add(key.value)
    return keys


def _reads_payload(node: ast.AST, aliases: set) -> bool:
    if _is_request_read(node):
        return True
    dotted = _dotted(node.func if isinstance(node, ast.Call) else node)
    root = dotted.split(".", 1)[0]
    return bool(root) and root in aliases


def _written_attrs(func: AnyFunc) -> set:
    """Attribute names this handler assigns to — `order.status = "shipped"` gives `status`."""
    out = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute):
                    out.add(target.attr)
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            if isinstance(node.target, ast.Attribute):
                out.add(node.target.attr)
        elif isinstance(node, ast.Call):
            # `order.update(status="shipped")` writes too — but only on a call that writes.
            # Reading the keywords of *every* call put `render_template(..., status=…)` in the
            # same bucket as a transition, which is how a map stops describing anything.
            if _dotted(node.func).rsplit(".", 1)[-1].lower() in _MUTATING:
                out.update(kw.arg for kw in node.keywords if kw.arg)
    return out


def _compared_attrs(func: AnyFunc) -> set:
    """Attribute names this handler tests — the guard in front of a transition, if there is one."""
    out = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Compare):
            for side in [node.left, *node.comparators]:
                if isinstance(side, ast.Attribute):
                    out.add(side.attr)
                elif isinstance(side, ast.Name):
                    out.add(side.id)
    return out


def _helpers_reached(func: AnyFunc, functions: dict) -> set:
    """Module-local functions this handler calls or references.

    Named in the map because they are where the evidence went in the codebases that factored it
    out, and because a reader who sees `helpers_reached: []` next to `auth_evidence: false` knows
    the absence is not hiding in a helper this extraction failed to follow.
    """
    out = set()
    for node in ast.walk(func):
        name = ""
        if isinstance(node, ast.Call):
            name = _dotted(node.func).rsplit(".", 1)[-1]
        elif isinstance(node, ast.Name):
            name = node.id
        if name and name in functions and functions[name] is not func:
            out.add(name)
    return out
