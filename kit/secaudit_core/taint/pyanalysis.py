"""Python taint analysis: an `ast` walk with per-function summaries.

The half of the engine with a real parser behind it. Reads the catalog, produces `TaintPath`
objects, and knows nothing about JavaScript or about how files are stitched together — the
cross-module pass in `__init__` owns that.
"""
from __future__ import annotations

import ast

from .catalog import (PY_SINKS, PY_METHOD_SINKS, PY_REQUEST_SOURCES, PY_SANITIZERS,
                      PY_LOG_SINK, _PY_LOG_CALLS, _PY_SENSITIVE_SOURCE)
from ..schema import Confidence
from .model import _SUMMARY_ROUNDS, FunctionSummary, PyFunc, Sink, TaintPath

# --------------------------------------------------------------------------- Python analysis

def _py_dotted(node: ast.AST) -> str:
    """`subprocess.call` from the Call's func node; '' when it is not a plain dotted name."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    else:
        return ""
    return ".".join(reversed(parts))


def _py_is_source(node: ast.AST) -> str:
    """The framework-request expression **at this node**, or '' — deliberately not recursive.

    Recursion belongs to `_PyScope.taint_of`, which must stop descending at a sanitizer call.
    A helper that walked the whole subtree would see through `int(request.args['n'])` and
    report taint the sanitizer had already removed."""
    if isinstance(node, ast.Subscript):
        node = node.value
    if isinstance(node, (ast.Attribute, ast.Name)):
        dotted = _py_dotted(node)
        if dotted and PY_REQUEST_SOURCES.match(dotted + "."):
            return dotted
    return ""


def _py_method_sink(dotted: str) -> Sink | None:
    """A `PY_METHOD_SINKS` entry matching the tail of `dotted`, or None.

    `Entry.objects.raw` matches on `raw`; `self.db.session.execute` matches on `execute` with
    `session` as the receiver. A bare `execute(q)` — no receiver at all — is not a database
    call in any framework this models, so it is not matched: the receiver requirement is what
    keeps this from labelling arbitrary one-word calls CWE-89.
    """
    if "." not in dotted:
        return None
    receiver, _, method = dotted.rpartition(".")
    entry = PY_METHOD_SINKS.get(method)
    if entry is None:
        return None
    sink, receivers = entry
    if receivers is None:
        return sink
    return sink if receiver.rpartition(".")[2] in receivers else None


# Keyword arguments a sink is dangerous through, by sink id. Only the ORM escapes need this:
# `.extra(where=[...], select={...}, tables=[...])` takes its injectable SQL by keyword, and
# `params=`/`select_params=` are the fix rather than the bug, so they are deliberately absent.
_PY_SINK_KWARGS: dict[str, tuple[str, ...]] = {
    "TAINT-PY-SQLI-ORM": ("where", "select", "tables", "order_by", "sql"),
}


# A decorator that turns the function below it into an HTTP route: `@app.get("/x")`,
# `@router.post(...)`, `@bp.route(...)`. Matched on the method name with a receiver present, so
# a bare `@get` (which is not a routing decorator in any of these frameworks) does not qualify.
_PY_ROUTE_METHODS = frozenset({"route", "get", "post", "put", "patch", "delete", "head",
                               "options", "websocket"})

# Parameters a framework injects rather than binds from the request. FastAPI's `Depends` is the
# common one: `db: Session = Depends(get_db)` is a database handle, and treating it as untrusted
# would report the connection object itself as attacker-controlled.
_PY_INJECTED_DEFAULTS = frozenset({"Depends", "Security", "Provide", "Inject"})


def _py_route_params(node: PyFunc) -> list[str]:
    """Parameters of `node` that carry request data, when `node` is a route handler.

    Two shapes, because the two dominant Python web stacks disagree about where request data
    arrives:

      * **FastAPI / Flask / Starlette** — a routing decorator, and the handler's parameters are
        bound from the path, query string and body by the framework. `def read(item_id: str)`
        under `@app.get("/items/{item_id}")` is request data by contract.
      * **Django** — no decorator; the convention is a first parameter literally named
        `request`, and everything after it is a URL capture group.

    Both were previously seen as ordinary parameters, which the engine rates a MEDIUM lead
    "because whether they carry untrusted data depends on callers". For a route handler there
    are no callers to depend on — the framework is the caller, and it passes attacker input.
    That downgrade is most of why real FastAPI and Django code scored the way it did on
    RealVuln: the finding was often there, one confidence rung below where anyone would look.
    """
    decorated = any(_py_dotted(d.func if isinstance(d, ast.Call) else d).rpartition(".")[2]
                    in _PY_ROUTE_METHODS
                    and "." in _py_dotted(d.func if isinstance(d, ast.Call) else d)
                    for d in node.decorator_list)

    positional = _py_positional_params(node)
    django_view = bool(positional) and positional[0] == "request"
    if not decorated and not django_view:
        return []

    injected = {arg.arg for arg, default in _py_defaults(node)
                if isinstance(default, ast.Call)
                and _py_dotted(default.func).rpartition(".")[2] in _PY_INJECTED_DEFAULTS}
    return [name for name in _py_taintable_params(node)
            if name != "request" and name not in injected]


def _py_defaults(node: PyFunc) -> list[tuple[ast.arg, ast.expr]]:
    """(arg, default) for every parameter that has one — defaults align to the END of the list."""
    args = node.args
    positional = [*args.posonlyargs, *args.args]
    pairs = list(zip(positional[len(positional) - len(args.defaults):], args.defaults))
    pairs += [(a, d) for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None]
    return pairs


def _py_names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


class _PyScope:
    """Taint state for one function body, in source order."""

    def __init__(self, path: str, lines: list[str],
                 summaries: dict[str, FunctionSummary] | None = None,
                 functions: dict[str, PyFunc] | None = None,
                 origins: dict[str, str] | None = None):
        self.path, self.lines = path, lines
        self.tainted: dict[str, tuple[int, str, str]] = {}   # name -> (line, expr, kind)
        self.paths: list[TaintPath] = []
        # Summaries of the other functions in scope, for interprocedural resolution. Includes
        # imported ones when the project pass supplied them; `origins` says which file each
        # non-local name came from, and is empty for a single-file analysis.
        self.summaries = summaries or {}
        self.functions: dict[str, PyFunc] = functions or {}
        self.origins = origins or {}
        # Parameters whose taint reaches this function's return value, and whether it returns
        # untrusted input it fetched itself — the two facts this function's own summary needs.
        self.returns_params: set[str] = set()
        self.returns_source = False

    def line_text(self, lineno: int) -> str:
        return self.lines[lineno - 1].strip()[:200] if 0 < lineno <= len(self.lines) else ""

    # -- taint queries ----------------------------------------------------
    def taint_of(self, node: ast.AST | None) -> tuple[str, int, str] | None:
        """(expr, line, kind) describing why `node` is tainted, or None.

        Recursive, and it stops at a sanitizer call — so `'sleep ' + str(int(n))` is clean
        even though the tainted `n` is still lexically inside it. A non-recursive check on
        the outermost node would only catch `int(n)` standing alone, which is the shape real
        code almost never takes."""
        if node is None:
            return None
        if isinstance(node, ast.Call):
            name = _py_dotted(node.func)
            if name in PY_SANITIZERS:
                return None                      # this subtree has been cleaned
            summary = self.summaries.get(name)
            if summary is not None:
                return self._taint_through(node, name, summary)
            children = [node.func, *node.args, *(k.value for k in node.keywords)]
            return next((t for t in map(self.taint_of, children) if t), None)

        src = _py_is_source(node)
        if src:
            return (src, getattr(node, "lineno", 0), "request")
        if isinstance(node, ast.Name) and node.id in self.tainted:
            line, expr, kind = self.tainted[node.id]
            return (expr, line, kind)
        return next((t for t in map(self.taint_of, ast.iter_child_nodes(node)) if t), None)

    def _taint_through(self, call: ast.Call, name: str,
                       summary: FunctionSummary) -> tuple[str, int, str] | None:
        """Taint of a call to a function defined in this same file, resolved by its summary.

        The `return None` at the end is the interesting half: a local function whose return
        value does not carry parameter taint **launders** it, exactly like a sanitizer. That is
        a precision win the generic subtree scan cannot make, because it has no way to know
        that `format_id(user_input)` returns an integer."""
        if summary.returns_source:
            return (f"{name}()", call.lineno, "request")
        for pos, arg in enumerate(call.args):
            if self._param_at(name, pos) in summary.returns_params:
                taint = self.taint_of(arg)
                if taint:
                    return taint
        for kw in call.keywords:
            if kw.arg in summary.returns_params:
                taint = self.taint_of(kw.value)
                if taint:
                    return taint
        return None

    def _param_at(self, name: str, pos: int) -> str | None:
        callee = self.functions.get(name)
        if callee is None:
            return None
        params = _py_positional_params(callee)
        return params[pos] if pos < len(params) else None

    # -- statement handling ----------------------------------------------
    def visit_body(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            self.visit(stmt)

    def visit(self, node: ast.stmt) -> None:
        if isinstance(node, ast.Assign):
            self.handle_assign(node.targets, node.value)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
            self.handle_assign([node.target], node.value)
        elif isinstance(node, ast.If):
            self.handle_if(node)
            return
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self.handle_assign([node.target], node.iter)
            self.visit_body(node.body)
            self.visit_body(node.orelse)
        elif isinstance(node, (ast.While, ast.With, ast.AsyncWith, ast.Try)):
            for attr in ("body", "orelse", "finalbody"):
                self.visit_body(getattr(node, attr, []) or [])
            for handler in getattr(node, "handlers", []):
                self.visit_body(handler.body)
        elif isinstance(node, ast.Return):
            self.handle_return(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return  # nested definitions get their own scope from the module walk

        for call in (n for n in ast.walk(node) if isinstance(n, ast.Call)):
            self.check_sink(call)
            self.check_local_call(call)

    def handle_return(self, node: ast.Return) -> None:
        """Record what this function hands back, which is its half of the summary contract."""
        taint = self.taint_of(node.value)
        if not taint:
            return
        expr, _, kind = taint
        if kind == "request":
            self.returns_source = True
        else:
            self.returns_params.add(expr)

    def handle_assign(self, targets: list[ast.expr], value: ast.expr) -> None:
        for call in (n for n in ast.walk(value) if isinstance(n, ast.Call)):
            self.check_sink(call)
        taint = self.taint_of(value)
        if not taint:
            for name in _py_target_names(targets):
                self.tainted.pop(name, None)
            return
        expr, line, kind = taint
        for name in _py_target_names(targets):
            self.tainted[name] = (line, expr, kind)

    def handle_if(self, node: ast.If) -> None:
        """`if <mentions tainted x>: raise/return` is a validation guard — it clears x."""
        guarded = _py_names(node.test) & set(self.tainted)
        exits = any(isinstance(n, (ast.Raise, ast.Return)) for n in ast.walk(node))
        self.visit_body(node.body)
        self.visit_body(node.orelse)
        for call in (n for n in ast.walk(node.test) if isinstance(n, ast.Call)):
            self.check_sink(call)
        if guarded and exits:
            for name in guarded:
                self.tainted.pop(name, None)

    def check_sink(self, call: ast.Call) -> None:
        dotted = _py_dotted(call.func)
        if self._check_log_sink(call, dotted):
            return
        sink = PY_SINKS.get(dotted) or _py_method_sink(dotted)
        if sink is None:
            return
        if sink.requires_kwarg:
            kw = next((k for k in call.keywords if k.arg == sink.requires_kwarg), None)
            if kw is None or not (isinstance(kw.value, ast.Constant) and kw.value.value):
                return
        positions = sink.taint_args or tuple(range(len(call.args)))
        for pos in positions:
            if pos >= len(call.args):
                continue
            taint = self.taint_of(call.args[pos])
            if not taint:
                continue
            expr, src_line, kind = taint
            self.paths.append(TaintPath(
                sink=sink, file=self.path, line=call.lineno, source=expr,
                source_line=src_line, source_kind=kind,
                steps=[(call.lineno, f"{sink.id} argument {pos}")],
                evidence=self.line_text(call.lineno)))
            return

        # Keyword arguments, checked only after every positional one came back clean. Django's
        # `.extra(where=[...])` and `.raw(sql, params=...)` are called with keywords far more
        # often than positionally, so a positional-only sink check misses the shape the bug
        # actually takes. Restricted to the sinks that name the keywords they are dangerous
        # through: scanning every keyword of every sink would report a value bound as a
        # parameter — which is the fix — as though it were the bug.
        for keyword in call.keywords:
            if keyword.arg not in _PY_SINK_KWARGS.get(sink.id, ()):
                continue
            taint = self.taint_of(keyword.value)
            if not taint:
                continue
            expr, src_line, kind = taint
            self.paths.append(TaintPath(
                sink=sink, file=self.path, line=call.lineno, source=expr,
                source_line=src_line, source_kind=kind,
                steps=[(call.lineno, f"{sink.id} keyword `{keyword.arg}`")],
                evidence=self.line_text(call.lineno)))
            return


    def _check_log_sink(self, call: ast.Call, dotted: str) -> bool:
        """Report a credential, cookie, header or raw body reaching a logging call.

        Returns True when this call was a logging call, handled or not, so the caller stops:
        `logger.info` is not a sink in `PY_SINKS` and must not fall through to one.

        The narrowing is the whole design. Any real service logs request-derived data on
        purpose — a path, a status, an id — so "tainted value reaches a logger" would fire on
        every well-behaved application, and the first thing anyone would do with a rule like
        that is switch it off. What is reported is the value whose own source expression names
        something that must not be persisted.
        """
        method = dotted.rpartition(".")[2]
        if method not in _PY_LOG_CALLS or "." not in dotted:
            return False
        receiver = dotted.rpartition(".")[0].rpartition(".")[2].lower()
        if "log" not in receiver:
            return False
        for arg in [*call.args, *(k.value for k in call.keywords)]:
            taint = self.taint_of(arg)
            if not taint or not _PY_SENSITIVE_SOURCE.search(taint[0]):
                continue
            expr, src_line, kind = taint
            self.paths.append(TaintPath(
                sink=PY_LOG_SINK, file=self.path, line=call.lineno, source=expr,
                source_line=src_line, source_kind=kind,
                steps=[(call.lineno, f"{PY_LOG_SINK.id} logged by {dotted}()")],
                evidence=self.line_text(call.lineno)))
            return True
        return True

    def _sink_step(self, sink: Sink, callee: str, where: str) -> str:
        """The path's last hop, phrased for where the sink actually is.

        Three cases, because collapsing them lies in one direction or the other: a sink in this
        file needs no location, a sink in the function we just called should name that
        function, and a sink further down the chain must NOT — writing
        `inside a/sink.py:relay()` would name a function that does not live in that file."""
        if where == self.path:
            return f"{sink.id} inside {callee}()"
        if where == self.origins.get(callee, self.path):
            return f"{sink.id} inside {where}:{callee}()"
        return f"{sink.id} in {where}, reached via {callee}()"

    def check_local_call(self, call: ast.Call) -> None:
        """Report a sink that lives inside a function defined in this same file.

        This is the shape almost all real code takes — a route handler reads the request and
        hands it to a helper, and the dangerous call is in the helper. An intra-procedural
        analysis sees a request source that goes nowhere and a sink fed by a parameter, and
        reports the second as a MEDIUM lead at best. Resolving the call joins them into one
        HIGH-confidence path that names both ends."""
        name = _py_dotted(call.func)
        summary = self.summaries.get(name)
        callee = self.functions.get(name)
        if not summary or callee is None or not summary.sink_params:
            return

        arguments = [(self._param_at(name, pos), arg) for pos, arg in enumerate(call.args)]
        arguments += [(kw.arg, kw.value) for kw in call.keywords]
        for param, arg in arguments:
            resolved = summary.sink_for(param) if param else None
            if resolved is None:
                continue
            sink, sink_line, where = resolved
            taint = self.taint_of(arg)
            if not taint:
                continue
            expr, src_line, kind = taint
            inside = self._sink_step(sink, name, where)
            self.paths.append(TaintPath(
                sink=sink, file=self.path, line=call.lineno, source=expr,
                source_line=src_line, source_kind=kind,
                steps=[(call.lineno, f"passed to {name}({param})"), (sink_line, inside)],
                evidence=self.line_text(call.lineno),
                sink_line=sink_line, sink_file=where))
            return


def _py_positional_params(node: PyFunc) -> list[str]:
    """Parameter names in positional order, `self`/`cls` included so argument positions line
    up with the call site — the seeding step skips them, the mapping must not."""
    args = node.args
    return [a.arg for a in [*args.posonlyargs, *args.args]]


def _py_taintable_params(node: PyFunc) -> list[str]:
    args = node.args
    return [a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]
            if a.arg not in ("self", "cls")]


def _py_target_names(targets: list[ast.expr]) -> set[str]:
    names: set[str] = set()
    for target in targets:
        for node in ast.walk(target):
            if isinstance(node, ast.Name):
                names.add(node.id)
    return names



def _python_functions(tree: ast.AST) -> dict[str, PyFunc]:
    """Every function defined in the module, by simple name.

    A name collision (two methods called `handle` on different classes) keeps the first and
    is a known imprecision, not a silent one: resolving it properly needs a qualified name
    and class-aware call resolution, which is a bigger analysis than this tier promises."""
    functions: dict[str, PyFunc] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.setdefault(node.name, node)
    return functions


def _python_summaries(functions: dict[str, PyFunc], path: str, lines: list[str],
                      resolve_functions: dict | None = None,
                      resolve_summaries: dict | None = None,
                      origins: dict[str, str] | None = None) -> dict[str, FunctionSummary]:
    """Derive each function's summary, iterating until nothing changes.

    Seeded with empty summaries, so the first round sees only intra-procedural facts; each
    later round can resolve calls the previous one could not. Two rounds already cover a
    handler → helper → sink chain, which is the common case."""
    summaries = {name: FunctionSummary() for name in functions}
    for _ in range(_SUMMARY_ROUNDS):
        changed = False
        for name, node in functions.items():
            # Imported names override local ones, because that is what an import statement
            # does to a namespace — resolving to the local definition would analyse a
            # function the call never reaches.
            scope = _PyScope(path, lines,
                             {**summaries, **(resolve_summaries or {})},
                             {**functions, **(resolve_functions or {})}, origins)
            params = _py_taintable_params(node)
            route = set(_py_route_params(node))
            for param in params:
                # Seed with the bare parameter name so a reported path can be matched back to
                # the parameter that caused it. A route handler's parameters are seeded as
                # `request` instead: the framework is their only caller and it binds them
                # from the path, query string or body.
                kind = "request" if param in route else "parameter"
                scope.tainted[param] = (node.lineno, param, kind)
            scope.visit_body(node.body)

            sink_params: dict[str, tuple[Sink, int, str]] = {}
            for tp in scope.paths:
                if tp.source_kind == "parameter" and tp.source in params:
                    sink_params.setdefault(tp.source, (tp.sink, tp.sink_line, tp.sink_file))
            summary = FunctionSummary(
                sink_params=tuple((param, sink, line, file)
                                  for param, (sink, line, file) in sorted(sink_params.items())),
                returns_params=frozenset(scope.returns_params & set(params)),
                returns_source=scope.returns_source)
            if summary != summaries[name]:
                summaries[name] = summary
                changed = True
        if not changed:
            break
    return summaries


def _python_paths(path: str, text: str, local: dict[str, PyFunc],
                  functions: dict[str, PyFunc], summaries: dict[str, FunctionSummary],
                  origins: dict[str, str]) -> list[TaintPath]:
    """Scan this file's own function bodies, resolving calls against `functions`/`summaries`
    — which may include names imported from other files in the analysed set."""
    lines = text.splitlines()
    out: list[TaintPath] = []
    for name, node in local.items():
        scope = _PyScope(path, lines, summaries, functions, origins)
        route = set(_py_route_params(node))
        for param in _py_taintable_params(node):
            kind = "request" if param in route else "parameter"
            scope.tainted[param] = (node.lineno, f"{name}({param})", kind)
        scope.visit_body(node.body)
        out.extend(scope.paths)
    return out



def _dedupe_paths(paths: list[TaintPath]) -> list[TaintPath]:
    """One bug, one path. A sink reached both directly and through a call would otherwise be
    reported twice; keep the higher-confidence one, since that is the claim being made."""
    best: dict[tuple, TaintPath] = {}
    for p in paths:
        # Keyed on where the dangerous call IS, not where the path was reported from. One
        # helper called by three routes is one bug with one fix; three findings would be three
        # tickets against the same line. The HIGH one survives, so the route that actually
        # reaches it is the one named.
        key = (p.sink_file, p.sink_line, p.sink.id)
        current = best.get(key)
        if current is None or (p.confidence == Confidence.HIGH
                               and current.confidence != Confidence.HIGH):
            best[key] = p
    return list(best.values())

