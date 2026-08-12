"""Taint analysis (Tier 0, still zero-dependency, still no LLM).

The regex pack in `detectors.py` matches a *sink*. This module answers the question that
actually decides whether a sink is a bug: **does untrusted input reach it?** That is the
difference between `db.query(sql)` (fine) and `db.query(sql)` where `sql` was built two lines
earlier from `req.query.name` (SQL injection). A single-line regex cannot see the difference;
real code almost never puts the source and the sink on the same line, which is exactly why
rule-based scanners score so poorly on real corpora.

What this does:

  * **Python** — a real AST walk (`ast`, stdlib). Sources, propagation through assignment,
    binary operations, f-strings, `.format()`, subscripts and call arguments; sanitizers and
    validate-then-raise guards clear taint. **Interprocedural within a file**: each function
    is reduced to a summary (which parameters reach a sink, which escape through the return
    value), and call sites are resolved against those, iterated to a fixed point. That is what
    connects the near-universal real shape — a handler reads the request, a helper does the
    dangerous thing — into one path instead of two unrelated half-findings.
  * **JavaScript / TypeScript** — there is no JS parser in the Python standard library and a
    vendored one would break the zero-runtime-dependency invariant, so this is a brace-aware
    statement scanner, not a parser. It tracks assignments, block scope, validate-then-return
    guards and per-argument taint at call sites. It runs the **same summary machinery** as
    Python over the functions it can delimit by brace matching: named declarations
    (`function f(…) {`) and named function/arrow expressions (`const f = (…) => {`). Anonymous
    callbacks — the route handler itself — are still analysed in the linear pass, which is the
    right split: a callback is where the source is read, a named helper is where the sink
    usually lives, and it is the edge between them that had been missing.

Honest bounds — read these before trusting a result:

  * **One cross-module hop.** A call to a function imported from another file in the analysed
    set is resolved against that file's summary, which already folds in everything the callee
    does inside its own module. A chain that launders through a *third* module to reach the
    sink is not followed. Each extra hop multiplies the chance that one wrong import
    resolution attaches a real sink to the wrong function, and a confidently wrong path costs
    more than a missing one.
  * **Named imports only.** `from .helpers import run` and `const { run } = require('./util')`
    resolve; so does Python's `import helpers` + `helpers.run(x)`, because a dotted call is
    still a name. A JavaScript namespace import (`const u = require('./util'); u.run(x)`) is
    not resolved — a call through a variable is not a name, and guessing which variable holds
    which module is where an analysis starts inventing edges. Bare specifiers are never
    resolved: a package is not our code.
  * **Name-resolved calls only.** Interprocedural resolution matches a call to a function
    defined in the same file by simple name; two same-named methods on different classes
    collapse to the first, and a call through a variable, a decorator or a dispatch table is
    not resolved. In JavaScript a helper assigned to an object property or defined as a class
    method is not delimited, so it carries no summary.
  * **Function parameters are a weak source.** Whether a parameter carries untrusted data is
    caller knowledge we do not have, so parameter-rooted paths are reported at MEDIUM
    confidence and framework-request-rooted paths at HIGH. The precision gate only fails on
    HIGH, which is what makes that distinction load-bearing rather than cosmetic.
  * **A guard is assumed to validate.** `if (bad(x)) return;` clears taint on `x` without
    checking that the predicate is meaningful. This trades recall for precision on purpose:
    an unhelpful guard produces a false negative here, and the sink still surfaces as a
    MEDIUM regex lead.
  * The JS scanner does not understand destructuring, closures capturing an outer tainted
    variable across a function boundary, `eval`-style dynamic property access, or JSX.

Everything above is a documented false-negative source, never a silent one: `limitations()`
returns this list so the report can print it.
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field

from .schema import Severity, Confidence


# --------------------------------------------------------------------------- model

@dataclass(frozen=True)
class Sink:
    """A call (or assignment target) that is dangerous when it receives untrusted input."""
    id: str
    title: str
    cwe: str
    owasp: str
    severity: Severity
    fix: str
    # Argument positions that make the call dangerous. Empty tuple = any argument.
    # This is what separates `db.query(taintedSql)` from `db.query('… ?', [tainted])`:
    # the second passes the taint as a *bound parameter*, which is the fix, not the bug.
    taint_args: tuple[int, ...] = ()
    # Python only: the call is a sink only when this keyword is set truthy (e.g. shell=True).
    requires_kwarg: str = ""
    maps_to: str = ""


@dataclass(frozen=True)
class FunctionSummary:
    """What a function does with the taint it is handed — the unit of interprocedural analysis.

    Summaries are what let a source in one function reach a sink in another without inlining
    every callee: analyse each function once, record only the two facts a caller needs, and
    resolve call sites against those. `sink_params` maps a parameter name to the sink its
    taint reaches; `returns_params` names the parameters whose taint flows out through the
    return value; `returns_source` marks a function that returns untrusted input it fetched
    itself, with no parameter involved (`def q(): return request.args['q']`).
    """
    # (parameter name, the sink it reaches, the line that sink is ON, the FILE it is in).
    # The location is what lets a caller report the chain against the place the bug actually
    # lives, and what lets dedup recognise the direct and the through-a-call view of one bug
    # as the same bug. The file has to travel with the line: in a chain A -> B -> C the sink
    # is in C, and a summary that carried only the line would let A blame B for it.
    sink_params: tuple[tuple[str, "Sink", int, str], ...] = ()
    returns_params: frozenset[str] = frozenset()
    returns_source: bool = False

    def sink_for(self, param: str) -> "tuple[Sink, int, str] | None":
        return next(((s, line, file) for p, s, line, file in self.sink_params if p == param),
                    None)


@dataclass
class TaintPath:
    """One source → … → sink chain: within a function, across a call, or across a module."""
    sink: Sink
    file: str
    line: int
    source: str            # the expression that introduced taint, e.g. "req.query.name"
    source_line: int
    source_kind: str       # "request" (framework input) | "parameter" (caller-supplied)
    steps: list[tuple[int, str]] = field(default_factory=list)
    evidence: str = ""
    # The line the dangerous call is on. Equal to `line` for a path that ends in this
    # function; for a path that ends inside a callee it is that callee's sink line, so the
    # same bug seen directly and seen through a call share one identity.
    sink_line: int = 0
    # The file the dangerous call is IN. Differs from `file` only for a cross-module path,
    # where the finding is reported against the caller (that is where the untrusted value
    # enters) but the fix belongs in the callee. Both ends are needed: reporting only the
    # sink loses which route reaches it, reporting only the caller loses what to change.
    sink_file: str = ""

    def __post_init__(self) -> None:
        if not self.sink_line:
            self.sink_line = self.line
        if not self.sink_file:
            self.sink_file = self.file

    @property
    def confidence(self) -> Confidence:
        # A framework request object is untrusted by construction. A function parameter is
        # only untrusted if some caller makes it so, and we cannot see callers.
        return Confidence.HIGH if self.source_kind == "request" else Confidence.MEDIUM

    def describe(self) -> str:
        """A human-readable path, which is the whole point — a finding you can follow."""
        hops = [f"L{self.source_line}: {self.source} ({self.source_kind})"]
        hops += [f"L{line}: {what}" for line, what in self.steps]
        return " → ".join(hops)


def limitations() -> list[str]:
    """The documented false-negative sources, for the report's limitations appendix."""
    return [
        "Taint analysis follows a value across calls to functions resolved by simple name, and "
        "across import edges into other files in the scanned set, to any depth — but only "
        "files that were scanned. A chain that passes through an excluded directory, a "
        "third-party package, or a language without taint depth stops there. In JavaScript "
        "only named declarations and named function/arrow expressions carry a summary — not "
        "object-property or class methods — and a namespace import "
        "(`const u = require('./util'); u.run(x)`) is not resolved.",
        "Function parameters are treated as a weak (MEDIUM-confidence) source because whether "
        "they carry untrusted data depends on callers, which are not analyzed.",
        "A validation guard (`if (bad(x)) return/throw`) is assumed to sanitize; an ineffective "
        "guard therefore hides its sink from this tier.",
        "The JavaScript/TypeScript scanner is a brace-aware statement scanner, not a parser: "
        "destructuring, cross-boundary closures, dynamic property access and JSX are not modeled.",
    ]


# --------------------------------------------------------------------------- sink catalog

S = Severity

PY_SINKS: dict[str, Sink] = {
    "os.system": Sink("TAINT-PY-CMDI", "Command injection — untrusted input reaches a shell",
                      "CWE-78", "A03", S.CRITICAL,
                      "Use subprocess with an argument list and no shell; validate the input.",
                      taint_args=(0,)),
    "subprocess.call": Sink("TAINT-PY-CMDI-SHELL",
                            "Command injection — untrusted input reaches `shell=True`",
                            "CWE-78", "A03", S.CRITICAL,
                            "Drop shell=True and pass an argument list; validate the input.",
                            taint_args=(0,), requires_kwarg="shell", maps_to="V19"),
    "subprocess.run": Sink("TAINT-PY-CMDI-SHELL",
                           "Command injection — untrusted input reaches `shell=True`",
                           "CWE-78", "A03", S.CRITICAL,
                           "Drop shell=True and pass an argument list; validate the input.",
                           taint_args=(0,), requires_kwarg="shell", maps_to="V19"),
    "subprocess.Popen": Sink("TAINT-PY-CMDI-SHELL",
                             "Command injection — untrusted input reaches `shell=True`",
                             "CWE-78", "A03", S.CRITICAL,
                             "Drop shell=True and pass an argument list; validate the input.",
                             taint_args=(0,), requires_kwarg="shell", maps_to="V19"),
    "subprocess.check_output": Sink("TAINT-PY-CMDI-SHELL",
                                    "Command injection — untrusted input reaches `shell=True`",
                                    "CWE-78", "A03", S.CRITICAL,
                                    "Drop shell=True and pass an argument list; validate input.",
                                    taint_args=(0,), requires_kwarg="shell", maps_to="V19"),
    "pickle.loads": Sink("TAINT-PY-DESER", "Insecure deserialization — untrusted bytes unpickled",
                         "CWE-502", "A08", S.CRITICAL,
                         "Never unpickle untrusted data; use JSON with a schema.",
                         taint_args=(0,), maps_to="V20"),
    "pickle.load": Sink("TAINT-PY-DESER", "Insecure deserialization — untrusted stream unpickled",
                        "CWE-502", "A08", S.CRITICAL,
                        "Never unpickle untrusted data; use JSON with a schema.",
                        taint_args=(0,), maps_to="V20"),
    "yaml.load": Sink("TAINT-PY-YAML", "Unsafe YAML load of untrusted input", "CWE-20", "A08",
                      S.HIGH, "Use yaml.safe_load (or Loader=SafeLoader).", taint_args=(0,)),
    "eval": Sink("TAINT-PY-EVAL", "Code injection — untrusted input reaches eval()",
                 "CWE-95", "A03", S.CRITICAL,
                 "Never eval untrusted input; parse data instead.", taint_args=(0,)),
    "exec": Sink("TAINT-PY-EXEC", "Code injection — untrusted input reaches exec()",
                 "CWE-95", "A03", S.CRITICAL,
                 "Never exec untrusted input.", taint_args=(0,)),
    "cursor.execute": Sink("TAINT-PY-SQLI", "SQL injection — untrusted input in the query string",
                           "CWE-89", "A03", S.CRITICAL,
                           "Use bind parameters: cursor.execute(sql, (value,)).",
                           taint_args=(0,), maps_to="V21"),
    "conn.execute": Sink("TAINT-PY-SQLI", "SQL injection — untrusted input in the query string",
                         "CWE-89", "A03", S.CRITICAL,
                         "Use bind parameters instead of building the SQL string.",
                         taint_args=(0,), maps_to="V21"),
    "requests.get": Sink("TAINT-PY-SSRF", "SSRF — server fetches an untrusted URL",
                         "CWE-918", "A10", S.HIGH,
                         "Allowlist the destination host; block private/link-local ranges.",
                         taint_args=(0,)),
    "requests.post": Sink("TAINT-PY-SSRF", "SSRF — server posts to an untrusted URL",
                          "CWE-918", "A10", S.HIGH,
                          "Allowlist the destination host; block private/link-local ranges.",
                          taint_args=(0,)),
    "urllib.request.urlopen": Sink("TAINT-PY-SSRF", "SSRF — server opens an untrusted URL",
                                   "CWE-918", "A10", S.HIGH,
                                   "Allowlist the destination host; block private ranges.",
                                   taint_args=(0,)),
    "open": Sink("TAINT-PY-PATH", "Path traversal — untrusted input in a filesystem path",
                 "CWE-22", "A01", S.HIGH,
                 "Resolve the path, then verify it stays inside an allowed base directory.",
                 taint_args=(0,)),
    "render_template_string": Sink("TAINT-PY-SSTI",
                                   "Template injection — untrusted input compiled as a template",
                                   "CWE-1336", "A03", S.CRITICAL,
                                   "Pass user data as template context, never as the template.",
                                   taint_args=(0,)),
}

# Framework request objects: untrusted by construction, so a path rooted here is HIGH.
PY_REQUEST_SOURCES = re.compile(
    r"^(?:request|self\.request|flask\.request)\."
    r"(?:args|form|values|json|data|files|cookies|headers|GET|POST|query_params|body)\b")

# Calls whose result is no longer attacker-controlled in any way that matters to a sink.
PY_SANITIZERS = {
    "int", "float", "bool", "len", "shlex.quote", "shlex.join", "re.escape", "html.escape",
    "urllib.parse.quote", "urllib.parse.quote_plus", "os.path.basename", "uuid.UUID",
}

JS_SINKS: list[tuple[re.Pattern, Sink]] = [
    (re.compile(r"\b(?:db|conn|connection|pool|client|sequelize|knex)\s*\.\s*(?:query|raw)\s*\("),
     Sink("TAINT-JS-SQLI", "SQL injection — untrusted input in the query string",
          "CWE-89", "A03", S.CRITICAL,
          "Use a parameterized query: pass placeholders and bind the value as a parameter.",
          taint_args=(0,), maps_to="V1")),
    (re.compile(r"(?<![.\w])exec(?:Sync)?\s*\(|child_process\s*\.\s*exec(?:Sync)?\s*\("),
     Sink("TAINT-JS-CMDI", "Command injection — untrusted input reaches a shell",
          "CWE-78", "A03", S.CRITICAL,
          "Use execFile/spawn with an argument array (no shell) and validate the input.",
          taint_args=(0,), maps_to="V2")),
    (re.compile(r"(?<![.\w])eval\s*\("),
     Sink("TAINT-JS-EVAL", "Code injection — untrusted input reaches eval()",
          "CWE-95", "A03", S.CRITICAL,
          "Never eval untrusted input; use JSON.parse for data.",
          taint_args=(0,), maps_to="V15")),
    (re.compile(r"\bnew\s+Function\s*\("),
     Sink("TAINT-JS-SSTI", "Template injection — untrusted input compiled as code",
          "CWE-94", "A03", S.CRITICAL,
          "Pass user data as template context; never compile it as code.",
          maps_to="V16")),
    (re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\("),
     Sink("TAINT-JS-XSS-WRITE", "XSS — untrusted input written into the document",
          "CWE-79", "A03", S.HIGH,
          "Build DOM nodes with textContent, or sanitize with DOMPurify first.",
          taint_args=(0,))),
    (re.compile(r"\bres(?:ponse)?\s*\.\s*redirect\s*\("),
     Sink("TAINT-JS-OPENREDIR", "Open redirect — untrusted input in the redirect target",
          "CWE-601", "A01", S.MEDIUM,
          "Redirect only to an allowlist of relative paths.", taint_args=(0,))),
    (re.compile(r"\bres(?:ponse)?\s*\.\s*writeHead\s*\("),
     Sink("TAINT-JS-OPENREDIR", "Open redirect — untrusted input in the Location header",
          "CWE-601", "A01", S.MEDIUM,
          "Redirect only to an allowlist of relative paths.",
          taint_args=(1,), maps_to="V11")),
    (re.compile(r"\bfs\s*\.\s*(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink)\s*\("),
     Sink("TAINT-JS-PATH", "Path traversal — untrusted input in a filesystem path",
          "CWE-22", "A01", S.HIGH,
          "Resolve the path, then verify it stays inside an allowed base directory.",
          taint_args=(0,), maps_to="V12")),
    (re.compile(r"require\(\s*['\"]https?['\"]\s*\)\s*\.\s*(?:get|request)\s*\(|"
                r"\bhttps?\s*\.\s*(?:get|request)\s*\(|\baxios\s*\.\s*(?:get|post)\s*\(|"
                r"(?<![.\w])fetch\s*\("),
     Sink("TAINT-JS-SSRF", "SSRF — server fetches an untrusted URL",
          "CWE-918", "A10", S.HIGH,
          "Allowlist the destination host and block private / link-local ranges.",
          taint_args=(0,), maps_to="V7")),
    (re.compile(r"\bObject\s*\.\s*assign\s*\("),
     Sink("TAINT-JS-MASSASSIGN", "Mass assignment — untrusted object copied onto a model",
          "CWE-915", "A08", S.HIGH,
          "Copy only an explicit field allowlist; never bind the raw body.",
          taint_args=(1,), maps_to="V13")),
]

# Assignment-shaped sinks: `x.innerHTML = <tainted>`.
JS_ASSIGN_SINKS: list[tuple[re.Pattern, Sink]] = [
    (re.compile(r"\.\s*(?:innerHTML|outerHTML)\s*=(?!=)"),
     Sink("TAINT-JS-XSS-DOM", "XSS — untrusted input assigned to innerHTML",
          "CWE-79", "A03", S.HIGH,
          "Use textContent, or sanitize with DOMPurify before assignment.", maps_to="V8")),
]

JS_REQUEST_SOURCES = re.compile(
    r"\breq(?:uest)?\s*\.\s*(?:query|params|body|headers|cookies|files)(?:\s*\.\s*\w+)?"
    r"|\bctx\s*\.\s*(?:query|params|request)\b"
    r"|\blocation\s*\.\s*(?:search|hash|href)\b"
    r"|\bdocument\s*\.\s*(?:URL|documentURI|referrer)\b"
    r"|\bwindow\s*\.\s*name\b"
    r"|\bprocess\s*\.\s*argv\b")

# A membership test constrains a value to a known finite set, so what comes out of one is no
# longer attacker-chosen. This is what makes `ALLOWLIST.has(next) ? next : '/'` safe.
JS_SANITIZER = re.compile(
    r"\.\s*(?:has|includes)\s*\(|DOMPurify\s*\.\s*sanitize\s*\(|encodeURIComponent\s*\(|"
    r"\bparseInt\s*\(|\bNumber\s*\(|\bescapeHtml\s*\(")

JS_GUARD_EXIT = re.compile(r"\breturn\b|\bthrow\b|\bnext\s*\(\s*[a-zA-Z]")


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


def _py_names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


class _PyScope:
    """Taint state for one function body, in source order."""

    def __init__(self, path: str, lines: list[str],
                 summaries: dict[str, FunctionSummary] | None = None,
                 functions: dict[str, ast.AST] | None = None,
                 origins: dict[str, str] | None = None):
        self.path, self.lines = path, lines
        self.tainted: dict[str, tuple[int, str, str]] = {}   # name -> (line, expr, kind)
        self.paths: list[TaintPath] = []
        # Summaries of the other functions in scope, for interprocedural resolution. Includes
        # imported ones when the project pass supplied them; `origins` says which file each
        # non-local name came from, and is empty for a single-file analysis.
        self.summaries = summaries or {}
        self.functions = functions or {}
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
        sink = PY_SINKS.get(_py_dotted(call.func))
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


    def _sink_step(self, sink: "Sink", callee: str, where: str) -> str:
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


def _py_positional_params(node: ast.AST) -> list[str]:
    """Parameter names in positional order, `self`/`cls` included so argument positions line
    up with the call site — the seeding step skips them, the mapping must not."""
    args = node.args
    return [a.arg for a in [*args.posonlyargs, *args.args]]


def _py_taintable_params(node: ast.AST) -> list[str]:
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


# How many times to re-derive summaries before giving up on convergence. Each round can only
# ADD facts (a parameter that reaches a sink, a parameter whose taint escapes through the
# return), so the lattice is finite and monotone and a fixed point is reached quickly; the cap
# exists so a mutually recursive pair cannot spin, not because convergence is in doubt.
_SUMMARY_ROUNDS = 4


def _python_functions(tree: ast.AST) -> dict[str, ast.AST]:
    """Every function defined in the module, by simple name.

    A name collision (two methods called `handle` on different classes) keeps the first and
    is a known imprecision, not a silent one: resolving it properly needs a qualified name
    and class-aware call resolution, which is a bigger analysis than this tier promises."""
    functions: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.setdefault(node.name, node)
    return functions


def _python_summaries(functions: dict[str, ast.AST], path: str, lines: list[str],
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
            for param in params:
                # Seed with the bare parameter name so a reported path can be matched back to
                # the parameter that caused it.
                scope.tainted[param] = (node.lineno, param, "parameter")
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


def _python_paths(path: str, text: str, local: dict[str, ast.AST],
                  functions: dict[str, ast.AST], summaries: dict[str, FunctionSummary],
                  origins: dict[str, str]) -> list[TaintPath]:
    """Scan this file's own function bodies, resolving calls against `functions`/`summaries`
    — which may include names imported from other files in the analysed set."""
    lines = text.splitlines()
    out: list[TaintPath] = []
    for name, node in local.items():
        scope = _PyScope(path, lines, summaries, functions, origins)
        for param in _py_taintable_params(node):
            scope.tainted[param] = (node.lineno, f"{name}({param})", "parameter")
        scope.visit_body(node.body)
        out.extend(scope.paths)
    return out


def analyze_python(path: str, text: str) -> list[TaintPath]:
    return analyze_files({path: text})


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


# --------------------------------------------------------------------------- JS/TS analysis

_JS_LINE_COMMENT = re.compile(r"//[^\n]*")
_JS_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def _js_strip_comments(text: str) -> str:
    """Blank comments out while preserving every character offset and line number, so a
    reported line still points at the right place in the original file."""
    def blank(m: re.Match) -> str:
        return "".join("\n" if c == "\n" else " " for c in m.group(0))
    return _JS_LINE_COMMENT.sub(blank, _JS_BLOCK_COMMENT.sub(blank, text))


def blank_strings(expr: str) -> str:
    """Blank the *contents* of string literals, preserving length, quotes and offsets.

    Without this, an identifier that merely appears inside a string is read as a use of the
    variable with that name: `new Function('data', …)` would report taint on argument 0
    because the literal `'data'` contains the parameter name `data`. Template-literal
    `${…}` interpolations are kept, because those genuinely are code.
    """
    out: list[str] = []
    quote, i = "", 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            if ch == "\\":
                out.append("  ")
                i += 2
                continue
            if ch == quote:
                quote = ""
                out.append(ch)
                i += 1
                continue
            if quote == "`" and ch == "$" and i + 1 < len(expr) and expr[i + 1] == "{":
                depth, j = 0, i + 1
                while j < len(expr):
                    if expr[j] == "{":
                        depth += 1
                    elif expr[j] == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                out.append(expr[i:j + 1])
                i = j + 1
                continue
            out.append(" ")
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
        out.append(ch)
        i += 1
    return "".join(out)


# Per-language lexical shape, for `code_view`. Anything not listed is returned unchanged —
# blanking a format we do not actually know how to lex would be worse than not blanking.
_LEXICAL: dict[str, tuple[tuple[str, ...], str, tuple[str, str] | None, bool]] = {
    # ext-group: (quote chars, line-comment token, (block open, block close) | None, triple-quoted)
    "py":   (("'", '"'), "#", None, True),
    "js":   (("'", '"', "`"), "//", ("/*", "*/"), False),
    "go":   (("'", '"', "`"), "//", ("/*", "*/"), False),
    "java": (("'", '"'), "//", ("/*", "*/"), False),
    "cs":   (("'", '"'), "//", ("/*", "*/"), False),
    "php":  (("'", '"'), "//", ("/*", "*/"), False),
    "rb":   (("'", '"'), "#", None, False),
    # Rust deliberately lists only the double quote: `'` is a lifetime marker (`&'a str`) far
    # more often than a char literal, and treating it as a string delimiter would blank from
    # the lifetime to the next apostrophe anywhere in the file.
    "rs":   (('"',), "//", ("/*", "*/"), False),
}
_EXT_GROUP = {
    ".py": "py", ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "js",
    ".tsx": "js", ".go": "go", ".java": "java", ".cs": "cs", ".php": "php", ".rb": "rb",
    ".rs": "rs",
}


def code_view(text: str, path: str) -> str | None:
    """Text with comments and string-literal *contents* blanked, offsets preserved.

    This is the view a code-shape rule should match against. Without it, `"eval": Sink(...)`
    in a rule catalog reads as a call to `eval`, and a vulnerability class named in a comment
    reads as the vulnerability. Matching inside literals and comments is a large part of why
    pattern-based scanners score badly on real code — the noise is not in the rules, it is in
    what the rules are allowed to see.

    Returns None for a language whose lexical shape is not modeled, which means "scan the raw
    text" — never a silent partial blanking.
    """
    group = _EXT_GROUP.get(os.path.splitext(path)[1].lower())
    if group is None:
        return None
    quotes, line_comment, block, triple = _LEXICAL[group]

    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        # --- comments ---
        if block and text.startswith(block[0], i):
            end = text.find(block[1], i + len(block[0]))
            end = n if end == -1 else end + len(block[1])
            out.append("".join("\n" if c == "\n" else " " for c in text[i:end]))
            i = end
            continue
        if text.startswith(line_comment, i):
            end = text.find("\n", i)
            end = n if end == -1 else end
            out.append(" " * (end - i))
            i = end
            continue
        # --- strings ---
        if ch in quotes:
            delim = ch * 3 if triple and text.startswith(ch * 3, i) else ch
            out.append(delim)
            i += len(delim)
            while i < n:
                if text[i] == "\\":
                    out.append("  " if i + 1 < n else " ")
                    i += 2
                    continue
                if text.startswith(delim, i):
                    out.append(delim)
                    i += len(delim)
                    break
                # A single-quote string never spans lines in these languages; if we hit a
                # newline the literal was unterminated, so stop rather than eat the file.
                if text[i] == "\n" and len(delim) == 1:
                    break
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def split_args(argstr: str) -> list[str]:
    """Split a call's argument list on top-level commas, respecting nesting and strings."""
    args, depth, quote, buf = [], 0, "", []
    i = 0
    while i < len(argstr):
        ch = argstr[i]
        if quote:
            if ch == "\\":
                buf.append(ch)
                i += 1
                if i < len(argstr):
                    buf.append(argstr[i])
                i += 1
                continue
            if ch == quote:
                quote = ""
        elif ch in "\"'`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if buf:
        args.append("".join(buf))
    return [a.strip() for a in args]


def _js_call_args(text: str, open_paren: int) -> str:
    """The text between `open_paren` and its matching close paren."""
    depth, quote, i = 0, "", open_paren
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "\"'`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:i]
        i += 1
    return text[open_paren + 1:]


_JS_ASSIGN = re.compile(r"^\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=(?!=)(.*)$")
_JS_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_JS_RETURN = re.compile(r"^\s*return\b")
# A call to a bare identifier — not a method call, which `(?<![.\w$])` excludes. Method calls
# are deliberately out: `obj.run(x)` cannot be resolved to a definition without knowing what
# `obj` is, and guessing by method name is how an analysis starts inventing paths.
_JS_CALL = re.compile(r"(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(")

# Function forms whose body we can delimit by brace matching. Everything else (object-property
# methods, class methods, arrows with an expression body) is analysed in the linear pass only,
# which is a documented false negative rather than a guess.
_JS_FUNC_FORMS = (
    # function f(a, b) {   /   async function* f(a) {
    re.compile(r"(?:^|[^.\w$])(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)"),
    # const f = (a, b) => {   /   let f = async function (a) {
    re.compile(r"(?:^|[^.\w$])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
               r"(?:async\s+)?(?:function\s*\*?\s*)?\(([^)]*)\)\s*(?:=>\s*)?\{"),
    # const f = a => {
    re.compile(r"(?:^|[^.\w$])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
               r"(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>\s*\{"),
)


@dataclass(frozen=True)
class _JsFunc:
    """A JS function whose body we could delimit — the unit a summary is derived from."""
    name: str
    params: tuple[str, ...]
    start: int      # line the body's opening brace is on
    end: int        # line the matching closing brace is on


def _js_param_names(group: str) -> list[str]:
    names = []
    for part in group.split(","):
        part = part.strip().split("=")[0].split(":")[0].strip()
        if part and _JS_IDENT.fullmatch(part):   # destructuring is out of scope
            names.append(part)
    return names


def _js_block_end(lines: list[str], start: int, col: int) -> int:
    """Line of the `}` matching the `{` at (start, col). Called on a string-blanked view, so a
    brace inside a literal cannot move the boundary."""
    depth = 0
    for lineno in range(start, len(lines) + 1):
        text = lines[lineno - 1]
        for ch in (text[col:] if lineno == start else text):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return lineno
    return len(lines)


def _js_functions(text: str, path: str) -> dict[str, _JsFunc]:
    """Every brace-delimited named function in the file, by simple name.

    Extraction runs over `code_view`, not the raw text: a brace inside a string literal or a
    commented-out function would otherwise shift every body boundary after it, and a wrong
    boundary is worse than no summary — it attributes a sink to a function that does not
    contain it."""
    structural = code_view(text, path)
    if structural is None:
        return {}
    lines = structural.splitlines()
    funcs: dict[str, _JsFunc] = {}
    for lineno, line in enumerate(lines, start=1):
        for pattern in _JS_FUNC_FORMS:
            m = pattern.search(line)
            if not m:
                continue
            name, group = m.group(1), m.group(2)
            brace = line.find("{", max(0, m.end() - 1))
            if brace == -1:
                continue
            # `group` is either a parenthesized parameter list or, for `const f = a => {`, a
            # single bare identifier. Splitting on commas handles both.
            funcs.setdefault(name, _JsFunc(name, tuple(_js_param_names(group)),
                                           lineno, _js_block_end(lines, lineno, brace)))
            break
    return funcs


def _js_sole_call(expr: str) -> tuple[str, str] | None:
    """(name, argument text) when `expr` is exactly one call to a bare identifier, else None.

    "Exactly one" is load-bearing. `helper(x)` can be resolved against `helper`'s summary,
    including the conclusion that it *launders* — but `helper(x) + y` cannot, because the
    laundering conclusion would then wrongly clear `y` as well."""
    s = expr.strip().rstrip(";").strip()
    if s.startswith("await "):
        s = s[6:].strip()
    m = re.match(r"^([A-Za-z_$][\w$]*)\s*\(", s)
    if not m:
        return None
    paren = s.index("(", m.end() - 1)
    args = _js_call_args(s, paren)
    if s[paren + 1 + len(args):].strip() != ")":
        return None                     # the call does not span the whole expression
    return m.group(1), args


class _JsScope:
    """Brace-depth-scoped taint state for one JS/TS file (or one function body within it)."""

    def __init__(self, path: str, text: str,
                 summaries: dict[str, FunctionSummary] | None = None,
                 functions: dict[str, _JsFunc] | None = None,
                 origins: dict[str, str] | None = None):
        self.path = path
        self.text = _js_strip_comments(text)
        self.raw_lines = text.splitlines()
        # name -> (depth, line, expr, kind)
        self.tainted: dict[str, tuple[int, int, str, str]] = {}
        self.paths: list[TaintPath] = []
        self.summaries = summaries or {}
        self.functions = functions or {}
        self.origins = origins or {}
        # This scope's own half of the summary contract, filled in as `return`s are seen.
        self.returns_params: set[str] = set()
        self.returns_source = False

    def line_text(self, lineno: int) -> str:
        return self.raw_lines[lineno - 1].strip()[:200] if 0 < lineno <= len(self.raw_lines) else ""

    def taint_of(self, expr: str) -> tuple[str, int, str] | None:
        # Identifiers inside string literals are text, not variable uses.
        expr = blank_strings(expr)

        # A call to a local function, alone in the expression, is resolved by its summary —
        # including the negative answer. A helper that does not pass its argument through to
        # the return value *launders* it, exactly like a sanitizer, and that is a precision
        # win no lexical scan can make: nothing in `formatId(userInput)` says the result is an
        # integer. Only the summary does.
        sole = _js_sole_call(expr)
        if sole:
            name, argstr = sole
            summary, fn = self.summaries.get(name), self.functions.get(name)
            if summary is not None and fn is not None:
                if summary.returns_source:
                    return (f"{name}()", 0, "request")
                for pos, arg in enumerate(split_args(argstr)):
                    if pos < len(fn.params) and fn.params[pos] in summary.returns_params:
                        taint = self.taint_of(arg)
                        if taint:
                            return taint
                return None

        m = JS_REQUEST_SOURCES.search(expr)
        if m:
            return (m.group(0).replace(" ", ""), 0, "request")
        for ident in set(_JS_IDENT.findall(expr)):
            if ident in self.tainted:
                _, line, src, kind = self.tainted[ident]
                return (src, line, kind)
        return None

    def drop_deeper_than(self, depth: int) -> None:
        for name in [n for n, (d, *_) in self.tainted.items() if d > depth]:
            del self.tainted[name]

    def run(self, region: tuple[int, int] | None = None) -> list[TaintPath]:
        """Scan the whole file, or just one function body when `region` is given."""
        all_lines = self.text.splitlines()
        first, last = region or (1, len(all_lines))
        depth = 0
        pending_params: list[str] = []
        for lineno in range(first, min(last, len(all_lines)) + 1):
            raw = all_lines[lineno - 1]
            line = raw.strip()
            opened = raw.count("{") - raw.count("}")

            # A function/arrow header introduces parameters as weak sources for its body.
            params = self._function_params(raw)
            if params:
                pending_params = params

            self._scan_line(lineno, line, depth)

            if opened > 0 and pending_params:
                for name in pending_params:
                    self.tainted.setdefault(name, (depth + 1, lineno, name, "parameter"))
                pending_params = []
            depth += opened
            if opened < 0:
                self.drop_deeper_than(depth)
        return self.paths

    _FUNC = re.compile(
        r"function\s+[\w$]*\s*\(([^)]*)\)"           # function foo(a, b)
        r"|(?:^|[=(,]\s*)\(([^)]*)\)\s*=>"           # (a, b) =>
        r"|(?:^|[=(,]\s*)([A-Za-z_$][\w$]*)\s*=>")   # a =>

    def _function_params(self, raw: str) -> list[str]:
        m = self._FUNC.search(raw)
        if not m:
            return []
        group = next((g for g in m.groups() if g is not None), "")
        names = []
        for part in group.split(","):
            part = part.strip().split("=")[0].split(":")[0].strip()
            # Destructuring is explicitly out of scope (see module docstring).
            if part and _JS_IDENT.fullmatch(part):
                names.append(part)
        return names

    def _scan_line(self, lineno: int, line: str, depth: int) -> None:
        # Two views of the same line, deliberately. Sink patterns match the RAW line, because
        # some of them are about a string literal (`require('http').get`) and blanking would
        # erase exactly the token that identifies the sink. Anything that reads *identifiers*
        # — guards, sanitizers, taint lookup — uses the blanked view, because a name inside a
        # literal is text, not a variable use. `taint_of` blanks on its own.
        safe = blank_strings(line)

        # 1) Validation guard: `if (<mentions tainted>) return/throw` clears the taint.
        if safe.startswith("if") and JS_GUARD_EXIT.search(blank_strings(self._guard_block(lineno, line))):
            for ident in set(_JS_IDENT.findall(safe)):
                self.tainted.pop(ident, None)
            return

        # 2) Assignment-shaped sinks (`el.innerHTML = …`).
        for pattern, sink in JS_ASSIGN_SINKS:
            m = pattern.search(line)
            if m and not JS_SANITIZER.search(blank_strings(line[m.end():])):
                self._report(sink, lineno, line[m.end():])

        # 3) Call sinks — per-argument, so a bound parameter is not mistaken for injection.
        for pattern, sink in JS_SINKS:
            for m in pattern.finditer(line):
                paren = line.find("(", m.end() - 1)
                if paren == -1:
                    continue
                args = split_args(_js_call_args(line, paren))
                positions = sink.taint_args or tuple(range(len(args)))
                for pos in positions:
                    if pos < len(args) and not JS_SANITIZER.search(blank_strings(args[pos])):
                        if self._report(sink, lineno, args[pos], pos):
                            break

        # 4) A call into a local function that carries the argument to a sink.
        self._check_local_call(lineno, line, safe)

        # 5) `return <tainted>` — this scope's contribution to its own summary. The sanitizer
        #    check is the same one assignment propagation applies, and it has to be: without
        #    it a helper that constrains its argument and returns the result (`return
        #    ALLOWED.has(v) ? v : 'a'`) would be summarised as passing taint straight through,
        #    and every caller would inherit a false positive from the one place that fixed it.
        if _JS_RETURN.match(safe):
            returned = line[safe.index("return") + 6:]
            taint = None if JS_SANITIZER.search(blank_strings(returned)) else self.taint_of(returned)
            if taint:
                expr, _, kind = taint
                if kind == "request":
                    self.returns_source = True
                else:
                    self.returns_params.add(expr)

        # 6) Assignment propagation.
        m = _JS_ASSIGN.match(safe)
        if m:
            name, rhs = m.group(1), line[m.start(2):] if m.start(2) >= 0 else m.group(2)
            if JS_SANITIZER.search(blank_strings(rhs)):
                self.tainted.pop(name, None)
                return
            taint = self.taint_of(rhs)
            if taint:
                src, src_line, kind = taint
                self.tainted[name] = (depth, src_line or lineno, src, kind)
            else:
                self.tainted.pop(name, None)

    def _sink_step(self, sink: "Sink", callee: str, where: str) -> str:
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

    def _check_local_call(self, lineno: int, line: str, safe: str) -> None:
        """Report a sink that lives inside a named function defined in this same file.

        This is the shape almost all real code takes: the route callback reads the request and
        hands it to a helper, and the dangerous call is in the helper. Seen one function at a
        time it is two half-findings — a source that goes nowhere, and a sink fed by a
        parameter that only *might* be untrusted. Resolving the call joins them into one
        HIGH-confidence path that names both ends."""
        for m in _JS_CALL.finditer(safe):
            name = m.group(1)
            summary, fn = self.summaries.get(name), self.functions.get(name)
            if not summary or fn is None or not summary.sink_params:
                continue
            paren = line.find("(", m.end() - 1)
            if paren == -1:
                continue
            for pos, arg in enumerate(split_args(_js_call_args(line, paren))):
                param = fn.params[pos] if pos < len(fn.params) else None
                resolved = summary.sink_for(param) if param else None
                if resolved is None:
                    continue
                sink, sink_line, where = resolved
                taint = self.taint_of(arg)
                if not taint:
                    continue
                src, src_line, kind = taint
                inside = self._sink_step(sink, name, where)
                self.paths.append(TaintPath(
                    sink=sink, file=self.path, line=lineno, source=src,
                    source_line=src_line or lineno, source_kind=kind,
                    steps=[(lineno, f"passed to {name}({param})"), (sink_line, inside)],
                    evidence=self.line_text(lineno),
                    sink_line=sink_line, sink_file=where))
                return

    def _guard_block(self, lineno: int, line: str) -> str:
        """The guard's statement — the line itself, plus its block when the brace opens here."""
        if "{" not in line:
            return line
        lines = self.text.splitlines()
        depth, out = 0, []
        for cur in lines[lineno - 1:lineno + 9]:      # a validation guard is never long
            out.append(cur)
            depth += cur.count("{") - cur.count("}")
            if depth <= 0 and len(out) > 1:
                break
        return "\n".join(out)

    def _report(self, sink: Sink, lineno: int, expr: str, pos: int = 0) -> bool:
        taint = self.taint_of(expr)
        if not taint:
            return False
        src, src_line, kind = taint
        self.paths.append(TaintPath(
            sink=sink, file=self.path, line=lineno, source=src,
            source_line=src_line or lineno, source_kind=kind,
            steps=[(lineno, f"{sink.id} argument {pos}")],
            evidence=self.line_text(lineno)))
        return True


def _js_summaries(path: str, text: str, functions: dict[str, _JsFunc],
                  resolve_functions: dict | None = None,
                  resolve_summaries: dict | None = None,
                  origins: dict[str, str] | None = None) -> dict[str, FunctionSummary]:
    """Derive each JS function's summary, iterating to a fixed point — the same lattice and the
    same termination argument as `_python_summaries`, over a different front end."""
    summaries = {name: FunctionSummary() for name in functions}
    for _ in range(_SUMMARY_ROUNDS if functions else 0):
        changed = False
        for name, fn in functions.items():
            scope = _JsScope(path, text,
                             {**summaries, **(resolve_summaries or {})},
                             {**functions, **(resolve_functions or {})}, origins)
            for param in fn.params:
                # Seeded at depth 0 with the bare parameter name, so a path reported inside the
                # body can be matched back to the parameter that caused it.
                scope.tainted[param] = (0, fn.start, param, "parameter")
            scope.run((fn.start, fn.end))

            sink_params: dict[str, tuple[Sink, int, str]] = {}
            for tp in scope.paths:
                if tp.source_kind == "parameter" and tp.source in fn.params:
                    sink_params.setdefault(tp.source, (tp.sink, tp.sink_line, tp.sink_file))
            summary = FunctionSummary(
                sink_params=tuple((param, sink, line, file)
                                  for param, (sink, line, file) in sorted(sink_params.items())),
                returns_params=frozenset(scope.returns_params & set(fn.params)),
                returns_source=scope.returns_source)
            if summary != summaries[name]:
                summaries[name] = summary
                changed = True
        if not changed:
            break
    return summaries


def analyze_js(path: str, text: str) -> list[TaintPath]:
    return analyze_files({path: text})


# --------------------------------------------------------------------------- entry point

# --------------------------------------------------------------------------- cross-module

# Which local symbol came from which local file. Deliberately a different question from the one
# `deps.py` asks — that index answers "is this package imported at all", for reachability; this
# one has to know that the name `runReport` in `server.js` *is* the `runReport` defined in
# `util.js`, because that binding is the edge a taint path crosses.
#
# Named imports only, in both languages, plus Python's `import mod` + `mod.f()` form which
# comes free from dotted-name resolution. A namespace import in JavaScript
# (`const u = require('./util'); u.runReport(x)`) is not resolved — a call through a variable
# is not a name, and guessing which variable holds which module is where an analysis starts
# inventing edges. Documented in `limitations()`, not silently absent.
_PY_FROM_IMPORT = re.compile(r"^\s*from\s+([.\w]+)\s+import\s+([^\n#]+)", re.M)
_PY_PLAIN_IMPORT = re.compile(r"^\s*import\s+([\w.]+)(?:\s+as\s+([\w]+))?\s*$", re.M)
_JS_NAMED_BINDING = re.compile(
    r"""(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""|import\s*\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]""")

_JS_RESOLVE_ORDER = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
                     "/index.js", "/index.ts", "/index.jsx", "/index.tsx")


def _norm(path: str) -> str:
    return path.replace("\\", "/")


def _resolve_js_module(spec: str, from_path: str, files: dict) -> str | None:
    """A relative specifier to a file in the analysed set, or None.

    Only relative specifiers. A bare specifier (`lodash`) is a package: it is not our code, we
    do not have its source, and resolving it by name would attach our summaries to someone
    else's function."""
    if not spec.startswith("."):
        return None
    base = _norm(os.path.normpath(os.path.join(os.path.dirname(from_path), spec)))
    if base in files:
        return base
    return next((c for c in (base + suffix for suffix in _JS_RESOLVE_ORDER) if c in files), None)


def _resolve_py_module(spec: str, from_path: str, files: dict) -> str | None:
    """`from .helpers import f` / `from helpers import f` / `import helpers` → a file we have.

    Leading dots are stripped to a directory walk; a bare name is tried in the importing file's
    own directory first, which is where a same-package module lives."""
    directory = os.path.dirname(from_path)
    dots = len(spec) - len(spec.lstrip("."))
    for _ in range(max(0, dots - 1)):
        directory = os.path.dirname(directory)
    tail = spec.lstrip(".").replace(".", "/")
    if not tail:
        return None
    for candidate in (os.path.join(directory, tail + ".py"),
                      os.path.join(directory, tail, "__init__.py"),
                      tail + ".py"):
        normalized = _norm(os.path.normpath(candidate))
        if normalized in files:
            return normalized
    return None


def _import_bindings(path: str, text: str, files: dict) -> dict[str, tuple[str, str]]:
    """{local name: (defining file, name in that file)} for this file's local imports."""
    # Comments blanked, string literals kept — the opposite of what most passes here want, and
    # the distinction is load-bearing: a JavaScript module specifier *is* a string literal, so
    # the usual `code_view` turns `require('./util')` into `require('      ')` and every
    # cross-module edge in the file silently disappears. Python has no such problem (an import
    # names a module, not a string), but using one view for both would leave the JS case
    # working by accident.
    bindings: dict[str, tuple[str, str]] = {}

    if path.lower().endswith(".py"):
        view = code_view(text, path)
        body = text if view is None else view      # a commented-out import is not an import
        for spec, names in _PY_FROM_IMPORT.findall(body):
            module = _resolve_py_module(spec, path, files)
            if not module:
                continue
            for entry in names.replace("(", " ").replace(")", " ").split(","):
                parts = entry.strip().split()
                if not parts or parts[0] == "*":
                    continue
                original = parts[0]
                local = parts[2] if len(parts) >= 3 and parts[1] == "as" else original
                bindings[local] = (module, original)
        for spec, alias in _PY_PLAIN_IMPORT.findall(body):
            module = _resolve_py_module(spec, path, files)
            if module:
                # `import helpers` then `helpers.run(x)`: the dotted call name resolves for
                # free, because that is exactly the key `_py_dotted` produces.
                bindings[f"{alias or spec.split('.')[-1]}.*"] = (module, "*")
        return bindings

    for a_names, a_spec, b_names, b_spec in _JS_NAMED_BINDING.findall(_js_strip_comments(text)):
        names, spec = (a_names, a_spec) if a_spec else (b_names, b_spec)
        module = _resolve_js_module(spec, path, files)
        if not module:
            continue
        for entry in names.split(","):
            parts = [p for p in entry.replace(":", " as ").split() if p]
            if not parts:
                continue
            original = parts[0]
            local = parts[2] if len(parts) >= 3 and parts[1] == "as" else original
            bindings[local] = (module, original)
    return bindings


# Which languages the taint tier analyses, by which front end, at what depth. `analyze`
# dispatches off this table and `scripts/gen_language_matrix.py` documents from it, so the
# published coverage claim and the code that backs it cannot drift apart — a language added
# here appears in the matrix on the next build, and one removed disappears from it.
TAINT_DEPTH: dict[str, dict] = {
    "Python": {"exts": (".py",), "frontend": "stdlib `ast` parse",
               "interprocedural": True, "cross_module": True},
    "JavaScript": {"exts": (".js", ".jsx", ".mjs", ".cjs"),
                   "frontend": "brace-aware statement scanner",
                   "interprocedural": True, "cross_module": True},
    "TypeScript": {"exts": (".ts", ".tsx"),
                   "frontend": "brace-aware statement scanner",
                   "interprocedural": True, "cross_module": True},
}

_TAINT_EXTS = {ext: name for name, spec in TAINT_DEPTH.items() for ext in spec["exts"]}


def _analyzable(path: str) -> str:
    return _TAINT_EXTS.get(os.path.splitext(path)[1].lower(), "")


def _per_file_context(files: dict[str, str]) -> dict[str, tuple[dict, dict]]:
    """{path: (functions, summaries)} for every analysable file, computed independently.

    Every summary here is already interprocedural *within* its own file, so one cross-module
    hop covers the common case on its own: the import edge lands in the callee's module, and
    everything the callee does inside that module is already folded in. Deeper chains are then
    reached by the fixed point below rather than by re-walking anything here."""
    context: dict[str, tuple[dict, dict]] = {}
    for path, text in files.items():
        language = _analyzable(path)
        if language == "Python":
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue        # a file we cannot parse is a note, not a crash
            functions = _python_functions(tree)
            context[path] = (functions, _python_summaries(functions, path, text.splitlines()))
        elif language in ("JavaScript", "TypeScript"):
            functions = _js_functions(text, path)
            context[path] = (functions, _js_summaries(path, text, functions))
    return context


def _imported_scope(path: str, bindings: dict, context: dict) -> tuple[dict, dict, dict]:
    """(functions, summaries, origins) contributed by this file's imports, by local name."""
    functions: dict = {}
    summaries: dict = {}
    origins: dict[str, str] = {}
    for local_name, (module, exported) in bindings.items():
        if module == path or module not in context:
            continue
        module_functions, module_summaries = context[module]
        # `import helpers` binds the whole module: every function in it becomes reachable as
        # `helpers.<name>`, which is exactly the key dotted-name resolution produces.
        pairs = ([(f"{local_name[:-2]}.{n}", n) for n in module_functions]
                 if exported == "*" else
                 [(local_name, exported)] if exported in module_functions else [])
        for key, original in pairs:
            functions[key] = module_functions[original]
            summaries[key] = module_summaries[original]
            origins[key] = module
    return functions, summaries, origins


def _resummarize(path: str, text: str, local_functions: dict,
                 imported: tuple[dict, dict, dict]) -> dict[str, FunctionSummary]:
    """This file's summaries, re-derived with its imports in scope."""
    functions, summaries, origins = imported
    if _analyzable(path) == "Python":
        return _python_summaries(local_functions, path, text.splitlines(),
                                 functions, summaries, origins)
    return _js_summaries(path, text, local_functions, functions, summaries, origins)


# Runaway guard on the module-graph fixed point, as a multiple of the analysable file count.
# The lattice is monotone (a round can only ADD facts) and finite, so the worklist below
# terminates on its own; this only bounds the damage if some future summary function stops
# being monotone. Hitting it is a bug, not a supported mode.
_MODULE_STEP_LIMIT = 40


def _module_fixed_point(files: dict[str, str], context: dict, bindings: dict) -> None:
    """Re-derive summaries across the module graph until nothing changes. Mutates `context`.

    A worklist over the REVERSE import graph, not a fixed number of passes over every file.
    That distinction is the whole point: with a fixed pass count the result depends on the
    order the files were walked in, because a pass that happens to visit a callee before its
    caller propagates the callee's new facts immediately while the opposite order defers them
    to the next pass. Two scans of the same repo would then disagree — and the one that
    disagreed would drop the *entry point*, the file where untrusted input actually enters,
    which is the finding that matters most. Running to convergence removes the order from the
    answer entirely: order changes how many steps this takes, never what it settles on.
    """
    importers: dict[str, set[str]] = {}
    for path, binding in bindings.items():
        for module, _ in binding.values():
            if module != path:
                importers.setdefault(module, set()).add(path)

    queue = [p for p in context if bindings.get(p)]
    queued = set(queue)
    budget = _MODULE_STEP_LIMIT * max(len(context), 1)

    while queue and budget > 0:
        budget -= 1
        path = queue.pop()
        queued.discard(path)
        local_functions, current = context[path]
        imported = _imported_scope(path, bindings[path], context)
        if not imported[0]:
            continue                          # nothing imported: the local summary is final
        refreshed = _resummarize(path, files[path], local_functions, imported)
        if refreshed == current:
            continue
        context[path] = (local_functions, refreshed)
        # This file's summaries moved, so everyone importing it may now learn something too.
        for importer in importers.get(path, ()):
            if importer in context and importer not in queued:
                queue.append(importer)
                queued.add(importer)


def analyze_files(files: dict[str, str]) -> list[TaintPath]:
    """Taint paths across a set of files analysed together — the project-level entry point.

    Cross-module resolution runs to a fixed point over the import graph, so a chain that
    launders through several modules is followed, not just a single hop, and the result does
    not depend on the order the files were walked in. Resolution is always by an explicit
    import statement, never by matching names globally: that is what keeps a longer chain from
    becoming a longer guess.

    Taking a dict rather than a directory keeps this testable without a filesystem, and keeps
    the caller in charge of which files are in scope.
    """
    files = {_norm(p): t for p, t in files.items()}
    context = _per_file_context(files)
    bindings = {path: _import_bindings(path, text, files)
                for path, text in files.items() if path in context}

    _module_fixed_point(files, context, bindings)

    out: list[TaintPath] = []
    for path, text in files.items():
        if path not in context:
            continue
        local_functions, local_summaries = context[path]
        imported_functions, imported_summaries, origins = _imported_scope(
            path, bindings[path], context)
        functions = {**local_functions, **imported_functions}
        summaries = {**local_summaries, **imported_summaries}

        if _analyzable(path) == "Python":
            out.extend(_python_paths(path, text, local_functions, functions, summaries, origins))
        else:
            out.extend(_JsScope(path, text, summaries, functions, origins).run())

    return _dedupe_paths(out)


def analyze(path: str, text: str) -> list[TaintPath]:
    """Taint paths in one file. Unknown extensions return [] — never an error.

    Routed through `analyze_files` so the single-file and project paths cannot diverge: a fix
    to one is a fix to both, and a behaviour that only appears when several files are in scope
    is a behaviour with no small test."""
    return analyze_files({path: text})
