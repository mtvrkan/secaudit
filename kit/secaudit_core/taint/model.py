"""Taint model — the value types every other module in this package speaks in.

Split out of the single 2,000-line `taint.py` so the sink catalog, the two language
analyzers and the cross-module resolver each import what they need rather than sharing one
namespace. Nothing here knows about a language; the dependency arrow points this way only.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Union

from ..schema import Severity, Confidence

# What the Python side means by "a function": the two node types that carry `.args`,
# `.body` and `.lineno`. Several helpers were annotated `ast.AST` — the base class, which
# has none of those — so a type checker could not tell a function definition from any other
# node, and the annotation said something looser than every caller actually relies on.
PyFunc = Union[ast.FunctionDef, ast.AsyncFunctionDef]

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
    # The taint arrives through the RECEIVER rather than through an argument. `pathlib` is the
    # reason this exists and it is a shape no argument-position model can express:
    #
    #     parcel_path = BASE_EXPORT_DIR / packet_ref     ← the attacker's value lands here
    #     data = parcel_path.read_text()                 ← the sink takes no arguments at all
    #
    # Every other sink here is `f(tainted)`. This one is `tainted.f()`, and reading it as the
    # former finds nothing: `read_text()` has no argument 0 to inspect. Ten of the 36 labelled
    # path-traversal misses on RealVuln were this, in FastAPI handlers whose route parameters
    # the engine already knew were attacker-controlled — the source was modelled, the sink was
    # not, and the two never met.
    taint_receiver: bool = False
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
    sink_params: tuple[tuple[str, Sink, int, str], ...] = ()
    returns_params: frozenset[str] = frozenset()
    returns_source: bool = False

    def sink_for(self, param: str) -> tuple[Sink, int, str] | None:
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
        "they carry untrusted data depends on callers, which are not analyzed. Two shapes are "
        "excepted and rated HIGH, because the framework is the caller and it binds them from "
        "the request: a handler under a routing decorator (`@app.get`, `@router.post`, "
        "`@bp.route`), and a Django view, recognised by a first parameter named `request`. A "
        "route registered some other way — a `urls.py` entry pointing at an undecorated "
        "function whose first parameter is not `request`, a class-based view's `get`/`post` — "
        "is not recognised, and its parameters stay a MEDIUM lead.",
        "SQL reached through an ORM is only seen at the escape hatches the ORM provides: "
        "`.raw()`, `.extra()`, `execute()`/`executemany()`/`exec_driver_sql()` on a receiver "
        "named like a connection or session (cursor, conn, connection, session, db, database, "
        "engine, pool, tx, trans). A database reached through a receiver this list does not "
        "name, or through a call whose receiver is not a plain dotted name "
        "(`get_conn().execute(sql)`), is not matched.",
        "Outbound HTTP is read from the written call: the `requests`, `httpx` and `urllib` "
        "functions by dotted name, and `request`/`putrequest` on a receiver named like a "
        "connection or a client (conn, connection, http, https, urllib3, pool, manager, client, "
        "httpx, requests). `.get()` and `.post()` on a receiver are deliberately NOT sinks and "
        "`session` is deliberately not a receiver: they are the most common method and variable "
        "names in Python, and `session.get(key)` is a Flask dictionary lookup rather than a "
        "request leaving the machine. A client reached only that way is a documented miss.",
        "A validation guard (`if (bad(x)) return/throw`) is assumed to sanitize; an ineffective "
        "guard therefore hides its sink from this tier.",
        "The JavaScript/TypeScript scanner is a brace-aware statement scanner, not a parser. "
        "Flat destructuring of a tainted value (`const { name } = req.query`, including "
        "renames, defaults and rest) is followed; a NESTED pattern "
        "(`const { a: { b } } = req.body`) is not, and neither are cross-boundary closures, "
        "dynamic property access or JSX.",
        "In JavaScript a value stored on `this` is not followed: a constructor that keeps a "
        "parameter as `this.file` and a method that later runs `exec('convert ' + this.file)` "
        "are two scopes with nothing carried between them. Object fields are the largest "
        "remaining shape in the command-injection class on SecBench.js and are named here "
        "rather than counted as covered.",
        "Which function `exec` is depends on what the file imported, so the shell sinks are "
        "resolved per file: a receiver bound to `child_process` or `shelljs` — including a "
        "promisified alias and the `child_process_1` form TypeScript emits — is a shell, and "
        "`pattern.exec(text)` in a file that imported neither is a regular expression. A "
        "receiver assigned indirectly (`const cp = deps.child_process`) is not resolved.",
    ]


# How many times to re-derive summaries before giving up on convergence. Each round can only
# ADD facts (a parameter that reaches a sink, a parameter whose taint escapes through the
# return), so the lattice is finite and monotone and a fixed point is reached quickly; the cap
# exists so a mutually recursive pair cannot spin, not because convergence is in doubt.
_SUMMARY_ROUNDS = 4
