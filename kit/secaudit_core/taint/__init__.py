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

  * **Cross-module to any depth, but only across files that were scanned.** A call to a
    function imported from another file in the analysed set is resolved against that file's
    summary, and those summaries are re-derived over the import graph until they stop changing
    (`_module_fixed_point`), so a chain that launders through a third and fourth module is
    followed too — `test_cross_module` pins that. What bounds it is scope, not depth: a chain
    that leaves the scanned set — into an excluded directory, a third-party package, or a
    language with no taint depth — stops at the boundary. Depth costs nothing in precision
    here because every edge comes from an explicit import statement; it is guessing at edges,
    not following them, that attaches a real sink to the wrong function.
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
  * **Flat destructuring only.** `const { name } = req.query` — the shape most Express
    handlers are actually written in — binds `name` to `req.query.name`, and the same holds
    for renames (`{ name: n }`), defaults, rest elements and array patterns, in a declaration
    or in a parameter list. A *nested* pattern (`const { a: { b } } = req.body`) is not
    destructured: reading one level is a lexical certainty, reading two means tracking a shape
    this scanner does not model.
  * The JS scanner does not understand closures capturing an outer tainted variable across a
    function boundary, `eval`-style dynamic property access, or JSX.

Everything above is a documented false-negative source, never a silent one: `limitations()`
returns this list so the report can print it.

## Layout

This was one 2,000-line module. It is now a package, split along the seams the file already
had as comment banners, because "god module" was the one design flag standing against an
otherwise well-gated engine:

* `model.py`     — `Sink`, `FunctionSummary`, `TaintPath`, and `limitations()`.
* `catalog.py`   — every sink, source and sanitizer. The file to read to answer "does it
                   detect X", and the file to edit to make it.
* `lexical.py`   — the offset-preserving views (`code_view`, `blank_strings`, `split_args`)
                   that decide what an analyzer is allowed to see.
* `pyanalysis.py`— the `ast`-based Python analysis.
* `jsanalysis.py`— the brace-aware JS/TS scanner.
* this file      — the cross-module resolver and the public entry points.

The import arrow runs one way (model → catalog → analyzers → here) and nothing re-exports
across it, so a cycle would be a build error rather than a subtle initialisation-order bug.
Every name the rest of the repository imported from `taint` is still importable from `taint`.
"""
from __future__ import annotations

import ast
import os
import re

from ..langs import JS_EXTS, PHP_EXTS, PY_EXTS, TS_EXTS
from .catalog import (JS_ASSIGN_SINKS, JS_SINKS, PY_METHOD_SINKS, PY_SINKS)
from .jsanalysis import (_JsScope, _js_functions, _js_summaries,
                         _js_param_names as _js_param_names)
from .lexical import (_js_strip_comments, blank_strings, code_view, split_args,
                      _EXT_GROUP as _EXT_GROUP, _LEXICAL as _LEXICAL)
from .model import FunctionSummary, PyFunc, Sink, TaintPath, limitations
from . import phpanalysis
from .pyanalysis import (_dedupe_paths, _python_functions, _python_paths,
                         _python_summaries)

# Re-exported so `from secaudit_core import taint; taint.X` keeps working for every X the
# repository already used — the split is an internal reorganisation, not an API change.
__all__ = [
    "JS_ASSIGN_SINKS", "JS_SINKS", "PY_METHOD_SINKS", "PY_SINKS", "TAINT_DEPTH",
    "FunctionSummary", "PyFunc", "Sink", "TaintPath",
    "analyze", "analyze_files", "analyze_js", "analyze_python", "blank_strings",
    "code_view", "limitations", "split_args",
]


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
    "Python": {"exts": PY_EXTS, "frontend": "stdlib `ast` parse",
               "interprocedural": True, "cross_module": True},
    "JavaScript": {"exts": JS_EXTS,
                   "frontend": "brace-aware statement scanner",
                   "interprocedural": True, "cross_module": True},
    "TypeScript": {"exts": TS_EXTS,
                   "frontend": "brace-aware statement scanner",
                   "interprocedural": True, "cross_module": True},
    # PHP is here so the published coverage matrix says what the engine does, and its two
    # `False`s are the point of the row rather than a gap in it: `phpanalysis` follows a
    # superglobal through one assignment inside one file, and claiming otherwise beside two
    # tiers that genuinely are interprocedural would make the matrix flatter and useless.
    "PHP": {"exts": PHP_EXTS,
            "frontend": "superglobal-rooted line scanner",
            "interprocedural": False, "cross_module": False},
}

_TAINT_EXTS = {ext: name for name, spec in TAINT_DEPTH.items() for ext in spec["exts"]}


def _analyzable(path: str) -> str:
    """The language of the SUMMARY-BASED engine below. PHP is excluded on purpose: it is
    analysed by `phpanalysis`, which is a different depth and shares none of this machinery —
    `_per_file_context` would otherwise hand a `.php` file to the JavaScript brace scanner,
    which is how a front end ends up analysing a language it cannot read."""
    language = _TAINT_EXTS.get(os.path.splitext(path)[1].lower(), "")
    return "" if language == "PHP" else language


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
            py_functions = _python_functions(tree)
            context[path] = (py_functions,
                             _python_summaries(py_functions, path, text.splitlines()))
        elif language in ("JavaScript", "TypeScript"):
            js_functions = _js_functions(text, path)
            context[path] = (js_functions, _js_summaries(path, text, js_functions))
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

    # PHP, from its own front end. Appended rather than branched into the loop above so that
    # nothing in the summary engine has to know PHP exists — see `phpanalysis`'s docstring for
    # why the two are kept apart, and its `limitations()` for what this one does not do.
    for path, text in files.items():
        if path.lower().endswith(phpanalysis.EXTS):
            out.extend(phpanalysis.analyze(path, text))

    return _dedupe_paths(out)


def analyze(path: str, text: str) -> list[TaintPath]:
    """Taint paths in one file. Unknown extensions return [] — never an error.

    Routed through `analyze_files` so the single-file and project paths cannot diverge: a fix
    to one is a fix to both, and a behaviour that only appears when several files are in scope
    is a behaviour with no small test."""
    return analyze_files({path: text})


def analyze_python(path: str, text: str) -> list[TaintPath]:
    """One Python file, analysed as a project of one. Kept for callers that have a single
    file and no tree; the whole-set pass is `analyze_files`."""
    return analyze_files({path: text})


def analyze_js(path: str, text: str) -> list[TaintPath]:
    """One JavaScript/TypeScript file, analysed as a project of one."""
    return analyze_files({path: text})
