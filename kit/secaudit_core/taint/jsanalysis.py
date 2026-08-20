"""JavaScript / TypeScript taint analysis: a brace-aware statement scanner, not a parser.

The bound is the design and it is documented in `limitations()`: no parser means named
declarations carry summaries and object-property methods do not, flat destructuring is
followed and nested patterns are not. Everything it cannot see is a stated false negative
rather than a silent one.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from .catalog import (JS_SINKS, JS_ASSIGN_SINKS, JS_INLINE_MODULE_SINKS,
                      JS_REQUEST_SOURCES, JS_SANITIZER, JS_GUARD_EXIT,
                      js_local_module_sinks)
from .lexical import _js_strip_comments, blank_strings, code_view, split_args
from .model import _SUMMARY_ROUNDS, FunctionSummary, Sink, TaintPath

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


# `(?:(?:const|let|var)\s*)?` rather than `(?:const|let|var)?\s*`: with the keyword absent the
# two `\s*` become adjacent and the engine splits one run of indentation between them in a
# quadratic number of ways. Every rewrite in this file was checked match-for-match against 7 MB
# of real JavaScript before it landed — the language is identical, the backtracking is not.
_JS_ASSIGN = re.compile(r"^\s*(?:(?:const|let|var)\s*)?([A-Za-z_$][\w$]*)\s*=(?!=)(.*)$")
# `const { name, id } = req.query` / `const [first] = req.body.items`, with an optional
# TypeScript annotation between the pattern and the `=`. Flat patterns only — the character
# classes exclude a nested brace on purpose, so a nested pattern simply does not match here.
_JS_DESTRUCTURE = re.compile(
    r"^\s*(?:(?:const|let|var)\s*)?(\{[^{}]*\}|\[[^\[\]]*\])"
    # The annotation and the whitespace before `=` are one alternation rather than two repeats:
    # the annotation class contains a space, so `[… ]+?\s*` was the same quadratic split.
    r"(?:\s*:[^=\n]*|\s*)=(?!=)(.*)$")
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
    re.compile(r"(?:^|[^.\w$])(?:async\s+)?function\s*(?:\*\s*)?([A-Za-z_$][\w$]*)\s*\(([^)]*)\)"),
    # const f = (a, b) => {   /   let f = async function (a) {
    re.compile(r"(?:^|[^.\w$])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
               r"(?:async\s+)?(?:function\s*(?:\*\s*)?)?\(([^)]*)\)\s*(?:=>\s*)?\{"),
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


def _js_binding_names(pattern: str) -> list[tuple[str, str]]:
    """(bound name, property key) for one flat destructuring pattern.

    `{ name }` binds `name` to the key `name`; `{ name: n }` binds `n` to the key `name`; a
    rest element and every array position bind to no key at all, because which property the
    value came from is exactly what those two forms do not say — and a key we cannot name is
    reported as the parent expression rather than guessed at.

    Nested patterns are declined, not approximated: `split_args` keeps `{ a: { b } }` in one
    piece and the inner braces fail the identifier check, so the binding is simply not made.
    """
    if len(pattern) < 2:
        return []
    is_object = pattern.startswith("{")
    out: list[tuple[str, str]] = []
    for part in split_args(pattern[1:-1]):
        part = part.split("=")[0].strip()             # default value
        key = ""
        if part.startswith("..."):                    # rest: no single key describes it
            part = part[3:].strip()
        elif is_object and ":" in part:
            key, part = (p.strip() for p in part.split(":", 1))
        elif is_object:
            key = part
        if part and _JS_IDENT.fullmatch(part):
            out.append((part, key if _JS_IDENT.fullmatch(key or "x") else ""))
    return out


# A parameter that is itself a destructuring pattern, with any TypeScript annotation after it.
_JS_PARAM_PATTERN = re.compile(r"^\s*(\{[^{}]*\}|\[[^\[\]]*\])")


def _js_param_names(group: str) -> list[str]:
    """Parameter names by POSITION — the list a call site is resolved against.

    A parameter this scanner cannot name (a destructuring pattern) yields an empty string
    rather than being dropped. Dropping it used to shift every later parameter one place left,
    so `f(a, {b}, c)` resolved a call's second argument against `c`: an interprocedural finding
    reported against the wrong argument. An empty name matches no summary entry, which is the
    correct answer — unknown, not misattributed. The bindings inside the pattern are still
    seeded as weak sources in the body by `_JsScope._function_params`.
    """
    names = []
    for part in split_args(group):
        part = part.strip().split("=")[0].strip()
        if _JS_PARAM_PATTERN.match(part):
            names.append("")                     # position held, name unknown
            continue
        part = part.split(":")[0].strip()        # TypeScript annotation
        names.append(part if _JS_IDENT.fullmatch(part) else "")
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


@lru_cache(maxsize=8)
def _split(text: str) -> tuple[str, ...]:
    """One file's lines, split once.

    The same shape as `_prepared` above and found the same way — by profiling, not by reading.
    A scope is built once per function per summary round, and its constructor split the whole
    file into lines while `run()` split the prepared text again, so a 17k-line file was split
    5,633 times for 1,483 functions. That was **5.7 of 12.7 seconds** on `lodash@4.17.21`, the
    single largest cost in the tier, and none of it was analysis.

    Returns a tuple rather than a list because the value is shared across every scope in the
    file: the callers index it and take its length, and a mutable list handed to thousands of
    readers is a defect waiting for the first caller that decides to normalise a line in place.

    Keyed on the source text, which is one shared string per file — an identity hit — and on the
    prepared text, which `_prepared` also returns from cache, so both keys are stable.
    """
    return tuple(text.splitlines())


@lru_cache(maxsize=4)
def _prepared(text: str) -> tuple[str, tuple[tuple[re.Pattern[str], Sink], ...]]:
    """The comment-stripped text and the sink list for one file, computed once.

    **Both halves are per file and both were being recomputed per scope**, and a scope is built
    once per function per summary round — twice over, since `_js_summaries` runs for the file's
    own pass and again for the cross-module one. On `lodash` that is a five-figure number of
    full-text scans, and this repository has a standing rule about that shape: performance here
    is a correctness property, because a scan slow enough to hit the harness timeout removes a
    package from the corpus and quietly changes the number.

    Measured on two of the corpus's heaviest packages, with the findings asserted identical
    either way: `lodash@4.17.15` **99.9s → 12.9s**, `total.js@3.4.6` **21.5s → 8.3s**. The
    comment-stripping half of that was already being repeated before this cache existed.

    The sink list is per file because **which function `exec` is depends on what the file
    imported** — see `catalog.js_local_module_sinks`. A file-level fact, cached at file level.

    Keyed on the source text, which the driver passes as one shared string per file, so the
    lookup is an identity hit rather than a rehash. Bounded at four entries: the cache exists to
    collapse repeated work inside one file's analysis, not to hold a project in memory.
    """
    stripped = _js_strip_comments(text)
    return stripped, (*JS_SINKS, *JS_INLINE_MODULE_SINKS, *js_local_module_sinks(stripped))


class _JsScope:
    """Brace-depth-scoped taint state for one JS/TS file (or one function body within it)."""

    def __init__(self, path: str, text: str,
                 summaries: dict[str, FunctionSummary] | None = None,
                 functions: dict[str, _JsFunc] | None = None,
                 origins: dict[str, str] | None = None):
        self.path = path
        self.text, self.sinks = _prepared(text)
        self.raw_lines = _split(text)
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
        # `dict.fromkeys`, not `set`, and the difference is a published number.
        #
        # This loop returns on the FIRST tainted identifier it sees, so iteration order decides
        # which source the finding is attributed to and therefore which line it is reported at.
        # A `set` of strings iterates in hash order, and Python randomises string hashing per
        # process — so the same engine scanning the same package reported the same finding at
        # line 739 or line 743 depending on the run. Measured, six runs of one package across
        # two engines: 4x743, 2x739. That is one SecBench.js label flickering in and out of the
        # +/-10 window, which is a published recall figure moving without the code changing —
        # the exact thing the engine digest is supposed to make impossible, and which it cannot
        # catch because the code really was identical.
        #
        # `dict.fromkeys` dedupes in first-occurrence order at the same cost, so the attributed
        # source is now the leftmost identifier in the expression: deterministic, and the more
        # defensible answer anyway.
        for ident in dict.fromkeys(_JS_IDENT.findall(expr)):
            if ident in self.tainted:
                _, line, src, kind = self.tainted[ident]
                return (src, line, kind)
        return None

    def drop_deeper_than(self, depth: int) -> None:
        for name in [n for n, (d, *_) in self.tainted.items() if d > depth]:
            del self.tainted[name]

    def run(self, region: tuple[int, int] | None = None) -> list[TaintPath]:
        """Scan the whole file, or just one function body when `region` is given."""
        all_lines = _split(self.text)
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
        r"function\s*(?:[\w$]+\s*)?\(([^)]*)\)"      # function foo(a, b) / function (a, b)
        r"|(?:^|[=(,]\s*)\(([^)]*)\)\s*=>"           # (a, b) =>
        r"|(?:^|[=(,]\s*)([A-Za-z_$][\w$]*)\s*=>"    # a =>
        # A method in an object literal or a class body: `exec (cmd, callback) {`. Its shape is
        # also `if (ready) {`, so the name is captured and filtered — see `_NOT_A_METHOD`. This
        # is a whole idiom, not an edge case: a utility module written as one exported object
        # binds every one of its parameters this way, and without it none of them is a source.
        r"|^\s*(?:static\s+)?(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{")

    # Words that open a parenthesised block and bind nothing. Seeding `if (cmd) {`'s `cmd` as a
    # caller-supplied parameter would make every guarded local a source, which is the direction
    # that manufactures findings rather than missing them.
    _NOT_A_METHOD = frozenset({
        "if", "for", "while", "switch", "catch", "with", "do", "else", "try", "finally",
        "function", "return", "typeof", "new", "delete", "void", "await", "yield", "in", "of",
        "case", "default", "class", "extends", "import", "export",
    })

    def _function_params(self, raw: str) -> list[str]:
        """Every name a function header binds in its body, destructuring patterns included.

        `app.post('/x', ({ body }, res) => …)` binds `body`, and a handler written that way is
        no less a handler than one that writes `req.body`. These are weak (parameter-kind)
        sources like any other parameter: what a caller passes is not knowledge this scope has.
        """
        m = self._FUNC.search(raw)
        if not m:
            return []
        if m.group(4) is not None:                   # the method-shorthand branch
            if m.group(4) in self._NOT_A_METHOD:
                return []
            group = m.group(5) or ""
        else:
            group = next((g for g in m.groups()[:3] if g is not None), "")
        names = []
        for part in split_args(group):
            part = part.strip().split("=")[0].strip()
            pattern = _JS_PARAM_PATTERN.match(part)
            if pattern:
                names += [n for n, _ in _js_binding_names(pattern.group(1))]
                continue
            part = part.split(":")[0].strip()
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
        for pattern, sink in self.sinks:
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
            return

        # 7) Destructuring propagation: `const { name } = req.query`. Handled apart from (6)
        #    because the left side binds several names at once and each one names a different
        #    property of the same untrusted value.
        m = _JS_DESTRUCTURE.match(safe)
        if m:
            rhs = line[m.start(2):] if m.start(2) >= 0 else m.group(2)
            taint = None if JS_SANITIZER.search(blank_strings(rhs)) else self.taint_of(rhs)
            for name, key in _js_binding_names(m.group(1)):
                if not taint:
                    self.tainted.pop(name, None)
                    continue
                src, src_line, kind = taint
                # Name the property in the reported source — `req.query.name` reads as the
                # thing an attacker controls, where `req.query` reads as the bag it came in.
                # Only for a request-rooted alias: a call on the right (`= parse(req.body)`)
                # returns something whose shape we do not know, and a PARAMETER-rooted source
                # has to keep the bare parameter name or the function summary can no longer
                # match the path back to the parameter that caused it.
                named = key and kind == "request" and "(" not in rhs
                self.tainted[name] = (depth, src_line or lineno,
                                      f"{src}.{key}" if named else src, kind)

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
        lines = _split(self.text)
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
                # body can be matched back to the parameter that caused it. A positional
                # placeholder (a destructuring pattern) has no name to match back to and is
                # skipped here; its inner bindings are seeded by the body scan instead.
                if param:
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


