"""Prototype pollution, asked as a question about a write rather than about a loop.

`SEC-JS-PROTO` used to be a pattern rule matching `for (… in …)`. On 594 real npm packages that
produced **950 findings and 9 of the 185 labelled bugs** — the worst result in this repository's
history and the clearest possible statement that the rule was reading the wrong line. A `for…in`
loop is not a vulnerability; it is the most ordinary loop in the language. The vulnerability is
one line further in, and it is a *write*:

    function merge(target, source) {
      for (const key in source) {            ← what the old rule matched
        target[key] = source[key];           ← where the bug is
      }
    }

Send `{"__proto__": {"isAdmin": true}}` through that and every object in the process gains
`isAdmin`. The three things that make it a bug are all visible at the write:

1. **The target is indexed by a variable**, not by a fixed property — `target[key] =`, never
   `target.name =`. A constant key cannot be `__proto__`.
2. **That variable is a key, not an index.** `arr[i] = x` in a loop over a length is the most
   common line in JavaScript and it is not this bug. So the index must be *bound as a key*: by
   `for…in`, by `Object.keys/entries/getOwnPropertyNames`, by the callback of a utility-library
   iteration (`_.each(src, (v, k) => …)`, where the second parameter is the key by convention),
   or by walking a `split()` path — the `set(obj, 'a.b.c', v)` helper, which is the other half of
   this class. That last one is reached two ways now: through the split itself, and through the
   **walk** (`cur = cur[part]`) that a path setter performs before its final write, which is what
   `_write_into_a_walk` decides. On SecBench.js the walk is the largest single group of labelled
   sinks no iteration binder could ever have seen.
3. **The caller chose that key.** The title says *attacker-named*, and a key this function
   invented is not one: `Object.keys(filters)` over state built from a literal has the shape and
   none of the substance. So the iterated object has to trace back to a parameter — through as
   many local bindings as it takes, because a query-string parser is two hops from its argument
   and is the real thing.
4. **Nothing in the function refuses the dangerous keys.** `__proto__`, `constructor` and
   `prototype` by name; `hasOwnProperty`; a null-prototype target; a `Map`; or an allowlist.

All three are decided inside one function body, which is why this is a structural analysis and
not a pattern. It reports the write, so a finding lands on the line an author has to change.

**What it will not see**, stated because a structural rule that overstates is worse than a
pattern one: a merge split across two modules; a guard implemented as an imported helper (that
one silences the rule rather than firing it, which is the direction to be wrong in);
`Object.assign`/spread, which pollute only through a target that is already `__proto__`; and a
key more than four local bindings from the parameter that carries it, which is given up on
rather than chased.

**The anonymous-callback limitation was the first item on that list and it is now gone, which is
worth reading as a method rather than as a fix.** The instance that proved it was
`js-extend@0.0.1`: the key is bound from `source`, and `source` is the parameter of a callback
handed to `each.call(sources, function (source) { … })`, so the enclosing function's parameter
list does not contain it and never will. The wrong response was to delimit the callback as a
function of its own. What the rule needs from a callback is not its span but the fact that **its
parameters carry whatever the iterated value carries** — which is decidable at the call site, in
`_caller_supplied`, without knowing where the callback ends.
"""
from __future__ import annotations

import re

from ..langs import JSTS_EXTS
from ..schema import Confidence, Finding, Severity, Verdict
from ..taint.lexical import code_view
from .js import _functions, _text, is_production_js

# A key bound by iterating an object's own keys. Group 1 is the bound name and group 2 is the
# thing being iterated, because a key is only dangerous if the *caller* chose it — see
# `_caller_supplied`.
_KEY_BINDERS = (
    # for (const key in source)
    re.compile(r"\bfor\s*\((?:\s*(?:const|let|var))?\s*([A-Za-z_$][\w$]*)\s+in\s+([\w$.\[\]]+)"),
    # for (const key of Object.keys(source)) — and of entries(), which destructures
    re.compile(r"\bfor\s*\((?:\s*(?:const|let|var))?\s*([A-Za-z_$][\w$]*)\s+of\s+"
               r"Object\.(?:keys|getOwnPropertyNames)\s*\(\s*([\w$.\[\]]+)"),
    # Object.keys(source).forEach(key => …) / .map(function (key) …). The iterated expression
    # comes first here, so the groups are swapped back by `_key_names`.
    re.compile(r"Object\.(?:keys|getOwnPropertyNames)\s*\(\s*([\w$.\[\]]+)"
               r"(?:[^)\w$.\[\]][^)]*)?\)\s*"
               r"\.\s*(?:forEach|map|reduce)\s*\(\s*(?:function\s*)?(?:\(\s*)?"
               r"(?:[A-Za-z_$][\w$]*\s*,\s*)?([A-Za-z_$][\w$]*)", ),
    # const parts = path.split('.') — the set-by-path helper's key source
    re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([\w$.\[\]]*)\.split\s*\("),
)
# The one binder whose groups are (iterated, bound) rather than (bound, iterated).
_SWAPPED = 2

# `for (const [key, value] of Object.entries(source))` — destructured, so the name is in a
# pattern rather than a single identifier. Kept separate because the shape is different enough
# that folding it into the list above would make that regex unreadable.
_ENTRIES_BINDER = re.compile(
    r"\bfor\s*\((?:\s*(?:const|let|var))?\s*\[\s*([A-Za-z_$][\w$]*)\s*[,\]]"
    r"[^)]*?\bObject\.entries\s*\(\s*([\w$.\[\]]+)")

# --------------------------------------------------------------------- whose key is it anyway
#
# The rule's own claim is an **attacker-named** key, and a key this function invented is not one.
# `Object.keys(filters)` over component state built from a literal has the shape of the bug and
# none of its substance: nothing outside the function can put `__proto__` in there. Measured on
# the RealVuln corpus, that exact line (`AdminAudit.tsx:18`) was the rule's only false positive.
#
# What counts as caller-supplied is the function's parameters, and anything derived from one.
# A single-hop check would be wrong in the other direction and lose the classic query-string
# parser — `str.split('&')` then `p.split('=')` is two hops from the parameter and is exactly the
# shape of a real `qs` prototype-pollution bug — so this is a small fixpoint over local bindings
# rather than a membership test.

# `(a, b)` in a function header, including arrows without parentheses.
_PARAM_LIST = re.compile(r"\(([^()]*)\)\s*(?:=>|\{)|(?:^|[^.\w$])([A-Za-z_$][\w$]*)\s*=>")
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
# A binding that can carry a value onward: `const x = expr`, `let [a, b] = expr`,
# `for (const x of expr)`, `for (const x in expr)`, and a plain `x = expr` to a name declared
# earlier. That last alternative is not a stylistic nicety. The pre-ES6 merge helper declares its
# locals up front and fills them in the loop:
#
#     function extend() {
#       var options, name, src;          ← declared, carrying nothing
#       for (; i < length; ++i) {
#         options = arguments[i];        ← THIS is where the caller's object arrives
#         for (name in options) { target[name] = options[name]; }
#
# Requiring `const`/`let`/`var` on the assignment was an accident of writing the pattern around
# declarations, and it made the rule silent on `extend@3.0.1` and `objtools@3.0.0` — two labelled
# SecBench.js bugs of exactly this shape. `=` but not `==`/`===`/`=>`, and the target is a bare
# identifier: `a.b = c` writes through a name, it does not rebind one.
_BINDING = re.compile(
    r"(?:const|let|var)\s+(\[[^\]]*\]|\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)"
    r"|\bfor\s*\((?:\s*(?:const|let|var))?\s*(\[[^\]]*\]|[A-Za-z_$][\w$]*)\s+(?:of|in)\s+([^)\n]+)"
    r"|(?:^|[;{}(,]|\n)\s*([A-Za-z_$][\w$]*)\s*=(?!=|>)\s*([^;\n]+)")
# Words that look like identifiers in an expression but carry nothing from a parameter.
_NOT_A_VALUE = frozenset({
    "const", "let", "var", "new", "function", "return", "typeof", "await", "of", "in",
    "true", "false", "null", "undefined", "this", "Object", "Array", "JSON", "String",
    "Number", "Boolean", "Math", "Symbol", "Map", "Set", "Promise", "require",
})

# The write. `target[key] =` or `cur[parts[i]] =`, with any number of leading property or index
# steps (`opts.data[key] =`). `=` but not `==`/`===`/`=>`, and not `+=`-style compounds, which
# mutate a value rather than create a property. The index alternation carries one level of
# nesting on purpose: `cur[parts[i]]` is the set-by-path shape, and a flat `[^\]]+` stops at the
# inner bracket and matches nothing at all.
_INDEX = r"(?:[^\[\]\n]|\[[^\]\n]*\])+?"
_WRITE = re.compile(rf"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[{_INDEX}\])*)"
                    rf"\[\s*({_INDEX})\s*\]\s*=(?!=|>)")

# Anything here means the author has thought about the dangerous keys. Deliberately generous:
# the cost of an unnecessary silence is one missed finding, and the cost of ignoring a real
# guard is a report that tells a careful author their guard does not exist.
# `hasOwnProperty` is deliberately NOT here, and it used to be.
#
# It reads like a guard and it is the opposite of one. The idiom it appears in is:
#
#     for (const k in src) { if (src.hasOwnProperty(k)) target[k] = src[k] }
#
# which is the *canonical vulnerable merge*, not a defence. `hasOwnProperty` asks whether the key
# is the source object's own rather than inherited — and when the source came from
# `JSON.parse('{"__proto__": {"isAdmin": true}}')`, `__proto__` **is** an own property. The check
# passes and the write happens. It excludes exactly the keys an attacker was never going to send.
#
# Treating it as a guard silenced 10 of the 115 unsealed labelled prototype-pollution misses on
# SecBench.js — measured, not estimated. The module's comment justified the guard list as
# "deliberately generous: the cost of an unnecessary silence is one missed finding", and that
# trade is fine for a check that means something. This one means the reverse of what it says, so
# generosity here is not caution, it is a rule declining to fire on the shape it was written for.
#
# The genuinely protective forms are still matched: an `Object.prototype.hasOwnProperty.call(...)`
# guard almost always sits beside a `__proto__` / `constructor` / `prototype` name test, and those
# three are matched on their own.
# `constructor` and `prototype` are matched only as **quoted strings**, for the same reason
# `hasOwnProperty` is gone: a guard is a comparison against a key *name*, and a name is a string.
# `if (key === 'constructor')` is a guard. `Object.prototype.hasOwnProperty.call(src, key)` and
# `Foo.prototype.bar = …` are property accesses that merely contain the word, and matching those
# silenced the rule on any function that touched a prototype at all — including, exactly, the
# `Object.prototype.hasOwnProperty` spelling of the non-guard above. `__proto__` stays unquoted:
# it has no innocent use in this position, and `obj.__proto__ = x` is itself the awareness the
# guard list is looking for.
_GUARD = re.compile(
    r"__proto__|['\"]constructor['\"]|['\"]prototype['\"]|Object\.create\s*\(\s*null\s*\)"
    r"|\bnew\s+Map\b|\bnew\s+WeakMap\b|Object\.defineProperty|\bfreeze\s*\("
    r"|\b(?:BLOCKED|FORBIDDEN|DENY|BLACKLIST|DISALLOWED|UNSAFE_KEYS|PROTO_KEYS)\b"
    r"|\bisSafeKey\b|\bsafeKey\b|\bvalidateKey\b", re.IGNORECASE)

_TITLE = "Prototype pollution — attacker-named key written to an object"


def _root(expression: str) -> str:
    """The identifier a member expression starts from: `opts.data[i]` → `opts`."""
    m = _IDENT.match(expression.strip())
    return m.group(0) if m else ""


def _params(header: str) -> set[str]:
    """The parameter names declared in a function header line.

    Destructured patterns contribute every identifier in them: `function f({a, b})` means a
    caller chose both, which is the only question being asked here.

    `arguments` is always in the set. It is not declared anywhere and it is the most
    caller-supplied thing in the language — `function extend() { … arguments[i] … }` is how every
    pre-ES6 merge helper was written, and it is a shape SecBench.js is full of.

    On its own this seeding moved nothing: measured across 593 packages it changed neither a
    true positive nor an unmatched finding, because the helpers it was meant to reach assign
    `options = arguments[i]` without a declaration keyword and `_BINDING` did not follow that.
    It is kept because it is a precondition for the fix that did move them, not because it was
    independently shown to.
    """
    params = {"arguments"}
    m = _PARAM_LIST.search(header)
    if not m:
        return params
    if m.group(2):                                   # `x => …`, no parentheses
        return params | {m.group(2)}
    return params | {i for i in _IDENT.findall(m.group(1) or "") if i not in _NOT_A_VALUE}


# A callback's parameters carry whatever the thing being iterated carries. Two spellings, both
# ordinary: the iterated value as the receiver (`Object.keys(src).forEach(k => …)`,
# `keys.forEach(function (prop, i) { … })`) and as the first argument (`_.each(src, fn)`,
# `each.call(sources, fn)`), which is how every pre-lodash utility library was written.
#
# This is the limitation the module's docstring has declared since it was written — *"a write
# inside an anonymous callback whose enclosing named function cannot delimit it"* — with the
# instance that proved it, `js-extend@0.0.1`. It is addressed here rather than by delimiting the
# callback: what the rule needs from the callback is not its span but the fact that its
# parameters are the caller's data, and that is decidable from the call.
#
# Two patterns rather than one alternation, and the parameter list is matched with its
# parentheses rather than around an optional pair. `\(?([^)\n]*)\)?` after `\s*` is two repeats
# that overlap on whitespace with a nullable thing between them, which is quadratic — reported by
# this repository's own ReDoS analysis in the dogfood gate, the second rule in this session it
# caught its author writing.
_CALLBACK_PARAMS = r"(?:async\s+)?(?:function[\s*]*)?(?:\(([^)\n]*)\)|([A-Za-z_$][\w$]*)\s*=>)"
_CALLBACK_RECEIVER = re.compile(
    r"([\w$.\[\]]+)\s*\.\s*(?:forEach|map|reduce|each|filter|some|every|flatMap)\s*\(\s*"
    + _CALLBACK_PARAMS)
_CALLBACK_ARGUMENT = re.compile(
    r"\b(?:_|lodash|each|forEach|forOwn|mapValues|extend)"
    r"(?:\.(?:each|forEach|forOwn|mapValues|call|apply))?\s*\(\s*([\w$.\[\]]+)\s*,\s*"
    + _CALLBACK_PARAMS)

# `cur = cur[k]` — the same name on both sides, which is a walk one level into an object. That is
# the set-by-path helper's whole mechanism, and the reason it belongs in this module rather than
# in a general "indexed write" rule: a function that walks *into* an object by a caller-chosen
# path and then writes a caller-chosen key at the end of it is `set(obj, 'a.b.__proto__', v)`,
# which is the other half of this CWE and is not otherwise reachable from an iteration binder.
_WALK = re.compile(r"(?:^|[;{}(\n]|\)\s*)\s*([A-Za-z_$][\w$]*)\s*=\s*\1\s*\[")


def _caller_supplied(body: str, params: set[str]) -> set[str]:
    """Names holding something a caller passed in, or derived from it.

    A fixpoint rather than a membership test, because one hop is not enough: a query-string
    parser does `str.split('&')` and then `p.split('=')`, and the key is two bindings away from
    the parameter that carries it. Bounded at four passes — deeper chains exist and are given up
    on rather than chased, which silences the rule instead of firing it.
    """
    derived = set(params)
    for _ in range(4):
        grew = False
        for m in _BINDING.finditer(body):
            target, expression = next(
                ((m.group(i), m.group(i + 1)) for i in (1, 3, 5) if m.group(i)), ("", ""))
            if not target or not expression:
                continue
            if not any(i in derived for i in _IDENT.findall(expression)):
                continue
            for name in _IDENT.findall(target):
                if name not in _NOT_A_VALUE and name not in derived:
                    derived.add(name)
                    grew = True
        for pattern in (_CALLBACK_RECEIVER, _CALLBACK_ARGUMENT):
            for m in pattern.finditer(body):
                iterated = m.group(1)
                if not iterated or _root(iterated) not in derived:
                    continue
                for name in _IDENT.findall(m.group(2) or m.group(3) or ""):
                    if name not in _NOT_A_VALUE and name not in derived:
                        derived.add(name)
                        grew = True
        if not grew:
            break
    return derived


def _walked(body: str) -> set[str]:
    """Names this function walks one level at a time — `cur = cur[part]`."""
    return {m.group(1) for m in _WALK.finditer(body)}


def _key_names(body: str, supplied: set[str]) -> set[str]:
    """Names bound as an object key **whose keys the caller chose**.

    The second half is the whole point. `Object.keys(filters)` over state this function built
    from a literal has the shape of prototype pollution and none of its substance: no caller can
    put `__proto__` in an object the function itself constructed.
    """
    names: set[str] = set()
    for index, pattern in enumerate(_KEY_BINDERS):
        for m in pattern.finditer(body):
            bound, iterated = ((m.group(2), m.group(1)) if index == _SWAPPED
                               else (m.group(1), m.group(2)))
            if bound and _root(iterated or "") in supplied:
                names.add(bound)
    for m in _ENTRIES_BINDER.finditer(body):
        if _root(m.group(2) or "") in supplied:
            names.add(m.group(1))
    # `_.each(source, function (value, key) { … })` — the utility-library spelling of `for…in`,
    # and by convention over an *object* the second parameter is the key. Only the second: over
    # an array the same call yields (value, index), and an index is not a key. This is the one
    # callback shape that binds a key rather than merely carrying the caller's data, which is why
    # it is here as well as in `_caller_supplied`.
    for m in _CALLBACK_ARGUMENT.finditer(body):
        if _root(m.group(1) or "") not in supplied:
            continue
        params = _IDENT.findall(m.group(2) or "")
        if len(params) >= 2:
            names.add(params[1])
    return names


def _index_is_a_key(index: str, keys: set[str]) -> str | None:
    """Why `index` names a key rather than an array position, or None if it does not.

    Two forms count: the bound name itself (`target[key]`), and one step into a name bound from
    a split path (`cur[parts[i]]`) — the second is the set-by-path helper, where the loop
    variable really is an integer but what it selects is a property name.
    """
    index = index.strip()
    if index in keys:
        return f"`{index}`, which this function binds as an object key"
    m = re.fullmatch(r"([A-Za-z_$][\w$]*)\s*\[[^\]]*\]", index)
    if m and m.group(1) in keys:
        return f"an element of `{m.group(1)}`, which this function builds from a path string"
    return None


def _write_into_a_walk(target: str, index: str, walked: set[str], supplied: set[str]) -> str | None:
    """Why this write is the end of a set-by-path walk, or None if it is not.

    Two things have to hold together, and each one is doing work. The target must be a name the
    function **walks** (`cur = cur[part]`), which is what makes it a path setter rather than an
    ordinary indexed assignment — without it every `store[name] = value` in the language is this
    finding. And the index must be **caller-supplied**, directly or one step into a caller-supplied
    array (`a[n - 1]`, the last segment of a split path); a walk indexed by something the function
    chose is not attacker-named.

    There was a third: an explicit refusal of numeric literal indexes, on the grounds that
    `cur[0] =` is an array position however the target was reached. It is gone, because mutation
    testing showed nothing could be written that would fail without it — `supplied` holds
    identifiers, so a digit string can never be in it, and the caller-supplied test refuses `0`
    on its own. A guard that cannot be falsified is a guard that is not deciding anything, and
    this module has deleted one before for the same reason.

    Without this, the class's largest remaining group is unreachable. A key at the end of a walk
    is never bound by `for…in` or `Object.keys`, so no iteration binder sees it — and
    `set(obj, 'a.b.__proto__', value)` is the half of CWE-1321 that this module's docstring has
    always named and never reached.
    """
    if _root(target) not in walked:
        return None
    index = index.strip()
    if index in supplied:
        return (f"`{index}`, the last segment of a path this function walked into "
                f"`{_root(target)}`")
    m = re.fullmatch(r"([A-Za-z_$][\w$]*)\s*\[[^\]]*\]", index)
    if m and m.group(1) in supplied:
        return (f"an element of `{m.group(1)}`, the path this function walked into "
                f"`{_root(target)}`")
    return None


def analyze_file(rel: str, text: str) -> list[Finding]:
    if not rel.lower().endswith(JSTS_EXTS) or not is_production_js(rel):
        return []
    view = code_view(text, rel)
    if view is None:
        return []
    lines = view.splitlines()
    raw = text.splitlines()

    findings: list[Finding] = []
    seen: set[int] = set()
    # A guard protects everything lexically inside the function that declares it, and
    # `_functions()` lists inner functions separately from the ones that contain them. Without
    # this, a `merge()` that checks `__proto__` once and then does the work in a local `walk()`
    # is reported on the inner function — the exact shape of a careful implementation, reported
    # for being careful. Outer functions come first because the list is sorted by span.
    guarded: set[int] = set()
    for name, (start, end) in sorted(_functions(lines).items(), key=lambda kv: kv[1]):
        if start in guarded:
            continue
        body = _text(lines, start, end)
        # This function's own parameters, and deliberately not its enclosing ones. A helper that
        # closes over an outer `source` is still reported, because the outer function's span
        # *contains* the inner body and its own pass sees the same write — so inheriting the
        # outer parameter list was four lines that no test could be made to fail without.
        # Written, then deleted when the mutation proving it survived its own removal.
        supplied = _caller_supplied(body, _params(lines[start - 1]))
        keys = _key_names(body, supplied)
        walked = _walked(body)
        # The guard is read from the RAW body and the writes from the blanked one, and the split
        # is the whole reason this rule works. `code_view` blanks string contents, which is right
        # for a write — a `target[key] =` inside a string is not a write — and exactly wrong for
        # a guard, because the guard is nearly always a string: `if (key === '__proto__')`. Read
        # both from the same view and every hand-written protection in the ecosystem disappears.
        if _GUARD.search(_text(raw, start, end)):
            guarded.update(range(start, end + 1))
            continue
        if not keys and not walked:
            continue
        for offset, line in enumerate(lines[start - 1:end]):
            lineno = start + offset
            if lineno in seen:
                continue
            m = _WRITE.search(line)
            if not m:
                continue
            why = (_index_is_a_key(m.group(2), keys)
                   or _write_into_a_walk(m.group(1), m.group(2), walked, supplied))
            if why is None:
                continue
            seen.add(lineno)
            target = m.group(1)
            findings.append(Finding(
                detector_id="PROTO-JS-WRITE", title=_TITLE,
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                cwe="CWE-1321", owasp="A08",
                file=rel, line=lineno,
                evidence=raw[lineno - 1].strip()[:200] if lineno <= len(raw) else "",
                fix=f"`{name}()` writes to `{target}` under a key it did not choose — the index "
                    f"is {why} — and nothing in the function refuses `__proto__`, `constructor` "
                    f"or `prototype`. A caller who controls that key controls every object in "
                    f"the process. Skip those three names before the write, or build the result "
                    f"on `Object.create(null)` or a `Map`, where they are ordinary strings.",
                source="structural", verdict=Verdict.UNVERIFIED))
    return sorted(findings, key=lambda f: f.line)


def analyze_files(files: dict[str, str]) -> list[Finding]:
    return [f for rel, text in sorted(files.items()) for f in analyze_file(rel, text)]


def limitations() -> list[str]:
    return [
        "Prototype pollution is decided inside one named function: a write whose key the "
        "function bound by iterating an object, by an iteration callback's parameter, by "
        "splitting a path, or by walking one level at a time into the object it then writes to — "
        "with no `__proto__` / `constructor` / `prototype` refusal, no null-prototype target and "
        "no `Map` anywhere in that function. A merge split across modules and a guard that lives "
        "in an imported helper are both outside it; the second silences the rule rather than "
        "firing it.",
    ]
