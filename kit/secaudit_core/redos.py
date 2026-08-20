"""Catastrophic-backtracking (ReDoS) analysis of regular expressions.

`docs/what-we-miss.md` listed this class as out of reach: *"Detecting a catastrophic
backtracking pattern needs automaton analysis of the regex, not a match against it."* The first
half of that is right and the conclusion does not follow — the automaton is what you need to
decide the question **exactly**, and the shapes that actually blow up in production are decided
by the regex's *structure*, which is parseable with far less machinery.

Three structural criteria, all standard. The first two decide **exponential** blowup:

* **Star height above one.** A quantifier applied to a group that itself contains a quantifier
  over variable-length content — `(a+)+`, `((a)+)+`, `(\\w+\\s?)*`, `(.*)*`. The engine can
  split the same input between the inner and outer loop in exponentially many ways, and every
  one is tried before it reports no match.
* **Overlapping alternation under a quantifier.** `(a|a)+`, `(a|ab)*` — two branches that can
  match the same text, so each repetition is an independent binary choice.

and the third decides **quadratic** blowup, which is what most published ReDoS advisories
actually are:

* **Two unbounded repeats over overlapping characters, followed by something that can fail.**
  `^\\S+@\\S+$`, `\\d*[.]?\\d+`, `(.*)\\s*\\*\\/`. All three conditions are load-bearing and the
  last one is the one that is easy to leave out — see `_can_fail_after`, which is the difference
  between this criterion and one that reports half of every codebase.

Neither criterion needs to know what the regex means, and all are decided from the parse tree
this module builds. What it deliberately does NOT do is claim the converse: a regex this module
passes is not certified safe. The criteria are sound-ish in the direction that matters for a
security tool — they under-report — and `limitations()` says so.

The two degrees are reported at different severities and the finding says which it is, because
an exponential pattern is an outage on forty characters and a quadratic one is a bill that grows
with the subject. Measured cost of adding the quadratic criterion, on the corpus that exists to
answer exactly that: the noise floor moved from 0.21 to 0.24 findings per 1,000 lines.

The regex the analysis reads is often not written at the call. `PATTERN = r"((a)+)+"` at module
level and `re.search(PATTERN, user_input)` two hundred lines later is the ordinary shape, so
module-level string constants are resolved before the pattern is judged.

**Two front ends, one analysis.** The criteria above are properties of the regex, not of the
language it was written in, so `backtracking_reason` is shared and only the extraction differs.
Python needs a call site because a pattern is an ordinary string until `re.search` runs it.
JavaScript does not: `/((a)+)+/` is a regex at the point it is written. That difference is why
this module gained a language rather than a copy.

It also produced a divergence that took a benchmark to notice. Because a literal is already a
regex, the JavaScript front end reported *only* the line the literal is written on — while the
Python front end had always reported the line where the pattern is **run**, since that is the
only line it has. The sink of a ReDoS is where an untrusted string meets the pattern, and in
JavaScript that is routinely a hundred lines from the `const` that declares it. Both are reported
now; `_use_sites` explains the rule for deciding one.

*Recorded because the order matters:* the JavaScript front end was written after
SecBench.js scored this module **0 of 87** on its ReDoS class — but that zero was
[predicted in ROADMAP.md in writing before the run](../../ROADMAP.md), for the stated reason
that the module was Python-only, and not one labelled sink was read while building it.

The quadratic criterion and the use-site reporting came later still, and those two **were**
selected by reading the benchmark's labelled misses — the front end had taken 0 to 8 of 87 and
the remaining 79 were read one at a time to find out why. That is corpus-informed selection and
it is disclosed the same way every other corpus-informed round in this repository is. What was
read is which *shape* the advisories have; the criteria themselves are textbook, and the negative
cases in `kit/tests/test_redos.py` come from ordinary code rather than from the benchmark.
"""
from __future__ import annotations

import ast
import re
import warnings

from .langs import JS_EXTS, PY_EXTS, TS_EXTS
from .schema import Confidence, Finding, Severity, Verdict

# Keyed by the same language names `structural.LANGS` uses, because `gen_language_matrix.py`
# looks both dictionaries up by the name in its own row list. A key that reads well here but
# does not match there produces a matrix row that silently claims less than the engine does.
_JS_FRONTEND = {"frontend": "regex-literal lexer",
                "resolves": "literals, `new RegExp(\"…\")` string arguments, and the lines where "
                            "a pattern bound to a constant is run"}
REDOS_LANGS: dict[str, dict] = {
    "Python": {"exts": PY_EXTS, "frontend": "stdlib `ast` parse",
               "resolves": "module-level pattern constants"},
    "JavaScript": {"exts": JS_EXTS, **_JS_FRONTEND},
    "TypeScript": {"exts": TS_EXTS, **_JS_FRONTEND},
}
REDOS_EXTS: tuple[str, ...] = tuple(
    ext for spec in REDOS_LANGS.values() for ext in spec["exts"])

# `re` functions that run a pattern against a subject string.
_RE_FUNCTIONS = ("match", "search", "fullmatch", "findall", "finditer", "sub", "subn",
                 "split", "compile")

_QUANTIFIERS = "*+"


class _Node:
    """A parsed regex fragment: a group with children, or a leaf."""

    __slots__ = ("alternatives", "children", "literal", "min_zero", "quantified", "unbounded")

    def __init__(self) -> None:
        self.children: list[_Node] = []
        self.quantified = False      # a quantifier is applied to this node
        self.unbounded = False       # ...and it is `*`, `+` or `{n,}` rather than `{n,m}`
        # ...and it can match nothing at all: `?`, `*`, `{0,n}`. Tracked separately from
        # `unbounded` because the quadratic criterion needs both halves of a quantifier and they
        # are independent: `+` is unbounded and not optional, `?` is optional and not unbounded.
        self.min_zero = False
        self.alternatives: list[list[_Node]] = []
        self.literal = ""


def _parse(pattern: str) -> _Node:
    """A structural parse of `pattern` — groups, quantifiers and alternation only.

    Not a regex engine and not trying to be. Character classes are read as opaque leaves, which
    is enough: what the criteria need is where the groups are, which of them repeat, and
    whether a repeat is unbounded.
    """
    root = _Node()
    stack = [root]
    branch_starts = [0]
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            leaf = _Node()
            leaf.literal = pattern[i:i + 2]
            stack[-1].children.append(leaf)
            i += 2
            continue
        if ch == "[":                                   # character class — opaque leaf
            j = i + 1
            if j < n and pattern[j] == "^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            leaf = _Node()
            leaf.literal = pattern[i:j + 1]
            stack[-1].children.append(leaf)
            i = j + 1
            continue
        if ch == "(":
            group = _Node()
            stack[-1].children.append(group)
            stack.append(group)
            branch_starts.append(len(group.children))
            # Skip the group flags — `(?:`, `(?P<name>`, `(?=`, … — none change the structure.
            j = i + 1
            if pattern.startswith("(?", i):
                j = i + 2
                if j < n and pattern[j] == "P":
                    j += 1
                if j < n and pattern[j] == "<":
                    while j < n and pattern[j] != ">":
                        j += 1
                    j += 1
                elif j < n and pattern[j] in "=!:>":
                    j += 1
            i = j
            continue
        if ch == ")":
            if len(stack) > 1:
                group = stack.pop()
                branch_starts.pop()
                if group.alternatives:
                    group.alternatives.append(group.children)
                    group.children = [c for branch in group.alternatives for c in branch]
            i += 1
            continue
        if ch == "|":
            current = stack[-1]
            current.alternatives.append(current.children)
            current.children = []
            i += 1
            continue
        if ch in _QUANTIFIERS or ch == "?":
            target = stack[-1].children[-1] if stack[-1].children else None
            if target is not None and ch in _QUANTIFIERS:
                target.quantified = True
                target.unbounded = True
            if target is not None and ch in "*?":
                target.min_zero = True
            i += 1
            # A lazy or possessive marker does not remove the ambiguity that causes the blowup.
            if i < n and pattern[i] in "?+":
                i += 1
            continue
        if ch == "{":
            j = pattern.find("}", i)
            if j == -1:
                leaf = _Node()
                leaf.literal = ch
                stack[-1].children.append(leaf)
                i += 1
                continue
            spec = pattern[i + 1:j]
            target = stack[-1].children[-1] if stack[-1].children else None
            if target is not None:
                target.quantified = True
                # `{2,}` is unbounded; `{2,5}` bounds the work and is not the shape that blows up.
                target.unbounded = spec.endswith(",") or (
                    "," in spec and not spec.split(",")[1].strip())
                target.min_zero = spec.split(",")[0].strip() in ("", "0")
            i = j + 1
            continue
        leaf = _Node()
        leaf.literal = ch
        stack[-1].children.append(leaf)
        i += 1

    # Unbalanced `(` — close what is open so the caller still gets a tree.
    while len(stack) > 1:
        group = stack.pop()
        if group.alternatives:
            group.alternatives.append(group.children)
            group.children = [c for branch in group.alternatives for c in branch]
    if root.alternatives:
        root.alternatives.append(root.children)
        root.children = [c for branch in root.alternatives for c in branch]
    return root


def _has_unbounded_repeat(node: _Node) -> bool:
    """Whether anything inside this node repeats without a bound."""
    for child in node.children:
        if child.quantified and child.unbounded:
            return True
        if _has_unbounded_repeat(child):
            return True
    return False


def _branch_prefixes(branch: list[_Node]) -> str:
    """A crude signature of what a branch starts with, for the overlap test."""
    for node in branch:
        if node.literal:
            return node.literal
        if node.children:
            return _branch_prefixes(node.children)
    return ""


def _overlapping_alternation(node: _Node) -> bool:
    """Two branches of an alternation that can match the same text."""
    if len(node.alternatives) < 2:
        return False
    prefixes = [_branch_prefixes(b) for b in node.alternatives]
    seen: set[str] = set()
    for p in prefixes:
        if not p:
            continue
        if p in seen:
            return True
        # `a` and `ab` overlap: one is a prefix of the other.
        if any(p.startswith(q) or q.startswith(p) for q in seen):
            return True
        seen.add(p)
    return False


# ------------------------------------------------------------------ polynomial (quadratic)
#
# The two criteria above decide EXPONENTIAL blowup, and SecBench.js measured what that is worth
# on real reports: 8 of 87 labelled ReDoS advisories. Reading the other 79 says the published
# ones are overwhelmingly POLYNOMIAL — `\d*[.]?\d+`, `\S+@\S+`, `.*\s*`, `[+-]?\d*[.]?\d+` — where
# the engine has a quadratic number of ways to split one input between two repeats rather than an
# exponential one. Quadratic is a real denial of service (100k characters is 10^10 steps) and it
# is the shape most advisories describe, so it is worth detecting; it is also a weaker claim than
# exponential, and the finding says so.
#
# The criterion is deliberately narrower than "two repeats in a row". Two repeats are only
# ambiguous if the boundary between them can MOVE, which needs their character sets to overlap:
#
#     \d*[.]?\d+     ambiguous — both repeat digits, and `[.]?` between them can match nothing
#     \S+@\S+        ambiguous — `@` is itself an `\S`, so the split point can slide across it
#     \d+\.\d+       NOT — `\.` is mandatory and is not a digit, so the boundary is pinned
#     [a-z]+[0-9]*   NOT — disjoint sets, one boundary only
#
# The last two are the reason this is not simply "a quantifier followed by a quantifier": that
# describes most regular expressions ever written, and a rule that fires on `\d+\.\d+` is one
# that gets switched off in a day.
#
# Overlap is decided by running each single-character construct against a sample alphabet with
# the standard library, rather than by a hand-written table of what `\S` and `[^;]` mean. A table
# is where this kind of analysis rots: `\W` overlapping `\s` is not obvious, and nobody revisits
# the table when a class gains a case. Running the construct answers it exactly for the sample.

# One character per equivalence class this analysis needs to tell apart. Not the whole alphabet:
# two constructs that agree on every one of these agree on everything that matters here, and the
# cost is paid once per distinct construct.
_ALPHABET = "aZ09_-. \t\n;,@/\\%+=#[](){}&?*$^|\"':!~<>é"


def _charset(atom: str) -> frozenset[str]:
    """Which of `_ALPHABET` the single-character construct `atom` matches.

    Empty when the construct is not a Python regex — a JavaScript `\\p{L}` under the `u` flag,
    say. Empty means "no overlap with anything", so an unreadable construct silently
    under-reports rather than guessing, which is this module's stated direction.
    """
    cached = _CHARSET_CACHE.get(atom)
    if cached is not None:
        return cached
    try:
        # A scanner that prints `FutureWarning: Possible nested set` while reading somebody
        # else's `[[]` is reporting on itself. The construct is theirs, it is legal in
        # JavaScript, and what this call wants to know is which characters it matches.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            rx = re.compile(atom)
        out = frozenset(ch for ch in _ALPHABET if rx.fullmatch(ch))
    except re.error:
        out = frozenset()
    _CHARSET_CACHE[atom] = out
    return out


_CHARSET_CACHE: dict[str, frozenset[str]] = {}


def _atom_text(node: _Node) -> str | None:
    """The source of `node` when it is a single-character construct, else None.

    `a`, `\\s`, `[^;]` and `.` are single-character constructs. A group is not, even a group
    holding one — `(\\s)` repeats one character per iteration but its parse tree has a level in
    between, and `_repeat_class` unwraps that case explicitly rather than here.
    """
    if node.children or node.alternatives:
        return None
    return node.literal or None


def _repeat_class(node: _Node) -> frozenset[str]:
    """The characters `node` can consume repeatedly and without bound, if it can.

    Three shapes qualify, and the third is the one that matters in practice — a repeat wrapped in
    an optional group is how every "optional integer part" is written:

        \\d+          the leaf itself repeats
        (\\d)+        a group that repeats, holding one character
        (?:\\d+)?     an optional group holding a repeat: the group is skippable, the repeat is not
    """
    if node.quantified and node.unbounded:
        atom = _atom_text(node)
        if atom:
            return _charset(atom)
        if len(node.children) == 1 and not node.alternatives:
            inner = _atom_text(node.children[0])
            return _charset(inner) if inner else frozenset()
        return frozenset()
    # An unquantified or optional group wrapping exactly one unbounded repeat.
    if not node.quantified or node.min_zero:
        if len(node.children) == 1 and not node.alternatives:
            return _repeat_class(node.children[0])
    return frozenset()


def _skippable(node: _Node, both: frozenset[str]) -> bool:
    """Whether `node` can sit between two repeats without pinning the boundary between them.

    Either it can match nothing (`[.]?`), or everything it matches is also matched by both
    repeats — which is what makes `@` in `\\S+@\\S+` part of the ambiguity rather than a wall
    across it.
    """
    if node.min_zero:
        return True
    atom = _atom_text(node)
    if atom:
        chars = _charset(atom)
        return bool(chars) and chars <= both
    return False


def _flatten(children: list[_Node]) -> list[_Node]:
    """Splice plain grouping parentheses away: `(?:ab)c` is the sequence `a b c`.

    Only groups that neither repeat nor alternate are spliced. A quantified group is a repeat in
    its own right and an alternation is a choice, and folding either into its parent's sequence
    would claim an adjacency the regex does not have.
    """
    out: list[_Node] = []
    for child in children:
        if child.children and not child.quantified and not child.alternatives:
            out.extend(_flatten(child.children))
        else:
            out.append(child)
    return out


def _universal(chars: frozenset[str]) -> bool:
    """Whether this class matches essentially everything — `.`, `[\\s\\S]`, `[^]`."""
    return len(chars) >= len(set(_ALPHABET)) - 1


def _can_fail_after(rest: list[_Node], right: frozenset[str]) -> bool:
    """Whether anything after the second repeat can refuse a split it is offered.

    **This is the condition that separates an ambiguous pattern from an expensive one, and
    leaving it out is what made the first version of this criterion report 28 regexes in this
    repository's own source.** Ambiguity alone costs nothing: `^(#{1,6})\\s+(.*)$` can divide its
    whitespace between `\\s+` and `.*` in as many ways as there are spaces, and it never does,
    because the first division it tries succeeds and nothing afterwards can reject it. A regex
    engine only walks the other divisions when something downstream says no.

    So the pattern needs something after the pair that can say no:

    * a mandatory element — a literal, a class, a group that must match something. `\\*\\/` after
      `(.*)\\s*` is why the sourceMappingURL scan is quadratic.
    * an end anchor, but only when the second repeat cannot reach the end by itself. `\\S+$` can
      fail (a subject ending in a space), so `^\\S+@\\S+$` is quadratic; `.*$` cannot, so
      `\\s+(.*)$` is not.
    """
    for node in rest:
        anchor = not node.children and node.literal in ("$", "\\Z", "\\z")
        if anchor:
            if not _universal(right):
                return True
            continue
        if not node.min_zero:
            return True
    return False


def _quadratic_pair(children: list[_Node],
                    following: list[_Node]) -> frozenset[str] | None:
    """The first pair of overlapping unbounded repeats in this sequence, if there is one."""
    seq = _flatten(children)
    for i, first in enumerate(seq):
        left = _repeat_class(first)
        if not left:
            continue
        for j in range(i + 1, len(seq)):
            right = _repeat_class(seq[j])
            both = left & right
            if right and both:
                if all(_skippable(seq[k], both) for k in range(i + 1, j)) \
                        and _can_fail_after(seq[j + 1:] + following, right):
                    return both
                break
            # Anything that is not itself a repeat has to be skippable for a later repeat to
            # still be adjacent to this one. `\d+ x \s*` is two repeats with a wall between.
            if not _skippable(seq[j], left):
                break
    return None


def _quadratic_reason(tree: _Node) -> str | None:
    """Why this pattern has a quadratic number of ways to match, or None.

    `following` is what comes after the sequence being examined, in the enclosing pattern. It has
    to be carried down: the ambiguity is usually written inside a capture group and the element
    that rejects a split is outside it — `^((?:\\d+)?\\.?\\d+) *(ms|s)?$` is the whole `ms`
    advisory, and the `$` that makes it expensive is two levels up from the pair that is.
    """
    def walk(seq: list[_Node], following: list[_Node]) -> str | None:
        flat = _flatten(seq)
        shared = _quadratic_pair(flat, following)
        if shared:
            sample = "".join(sorted(c for c in shared if c.isprintable() and c != " "))[:6]
            return ("two unbounded repeats over overlapping characters"
                    + (f" ({sample!r} matches both)" if sample else "")
                    + " — the engine can split one input between them in a quadratic number of "
                      "ways, and tries all of them before reporting no match")
        for i, child in enumerate(flat):
            if not child.children and not child.alternatives:
                continue
            rest = flat[i + 1:] + following
            for branch in (child.alternatives or [child.children]):
                found = walk(branch, rest)
                if found:
                    return found
        return None

    for top in (tree.alternatives or [tree.children]):
        reason = walk(top, [])
        if reason:
            return reason
    return None


def backtracking_reason(pattern: str) -> tuple[str, str] | None:
    """`(degree, why)` for `pattern`, or None if this analysis sees no reason.

    `degree` is `exponential` or `quadratic`, and the difference is the whole point of reporting
    them separately: an exponential pattern is unusable on a few dozen adversarial characters and
    a quadratic one needs a large input to hurt. They are the same defect class and they are not
    the same urgency, so the finding's severity is decided from this rather than from a constant.

    Exponential is tested first. A pattern that is both is the more serious of the two, and
    saying "quadratic" about `(a+)+` would understate it.

    Renamed from `catastrophic_reason` when the quadratic criterion landed: "catastrophic
    backtracking" means the exponential case in every textbook that uses the phrase, and a
    function that had quietly started answering a wider question under the old name would have
    been read as the narrow one by everything already calling it.
    """
    try:
        tree = _parse(pattern)
    except (IndexError, RecursionError):
        return None

    def walk(node: _Node, depth: int) -> str | None:
        for child in node.children:
            if child.quantified and child.unbounded:
                if _has_unbounded_repeat(child):
                    return ("a quantified group whose body also repeats without a bound "
                            "(star height 2) — the engine can split one input between the two "
                            "loops in exponentially many ways")
                if _overlapping_alternation(child):
                    return ("a repeated group whose alternatives can match the same text, so "
                            "every repetition is an independent choice to backtrack through")
            found = walk(child, depth + 1)
            if found:
                return found
        return None

    exponential = walk(tree, 0)
    if exponential:
        return "exponential", exponential
    quadratic = _quadratic_reason(tree)
    return ("quadratic", quadratic) if quadratic else None


# --------------------------------------------------------------------------- Python analysis

def _module_constants(tree: ast.Module) -> dict[str, str]:
    """Module-level `NAME = "pattern"` bindings, which is where patterns usually live."""
    out: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out[target.id] = node.value.value
    return out


def _pattern_of(node: ast.AST, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _finding(detector_id: str, rel: str, line: int, pattern: str, degree: str, reason: str,
             lines: list[str]) -> Finding:
    """The one finding shape, built the same way from either front end.

    Severity follows the degree, because the two are not the same emergency. Exponential is High:
    a few dozen characters hang the process, so any reachable path to it is a live outage.
    Quadratic is Medium: it needs a large subject to hurt, which makes it a real denial of service
    where the input is unbounded and a performance note where it is not — a distinction the
    finding states rather than resolves, since only the caller knows which one it is.

    **Confidence stays MEDIUM and does not gain a third value for this.** `Confidence.HIGH` means
    an unambiguous sink and MEDIUM means a lead that wants triage, which is exactly what a
    quadratic pattern is: this module reads regular expressions, not the strings they are run
    against, and quadratic cost is only a vulnerability when the subject is attacker-supplied and
    unbounded — a claim about the caller that nothing here has checked. Adding a LOW rung to say
    that would be describing the same fact twice, since the severity already carries it.
    Dogfooding says it from the other end: this repository's own source holds twenty of these,
    every one a correct reading of the regex and none of them an incident.
    """
    quadratic = degree == "quadratic"
    return Finding(
        detector_id=detector_id,
        title=("Regular expression backtracks quadratically on unmatching input (ReDoS)"
               if quadratic else
               "Regular expression vulnerable to catastrophic backtracking (ReDoS)"),
        severity=Severity.MEDIUM if quadratic else Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe="CWE-1333", owasp="A06",
        file=rel, line=line,
        evidence=lines[line - 1].strip()[:200] if line <= len(lines) else "",
        fix=f"`{pattern[:60]}` contains {reason}. Rewrite it so the repetition is "
            f"unambiguous (bound the inner quantifier, make the branches disjoint, or "
            f"anchor the match), or run it under a timeout with a length-capped subject."
            + (" Quadratic means the cost grows with the square of the subject's length: "
               "harmless on a short field, an outage on an unbounded one." if quadratic else ""),
        source="redos", verdict=Verdict.UNVERIFIED)


def _analyze_python(rel: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []

    constants = _module_constants(tree)
    lines = text.splitlines()
    # One finding per call site, but never two for the same line: `re.compile` on the line a
    # pattern constant is defined and the call that uses it are the same defect twice.
    seen: set[int] = set()
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted(node.func)
        head, _, tail = dotted.rpartition(".")
        if tail not in _RE_FUNCTIONS or head.rsplit(".", 1)[-1] not in ("re", "regex"):
            continue
        if not node.args:
            continue
        pattern = _pattern_of(node.args[0], constants)
        if pattern is None:
            continue
        verdict = backtracking_reason(pattern)
        if verdict is None or node.lineno in seen:
            continue
        seen.add(node.lineno)
        findings.append(_finding("REDOS-PY", rel, node.lineno, pattern, *verdict, lines))
    return findings


# ----------------------------------------------------------------- JavaScript / TypeScript
#
# There is no JS parser here and there will not be one — the kit has no runtime dependencies.
# What a regex literal needs is less than a parser anyway: somewhere to start, and the one
# genuinely ambiguous character in the language.
#
# `/` is that character. `a / b` divides and `a.replace(/b/, '')` does not, and the two are told
# apart by what came *before* the slash — an operand means division, an operator or a keyword
# means a regex may begin. This is the standard lexer heuristic and it is not exact: after `}`
# the answer depends on whether the brace closed a block or an object literal, and this reads it
# as a block. That choice is deliberate and it errs toward *reading* a regex, because the
# alternative silently drops one.

# After one of these, a `/` starts a regex rather than dividing.
_REGEX_AFTER_CHARS = frozenset("(,=:[!&|?{};+-*%^~<>")
_REGEX_AFTER_WORDS = frozenset({
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
    "case", "do", "else", "yield", "await",
})

# `new RegExp("…")` / `RegExp('…')`. The pattern lives in a *string*, so it arrives with one
# more layer of escaping than a literal does and `_unescape_js_string` takes that layer off.
_REGEXP_CTOR = re.compile(r"\bRegExp\s*\(\s*(['\"])((?:\\.|(?!\1)[^\\\n])*)\1")

# In a JavaScript string literal, `\d` is just `d` — the escape is consumed by the string, which
# is why a pattern written for `new RegExp` carries doubled backslashes. Only the sequences that
# stand for another character are translated; everything else loses its backslash, which is what
# the language does.
_JS_STRING_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v",
                      "0": "\0", "\\": "\\", "'": "'", '"': '"', "`": "`"}


def _unescape_js_string(raw: str) -> str:
    out: list[str] = []
    i, n = 0, len(raw)
    while i < n:
        if raw[i] == "\\" and i + 1 < n:
            nxt = raw[i + 1]
            out.append(_JS_STRING_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        out.append(raw[i])
        i += 1
    return "".join(out)


def _read_js_regex(text: str, start: int) -> tuple[str, int] | None:
    """The body of the regex literal opening at `start`, and the index past its flags."""
    i, n = start + 1, len(text)
    body: list[str] = []
    in_class = False
    while i < n:
        ch = text[i]
        if ch == "\\":
            body.append(text[i:i + 2])
            i += 2
            continue
        if ch == "\n":
            return None          # a regex literal cannot span a line — this was division
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "/" and not in_class:
            i += 1
            while i < n and text[i].isalpha():
                i += 1           # flags
            return "".join(body), i
        body.append(ch)
        i += 1
    return None


def _js_patterns(text: str) -> list[tuple[int, str, str]]:
    """Every regex this file writes down, as (line, pattern, name), in source order.

    `name` is the identifier the pattern was assigned to (`const TOKEN_RE = /…/`) and empty for a
    literal written where it is used. It exists because the *sink* of a ReDoS is the line where
    an untrusted string is matched, not the line where the pattern was declared — see
    `_use_sites`.
    """
    out: list[tuple[int, str, str]] = []
    i, n, line = 0, len(text), 1
    prev_char = ""     # last significant character
    prev_word = ""     # ...and it, when that character ended an identifier or keyword
    last_word = ""     # the most recent identifier, surviving the punctuation after it
    assign_to = ""     # ...captured when an `=` follows it, so `X = /…/` binds the pattern to X
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch in " \t\r":
            i += 1
            continue
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            line += text.count("\n", i, end)
            i = end
            continue
        if ch in "'\"`":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == ch:
                    j += 1
                    break
                if text[j] == "\n" and ch != "`":
                    break        # unterminated: do not swallow the rest of the file
                j += 1
            line += text.count("\n", i, min(j, n))
            i = j
            prev_char, prev_word = ch, ""
            continue
        if ch == "/":
            allowed = prev_word in _REGEX_AFTER_WORDS if prev_word else (
                prev_char == "" or prev_char in _REGEX_AFTER_CHARS)
            if allowed:
                got = _read_js_regex(text, i)
                if got is not None:
                    body, end = got
                    if body:
                        out.append((line, body, assign_to if prev_char == "=" else ""))
                    i = end
                    prev_char, prev_word = "/", ""
                    continue
            i += 1
            prev_char, prev_word = "/", ""
            continue
        if ch.isalnum() or ch in "_$":
            j = i
            while j < n and (text[j].isalnum() or text[j] in "_$"):
                j += 1
            prev_word = text[i:j]
            prev_char = prev_word[-1]
            last_word = prev_word
            i = j
            continue
        # A single `=` after an identifier binds what follows to it. `==`, `===`, `=>`, `!=` and
        # the compound assignments are not that, and treating `x === /re/` as a binding would
        # attach the pattern to a name nothing declared.
        if ch == "=" and prev_char not in "=!<>+-*/%&|^" and text[i + 1:i + 2] not in ("=", ">"):
            assign_to = last_word
        prev_char, prev_word = ch, ""
        i += 1

    for m in _REGEXP_CTOR.finditer(text):
        pattern = _unescape_js_string(m.group(2))
        if pattern:
            head = text.rfind("\n", 0, m.start()) + 1
            named = _CTOR_ASSIGN.search(text[head:m.start()])
            out.append((text.count("\n", 0, m.start()) + 1, pattern,
                        named.group(1) if named else ""))
    return out


# `RGX = new RegExp(…)` — the name, read from what precedes the constructor on its own line.
_CTOR_ASSIGN = re.compile(r"([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+)?$")

# How a pattern gets applied to a subject. The identifier may own the call (`RE.test(s)`) or be
# handed to a string method (`s.replace(RE, '')`); both are the line where the match runs.
_APPLY_OWN = "test|exec"
_APPLY_ARG = "match|matchAll|replace|replaceAll|split|search"


def _use_sites(text: str, name: str) -> list[int]:
    """The lines where the regex bound to `name` is actually run against a subject.

    **The sink of a ReDoS is where the untrusted string meets the pattern, not where the pattern
    was written**, and in JavaScript those are routinely hundreds of lines apart — a
    `const TOKEN_RE = /…/` at the top of the module and `TOKEN_RE.exec(input)` inside the handler.
    The Python front end has always reported the call site, because in Python a pattern is an
    ordinary string until `re.search` runs it and there is nothing else to report; the JavaScript
    front end reported the literal, because a literal is already a regex. Same analysis, two
    different answers to "where is the defect", and the reason was an implementation detail
    rather than anything about the languages.

    Both are reported now. The declaration is where the fix goes and the call is where the
    exposure is, and a reader given only one of them has to find the other.
    """
    if not name:
        return []
    ident = re.escape(name)
    lines: set[int] = set()
    for pattern in (rf"\b{ident}\s*\.\s*(?:{_APPLY_OWN})\s*\(",
                    rf"\.\s*(?:{_APPLY_ARG})\s*\(\s*{ident}\b"):
        for m in re.finditer(pattern, text):
            lines.add(text.count("\n", 0, m.start()) + 1)
    return sorted(lines)


def _analyze_js(rel: str, text: str) -> list[Finding]:
    lines = text.splitlines()
    seen: set[int] = set()
    findings: list[Finding] = []
    for line, pattern, name in _js_patterns(text):
        verdict = backtracking_reason(pattern)
        if verdict is None:
            continue
        for where in [line, *_use_sites(text, name)]:
            if where in seen:
                continue
            seen.add(where)
            findings.append(_finding("REDOS-JS", rel, where, pattern, *verdict, lines))
    return sorted(findings, key=lambda f: f.line)


def analyze_file(rel: str, text: str) -> list[Finding]:
    lowered = rel.lower()
    if lowered.endswith(PY_EXTS):
        return _analyze_python(rel, text)
    if lowered.endswith(JS_EXTS + TS_EXTS):
        return _analyze_js(rel, text)
    return []


def analyze_files(files: dict[str, str]) -> list[Finding]:
    return [f for rel, text in sorted(files.items()) for f in analyze_file(rel, text)]


def limitations() -> list[str]:
    langs = ", ".join(sorted(REDOS_LANGS))
    return [
        f"ReDoS analysis ({langs} only) decides backtracking cost from the regex's structure — "
        f"star height above one and repeated groups with overlapping alternatives for the "
        f"exponential case, and two unbounded repeats over overlapping characters followed by "
        f"something that can fail for the quadratic one. "
        f"In Python it reads patterns written at the call site or bound to a module-level "
        f"constant; in JavaScript and TypeScript it reads regex literals and the string argument "
        f"to `new RegExp`. A pattern built at runtime or loaded from configuration is not "
        f"analysed in either.",
        "A quadratic finding is a claim about the regular expression and not about the subject "
        "it runs on. It costs quadratic time on input that fails to match, so it is a denial of "
        "service where that input is attacker-supplied and unbounded and a performance note "
        "where it is neither. Nothing in this analysis knows which one the caller has.",
        "A regex this analysis does not report is not certified safe: the criteria are chosen "
        "to under-report rather than to be complete, and an exact answer needs the automaton.",
    ]
