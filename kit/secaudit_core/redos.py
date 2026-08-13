"""Catastrophic-backtracking (ReDoS) analysis of regular expressions.

`docs/what-we-miss.md` listed this class as out of reach: *"Detecting a catastrophic
backtracking pattern needs automaton analysis of the regex, not a match against it."* The first
half of that is right and the conclusion does not follow — the automaton is what you need to
decide the question **exactly**, and the shapes that actually blow up in production are decided
by the regex's *structure*, which is parseable with far less machinery.

Two structural criteria, both standard:

* **Star height above one.** A quantifier applied to a group that itself contains a quantifier
  over variable-length content — `(a+)+`, `((a)+)+`, `(\\w+\\s?)*`, `(.*)*`. The engine can
  split the same input between the inner and outer loop in exponentially many ways, and every
  one is tried before it reports no match.
* **Overlapping alternation under a quantifier.** `(a|a)+`, `(a|ab)*` — two branches that can
  match the same text, so each repetition is an independent binary choice.

Neither criterion needs to know what the regex means, and both are decided from the parse tree
this module builds. What it deliberately does NOT do is claim the converse: a regex this module
passes is not certified safe. The criteria are sound-ish in the direction that matters for a
security tool — they under-report — and `limitations()` says so.

The regex the analysis reads is often not written at the call. `PATTERN = r"((a)+)+"` at module
level and `re.search(PATTERN, user_input)` two hundred lines later is the ordinary shape, so
module-level string constants are resolved before the pattern is judged.
"""
from __future__ import annotations

import ast

from .schema import Confidence, Finding, Severity, Verdict

REDOS_LANGS: dict[str, dict] = {
    "Python": {"exts": (".py",), "frontend": "stdlib `ast` parse",
               "resolves": "module-level pattern constants"},
}
REDOS_EXTS: tuple[str, ...] = tuple(
    ext for spec in REDOS_LANGS.values() for ext in spec["exts"])

# `re` functions that run a pattern against a subject string.
_RE_FUNCTIONS = ("match", "search", "fullmatch", "findall", "finditer", "sub", "subn",
                 "split", "compile")

_QUANTIFIERS = "*+"


class _Node:
    """A parsed regex fragment: a group with children, or a leaf."""

    __slots__ = ("alternatives", "children", "literal", "quantified", "unbounded")

    def __init__(self) -> None:
        self.children: list[_Node] = []
        self.quantified = False      # a quantifier is applied to this node
        self.unbounded = False       # ...and it is `*`, `+` or `{n,}` rather than `{n,m}`
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


def catastrophic_reason(pattern: str) -> str | None:
    """Why `pattern` can backtrack catastrophically, or None if this analysis sees no reason."""
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

    return walk(tree, 0)


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


def analyze_file(rel: str, text: str) -> list[Finding]:
    if not rel.lower().endswith(REDOS_EXTS):
        return []
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
        reason = catastrophic_reason(pattern)
        if reason is None or node.lineno in seen:
            continue
        seen.add(node.lineno)
        findings.append(Finding(
            detector_id="REDOS-PY",
            title="Regular expression vulnerable to catastrophic backtracking (ReDoS)",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            cwe="CWE-1333", owasp="A06",
            file=rel, line=node.lineno,
            evidence=lines[node.lineno - 1].strip()[:200] if node.lineno <= len(lines) else "",
            fix=f"`{pattern[:60]}` contains {reason}. Rewrite it so the repetition is "
                f"unambiguous (bound the inner quantifier, make the branches disjoint, or "
                f"anchor the match), or run it under a timeout with a length-capped subject.",
            source="redos", verdict=Verdict.UNVERIFIED))
    return findings


def analyze_files(files: dict[str, str]) -> list[Finding]:
    return [f for rel, text in sorted(files.items()) for f in analyze_file(rel, text)]


def limitations() -> list[str]:
    langs = ", ".join(sorted(REDOS_LANGS))
    return [
        f"ReDoS analysis ({langs} only) decides catastrophic backtracking from the regex's "
        f"structure — star height above one, and repeated groups with overlapping alternatives. "
        f"It reads patterns written at the call site or bound to a module-level constant; a "
        f"pattern built at runtime or loaded from configuration is not analysed.",
        "A regex this analysis does not report is not certified safe: the criteria are chosen "
        "to under-report rather than to be complete, and an exact answer needs the automaton.",
    ]
