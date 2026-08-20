"""What the analyzers are allowed to see: comments and string contents blanked in place.

Offset-preserving by construction — every function here returns a string the same length as
its input, because a reported line number is only meaningful against the original file.
Shared by both language analyzers, which is why it is its own module.
"""
from __future__ import annotations

import os
import re
from functools import lru_cache

from ..langs import JSTS_EXTS, PY_EXTS

# --------------------------------------------------------------------------- JS/TS analysis

_JS_LINE_COMMENT = re.compile(r"//[^\n]*")
_JS_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def _js_strip_comments(text: str) -> str:
    """Blank comments out while preserving every character offset and line number, so a
    reported line still points at the right place in the original file."""
    def blank(m: re.Match) -> str:
        return "".join("\n" if c == "\n" else " " for c in m.group(0))
    return _JS_LINE_COMMENT.sub(blank, _JS_BLOCK_COMMENT.sub(blank, text))


@lru_cache(maxsize=8192)
def blank_strings(expr: str) -> str:
    """Blank the *contents* of string literals, preserving length, quotes and offsets.

    Cached because the callers ask the same question thousands of times: the JS analyzer scans
    every function body once per summary round and twice over for the cross-module pass, so one
    line is blanked repeatedly and the answer cannot differ — this is a pure function of its
    argument. It was 1.5 of the 5.0 seconds left on `lodash@4.17.21` after the line-split cache,
    on 111,398 calls. Bounded, because the cache exists to collapse repetition inside one
    analysis and not to hold a corpus: an entry is one source line.

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
_LEXICAL: dict[str, tuple[tuple[str, ...], str | None, tuple[str, str] | None, bool]] = {
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
    # HTML and the template languages that embed in it. **No quote characters**, deliberately:
    # in a document an attribute value is content, not a literal to blank, and blanking it would
    # hide the very thing the template rules read. The line-comment token is a NUL, which is to
    # say there is no line comment — a language without one has to name a token that cannot
    # occur, because an empty string starts every position.
    #
    # This closes a debt row rather than adding a feature: `SEC-TPL-FORM-NO-CSRF` reported a POST
    # form inside a multi-line `<!-- … -->` block as a live hole, and could not do otherwise,
    # because Python's `re` allows only a fixed-width lookbehind and a comment can open any
    # number of lines above. A lexer does not have that limit.
    #
    # `None` for the line comment, not a sentinel string: HTML has no line comment, and every
    # candidate sentinel is a lie the next reader has to check. An empty string would be worse
    # than a lie — it starts at every position, so it would blank the whole file.
    "html": ((), None, ("<!--", "-->"), False),
}
_EXT_GROUP = {
    **{ext: "py" for ext in PY_EXTS},
    # Derived, not listed: `.mts` and `.cts` were missing here while `structural/js.py` claimed
    # them and the generated language matrix published the claim, so `code_view` returned None
    # and every route analysis on those two file types returned nothing at all — silently.
    **{ext: "js" for ext in JSTS_EXTS},
    ".go": "go", ".java": "java", ".cs": "cs", ".php": "php", ".rb": "rb",
    ".rs": "rs",
    **{ext: "html" for ext in (".html", ".htm", ".jinja", ".jinja2", ".j2", ".twig", ".hbs",
                               ".mustache", ".ejs", ".erb")},
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
        if line_comment is not None and text.startswith(line_comment, i):
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

