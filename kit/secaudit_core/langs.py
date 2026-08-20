"""One answer to "what kind of file is this", for every tier that has to ask.

Two questions live here, and both were previously answered once per consumer: which extensions
are a given language, and whether a file is this application's source at all.

Four places asked it independently and gave three different answers, which is the shape of bug
this repository keeps finding in itself: a fact that decays in one direction, typed once per
consumer instead of derived once for all of them.

    detectors.py      (".js", ".ts")                                    — 31 rules
    taint/lexical.py  .js .jsx .mjs .cjs .ts .tsx                       — the code view
    taint/__init__.py .js .jsx .mjs .cjs / .ts .tsx                     — the depth table
    structural/js.py  .js .jsx .mjs .cjs / .ts .tsx .mts .cts           — the route analyses

Two live defects came out of that disagreement, both proven before this module was written:

* **A React or Next.js codebase got zero pattern detectors.** The same file, byte for byte,
  produced `SEC-JS-MD5` as `vuln.ts` and nothing at all as `vuln.tsx` — and with it went every
  other `SEC-JS-*` rule and the JS half of the secret pack. `.jsx`, `.tsx`, `.mjs`, `.cjs`,
  `.mts` and `.cts` were named by the taint tier and by the structural tier, so the *other* two
  tiers reported on files this one silently skipped.
* **`.mts` and `.cts` were advertised and unreachable.** `structural/js.py` claims them, the
  language-coverage matrix is generated from that claim — and `code_view` had no lexical group
  for either, so `analyze_file` took the `view is None` path and returned no findings for a file
  type the documentation says is analysed. A published coverage claim the code could not honour.

A family here is a set of extensions that are *the same language to a rule*. `.tsx` is
TypeScript with JSX syntax; a rule about `createHash('md5')` does not become wrong because the
file also contains markup. That is the whole justification for the grouping, and it is also why
`check_consistency.py` gates it as all-or-nothing: naming one member of a family and not the
rest is never a decision, it is always an omission.
"""
from __future__ import annotations

import re

# Node's ESM/CJS variants (`.mjs`, `.cjs`) are the same language with a module system pinned by
# the extension; TypeScript's (`.mts`, `.cts`) are the same again. Nothing that distinguishes
# them is visible to a security rule.
JS_EXTS: tuple[str, ...] = (".js", ".jsx", ".mjs", ".cjs")
TS_EXTS: tuple[str, ...] = (".ts", ".tsx", ".mts", ".cts")

# The union, for the tiers that treat the two as one language — which is all of them: the
# lexical model, the pattern pack and the structural analyses have no TypeScript-specific rule.
JSTS_EXTS: tuple[str, ...] = JS_EXTS + TS_EXTS

PY_EXTS: tuple[str, ...] = (".py",)

# PHP, and the one other extension that is the same language: `.phtml` is a PHP file that opens
# in HTML mode, which is a *template* convention and not a different parser. Added when the noise
# floor grew a PHP half and this module was asked, for the first time, what a PHP file is —
# before that the three PHP detectors each spelled `(".php",)` inline, which is the same
# typed-once-per-consumer shape this module's docstring is about.
PHP_EXTS: tuple[str, ...] = (".php", ".phtml")

# Server-rendered template families. These carry executable output logic — `{{ x|safe }}`,
# `{% autoescape off %}` — and are the half of the XSS surface that lives outside the handler.
DJANGO_TEMPLATE_EXTS: tuple[str, ...] = (".html", ".htm")
JINJA_TEMPLATE_EXTS: tuple[str, ...] = (".jinja", ".jinja2", ".j2")
TEMPLATE_EXTS: tuple[str, ...] = DJANGO_TEMPLATE_EXTS + JINJA_TEMPLATE_EXTS

# Every family a detector may name, keyed by the name the gate reports. A detector that names
# one member of a family must name all of them; `check_consistency.py` reads this map to say so.
FAMILIES: dict[str, tuple[str, ...]] = {
    "JavaScript": JS_EXTS,
    "TypeScript": TS_EXTS,
    "PHP": PHP_EXTS,
    "Django template": DJANGO_TEMPLATE_EXTS,
    "Jinja template": JINJA_TEMPLATE_EXTS,
}


# --------------------------------------------------------------------------- provenance
#
# A vendored JavaScript bundle is not this application's source, and every finding reported in
# one is addressed to the wrong person. Measured on the external benchmark before this predicate
# was written: **117 of 525 false positives came from vendored bundles, against a single true
# positive** — and that one was a labelled flaw *inside minified jQuery 3.2.1, at column forty
# thousand of one line*. Losing it is the correct behaviour, not a regression: nobody patches
# jQuery's internals in their own `static/` directory, they upgrade the dependency, which is the
# dependency tier's job and not this one's.
#
# `node_modules/` was already skipped wholesale by the walker. That covers the JavaScript
# convention and none of the others: a Django or Flask project vendors its front end by copying
# `jquery.min.js` into `static/`, which no directory rule sees. `SEC-JS-RANDOM` (33 FP),
# `SEC-JS-PROTO` (30) and `SEC-JS-EVAL` (10) were scoring *zero* true positives on this corpus
# and were, essentially in their entirety, reports about jQuery and Bootstrap.
#
# Deliberately NOT a list of library names. `jquery`, `bootstrap`, `lodash` is a list that is
# wrong the moment a project vendors the next thing; these four signals are properties of the
# artifact. Deliberately NOT applied to Python either: `/lib/` is ordinary application structure
# in a Python project, and an early version that treated it as a vendor directory cost real
# findings in application code (three rate-limit, one SQL injection, one pickle) — measured, and
# that is why the predicate is scoped to the JS/TS families.
#
# It is also, for free, the fix for a performance trap this repository has already hit: the
# exponential traversal that hung a scan outright did so on `materialize.js`, a vendored bundle.
# The traversal bug was fixed on its own terms; this stops handing it the input.

_MINIFIED_NAME = re.compile(r"(?:\.min\.|-min\.|\.bundle\.)(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$",
                            re.IGNORECASE)

# The conventional names for "code that came from somewhere else". `/lib/` and `/libs/` are
# excluded on purpose — see above.
_VENDOR_DIRS = ("/vendor/", "/vendors/", "/third_party/", "/third-party/", "/bower_components/",
                "/node_modules/")

# A line this long in a JS file is not something a person typed. 500 is comfortably above any
# formatter's limit (Prettier defaults to 80, the loosest house styles reach 120) and far below
# a minifier's output, which puts an entire library on one line.
_MINIFIED_LINE = 500

# How far in to look. A banner is at the top by definition, and a bundle's first long line
# arrives immediately; reading the whole of a megabyte file to answer this would cost more than
# the scan it is saving.
_PROVENANCE_SCAN_LINES = 400

# A UMD/AMD preamble, or a licence banner written the way a release writes one. Nothing else
# produces either: a UMD wrapper exists so one file can be loaded by a script tag, a CommonJS
# `require` and an AMD loader at once, which is a question only a *distributed library* has to
# answer, and `@license`/`@preserve` are the pragmas build tools keep precisely because the file
# is somebody else's.
#
# Added as the fifth signal because the four above miss the shape the external corpus actually
# contains — `static/js/foundation/foundation.js`, an unminified third-party library checked into
# a Django app's static directory, neither minified nor under a directory named `vendor`. It was
# the single false positive the prototype-pollution round added across 62 repositories. The
# accounting rule from the previous version of this filter still applies and is why the reach of
# this one is measured rather than argued: that version removed 143 false positives for one true
# positive.
_RELEASE_PREAMBLE = (
    "typeof define === 'function' && define.amd",
    'typeof define === "function" && define.amd',
    "typeof exports === 'object' && typeof module",
    'typeof exports === "object" && typeof module',
    "(function (root, factory)",
    "(function(root, factory)",
    "(function (global, factory)",
    "(function(global, factory)",
    "@license",
    "@preserve",
)

# How far in a release preamble can be. Both live in the opening lines by construction — a UMD
# wrapper is the first statement and a licence banner is above it — so this is deliberately much
# shorter than the minified-line scan, which has to reach a bundle's first packed line.
_PREAMBLE_SCAN_LINES = 40


def has_release_preamble(text: str) -> bool:
    """Signals 3 and 5 alone: does this file announce itself as somebody's distributed release?

    Split out of `is_vendored_asset` so a *directory* can be asked the same question about its
    contents — see `engine._is_vendor_drop`. Deliberately excludes the other three signals: a
    minified filename and a `node_modules/` path are facts about one file, and neither says
    anything about the file beside it.
    """
    if text.lstrip()[:3] == "/*!":
        return True
    head = text.split("\n", _PREAMBLE_SCAN_LINES)[:_PREAMBLE_SCAN_LINES]
    return any(marker in line for line in head for marker in _RELEASE_PREAMBLE)


def is_vendored_asset(rel: str, text: str, own_release: bool = False,
                      vendor_drop: bool = False) -> bool:
    """True when this JS/TS file is a third-party artifact rather than application source.

    `own_release` says the scanned project's own manifest publishes this file — see
    `engine._is_own_release`. It turns off signals 3 and 5, and only those, because those two ask
    *"is this a distributed release?"* while the question that matters is *"is this somebody
    ELSE's code, relative to what I was asked to audit?"* Those are the same question for an
    application with a library copied into it, and opposite questions when the thing under audit
    IS a library: a package's own `index.js` opens with `/*!` and a licence line precisely
    because it is a release — its own.

    Measured, because this was published for two rounds before it was found: on SecBench.js,
    where every entry is an npm package, **59 of 516 resolvable labelled sink files were never
    read**, concentrated in the two classes with the worst recall — 19% of prototype-pollution
    and 27% of ReDoS. A rule cannot miss what a scanner never opens, and the recall those two
    classes published was partly a scoping decision reported as a detection failure.

    Signals 1, 2 and 4 keep applying either way: a minified file is unreadable whoever wrote it,
    and a copy under `node_modules/` is somebody else's however the root manifest is worded.

    Five signals, any one of which is sufficient:

    1. **A minifier's filename** — `.min.js`, `-min.js`, `.bundle.js`.
    2. **A vendor directory** — the conventional homes for copied-in dependencies.
    3. **A `/*!` banner** — the preserved-comment marker. Build tools keep `/*!` and strip `/*`
       precisely because it carries a distributed artifact's licence, so a file that opens with
       one is announcing that it is somebody else's release.
    4. **A line no human wrote** — minified output with an ordinary filename, which is how
       `loader.js` and friends arrive.
    5. **A release preamble** — a UMD/AMD module-system negotiation, or an `@license` /
       `@preserve` pragma. A file that negotiates how it will be loaded, or that carries the
       pragma a minifier is told to keep, is a library release whatever directory it sits in.
    6. **A sibling that is one** (`vendor_drop`) — a library does not arrive as one file. The
       five signals above decide per file, and on `static/js/foundation/` that produced the
       wrong answer fourteen times: two files there carry a `/*!` banner (jQuery Cookie and a
       placeholder shim, neither of them Foundation itself) and the other twelve carry nothing,
       so a copied-in library drop was read as twelve files of application source. Measured when
       `SEC-JS-HTML-CONCAT` landed: **20 of its 22 RealVuln findings were those twelve files.**
       `engine._is_vendor_drop` asks the directory instead, and the answer generalises without a
       list of library names — which is the property the whole predicate is built on.

       Bounded twice, because a silencing signal that spreads is the dangerous kind. It needs
       **two** bannered files in one directory, not one, and it never applies to a file the
       scanned project's own manifest publishes. Measured across four trees: 17 files newly
       silenced in 62 RealVuln repositories, 5 in phpMyAdmin, and **zero** in `axios` and
       `date-fns` — 1,878 files of modern application source, none of it touched.
    """
    lowered = "/" + rel.replace("\\", "/").lstrip("/").lower()
    if not lowered.endswith(JSTS_EXTS):
        return False
    if _MINIFIED_NAME.search(lowered) or any(v in lowered for v in _VENDOR_DIRS):
        return True
    # Signal 6: a library does not arrive as one file. See `engine._is_vendor_drop` for how the
    # directory is decided, and the docstring above for what it cost and saved.
    if vendor_drop and not own_release:
        return True
    if not own_release and text.lstrip()[:3] == "/*!":
        return True
    head = text.split("\n", _PROVENANCE_SCAN_LINES)[:_PROVENANCE_SCAN_LINES]
    if any(len(line) > _MINIFIED_LINE for line in head):
        return True
    if own_release:
        return False
    return any(marker in line
               for line in head[:_PREAMBLE_SCAN_LINES] for marker in _RELEASE_PREAMBLE)
