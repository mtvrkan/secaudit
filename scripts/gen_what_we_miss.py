#!/usr/bin/env python3
"""Generate `docs/what-we-miss.md` — the false negatives, read out of the tool itself.

    python3 scripts/gen_what_we_miss.py           # write it
    python3 scripts/gen_what_we_miss.py --check   # fail if the committed file is stale (CI)

Every security scanner has a page like this in the heads of the people who built it and in no
repository anywhere. The reason is not dishonesty, it is decay: a hand-written limitations page
is accurate for one release and then silently becomes an understatement, which is the worst
direction for this particular document to drift in.

So it is generated. The measured misses come from the committed scorecard, the analysis bounds
from `taint.limitations()` (the same list every report prints), the language gaps from the same
dispatch tables the coverage matrix reads, and the class gaps from checking the engine's own
CWE set against a vocabulary of classes worth naming. Improve the engine and lines disappear
from this page on the next build; let it rot and the lines stay, in CI, in front of everyone.

The typed part is the **vocabulary** — which vulnerability classes are worth listing as absent.
Naming a class we do not detect can only cost us, so a wrong entry there errs against us. That
sentence used to be an overstatement: eight measured counts were typed into the prose too, and
`fill()` now refuses them, because the drift check cannot catch a stale number that this file
and the markdown agree on.
"""
from __future__ import annotations

import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "kit"))
sys.path.insert(0, os.path.join(REPO, "scripts"))

from secaudit_core import compliance, redos, structural, taint  # noqa: E402
from secaudit_core.detectors import DETECTORS                # noqa: E402

import gen_language_matrix as matrix                         # noqa: E402

OUT = os.path.join(REPO, "docs", "what-we-miss.md")
SCORECARD = os.path.join(REPO, "eval", "scorecard.json")
REALVULN = os.path.join(REPO, "eval", "realvuln", "result.json")

# Measured figures the prose below quotes, and where each one comes from. The module docstring
# says the typed part of this page is the *vocabulary*; it was not true, because eight counts
# were typed into the prose as well — and one of them rotted. The access-control row read
# "1 of 76" for the seven days after the scorer started saying 2, on the page whose entire job
# is to state a weakness accurately, and no gate noticed: the drift check compares this file's
# output to the committed markdown, so a stale number here is stale in both and matches.
#
# FAMILIES are derived from `eval/realvuln/result.json` on every build and cannot rot. DATED are
# per-rule counts against the same corpus that no committed file holds — they were measured on
# the date recorded here and the page prints that date, because a figure whose provenance is one
# analysis run on one day should say so rather than borrow the authority of the derived ones.
FAMILIES = {"authz": "broken_access_control"}
DATED: dict[str, tuple[str, str]] = {
    "alloc": ("15 of 43", "2026-08-18"),
    "cleartext": ("19 of 62", "2026-08-18"),
    "csv": ("25 of 29", "2026-08-18"),
    "enumeration": ("40 of 40", "2026-08-18"),
    "header_state": ("30 of 30", "2026-08-18"),
    "disclosure": ("36 of 83", "2026-08-18"),
}

# Vocabulary only — classes worth naming, and the CWEs that would evidence coverage. A class is
# reported as a gap when the engine emits none of its CWEs. Listing a class here can only ever
# make our coverage look worse, which is the right direction for this file's errors to run.
# Figures go in `[[token]]`, never in the prose: see FAMILIES/DATED above and `figures()` below.
CLASSES: list[tuple[str, tuple[str, ...], str]] = [
    ("Broken access control / IDOR", ("CWE-639", "CWE-284", "CWE-863"),
     "Partially covered, and barely: the structural rule reports a handler that has an "
     "authenticated principal, looks a row up by a caller-supplied id, and never uses the "
     "principal to constrain it. Any call that receives the principal is treated as a check "
     "delegated, because counting otherwise reported correct fetch-then-authorize code — so a "
     "handler that passes the principal somewhere without checking it is invisible. Measured "
     "against the external corpus this finds [[authz]] labelled cases. Tier 1's business-logic "
     "pass adjudicates the same handlers and refuses to restate what the rule already found, "
     "but it is unmeasured and the figure above is still the only number there is."),
    ("Business-logic flaws (state-machine skips, price/quantity trust)", ("CWE-841", "CWE-840"),
     "The rules being broken are the product's, and they are not written down anywhere the "
     "analyzer can read. Tier 1 now asks about them: `--backend` sends a deterministic handler "
     "map — who the handler thinks its caller is, which identifiers the request chose, which "
     "state fields it writes without checking, which prices it takes from the body — and a "
     "model adjudicates that shortlist. This class stays listed here because that pass is a "
     "model call with NO measured recall or precision, and an unmeasured tier is not coverage. "
     "Nothing on this page or in the benchmark figures depends on it."),
    ("Race conditions / TOCTOU", ("CWE-362", "CWE-367"),
     "Needs an interleaving model. A lexical pass reads one execution, never two at once."),
    ("Second-order injection", ("CWE-89",),
     "The value is stored on one request and executed on another; the two ends are in "
     "different files and usually different services."),
    ("Cryptographic protocol misuse (nonce reuse, ECB, weak KDF params)",
     ("CWE-323", "CWE-327", "CWE-916"),
     "Partially covered: named weak primitives are detected, parameter-level misuse is not."),
    ("Authentication flow flaws (session fixation, weak reset tokens)",
     ("CWE-384", "CWE-640"),
     "Requires modelling a multi-request flow, which the source-mode scan does not do. Note "
     "that a *missing* authentication check on a state-changing endpoint (CWE-306) is now "
     "reported; a flawed authentication flow that is present is not."),
    ("Denial of service via algorithmic complexity (ReDoS)", ("CWE-1333", "CWE-400"),
     "Partially covered, in two degrees. **Exponential** backtracking is decided from the "
     "regex's parse tree — star height above one, repeated groups with overlapping alternatives "
     "— and reported at High. **Quadratic** backtracking is decided from two unbounded repeats "
     "over overlapping characters followed by something that can fail, and reported at Medium, "
     "because whether that is a denial of service depends on a subject this analysis cannot "
     "see: the cost grows with the input, so it is an outage where the input is unbounded and "
     "attacker-supplied and a performance note where it is not. In Python the pattern is read "
     "at the `re` call site or from a module-level constant; in JavaScript and TypeScript it is "
     "read from the regex literal, from the string argument to `new RegExp`, and at the lines "
     "where a pattern bound to a constant is run. A pattern built at runtime is not analysed in "
     "either, a regex the criteria pass is not certified safe, and resource-exhaustion denial "
     "of service that is not a regex is covered only in the one shape a single function "
     "carries — see the row below."),
    ("Uncontrolled resource consumption (not a regex)", ("CWE-400", "CWE-770"),
     "Partially covered: a request-supplied number reaching an allocation whose size is that "
     "number — a range, a sequence repeat, a buffer, a sleep — where nothing in the function "
     "bounds it. It cannot price the work, so a loop building ten small dicts reads the same "
     "as one allocating a megabyte each, and an unbounded *read* (a response streamed whole "
     "into memory) is still not covered. Measured against the external corpus: [[alloc]]."),
    ("Brute force / credential stuffing (no rate limit)", ("CWE-307", "CWE-770"),
     "Partially covered: a credential-testing endpoint (login, registration, password reset, "
     "token or OTP issuance) that reaches a credential check with no limiter in its decorators, "
     "dependencies, module-local helpers or app registration is reported. A missing limit on any "
     "other endpoint is a capacity decision this does not make, and a limiter enforced at a "
     "gateway, WAF or reverse proxy is invisible here and reads as missing. A login the "
     "project did not write is read separately and in one shape only: Django's own "
     "`LoginView` or `PasswordResetView` mounted in a URL conf, in a project where nothing "
     "names a limiter anywhere. `include('django.contrib.auth.urls')` mounts the same "
     "login through a module this does not open, and a class-based view the project wrote "
     "itself has a body no rule here reads — both are misses rather than decisions."),
    ("Unrestricted file upload", ("CWE-434",),
     "Partially covered: an upload that is read and then written with no check between the two "
     "is reported. Whether a check is *adequate* is not decided — an allowlist containing a "
     "dangerous type reads as validated."),
    ("Mass assignment", ("CWE-915",),
     "Partially covered: a request-supplied mapping spread into a persisted object with no field "
     "allowlist is reported. A schema, serializer or typed body counts as the allowlist, so a "
     "handler whose schema declares a field it should not accept is not reported."),
    ("Deserialization gadget chains", ("CWE-502",),
     "Partially covered: the unsafe call is detected, whether an exploitable gadget exists in "
     "the dependency graph is not."),
    ("Template variable in a JavaScript context", ("CWE-79",),
     "Partially covered, and the boundary is a parser. Autoescaping is HTML escaping: it stops "
     "at `&lt;`, and the browser HTML-decodes an attribute value before the JavaScript parser "
     "reads it, so an interpolation in a JS position is unprotected even in a correctly "
     "escaping template. The event-handler case is reported, because `onclick=\"…{{ x }}\"` is "
     "one lexical shape. The `<script>` block case is NOT: deciding that an interpolation sits "
     "inside a script element means knowing where that element started, which is a lookbehind "
     "of unbounded length. The engine now HAS an HTML lexer — `taint.code_view` blanks "
     "`<!-- … -->` with one, which is what stopped a commented-out form being reported as a "
     "live hole — but blanking comments is not tracking elements, and this case needs the "
     "second. Matching forward from `<script` instead would report the wrong line, which is "
     "worse than reporting nothing."),
    ("Cleartext storage of sensitive data", ("CWE-256", "CWE-312", "CWE-922"),
     "Partially covered, and the part left out is the one this page used to give as the reason "
     "the whole class was undecidable. A `password` column IS still outside it: a bcrypt digest "
     "is an ordinary string of the same length, so the declaration cannot carry whether "
     "anything hashed the value, and a rule there would fire on every correctly-hashed schema "
     "it ever saw — measured, at 18 columns across the corpus with none labelled. What IS "
     "reported is the vocabulary where the name is the value — a webhook `secret`, an `ssn`, an "
     "`api_key`, a card number — declared as a plain column. A bare `token` column is excluded "
     "and that exclusion was measured too: adding it bought two labels for seventeen more "
     "reports, because `token` is what an application calls the value in its session table and "
     "its CSRF field. Plus a write to durable "
     "storage whose payload names such a field in a module that encrypts nothing. Names "
     "carrying their own protection (`*_hash`, `*_last4`, `masked_*`, `encrypted_*`) are "
     "excluded. Measured: [[cleartext]]."),
    ("CSV formula injection", ("CWE-1236",),
     "Reported once per file: a function producing CSV whose rows carry non-literal values, in "
     "a module where nothing neutralises a leading `=`, `+`, `-` or `@`. It does not decide "
     "whether those values are reachable by a user, and a file holding several exports is "
     "reported once rather than per export, because the fix is one shared helper. The person "
     "attacked here is the colleague who opens the file, not this application. "
     "Measured: [[csv]]."),
    ("Account enumeration", ("CWE-204", "CWE-203"),
     "Reported when a handler's own messages name different factors in different branches — "
     "one the identity, one the credential — or when a named credential flow discloses account "
     "existence. It reads the vocabulary the code writes, so a handler answering \"invalid "
     "username or password\" everywhere is silent, and so is one that leaks through *timing* "
     "rather than through text, which nothing here measures. Measured: [[enumeration]]."),
    ("Access decided by caller-controlled state", ("CWE-807",),
     "Reported when a header or cookie is compared against a literal and the comparison decides "
     "a branch. Transport headers are excluded by name (content type, accept, user agent, "
     "X-Requested-With, referer, origin, host), and a module that verifies a signature anywhere "
     "in it is left alone — so a file that authenticates one header and trusts another is not "
     "reported for the second. Measured: [[header_state]]."),
    ("Response discloses server internals", ("CWE-209", "CWE-215"),
     "Reported when a caught exception's own text, or an environment/settings/path value, "
     "reaches a response body the handler builds itself. A value passed to a template is not "
     "reported — the template decides what it renders — and neither is a framework debug page, "
     "which is a deployment setting rather than a line of code. It cannot tell a harmless "
     "exception message from a revealing one, because which exceptions arrive is a runtime "
     "fact. Measured: [[disclosure]]."),
    ("Permissive CORS", ("CWE-942", "CWE-346"),
     "Both halves now, in Python as well as JavaScript: the literal `*` and the reflected "
     "`Origin`. What is not decided is whether an allowlist that exists is correct — a pattern "
     "matching `evil-example.com.attacker.tld` reads as an allowlist."),
]


def load_scorecard() -> dict:
    with open(SCORECARD, encoding="utf-8") as f:
        return json.load(f)


def emitted_cwes() -> set[str]:
    """Every CWE the deterministic tier can produce.

    The structural analyses have to be in here. They emit CWEs no detector and no taint sink
    does, and if this function only knew about the pattern pack and the sink catalogs, this page
    would go on listing access control and ReDoS as classes with no coverage at all — the exact
    decay it exists to prevent, in the file that promises it does not happen.
    """
    return ({d.cwe for d in DETECTORS}
            | {s.cwe for s in taint.PY_SINKS.values()}
            | {s.cwe for _, s in taint.JS_SINKS}
            | {s.cwe for _, s in taint.JS_ASSIGN_SINKS}
            | structural_cwes())


def structural_cwes() -> set[str]:
    """CWEs the whole-handler analyses emit, read by running them over snippets that trigger
    each rule rather than by listing the ids here — a list would be one more typed claim, and
    it would keep saying the right thing for exactly as long as nobody changed a rule."""
    idor = (
        "from flask import request\n"
        "@app.route('/o', methods=['GET'])\n"
        "@login_required\n"
        "def o(current_user):\n"
        "    return Order.query.get(request.args.get('order_id'))\n"
    )
    noauth = (
        "from flask import request\n"
        "@app.route('/evaluate', methods=['POST'])\n"
        "def evaluate():\n"
        "    return str(request.form['expression'])\n"
    )
    catastrophic = 'import re\nP = r"((a)+)+"\nre.search(P, x)\n'
    # A credential-testing endpoint with nothing bounding attempts: CWE-307.
    unlimited = (
        "@app.post('/api/auth/login')\n"
        "def login(payload):\n"
        "    return verify_password(payload.password, load(payload.email))\n"
    )
    # An upload read and written with no check between the two: CWE-434.
    unchecked_upload = (
        "from flask import request\n"
        "@app.route('/upload', methods=['POST'])\n"
        "def up():\n"
        "    f = request.files['file']\n"
        "    f.save('/srv/' + f.filename)\n"
    )
    # A request body spread into a persisted object: CWE-915.
    spread = (
        "from flask import request\n"
        "@app.route('/p', methods=['POST'])\n"
        "def p():\n"
        "    data = request.get_json()\n"
        "    User.objects.filter(pk=1).update(**data)\n"
    )

    found: set[str] = set()
    for code in (idor, noauth, unlimited, unchecked_upload, spread):
        found |= {f.cwe for f in structural.analyze_file("probe.py", code)}
    found |= {f.cwe for f in redos.analyze_file("probe.py", catastrophic)}

    # Each rule must be represented. A silent drop here is the specific failure this page
    # exists to prevent: a class would move back into "no deterministic coverage" and the page
    # would under-report the engine while looking freshly generated.
    missing = {"CWE-284", "CWE-306", "CWE-307", "CWE-434", "CWE-915", "CWE-1333"} - found
    if missing:
        raise SystemExit(f"gen_what_we_miss: probes produced no finding for {sorted(missing)} — "
                         f"either a rule changed shape or this page is about to under-report "
                         f"the coverage it is supposed to be honest about")
    return found


_TYPED_FIGURE_RE = re.compile(r"\d+[\s-]of[\s-]\d+")


def figures() -> dict[str, str]:
    """`[[token]]` → the text that replaces it, derived where it can be derived.

    A DATED figure renders with the date it was measured. That looks like clutter next to a
    derived one and it is the point: the reader can see which numbers this build stands behind
    and which ones a person wrote down once.
    """
    with open(REALVULN, encoding="utf-8") as fh:
        by_family = json.load(fh)["by_family"]

    out = {}
    for token, family in FAMILIES.items():
        if family not in by_family:
            raise SystemExit(f"gen_what_we_miss: result.json has no `{family}` family, and this "
                             f"page quotes its score")
        cell = by_family[family]
        out[f"[[{token}]]"] = f"{cell['tp']} of {cell['total']}"
    for token, (value, when) in DATED.items():
        out[f"[[{token}]]"] = f"{value} as of {when}"
    return out


def fill(text: str, values: dict[str, str]) -> str:
    """Substitute the figures, and refuse prose that types one instead of referencing it."""
    if _TYPED_FIGURE_RE.search(text):
        raise SystemExit(f"gen_what_we_miss: prose types a measured figure — {text[:70]!r}. Put "
                         f"it in FAMILIES or DATED and reference it as [[token]]. A count typed "
                         f"into this page is the one thing on it the drift check cannot catch: "
                         f"stale here is stale in the markdown too, and the two then agree.")
    for token, value in values.items():
        text = text.replace(token, value)
    if "[[" in text:
        raise SystemExit(f"gen_what_we_miss: prose references a figure nothing supplies — "
                         f"{text[:70]!r}")
    return text


def render() -> str:
    card = load_scorecard()
    cwes = emitted_cwes()
    overall = card["overall"]

    measured = [f"- **{m}** — no detector or taint path reached it."
                for m in card["misses"]] or ["- _Nothing on this corpus._"]

    values = figures()
    absent, partial = [], []
    for name, class_cwes, why in CLASSES:
        covered = sorted(set(class_cwes) & cwes)
        (partial if covered else absent).append((name, covered, fill(why, values)))

    absent_rows = [f"| {name} | {why} |" for name, _, why in absent]
    partial_rows = [f"| {name} | {', '.join(covered)} | {why} |"
                    for name, covered, why in partial]

    lang_gaps = [n for n, e in matrix.LANGUAGES if matrix.tier_for(e) != "taint"]
    no_reach = [n for n, e in matrix.LANGUAGES if not matrix.dependency_reachable(e)]

    return "\n".join([
        "# What SecAudit misses",
        "",
        "<!-- Generated by `python3 scripts/gen_what_we_miss.py` from the engine's own "
        "limitations, the committed scorecard and the detector pack's CWE set. Do not edit by "
        "hand; CI fails on drift. -->",
        "",
        "A scanner's useful output is not the list of things it found. It is that list "
        "**plus** an accurate account of what it could not have found — because without the "
        "second, a clean report reads as \"this code is safe\" when it means \"these rules did "
        "not fire\".",
        "",
        "This page is generated. Improve the engine and a line disappears from it on the next "
        "build; let the engine sit still and the line stays here, in CI, in front of everyone.",
        "",
        "## 1. Measured misses on our own corpus",
        "",
        f"Recall **{overall['recall']:.1%}** ({overall['tp']}/{overall['tp'] + overall['fn']}) "
        f"on [the shipped fixtures](../eval/scorecard.md). What the engine did not find:",
        "",
        *measured,
        "",
        "These fixtures were written alongside the detectors, so this is a floor, not a "
        "forecast. The number that would mean something is an external one — see "
        "[`eval/realvuln/`](../eval/realvuln/).",
        "",
        "## 2. Vulnerability classes with no deterministic coverage",
        "",
        "No detector and no taint sink in the pack emits any CWE for these. They are not "
        "\"hard for us\"; they are outside what this tier of analysis can decide.",
        "",
        "A count in this table and the next is against the external corpus. One is read from "
        "[the scorer's own output](../eval/realvuln/result.json) every time this page is "
        "built and cannot go stale; the rest carry the date they were measured, because no "
        "committed file holds them and nothing re-checks them against the current engine. "
        "Both kinds used to be typed into the prose, and the derived one is derived now "
        "because of what that cost: the access-control figure below sat a week stale, on the "
        "page whose whole job is to state a weakness accurately, and no gate could see it.",
        "",
        "| Class | Why it is out of reach |",
        "|---|---|",
        *absent_rows,
        "",
        "The LLM enrichment tier can reason about several of these and does. It is not "
        "deterministic and it is not a gate: two runs on the same code can disagree, which is "
        "why the measured numbers on this repo exclude it entirely.",
        "",
        "## 3. Classes covered only in part",
        "",
        "A CWE is emitted, so these do not look absent in any coverage table. Read what is "
        "actually detected before treating one as handled.",
        "",
        "| Class | CWEs the engine emits | What is still missing |",
        "|---|---|---|",
        *partial_rows,
        "",
        "## 4. Analysis bounds",
        "",
        "The taint tier's own list, printed in every report's limitations appendix:",
        "",
        *[f"- {line}" for line in taint.limitations()],
        "",
        "## 5. Language gaps",
        "",
        f"- **No dataflow depth:** {', '.join(lang_gaps)}. Findings there are located "
        "patterns — the source is never proven, so a sink built across two lines is missed.",
        f"- **No dependency reachability:** {', '.join(no_reach)}. An advisory for these "
        "ecosystems stays `under_investigation` rather than being called unreachable.",
        "- Full breakdown: [language coverage](language-coverage.md).",
        "",
        "## 6. Compliance gaps",
        "",
        "- **PCI DSS, SOC 2, ISO 27001 are not mapped.** Each needs a citable source per "
        "control. A plausible guess for a standard an auditor checks is worse than nothing.",
        "- **ASVS is mapped at chapter level, not requirement level.** ASVS 5.0 moved external "
        "cross-references to OWASP's CRE project, so there is no crosswalk to copy and we are "
        "not inventing one.",
        "- **The CRA evidence pack is input to a compliance process, not a certificate.** "
        "Nothing this tool emits makes a product conformant.",
        *[f"- **{cwe}** is emitted but unmapped: {why}"
          for cwe, why in sorted(compliance.UNMAPPED_CWES.items())],
        "",
        "## 7. What this means for a clean report",
        "",
        "A report with no findings means the deterministic tier's rules did not fire and no "
        "taint path was proven, in the languages listed as covered, across the files that were "
        "actually scanned. It "
        "does not mean the code is safe. Anyone reading one as an all-clear is reading it "
        "wrong, and this page exists so that misreading is not our doing.",
        "",
    ]) + "\n"


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    rendered = render()
    if "--check" in argv:
        try:
            with open(OUT, encoding="utf-8") as f:
                current = f.read()
        except OSError:
            print(f"FAIL — {os.path.relpath(OUT, REPO)} is missing. "
                  f"Run: python3 scripts/gen_what_we_miss.py")
            return 1
        if current != rendered:
            print(f"FAIL — {os.path.relpath(OUT, REPO)} no longer matches what the engine "
                  f"misses. Run: python3 scripts/gen_what_we_miss.py")
            return 1
        print("What-we-miss page is current.")
        return 0

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(rendered)
    absent = sum(1 for _, c, _ in CLASSES if not set(c) & emitted_cwes())
    print(f"Wrote {os.path.relpath(OUT, REPO)} — {len(load_scorecard()['misses'])} measured "
          f"miss(es), {absent} class(es) with no deterministic coverage.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
