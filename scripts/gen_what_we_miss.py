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
Naming a class we do not detect can only cost us, so a wrong entry there errs against us.
"""
from __future__ import annotations

import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "kit"))
sys.path.insert(0, os.path.join(REPO, "scripts"))

from secaudit_core import authz, compliance, redos, taint     # noqa: E402
from secaudit_core.detectors import DETECTORS                # noqa: E402

import gen_language_matrix as matrix                         # noqa: E402

OUT = os.path.join(REPO, "docs", "what-we-miss.md")
SCORECARD = os.path.join(REPO, "eval", "scorecard.json")

# Vocabulary only — classes worth naming, and the CWEs that would evidence coverage. A class is
# reported as a gap when the engine emits none of its CWEs. Listing a class here can only ever
# make our coverage look worse, which is the right direction for this file's errors to run.
CLASSES: list[tuple[str, tuple[str, ...], str]] = [
    ("Broken access control / IDOR", ("CWE-639", "CWE-284", "CWE-863"),
     "Partially covered, and barely: the structural rule reports a handler that has an "
     "authenticated principal, looks a row up by a caller-supplied id, and never uses the "
     "principal to constrain it. Any call that receives the principal is treated as a check "
     "delegated, because counting otherwise reported correct fetch-then-authorize code — so a "
     "handler that passes the principal somewhere without checking it is invisible. Measured "
     "against the external corpus this finds 1 of 76 labelled cases."),
    ("Business-logic flaws (state-machine skips, price/quantity trust)", ("CWE-841", "CWE-840"),
     "The rules being broken are the product's, and they are not written down anywhere the "
     "analyzer can read."),
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
     "Partially covered: catastrophic backtracking is decided from the regex's parse tree "
     "(star height above one, repeated groups with overlapping alternatives), for patterns "
     "written at the call site or bound to a module-level constant. A pattern built at runtime "
     "is not analysed, a regex the criteria pass is not certified safe, and resource-exhaustion "
     "denial of service that is not a regex — unbounded reads, unbounded allocation — is not "
     "covered at all."),
    ("Deserialization gadget chains", ("CWE-502",),
     "Partially covered: the unsafe call is detected, whether an exploitable gadget exists in "
     "the dependency graph is not."),
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

    found: set[str] = set()
    for code in (idor, noauth):
        found |= {f.cwe for f in authz.analyze_file("probe.py", code)}
    found |= {f.cwe for f in redos.analyze_file("probe.py", catastrophic)}
    if not found:
        raise SystemExit("gen_what_we_miss: the structural probes produced no findings — "
                         "either a rule changed shape or this page is about to under-report "
                         "the coverage it is supposed to be honest about")
    return found


def render() -> str:
    card = load_scorecard()
    cwes = emitted_cwes()
    overall = card["overall"]

    measured = [f"- **{m}** — no detector or taint path reached it."
                for m in card["misses"]] or ["- _Nothing on this corpus._"]

    absent, partial = [], []
    for name, class_cwes, why in CLASSES:
        covered = sorted(set(class_cwes) & cwes)
        (partial if covered else absent).append((name, covered, why))

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
