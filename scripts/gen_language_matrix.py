#!/usr/bin/env python3
"""Generate `docs/language-coverage.md` from what the engine actually implements.

    python3 scripts/gen_language_matrix.py           # write it
    python3 scripts/gen_language_matrix.py --check   # fail if the committed file is stale (CI)

Why generate it. "Supported languages" is the most-read and least-checked line in any scanner's
documentation, and it decays in one direction only: a language gets listed when work starts on
it and never gets unlisted when the work stops. Everything below that could be a claim is read
out of the code instead — the taint tier's dispatch table, the detector pack's extension
tuples, the lexical models `code_view` knows how to blank, and the file types the dependency
import index walks. Adding a language to the engine puts it in this table on the next build;
nothing puts it here otherwise.

The one typed thing is the **vocabulary**: which extensions belong to which language name, and
which languages are worth listing as absent. That is a naming decision, not a capability claim,
and a wrong entry there shows up as a language with zero of everything rather than as an
overstatement.
"""
from __future__ import annotations

import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "kit"))

from secaudit_core import deps, taint                        # noqa: E402
from secaudit_core.detectors import DETECTORS                # noqa: E402

OUT = os.path.join(REPO, "docs", "language-coverage.md")

# Vocabulary only — see the module docstring. Order is the order of the published table.
LANGUAGES: list[tuple[str, tuple[str, ...]]] = [
    ("JavaScript", (".js", ".jsx", ".mjs", ".cjs")),
    ("TypeScript", (".ts", ".tsx")),
    ("Python", (".py",)),
    ("Go", (".go",)),
    ("Java", (".java",)),
    ("Kotlin", (".kt", ".kts")),
    ("C#", (".cs",)),
    ("PHP", (".php",)),
    ("Ruby", (".rb",)),
    ("Rust", (".rs",)),
    ("Swift", (".swift",)),
    ("Dart", (".dart",)),
]

# Not programming languages, but they carry a large share of real findings and leaving them
# out of a coverage table is its own kind of misleading.
INFRA: list[tuple[str, tuple[str, ...]]] = [
    ("Dockerfile", ("Dockerfile",)),
    ("Terraform / HCL", (".tf",)),
    ("YAML (CI, k8s, compose)", (".yml", ".yaml")),
    ("JSON config", (".json",)),
    ("Shell", (".sh",)),
    ("XML / plist", (".xml", ".plist")),
]

TIERS = {"taint": "**Taint**", "rules": "**Rules**", "regex": "**Regex**", "none": "none"}


def detector_count(exts: tuple[str, ...]) -> int:
    return sum(1 for d in DETECTORS if set(d.exts) & set(exts))


def tier_for(exts: tuple[str, ...]) -> str:
    """The deepest analysis any of these extensions gets. Derived, in this order of strength."""
    if any(ext in taint._TAINT_EXTS for ext in exts):
        return "taint"
    if not detector_count(exts):
        return "none"
    # A detector pack backed by a lexical model can be told not to match inside comments and
    # string literals; without one it can only match raw text, which is measurably noisier.
    return "rules" if any(taint.code_view("", f"x{ext}") is not None for ext in exts) else "regex"


def taint_note(name: str) -> str:
    """The front end and the scope it reaches — read from the dispatch table, never typed here.

    An earlier version spelled the scope out as a literal string in this function. It said
    "single file" for months after the engine grew a module-graph fixed point, and the
    `--check` gate could not notice, because the gate compares the generated file against this
    generator: a claim typed into the generator is not a derived claim, it is the same
    hand-written sentence one directory further from the reader.
    """
    spec = taint.TAINT_DEPTH.get(name)
    if not spec:
        return "—"
    scope = ["intraprocedural"]
    if spec.get("interprocedural"):
        scope.append("interprocedural")
    if spec.get("cross_module"):
        scope.append("cross-module")
    return f"{spec['frontend']}, {' + '.join(scope)}"


def dependency_reachable(exts: tuple[str, ...]) -> bool:
    """Whether the import index — which is what turns a CVE into `affected` vs `not_affected` —
    can read this language at all."""
    indexed = set(deps._JS_EXTS) | {".py"}
    return bool(set(exts) & indexed)


def render() -> str:
    rows = []
    for name, exts in LANGUAGES:
        tier = tier_for(exts)
        rows.append(
            f"| {name} | {TIERS[tier]} | {detector_count(exts)} | "
            f"{taint_note(name)} | {'yes' if dependency_reachable(exts) else 'no'} |")

    infra_rows = [f"| {name} | {TIERS[tier_for(exts)]} | "
                  f"{detector_count(exts)} |" for name, exts in INFRA]

    covered = [n for n, e in LANGUAGES if tier_for(e) == "taint"]
    cross = [n for n, _ in LANGUAGES if taint.TAINT_DEPTH.get(n, {}).get("cross_module")]
    ruled = [n for n, e in LANGUAGES if tier_for(e) in ("rules", "regex")]
    absent = [n for n, e in LANGUAGES if tier_for(e) == "none"]

    return "\n".join([
        "# Language coverage",
        "",
        "<!-- Generated by `python3 scripts/gen_language_matrix.py` from the engine's own "
        "dispatch tables. Do not edit by hand; CI fails on drift. -->",
        "",
        "What depth of analysis each language actually gets. Every number and tier below is "
        "read out of the code at build time — the taint tier's dispatch table, the detector "
        "pack's extension tuples, the lexical models `code_view` can blank, and the file types "
        "the dependency import index walks.",
        "",
        "## Tiers",
        "",
        "| Tier | What it means | What it costs you when it is the ceiling |",
        "|---|---|---|",
        "| **Taint** | Source→sink dataflow: the finding names where untrusted input entered "
        "and where it landed. | — |",
        "| **Rules** | Pattern pack matching a view with comments and string literals blanked. "
        "| A sink built across two lines is missed; the source is never proven. |",
        "| **Regex** | Pattern pack matching raw text. | The above, plus a rule can match "
        "inside a comment or a string literal. |",
        "| **none** | No detector claims the extension. | The file is walked and skipped. |",
        "",
        "## Programming languages",
        "",
        "| Language | Depth | Detectors | Taint front end | Dependency reachability |",
        "|---|---|---|---|---|",
        *rows,
        "",
        "## Infrastructure and configuration",
        "",
        "| Format | Depth | Detectors |",
        "|---|---|---|",
        *infra_rows,
        "",
        "## How to read this",
        "",
        f"- **Taint depth exists for {', '.join(covered)}.** Those are the languages where a "
        "finding can state a proven path from an untrusted source to a dangerous sink. "
        "Everywhere else, a finding is a located pattern — worth triaging, not proof.",
        f"- **Pattern-only: {', '.join(ruled)}.** Real detectors, real classes, no dataflow. "
        "Recall on these is bounded by whether the dangerous call and the untrusted value "
        "appear close enough together to match one expression.",
        (f"- **Not covered: {', '.join(absent)}.** Listed so the absence is visible. A scanner "
         "that omits the languages it cannot read is describing its rule pack, not your repo."
         if absent else
         "- Every language in the vocabulary has at least one detector."),
        "- **Dependency reachability** is the import-level index behind the OpenVEX statuses. "
        "Where it says no, an advisory for that ecosystem is left `under_investigation` rather "
        "than assumed unreachable — see [`kit/secaudit_core/deps.py`](../kit/secaudit_core/deps.py).",
        f"- **Cross-module depth: {', '.join(cross) if cross else 'none'}.** A value is "
        "followed across import edges to any depth, but only through files that were actually "
        "scanned — a chain leaving into an excluded directory, a third-party package, or a "
        "language without taint depth stops at that edge. The full bounds list is in "
        "[`kit/secaudit_core/taint.py`](../kit/secaudit_core/taint.py) and is printed in every "
        "report's limitations appendix.",
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
                  f"Run: python3 scripts/gen_language_matrix.py")
            return 1
        if current != rendered:
            print(f"FAIL — {os.path.relpath(OUT, REPO)} no longer matches what the engine "
                  f"implements. Run: python3 scripts/gen_language_matrix.py")
            return 1
        print("Language coverage matrix is current.")
        return 0

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(rendered)
    tiers = [tier_for(e) for _, e in LANGUAGES]
    print(f"Wrote {os.path.relpath(OUT, REPO)} — {tiers.count('taint')} language(s) with taint "
          f"depth, {tiers.count('rules') + tiers.count('regex')} pattern-only, "
          f"{tiers.count('none')} not covered.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
