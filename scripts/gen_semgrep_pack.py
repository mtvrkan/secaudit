#!/usr/bin/env python3
"""Generate `rules/secaudit/*.yaml` — SecAudit's detector pack as Semgrep rules.

    python3 scripts/gen_semgrep_pack.py           # write it
    python3 scripts/gen_semgrep_pack.py --check   # fail if the committed pack is stale (CI)

Why ship this at all. Plenty of teams already run Semgrep in CI and are not going to add a
second scanner to try someone's rules. Exporting the pack means they can have the rules without
the tool, and it gives this project a second, independently maintained way to run its own
detections — which is worth having when the first one is the thing under test.

WHAT IS NOT EXPORTED, AND WHY IT MATTERS

Only the detectors Semgrep can reproduce *faithfully* are exported. Two properties of this
pack's rules do not survive a mechanical translation to `pattern-regex`:

  - **Code-shape rules** (`literal=False`, 39 of them) are matched against a view of the file
    with comments and string-literal contents blanked, so `"eval("` written inside a rule
    catalog, or a comment naming a vulnerability class, is not read as the vulnerability.
    Semgrep's `pattern-regex` runs on raw text. The same rule exported would fire on both, and
    be measurably noisier than the rule it came from.
  - **Suppressed rules** (`suppress_if`, 4 of them) are cleared when a control marker appears
    anywhere in the file — a `// SAFETY:` comment above an `unsafe` block, a `SafeLoader`
    import. Semgrep's `pattern-not-regex` filters the matched text, not the file, so there is
    no faithful equivalent.

Exporting them anyway was the other option and it is the wrong one. The precision numbers this
project publishes are measured on its own engine; shipping rules that are knowingly noisier
under the same name would make those numbers describe something nobody is running. The withheld
list is published with its reasons in the generated README, and the way to get those checks is
to run SecAudit, which is a real argument rather than a marketing one.
"""
from __future__ import annotations

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "kit"))

from secaudit_core.detectors import DETECTORS, group_of                 # noqa: E402
from secaudit_core.schema import Severity                               # noqa: E402

OUT_DIR = os.path.join(REPO, "rules", "secaudit")

# Semgrep has three levels; this pack has five. Collapsing is lossy in one direction only, so
# the original severity is kept in metadata rather than thrown away.
SEVERITY = {Severity.CRITICAL: "ERROR", Severity.HIGH: "ERROR", Severity.MEDIUM: "WARNING",
            Severity.LOW: "INFO", Severity.INFO: "INFO"}


def exportable(detector) -> str:
    """"" if the rule survives translation, else the reason it does not."""
    if not detector.literal:
        return ("matches a view with comments and string literals blanked; `pattern-regex` "
                "runs on raw text, so the exported rule would fire inside a comment or a "
                "string and be noisier than the original")
    if detector.suppress_if:
        return (f"cleared when `{detector.suppress_if}` appears anywhere in the file; "
                f"`pattern-not-regex` filters the matched text, not the file")
    return ""


def semgrep_regex(detector) -> str:
    """The detector's pattern with its Python flags made inline, so no flag is lost in transit.

    Every pattern in the pack compiles with `re.M`, and with `re.I` unless the detector opted
    into case sensitivity (token-shaped secrets encode a fixed case, and matching them
    case-insensitively widens them into false positives). Inline `(?im)` is understood by both
    regex engines Semgrep uses, so this is portable rather than a guess about which one runs.
    """
    flags = "m" if detector.case_sensitive else "im"
    return f"(?{flags}){detector.pattern}"


def yaml_single_quoted(text: str) -> str:
    """A YAML single-quoted scalar: everything is literal, only `'` needs doubling.

    Used for every generated string. Regexes are full of backslashes, braces and quotes, and a
    double-quoted scalar would require escaping rules that are easy to get subtly wrong — the
    kind of wrong that produces a valid file with a different regex in it.
    """
    return "'" + text.replace("'", "''") + "'"


def paths_for(detector) -> list[str]:
    """Glob patterns for the files this rule applies to, from the detector's extension tuple."""
    out = []
    for ext in detector.exts:
        out.append(ext if not ext.startswith(".") else f"*{ext}")
    return out


def rule_yaml(detector) -> list[str]:
    """One Semgrep rule, as lines."""
    message = (f"{detector.title} ({detector.cwe}, OWASP {detector.owasp}). {detector.fix}")
    lines = [
        f"  - id: secaudit.{detector.id.lower()}",
        f"    message: {yaml_single_quoted(message)}",
        # `regex` rather than a named language: these are pure text patterns, and asking
        # Semgrep to parse the file first would change which of them match and where.
        "    languages: [regex]",
        f"    severity: {SEVERITY[detector.severity]}",
        "    patterns:",
        f"      - pattern-regex: {yaml_single_quoted(semgrep_regex(detector))}",
        "    paths:",
        "      include:",
    ]
    lines += [f"        - {yaml_single_quoted(p)}" for p in paths_for(detector)]
    lines += [
        "    metadata:",
        f"      cwe: {yaml_single_quoted(detector.cwe)}",
        f"      owasp: {yaml_single_quoted(detector.owasp)}",
        f"      secaudit-id: {yaml_single_quoted(detector.id)}",
        f"      secaudit-severity: {yaml_single_quoted(detector.severity.value)}",
        f"      confidence: {yaml_single_quoted(detector.confidence.value.upper())}",
        f"      category: security",
        f"      source: 'https://github.com/mtvrkan/secaudit'",
    ]
    if detector.mask:
        lines.append("      # This rule matches credential material. Semgrep prints the "
                     "matched line; SecAudit redacts it.")
    return lines


def group_file(group: str, detectors: list) -> str:
    return "\n".join([
        f"# SecAudit detector pack — `{group}` group ({len(detectors)} rules).",
        "#",
        "# Generated by `python3 scripts/gen_semgrep_pack.py` from kit/secaudit_core/"
        "detectors.py.",
        "# Do not edit by hand; CI fails on drift. See ../README.md for what is deliberately",
        "# NOT in this pack and why.",
        "rules:",
        *[line for d in detectors for line in rule_yaml(d)],
        "",
    ])


def readme(exported: dict, withheld: list) -> str:
    total = sum(len(v) for v in exported.values())
    rows = [f"| `{g}` | {len(v)} | {', '.join(sorted(set(e for d in v for e in paths_for(d))))} |"
            for g, v in sorted(exported.items())]
    held = [f"| `{d.id}` | {reason} |" for d, reason in withheld]

    return "\n".join([
        "# SecAudit rules for Semgrep",
        "",
        "<!-- Generated by `python3 scripts/gen_semgrep_pack.py`. Do not edit by hand. -->",
        "",
        f"{total} of SecAudit's {len(DETECTORS)} detectors, as Semgrep rules.",
        "",
        "```bash",
        "semgrep --config rules/secaudit/",
        "```",
        "",
        "Or from a checkout of this repository, pinned:",
        "",
        "```yaml",
        "# .semgrep.yml",
        "rules:",
        "  - ...   # or: semgrep --config https://raw.githubusercontent.com/mtvrkan/secaudit/"
        "v1.0.0/rules/secaudit/",
        "```",
        "",
        "## What is here",
        "",
        "| Group | Rules | Applies to |",
        "|---|---|---|",
        *rows,
        "",
        "## What is deliberately not here",
        "",
        f"{len(withheld)} detectors are withheld because Semgrep's `pattern-regex` cannot "
        "reproduce them faithfully, and a rule that is noisier than the one it claims to be is "
        "worse than an absent rule — it would make the precision numbers this project publishes "
        "describe something nobody is running.",
        "",
        "| Detector | Why it is not exported |",
        "|---|---|",
        *held,
        "",
        "Running SecAudit itself is how you get these. That is a real difference in what the "
        "two tools can express, not a packaging decision:",
        "",
        "```bash",
        "pip install secaudit-kit && secaudit .",
        "```",
        "",
        "## Fidelity",
        "",
        "Every exported rule carries the same regex as the detector it came from, with the "
        "Python flags made inline (`(?im)`, or `(?m)` where the detector is case-sensitive "
        "because the token shape encodes a fixed case). "
        "[`kit/tests/test_semgrep_pack.py`](../../kit/tests/test_semgrep_pack.py) applies each "
        "exported pattern to the shipped fixtures and requires the exact same set of "
        "`(file, line)` hits as the detector — so this is checked equivalence, not a claim that "
        "the translation looked right.",
        "",
        "Two differences remain, and neither is fixable from this side:",
        "",
        "- **Severity** — SecAudit has five levels, Semgrep has three. Critical and High both "
        "become `ERROR`; the original is preserved in `metadata.secaudit-severity`.",
        "- **Secret redaction** — SecAudit never prints a matched credential. Semgrep prints "
        "the matching line. Rules that match credential material are marked in the YAML.",
        "",
        "## No taint analysis here",
        "",
        "Source→sink dataflow is not part of this pack. These are the pattern rules only. A "
        "finding from the taint tier states where untrusted input entered and every hop to the "
        "dangerous call, across function and module boundaries — see "
        "[language coverage](../../docs/language-coverage.md). Semgrep has its own taint mode; "
        "this pack does not attempt to translate into it, because a half-translated dataflow "
        "rule proves nothing and reads as though it does.",
        "",
    ]) + "\n"


def render() -> dict[str, str]:
    exported: dict[str, list] = {}
    withheld: list = []
    for d in DETECTORS:
        reason = exportable(d)
        if reason:
            withheld.append((d, reason))
        else:
            exported.setdefault(group_of(d.id), []).append(d)

    files = {f"{g}.yaml": group_file(g, v) for g, v in exported.items()}
    files["README.md"] = readme(exported, withheld)
    return files


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    files = render()

    if "--check" in argv:
        existing = set()
        if os.path.isdir(OUT_DIR):
            existing = {n for n in os.listdir(OUT_DIR) if n.endswith((".yaml", ".md"))}
        if existing != set(files):
            print(f"FAIL — rules/secaudit/ holds {sorted(existing)}; the detector pack now "
                  f"produces {sorted(files)}. Run: python3 scripts/gen_semgrep_pack.py")
            return 1
        for name, body in files.items():
            path = os.path.join(OUT_DIR, name)
            with open(path, encoding="utf-8") as f:
                if f.read() != body:
                    print(f"FAIL — rules/secaudit/{name} no longer matches the detector pack. "
                          f"Run: python3 scripts/gen_semgrep_pack.py")
                    return 1
        print(f"Semgrep pack is current — {len(files) - 1} group file(s).")
        return 0

    os.makedirs(OUT_DIR, exist_ok=True)
    for stale in os.listdir(OUT_DIR) if os.path.isdir(OUT_DIR) else []:
        if stale.endswith((".yaml", ".md")) and stale not in files:
            os.remove(os.path.join(OUT_DIR, stale))
    for name, body in files.items():
        with open(os.path.join(OUT_DIR, name), "w", encoding="utf-8") as f:
            f.write(body)

    rules = sum(1 for d in DETECTORS if not exportable(d))
    print(f"Wrote rules/secaudit/ — {rules} rule(s) in {len(files) - 1} group file(s); "
          f"{len(DETECTORS) - rules} detector(s) withheld with reasons in README.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
