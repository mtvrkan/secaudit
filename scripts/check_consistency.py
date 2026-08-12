#!/usr/bin/env python3
"""Consistency gate — every number SecAudit states about itself must be derived from the repo.

A security tool that overstates its own coverage has already lost the argument. This script
computes the facts from the source of truth (the detector table, the golden set, the shipped
plugin tree) and fails the build when a document states a different number, or when an internal
reference (a detector's `maps_to`, a golden id) points at nothing.

Run:  python3 scripts/check_consistency.py [--facts]

`--facts` prints the derived values as JSON instead of checking — that is what the docs
generator and the site generator read, so a count can never be typed by hand in either.

Adding a check: append to CHECKS. Each returns a list of failure strings (empty = pass).

Check numbers are **global across both gate scripts** and appear in build output, so they are
stable identifiers: this file owns 01-10 and 21+, `check_repo.py` owns 11-20. Never renumber an
existing check; append the next free number.
"""
from __future__ import annotations

import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KIT = os.path.join(REPO, "kit")
PLUGIN = os.path.join(REPO, "plugins", "secaudit")
SKILL_DIR = os.path.join(PLUGIN, "skills", "security-audit")
REFS = os.path.join(SKILL_DIR, "references")

sys.path.insert(0, KIT)
from secaudit_core.detectors import DETECTORS  # noqa: E402


# --------------------------------------------------------------------------- helpers

def read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def md_files(directory: str) -> list[str]:
    return sorted(f for f in os.listdir(directory) if f.endswith(".md"))


# --------------------------------------------------------------------------- facts

def derive_facts() -> dict:
    """Everything the docs are allowed to state about the kit, computed from the kit."""
    golden = read(os.path.join(REPO, "tests", "expected-findings.md"))
    # Golden ids are the leading cell of each table row: | V1 | ... |
    golden_ids = re.findall(r"^\|\s*(V\d+)\s*\|", golden, re.M)

    # Extensions a detector can select on, minus the special "Dockerfile" name selector.
    exts = {e for d in DETECTORS for e in d.exts if e.startswith(".")}

    mapped = {d.maps_to for d in DETECTORS if d.maps_to}

    return {
        "detectors": len(DETECTORS),
        "detector_ids": sorted(d.id for d in DETECTORS),
        "detector_extensions": sorted(exts),
        "detector_extension_count": len(exts),
        "cwes_covered": len({d.cwe for d in DETECTORS}),
        "references": len(md_files(REFS)),
        "commands": len(md_files(os.path.join(PLUGIN, "commands"))),
        "agents": len(md_files(os.path.join(PLUGIN, "agents"))),
        "golden_code_findings": len(golden_ids),
        "golden_ids": golden_ids,
        "golden_ids_mapped": sorted(mapped, key=lambda v: int(v[1:])),
        # The deterministic tier's stated target: every golden class except the ones a
        # regex/dataflow pack provably cannot reach. Sourced from the eval, not typed.
        "deterministic_target_classes": len(mapped),
    }


# --------------------------------------------------------------------------- checks

def check_01_detector_ids_unique(f: dict) -> list[str]:
    """Two detectors sharing an id silently collapse in dedup and in the eval's maps_to set."""
    seen, dupes = set(), []
    for d in DETECTORS:
        if d.id in seen:
            dupes.append(f"check 01: duplicate detector id `{d.id}`")
        seen.add(d.id)
    return dupes


def check_02_detector_regexes_compile(f: dict) -> list[str]:
    """A detector whose pattern does not compile is dead weight that only fails at scan time."""
    bad = []
    for d in DETECTORS:
        for attr, pat in (("pattern", d.pattern), ("suppress_if", d.suppress_if)):
            if not pat:
                continue
            try:
                re.compile(pat)
            except re.error as e:
                bad.append(f"check 02: `{d.id}`.{attr} does not compile: {e}")
    return bad


def check_03_maps_to_resolves(f: dict) -> list[str]:
    """`maps_to` ties a detector to a golden-set id. A dangling one silently deflates recall."""
    known = set(f["golden_ids"])
    return [f"check 03: `{d.id}` maps_to `{d.maps_to}`, which is not a golden-set id"
            for d in DETECTORS if d.maps_to and d.maps_to not in known]


def check_04_golden_count_stated_consistently(f: dict) -> list[str]:
    """The golden set's own header, its pass criteria, and the README must agree on the count."""
    n = f["golden_code_findings"]
    fails = []
    golden = read(os.path.join(REPO, "tests", "expected-findings.md"))
    m = re.search(r"must all be found:\s*(\d+)\s*total", golden)
    if not m:
        fails.append("check 04: expected-findings.md lost its 'must all be found: N total' header")
    elif int(m.group(1)) != n:
        fails.append(f"check 04: expected-findings.md header says {m.group(1)}, table has {n}")
    m = re.search(r"\*\*All (\d+) code findings\*\*", golden)
    if m and int(m.group(1)) != n:
        fails.append(f"check 04: expected-findings.md pass criteria says {m.group(1)}, table has {n}")

    readme = read(os.path.join(REPO, "README.md"))
    m = re.search(r"plants \*\*(\d+) code flaws\*\*", readme)
    if not m:
        fails.append("check 04: README lost its 'plants **N code flaws**' claim")
    elif int(m.group(1)) != n:
        fails.append(f"check 04: README says {m.group(1)} planted code flaws, golden set has {n}")
    return fails


def check_05_measured_claim_present(f: dict) -> list[str]:
    """The README must still carry a measurement claim, and exactly one denominator for it.

    This used to require the phrase `**N/N** target sink classes`, checked against the number
    of distinct `maps_to` values in the detector table. That number is bookkeeping about the
    *pack* — how many golden classes a detector declares it targets — and it sat in the README
    beside the scorecard's recall, which counts labelled vulnerabilities found. Two different
    numerators over two different denominators, both called a measurement, one paragraph apart.
    Removing it does not weaken anything: check 23 already compares every metric the README
    states against `eval/scorecard.json`, which is generated. This check now guards what
    actually matters — that the claim is not silently deleted, leaving a README with no
    measurement at all and no gate noticing.
    """
    readme = read(os.path.join(REPO, "README.md"))
    fails = []
    if not re.search(r"\|\s*Recall\s*\|", readme):
        fails.append("check 05: README lost its measured-metrics table — check 23 can only "
                     "verify numbers that are stated, so deleting them all would pass silently")
    if "eval/scorecard.md" not in readme:
        fails.append("check 05: README must link the generated scorecard the numbers come from")
    if re.search(r"\*\*\d+/\d+\*\*\s+target\s+sink\s+classes", readme):
        fails.append("check 05: README states a second measurement denominator ('N/N target "
                     "sink classes') beside the scorecard's recall — one measurement, one "
                     "denominator, or readers pick whichever looks better")
    return fails


def check_06_every_reference_is_routed(f: dict) -> list[str]:
    """A reference file no phase or cross-cutting list points at is unreachable — it will never
    be loaded, so it is documentation pretending to be behavior."""
    skill = read(os.path.join(SKILL_DIR, "SKILL.md"))
    routed = set(re.findall(r"references/([a-z0-9-]+\.md)", skill))
    present = set(md_files(REFS))
    orphans = sorted(present - routed)
    return [f"check 06: `references/{name}` is shipped but never routed from SKILL.md"
            for name in orphans]


def check_07_changelog_has_unreleased(f: dict) -> list[str]:
    """Keep a Changelog discipline: work lands under [Unreleased] until a release cuts it."""
    ch = read(os.path.join(REPO, "CHANGELOG.md"))
    if "## [Unreleased]" not in ch:
        return ["check 07: CHANGELOG.md has no `## [Unreleased]` section"]
    return []


# A line inside one of these blocks is a record of what was true on a stated date, not a claim
# about what is true now. Forcing a snapshot to track the current value would quietly rewrite
# the repo's own history — and the baseline a roadmap measures its progress against is exactly
# the number that must NOT move. Marked with an HTML comment so the exemption is visible in the
# document it applies to, rather than living only in this script.
_SNAPSHOT_OPEN = "<!-- snapshot:begin -->"
_SNAPSHOT_CLOSE = "<!-- snapshot:end -->"


def _outside_snapshots(text: str) -> str:
    """The document with every dated-snapshot block blanked, offsets and lines preserved."""
    out, i = [], 0
    while True:
        start = text.find(_SNAPSHOT_OPEN, i)
        if start == -1:
            out.append(text[i:])
            return "".join(out)
        end = text.find(_SNAPSHOT_CLOSE, start)
        end = len(text) if end == -1 else end + len(_SNAPSHOT_CLOSE)
        out.append(text[i:start])
        out.append("".join("\n" if c == "\n" else " " for c in text[start:end]))
        i = end


def check_08_no_typed_detector_count(f: dict) -> list[str]:
    """Detector counts drift the moment someone adds a rule. Any doc stating one must state
    the derived value — outside a dated snapshot block, which is history, not a claim."""
    n = f["detectors"]
    fails = []
    for rel in ("README.md", "kit/README.md", "ROADMAP.md"):
        path = os.path.join(REPO, rel)
        if not os.path.isfile(path):
            continue
        body = _outside_snapshots(read(path))
        for m in re.finditer(r"(\d+)\s+(?:built-in\s+)?(?:regex\s+)?detectors\b", body):
            if int(m.group(1)) != n:
                fails.append(f"check 08: {rel} states {m.group(1)} detectors; the table has {n}")
    return fails


def check_09_severity_confidence_sanity(f: dict) -> list[str]:
    """A CRITICAL finding at MEDIUM confidence is a contradiction the report cannot render
    honestly — criticals gate CI and page people. Keep the invariant enforced, not assumed."""
    from secaudit_core.schema import Severity, Confidence
    return [f"check 09: `{d.id}` is {d.severity.value} at {d.confidence.value} confidence — "
            f"a Critical detector must match an unambiguous sink"
            for d in DETECTORS
            if d.severity == Severity.CRITICAL and d.confidence != Confidence.HIGH]


def check_10_secret_detectors_mask(f: dict) -> list[str]:
    """Any detector that can match a credential must redact its evidence line. A security tool
    that prints the secret it found has created the incident it was hired to prevent."""
    return [f"check 10: `{d.id}` looks like a secret detector (CWE-798) but does not set mask=True"
            for d in DETECTORS if d.cwe == "CWE-798" and not d.mask]


def check_21_code_shape_ids_resolve(f: dict) -> list[str]:
    """`CODE_SHAPE_DETECTORS` is an id set held apart from the definitions it modifies, so a
    renamed detector would silently stop being scanned against the blanked view and start
    matching inside string literals again — a precision regression with no error message."""
    from secaudit_core.detectors import CODE_SHAPE_DETECTORS
    known = set(f["detector_ids"])
    return [f"check 21: CODE_SHAPE_DETECTORS names `{i}`, which is not a detector id"
            for i in sorted(CODE_SHAPE_DETECTORS - known)]


def check_22_taint_sinks_have_fixes(f: dict) -> list[str]:
    """A finding without a specific fix is a complaint. Every taint sink must carry one, and
    a CWE, because the report and the compliance mapping both key on it."""
    from secaudit_core.taint import PY_SINKS, JS_SINKS, JS_ASSIGN_SINKS
    all_sinks = list(PY_SINKS.values()) + [s for _, s in JS_SINKS + JS_ASSIGN_SINKS]
    bad = []
    for sink in all_sinks:
        if len(sink.fix) < 20:
            bad.append(f"check 22: taint sink `{sink.id}` has no actionable fix text")
        if not sink.cwe.startswith("CWE-"):
            bad.append(f"check 22: taint sink `{sink.id}` has a malformed CWE (`{sink.cwe}`)")
    return bad


def check_23_readme_matches_scorecard(f: dict) -> list[str]:
    """The README quotes measured detection quality. Those figures must come from the
    scorecard the harness wrote, not from whatever was true when someone last edited prose —
    a stale recall number in a security tool's README is the exact failure this repo's
    consistency gate exists to prevent."""
    scorecard = os.path.join(REPO, "eval", "scorecard.json")
    if not os.path.isfile(scorecard):
        return ["check 23: eval/scorecard.json is missing — run `python3 eval/harness.py`"]
    with open(scorecard, encoding="utf-8") as fh:
        overall = json.load(fh)["overall"]
    readme = read(os.path.join(REPO, "README.md"))

    fails = []
    claims = {
        "Recall": (r"\|\s*Recall\s*\|\s*\*\*(\d+)%\*\*", round(overall["recall"] * 100)),
        "Precision": (r"\|\s*Precision\s*\|\s*\*\*(\d+)%\*\*", round(overall["precision"] * 100)),
    }
    for label, (pattern, expected) in claims.items():
        m = re.search(pattern, readme)
        if not m:
            fails.append(f"check 23: README lost its measured {label} row")
        elif int(m.group(1)) != expected:
            fails.append(f"check 23: README states {label} {m.group(1)}%, the scorecard "
                         f"measures {expected}%")

    m = re.search(r"\*\*([\d.]+)\*\*\s*·\s*\*\*([\d.]+)\*\*", readme)
    if not m:
        fails.append("check 23: README lost its measured F1 · F3 row")
    else:
        for name, stated, actual in (("F1", m.group(1), overall["f1"]),
                                     ("F3", m.group(2), overall["f3"])):
            if abs(float(stated) - actual) > 0.0005:
                fails.append(f"check 23: README states {name} {stated}, the scorecard "
                             f"measures {actual:.3f}")

    m = re.search(r"safe-implementation traps \|\s*\*\*(\d+)\*\*", readme)
    if not m:
        fails.append("check 23: README lost its trap false-positive row")
    elif int(m.group(1)) != overall["fp"]:
        fails.append(f"check 23: README states {m.group(1)} trap false positives, the "
                     f"scorecard measures {overall['fp']}")
    return fails


def check_24_compliance_mapping_is_complete(f: dict) -> list[str]:
    """Every CWE the engine can emit must map to an ASVS chapter, or be listed as knowingly
    unmapped with a reason.

    A compliance mapping that silently omits the weakness you actually found is worse than no
    mapping: the report shows a clean compliance section next to an unmapped Critical. Keying
    the check on what the engine emits — rather than on the mapping table — means adding a
    detector forces the decision instead of deferring it."""
    from secaudit_core.compliance import CWE_TO_ASVS, UNMAPPED_CWES, ASVS_CHAPTERS
    from secaudit_core.taint import PY_SINKS, JS_SINKS, JS_ASSIGN_SINKS

    emitted = {d.cwe for d in DETECTORS}
    emitted |= {s.cwe for s in PY_SINKS.values()}
    emitted |= {s.cwe for _, s in JS_SINKS + JS_ASSIGN_SINKS}
    emitted.add("CWE-1395")     # dependency advisories, emitted by scan_dependencies

    fails = [f"check 24: `{cwe}` is emitted by the engine but has no ASVS chapter "
             f"(add it to CWE_TO_ASVS, or to UNMAPPED_CWES with a reason)"
             for cwe in sorted(emitted - set(CWE_TO_ASVS) - set(UNMAPPED_CWES))]
    fails += [f"check 24: CWE_TO_ASVS maps `{cwe}` to `{chapter}`, which is not an ASVS chapter"
              for cwe, chapter in sorted(CWE_TO_ASVS.items()) if chapter not in ASVS_CHAPTERS]
    return fails


# Documents that quote a derived *subset* of the detector table. `rules/secaudit/README.md` is
# generated so it tracks on its own; these are hand-written and do not.
_SUBSET_CLAIM_DOCS = ("README.md", "ROADMAP.md", "kit/README.md", "docs/ci.md")

# A phrase of the form "N of M detectors" says nothing on its own about WHICH subset N counts.
# Rather than guess, each subset is recognised by a marker that has to appear near the claim —
# so a new kind of subset claim is not silently checked against the wrong denominator. An
# unattributed claim is still checked on its total, which is the half we can always attribute.
_SUBSET_MARKERS = (
    ("semgrep_exported", re.compile(r"semgrep|exported", re.I)),
    ("code_shape",       re.compile(r"blanked view|literals and comments", re.I)),
)


def check_25_detector_subset_claims_are_derived(f: dict) -> list[str]:
    """Every "N of M detectors" claim must be recomputed, not remembered.

    Two subsets of the detector table are quoted in prose: how many survive translation into
    the Semgrep pack, and how many scan the blanked code view. Both move whenever a detector
    changes shape — gaining a `suppress_if`, or being added to `CODE_SHAPE_DETECTORS` — and
    both had drifted by one, in opposite documents, before this check existed. Check 08 did not
    catch it because it only reads the *total* in that same sentence, which was right the whole
    time. That is this repo's own declared failure mode: a number typed once and then left to
    decay. The fix is the gate, not the correction."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import gen_semgrep_pack as pack                                        # noqa: PLC0415
    from secaudit_core.detectors import CODE_SHAPE_DETECTORS               # noqa: PLC0415

    total = len(DETECTORS)
    withheld = sum(1 for d in DETECTORS if pack.withheld_reason(d))
    subsets = {
        "semgrep_exported": (total - withheld, "exported to the Semgrep pack"),
        "code_shape": (len(CODE_SHAPE_DETECTORS), "scanning the blanked code view"),
    }

    fails = []
    for rel in _SUBSET_CLAIM_DOCS:
        path = os.path.join(REPO, rel)
        if not os.path.isfile(path):
            continue
        body = _outside_snapshots(read(path))
        for m in re.finditer(r"(\d+)\s+of\s+(?:the\s+)?(\d+)\s+detectors", body):
            stated, stated_total = int(m.group(1)), int(m.group(2))
            if stated_total != total:
                fails.append(f"check 25: {rel} states a subset of {stated_total} detectors; "
                             f"the table has {total}")
            context = body[max(0, m.start() - 200): m.end() + 200]
            for name, marker in _SUBSET_MARKERS:
                if not marker.search(context):
                    continue
                expected, label = subsets[name]
                if stated != expected:
                    fails.append(f"check 25: {rel} states {stated} of {stated_total} detectors "
                                 f"{label}; the derived count is {expected}")
        # The other half of the Semgrep split, stated separately from the "N of M" phrase.
        for m in re.finditer(r"(\d+)\s+(?:are\s+)?withheld", body):
            if int(m.group(1)) != withheld:
                fails.append(f"check 25: {rel} states {m.group(1)} withheld detectors; the "
                             f"generator withholds {withheld}")
    return fails


def check_26_every_local_gate_runs_in_ci(f: dict) -> list[str]:
    """A gate only the local runner knows about is a gate a pull request goes around.

    `scripts/run_checks.py` and `.github/workflows/validate.yml` are two hand-maintained copies
    of the same list, and run_checks' own docstring asked for them to be kept in sync by hand.
    They were not: the advertised-Python-floor check sat in the local runner and in no workflow
    at all, so the promise `requires-python` makes to pip was enforced by a script that only ran
    when a contributor remembered to run it. Two lists, one of them authoritative, and nothing
    comparing them is the same shape of bug as a typed number — so it gets the same treatment.
    """
    runner = read(os.path.join(REPO, "scripts", "run_checks.py"))
    workflows_dir = os.path.join(REPO, ".github", "workflows")
    ci = "\n".join(read(os.path.join(workflows_dir, name))
                   for name in sorted(os.listdir(workflows_dir)) if name.endswith(".yml"))

    # The script each gate invokes: the first entry of every argv list in GATES.
    scripts = re.findall(r'\(\s*"[^"]+",\s*\[\s*"([^"]+\.py)"', runner)
    if not scripts:
        return ["check 26: could not read the gate list out of scripts/run_checks.py — the "
                "GATES table changed shape and this check is now blind"]
    return [f"check 26: `{s}` is a gate in scripts/run_checks.py but runs in no workflow — "
            f"a gate CI does not run is one a pull request can go around"
            for s in sorted(set(scripts)) if s not in ci]


CHECKS = [
    check_01_detector_ids_unique,
    check_02_detector_regexes_compile,
    check_03_maps_to_resolves,
    check_04_golden_count_stated_consistently,
    check_05_measured_claim_present,
    check_06_every_reference_is_routed,
    check_07_changelog_has_unreleased,
    check_08_no_typed_detector_count,
    check_09_severity_confidence_sanity,
    check_10_secret_detectors_mask,
    check_21_code_shape_ids_resolve,
    check_22_taint_sinks_have_fixes,
    check_23_readme_matches_scorecard,
    check_24_compliance_mapping_is_complete,
    check_25_detector_subset_claims_are_derived,
    check_26_every_local_gate_runs_in_ci,
]


def main(argv: list[str]) -> int:
    # A legacy console codepage (e.g. Windows cp1254) must not crash a gate on an em dash.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    facts = derive_facts()
    if "--facts" in argv:
        print(json.dumps(facts, indent=2))
        return 0

    failures: list[str] = []
    for check in CHECKS:
        failures.extend(check(facts))

    print(f"Consistency — {len(CHECKS)} checks over {facts['detectors']} detectors, "
          f"{facts['references']} references, {facts['golden_code_findings']} golden findings")
    if failures:
        print("FAIL:")
        print("\n".join("  - " + f for f in failures))
        return 1
    print("PASS — every stated number is derived from the repo.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
