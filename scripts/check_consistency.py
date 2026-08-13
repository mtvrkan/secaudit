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
    from secaudit_core.detectors import CODE_SHAPE_DETECTORS               # noqa: PLC0415
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
    from secaudit_core.detectors import CODE_SHAPE_DETECTORS

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


def check_28_code_shape_has_one_source_of_truth(f: dict) -> list[str]:
    """`CODE_SHAPE_DETECTORS` must be the only thing that sets `literal=False`.

    The set is applied in one pass at the bottom of `detectors.py`, which makes it the source
    of truth — but nothing stopped a detector from passing `literal=False` in its own
    constructor, and four did. They behaved correctly, so nothing failed: the pack scanned the
    blanked view for 42 detectors while the set that documents which ones listed 38, and check
    25 compares the prose against the *set*. A prose number, a set, and a field, with the field
    silently outvoting the other two — this repository's own declared failure mode, one level
    down from where it was last looked for.
    """
    from secaudit_core.detectors import CODE_SHAPE_DETECTORS  # noqa: PLC0415

    inline = sorted(d.id for d in DETECTORS
                    if not d.literal and d.id not in CODE_SHAPE_DETECTORS)
    fails = [f"check 28: `{d}` sets `literal` in its own constructor instead of joining "
             f"CODE_SHAPE_DETECTORS — two sources for one fact, and the set is the one the "
             f"docs are checked against" for d in inline]

    stale = sorted(i for i in CODE_SHAPE_DETECTORS if i not in {d.id for d in DETECTORS})
    fails += [f"check 28: CODE_SHAPE_DETECTORS names `{i}`, which is not a detector any more"
              for i in stale]
    return fails


# A check script that nothing runs, with the reason it is exempt. An entry here is a decision,
# which is the point: the alternative to an explicit list is a check that quietly stops covering
# whatever was added last.
_NOT_A_GATE = {
    "kit/tests/test_zz_suite_mains.py":
        "pytest-only. It has no main() because it IS the pytest wrapper that calls every other "
        "suite's main(); running it as a script would be circular. Covered by the coverage gate, "
        "which runs pytest.",
}


def check_26_nothing_runs_outside_the_gate_list(f: dict) -> list[str]:
    """Every check in this repository must be in the one list, and that list must run in CI.

    The original form of this check compared two hand-maintained copies of the gate list —
    `scripts/run_checks.py` and the twenty steps of `validate.yml` — because they had already
    drifted once: the advertised-Python-floor gate lived in the runner and in no workflow at
    all. The copies are gone; the Linux job calls the runner, like the Windows job always did.

    That leaves the hole the two-copy check could never see, which is the one that matters now:
    a suite or check script that is in NEITHER list. Nothing about adding
    `kit/tests/test_something.py` makes anything run it, and a test file nobody runs looks
    exactly like a test file that passes. So the direction is inverted — the repository is
    walked, and every check it contains must appear in GATES or be exempt in `_NOT_A_GATE`
    with a stated reason.
    """
    runner = read(os.path.join(REPO, "scripts", "run_checks.py"))
    workflows_dir = os.path.join(REPO, ".github", "workflows")
    ci = "\n".join(read(os.path.join(workflows_dir, name))
                   for name in sorted(os.listdir(workflows_dir)) if name.endswith(".yml"))

    # The script each gate invokes: the first entry of every argv list in GATES.
    gated = set(re.findall(r'\(\s*"[^"]+",\s*\[\s*"([^"]+\.py)"', runner))
    if not gated:
        return ["check 26: could not read the gate list out of scripts/run_checks.py — the "
                "GATES table changed shape and this check is now blind"]

    fails = []

    # 1. The runner itself has to be what CI invokes, or the whole list runs nowhere.
    if "scripts/run_checks.py" not in ci:
        fails.append("check 26: no workflow runs `scripts/run_checks.py`, so none of the "
                     f"{len(gated)} gates it lists runs in CI at all")

    # 2. Everything that looks like a check must be in the list.
    candidates: list[str] = []
    for directory, prefix in (("kit/tests", "test_"), ("scripts", "check_"), ("tests", "")):
        full = os.path.join(REPO, *directory.split("/"))
        if not os.path.isdir(full):
            continue
        candidates += [f"{directory}/{name}" for name in sorted(os.listdir(full))
                       if name.endswith(".py") and name.startswith(prefix)
                       and name != "conftest.py"]

    for candidate in candidates:
        if candidate in gated or candidate in _NOT_A_GATE:
            continue
        fails.append(f"check 26: `{candidate}` looks like a check but is not a gate in "
                     f"scripts/run_checks.py — nothing runs it, and a check nobody runs is "
                     f"indistinguishable from a check that passes. Add it to GATES, or add it "
                     f"to _NOT_A_GATE with the reason.")

    # 3. An exemption for a file that no longer exists is a stale decision; say so.
    fails += [f"check 26: `{path}` is exempt in _NOT_A_GATE but does not exist — remove the "
              f"exemption rather than leaving it to cover a future file by accident"
              for path in sorted(_NOT_A_GATE)
              if not os.path.isfile(os.path.join(REPO, *path.split("/")))]
    return fails


def check_29_no_typed_gate_count(f: dict) -> list[str]:
    """The gate count is a derived number like any other, and it drifted anyway.

    `validate.yml` described the Windows job as running "the same 32 gates" while the runner
    listed 35. Nothing caught it, because every other derived number in this repository is
    checked inside a document the generators own, and a YAML *comment* is owned by nobody. That
    is the whole failure mode this repo exists to argue about: the claim was typed, so it decayed
    in one direction, and the direction was flattering — a stale count always understates.

    So the count is read out of `GATES` and every prose statement of it, in any workflow, script
    or document, must agree. Dated snapshot blocks are exempt for the same reason as check 08:
    a line recording what was true on a date is history, and history does not drift.
    """
    runner = read(os.path.join(REPO, "scripts", "run_checks.py"))
    gates = len(re.findall(r'\(\s*"[^"]+",\s*\[\s*"[^"]+\.py"', runner))
    if not gates:
        return ["check 29: could not count the GATES table in scripts/run_checks.py — the table "
                "changed shape and this check is now blind"]

    # Any "<n> gate(s)" or "<n> checks" in prose. The runner's own f-string prints the derived
    # value at runtime and is not a typed claim, so digits are what this looks for.
    pattern = re.compile(r"\b(\d+)\s+(?:gate|check)s?\b", re.I)
    fails = []
    for rel in _gate_count_documents():
        body = _outside_snapshots(read(os.path.join(REPO, *rel.split("/"))))
        for m in pattern.finditer(body):
            if int(m.group(1)) != gates:
                fails.append(f"check 29: {rel} states {m.group(1)} gates; scripts/run_checks.py "
                             f"lists {gates}. Derive it or delete the number.")
    return fails


def _gate_count_documents() -> list[str]:
    """Where a gate count can be stated: the workflows, the docs a reader is pointed at, and the
    contributor guide. Walked rather than listed, so a new workflow is covered the day it lands."""
    out = []
    workflows = os.path.join(REPO, ".github", "workflows")
    if os.path.isdir(workflows):
        out += [f".github/workflows/{name}" for name in sorted(os.listdir(workflows))
                if name.endswith(".yml")]
    out += [rel for rel in ("README.md", "kit/README.md", "CONTRIBUTING.md", "docs/ci.md",
                            "ROADMAP.md")
            if os.path.isfile(os.path.join(REPO, *rel.split("/")))]
    return out


def check_27_realvuln_claims_match_the_scorer(f: dict) -> list[str]:
    """Every stated RealVuln figure must equal what the benchmark's scorer wrote.

    This is the number with the strongest pull toward drift, in one direction. It is the only
    figure here that a third party produced, it is unflattering, and it will be quoted in a
    README, a roadmap and eventually a launch post — three places where a rounded-up retelling
    would never be noticed, because nothing in this repo would have to change for the prose to
    stop being true. `eval/realvuln/result.json` is the scorer's own output, committed verbatim;
    every place that names an F3, precision or recall for RealVuln is checked against it.

    Rerunning the benchmark is what changes these numbers. Editing the prose is not.
    """
    path = os.path.join(REPO, "eval", "realvuln", "result.json")
    if not os.path.isfile(path):
        return ["check 27: eval/realvuln/result.json is missing — it is the committed output of "
                "the benchmark's own scorer and the source for every stated RealVuln figure"]
    with open(path, encoding="utf-8") as fh:
        result = json.load(fh)
    overall = result["overall"]
    history = result.get("previous_runs", [])

    # Anchored on phrases that name OUR result, not on any number that looks like a score. The
    # same pages quote RealVuln's published baselines (Semgrep 17.7) and this repo's own fixture
    # F3, and a check that cannot tell those apart either fails on correct prose or gets loosened
    # until it proves nothing. Every anchor is also required to be PRESENT: deleting the row a
    # number lives in must fail this check, or the gate is one edit away from vacuous.
    f3, prec, rec = overall["f3_score"], overall["precision"], overall["recall"]
    anchors = [
        ("README.md", "the external-number heading",
         r"external number:\s*F3\s*([\d.]+)", f3, 1),
        ("README.md", "the baseline-comparison row",
         r"\|\s*\*\*SecAudit Tier 0\*\*\s*\|\s*\*\*([\d.]+)\*\*", f3, 1),
        ("README.md", "the baseline-comparison row's precision",
         r"\|\s*\*\*SecAudit Tier 0\*\*\s*\|\s*\*\*[\d.]+\*\*\s*\|\s*\*\*([\d.]+)\*\*", prec, 3),
        ("README.md", "the baseline-comparison row's recall",
         r"\|\s*\*\*SecAudit Tier 0\*\*\s*\|\s*\*\*[\d.]+\*\*\s*\|\s*\*\*[\d.]+\*\*\s*\|"
         r"\s*\*\*([\d.]+)\*\*", rec, 3),
        ("ROADMAP.md", "the roadmap's published result",
         r"RealVuln, run and published: F3\s*([\d.]+)", f3, 1),
        ("ROADMAP.md", "the roadmap's precision comparison",
         r"precision \(([\d.]+) vs", prec, 3),
        ("ROADMAP.md", "the roadmap's recall comparison",
         r"recall\s*\n?\s*\(([\d.]+) vs", rec, 3),
        (os.path.join("eval", "realvuln", "README.md"), "the result headline",
         r"\*\*Result: F3\s*([\d.]+)", f3, 1),
        (os.path.join("eval", "realvuln", "README.md"), "the headline metric table",
         r"RealVuln's primary metric\)\s*\|\s*\*\*([\d.]+)\*\*", f3, 1),

        # PROSE anchors. The headings and table rows above were gated from the start; the
        # sentences were not, and on the 26.0 -> 30.9 round four of them kept the previous
        # round's figure while every gate stayed green — the exact drift this check exists to
        # stop, in the one place it was not looking. A sentence that asserts the CURRENT result
        # is a claim, not narration, so each one is anchored on the phrase that makes it
        # present-tense. Sentences that quote an EARLIER run as history ("the first two runs
        # scored 12.5 and 13.3") are deliberately not anchored here: they are gated instead by
        # the run-history table below, which ties every past figure to `previous_runs`.
        ("README.md", "the newest entry of the not-blind list",
         r"([\d.]+)\s+are\s+not:\s+the\s+rules\s+added", f3, 1),
        ("README.md", "the present-tense claim about a corpus it has read",
         r"is\s+what\s+this\s+engine\s+did\s+on\s+a\s+corpus\s+it\s+had\s+not\s+read;"
         r"\s*([\d.]+)\s+is\s+what\s+it\s+does", f3, 1),
        ("README.md", "the two-numbers summary",
         r"corpus\s+it\s+was\s+built\s+against,\s*([\d.]+)\s+is\s+what\s+it\s+does\s+on"
         r"\s+62\s+real\s+repositories",
         f3, 1),
        (os.path.join("eval", "realvuln", "README.md"), "the not-blind verdict",
         r"\*\*Neither[^*]*?\bnor\s*([\d.]+) is\.\*\*", f3, 1),
        (os.path.join("eval", "realvuln", "README.md"), "the how-to-read-it sentence",
         r"So\s+read\s+([\d.]+)\s+as\s+\"what\s+the\s+engine\s+does\s+on\s+a\s+corpus"
         r"\s+it\s+has\s+been\s+tuned", f3, 1),
        # Anchored with `\s+` between every word rather than a literal space: these sentences get
        # reflowed whenever a figure changes width, and an anchor that a reflow can break is an
        # anchor that goes missing in exactly the edit it exists to police.
        (os.path.join("eval", "realvuln", "README.md"), "the size-of-the-advantage sentence",
         r"gap\s+between\s+12\.5\s+and\s+([\d.]+)\s+is\s+the\s+size\s+of\s+the\s+advantage",
         f3, 1),
        (os.path.join("eval", "realvuln", "README.md"), "the Tier-1 comparison caveat",
         r"not\s+with\s+the\s+([\d.]+)\s+above", f3, 1),
    ]

    fails = []
    for name, what, pattern, actual, places in anchors:
        m = re.search(pattern, read(os.path.join(REPO, name)))
        if not m:
            fails.append(f"check 27: {name} lost {what} — the RealVuln figure it carried is no "
                         f"longer checked against eval/realvuln/result.json")
        elif round(float(m.group(1)), places) != round(actual, places):
            fails.append(f"check 27: {name} states {m.group(1)} in {what}, the committed scorer "
                         f"output says {round(actual, places)}")

    fails += _realvuln_history_table(overall, history)
    fails += _realvuln_family_table(result, history)
    fails += _realvuln_repo_table(result)
    fails += _realvuln_run_count(history)
    return fails


def _realvuln_repo_table(result: dict) -> list[str]:
    """The best-five-repositories table, and the count of repositories that scored nothing.

    A leaderboard nobody regenerates only ever drifts one way. This one was two rounds stale
    when it was found — showing a top repo at 45.5 the engine had since moved to 58.8, and
    claiming four zero-scoring repositories when the committed output said two. Both errors
    happened to understate, which is luck, not a property of typing numbers by hand.
    """
    rel = os.path.join("eval", "realvuln", "README.md")
    text = read(os.path.join(REPO, rel))
    by_repo = result.get("by_repo", {})
    if not by_repo:
        return [f"check 27: result.json has no by_repo block for {rel}'s per-repository table"]

    ranked = sorted(by_repo.items(), key=lambda kv: -(kv[1].get("f3") or 0))[:5]
    want = [f"| `{name}` | {v['f3']} | {v['precision']:.3f} | {v['recall']:.3f} | "
            f"{v['tp']} | {v['fp']} | {v['fn']} |" for name, v in ranked]

    section = text.split("## Per repository", 1)
    if len(section) < 2:
        return [f"check 27: {rel} lost its per-repository section"]
    stated = [line.strip() for line in section[1].splitlines()
              if line.startswith("| `") and line.count("|") == 8]

    fails = []
    if stated[:5] != want:
        for i, row in enumerate(want):
            got = stated[i] if i < len(stated) else "(missing)"
            if got != row:
                fails.append(f"check 27: {rel} per-repository row {i + 1} reads {got!r}, "
                             f"result.json gives {row!r}")

    zeros = sum(1 for v in by_repo.values() if not v.get("f3"))
    m = re.search(r"\*\*(\d+) of (\d+) repositories scored 0\.0\*\*", text)
    if not m:
        fails.append(f"check 27: {rel} lost its zero-scoring count — the number of repositories "
                     f"this engine found nothing in is the least flattering figure on the page")
    elif (int(m.group(1)), int(m.group(2))) != (zeros, len(by_repo)):
        fails.append(f"check 27: {rel} says {m.group(1)} of {m.group(2)} repositories scored "
                     f"0.0, result.json says {zeros} of {len(by_repo)}")
    return fails


def _realvuln_family_table(result: dict, history: list[dict]) -> list[str]:
    """The per-family recall table must reproduce `by_family`, cell by cell.

    It was typed, and it went stale the first time a family moved: the table read `other
    219 / 831` while the scorer said 229, and every gate was green. That is the same defect the
    prose anchors above exist for, in the one table a reader consults to decide whether this
    engine finds the class of bug they care about — the most consequential place in the
    repository for a number to be quietly wrong.
    """
    rel = os.path.join("eval", "realvuln", "README.md")
    text = read(os.path.join(REPO, rel))
    current = result["by_family"]
    previous = history[0]["by_family"] if history else {}
    first = history[-1]["by_family"] if history else {}

    fails = []
    seen = set()
    for row in re.finditer(r"^\|\s*`(\w+)`\s*\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|\s*$",
                           text, re.M):
        family, found, recall, prev_cell, first_cell = (g.strip() for g in row.groups())
        if family not in current:
            fails.append(f"check 27: {rel} lists family `{family}`, which result.json does "
                         f"not score")
            continue
        seen.add(family)
        tp, total = current[family]["tp"], current[family]["total"]
        expectations = [
            (found, f"{tp} / {total}", "found / labelled"),
            (recall, f"{tp / total * 100:.1f}%", "recall"),
            (first_cell, f"{first.get(family, {}).get('tp', 0)} / {total}", "first run"),
        ]
        prev_tp = previous.get(family, {}).get("tp", 0)
        want_prev = f"{prev_tp} / {total}" + (f" **+{tp - prev_tp}**" if tp != prev_tp else "")
        expectations.append((prev_cell, want_prev, "previous run"))
        for stated, want, what in expectations:
            if stated != want:
                fails.append(f"check 27: {rel} states {stated!r} as `{family}`'s {what}, "
                             f"result.json gives {want!r}")

    # A family big enough to matter must not be quietly dropped from the table — deleting a row
    # is how a bad number stops being wrong without becoming right.
    missing = sorted(f for f, v in current.items() if v["total"] >= 10 and f not in seen)
    if missing:
        fails.append(f"check 27: {rel}'s recall table omits {', '.join(missing)} — every family "
                     f"with 10 or more labelled findings belongs in it")
    return fails


# Number words for the run count. The count is small by construction — one line per benchmark
# run ever published — so a table beats a dependency.
_COUNT_WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven",
                8: "eight", 9: "nine", 10: "ten"}


def _realvuln_history_table(overall: dict, history: list[dict]) -> list[str]:
    """The five-column run-history table must reproduce `previous_runs`, cell by cell.

    Every past figure this repository quotes lives in that table, so gating the table gates the
    history: a retelling that improves an earlier run to flatter a delta has to edit a cell that
    is compared against the scorer's own committed output. It also makes the columns countable,
    which is what `_realvuln_run_count` needs to catch "all four runs" after a fifth.
    """
    rel = os.path.join("eval", "realvuln", "README.md")
    text = read(os.path.join(REPO, rel))
    rows = [("F3", "f3_score", 1), ("F2", "f2_score", 1),
            ("Precision", "precision", 3), ("Recall", "recall", 3)]
    expected_cols = 1 + len(history)
    fails = []
    for label, key, places in rows:
        m = re.search(rf"^\|\s*{label}\b[^|]*\|(.+?)\|\s*$", text, re.M)
        if not m:
            fails.append(f"check 27: {rel} lost the run-history table's {label} row — the past "
                         f"figures it carried are no longer tied to previous_runs")
            continue
        cells = [c.strip().strip("*").strip() for c in m.group(1).split("|")]
        if len(cells) != expected_cols:
            fails.append(f"check 27: {rel} run-history {label} row has {len(cells)} columns, "
                         f"result.json describes {expected_cols} runs (current + "
                         f"{len(history)} previous)")
            continue
        for i, (cell, run) in enumerate(zip(cells, [{"overall": overall}, *history])):
            actual = run["overall"][key]
            try:
                stated = float(cell)
            except ValueError:
                fails.append(f"check 27: {rel} run-history {label} column {i + 1} reads "
                             f"{cell!r}, which is not a number")
                continue
            if round(stated, places) != round(actual, places):
                fails.append(f"check 27: {rel} run-history {label} column {i + 1} states "
                             f"{cell}, result.json says {round(actual, places)}")
    return fails


def _realvuln_run_count(history: list[dict]) -> list[str]:
    """Prose that counts the runs must count the runs result.json holds.

    "all four runs" survived a fifth run because nothing tied the word to the data. It is the
    same failure as a stale figure and it is invisible in exactly the same way.
    """
    total = 1 + len(history)
    word = _COUNT_WORDS.get(total)
    if word is None:                       # more runs than words — say so rather than pass
        return [f"check 27: {total} RealVuln runs is past the number-word table in "
                f"scripts/check_consistency.py; extend _COUNT_WORDS"]
    fails = []
    for rel, what in (("README.md", "the full-result pointer"),):
        m = re.search(r"all (\w+) runs", read(os.path.join(REPO, rel)))
        if not m:
            fails.append(f"check 27: {rel} lost {what}'s run count — 'all N runs' is no longer "
                         f"checked against the runs result.json holds")
        elif m.group(1).lower() != word:
            fails.append(f"check 27: {rel} says 'all {m.group(1)} runs' in {what}, "
                         f"result.json holds {total} ({word})")
    return fails


def check_30_version_headings_have_tags(f: dict) -> list[str]:
    """A `## [x.y.z]` heading claims a fetchable artefact. Refuse the ones nobody can fetch.

    This gate exists because a heading reading `## [1.0.0] — 2026-07-11 · Initial public release`
    sat at the bottom of CHANGELOG.md for a month while no `v1.0.0` tag existed, nothing had been
    uploaded to PyPI, and the repository was private. Every other number in this repo is derived
    from the thing it describes; the release history was the one claim still typed by hand, and it
    was wrong in the direction that flatters — a reader would have concluded the project had
    shipped and that everything above the heading was a later increment.

    Tags are the source of truth, not PyPI: the release workflow fires on a `v*` tag and refuses
    to build when the tag disagrees with `kit/pyproject.toml`, so a tag is the point at which a
    version stops being an intention. Git that cannot answer is a failure rather than a pass —
    the gate is undecidable then, and a gate that quietly degrades to "fine" is the shape of the
    bug it was written for. CI must therefore fetch tags (`fetch-depth: 0` in validate.yml); a
    shallow clone answers "no tags" for a repository that has them, which is exactly the false
    "fine" this refuses to emit.
    """
    import subprocess                                                       # noqa: PLC0415

    ch = read(os.path.join(REPO, "CHANGELOG.md"))
    claimed = re.findall(r"^## \[(\d+\.\d+\.\d+)\]", ch, re.M)
    if not claimed:
        return []
    try:
        proc = subprocess.run(["git", "-C", REPO, "tag", "--list"],
                              capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        return [f"check 30: CHANGELOG.md claims release(s) {', '.join(claimed)} but git cannot "
                f"be asked whether the matching tags exist ({exc.__class__.__name__}), so the "
                f"claim is unverifiable rather than verified"]
    if proc.returncode != 0:
        return [f"check 30: CHANGELOG.md claims release(s) {', '.join(claimed)} but "
                f"`git tag --list` failed, so the claim is unverifiable rather than verified"]
    tags = {t.strip() for t in proc.stdout.splitlines() if t.strip()}
    return [f"check 30: CHANGELOG.md has a `## [{v}]` release heading but no `v{v}` tag exists — "
            f"a version heading is a claim that an artefact with that number can be fetched. "
            f"Either push the tag or keep the entries under `## [Unreleased]`."
            for v in claimed if f"v{v}" not in tags]


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
    check_26_nothing_runs_outside_the_gate_list,
    check_27_realvuln_claims_match_the_scorer,
    check_28_code_shape_has_one_source_of_truth,
    check_29_no_typed_gate_count,
    check_30_version_headings_have_tags,
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
