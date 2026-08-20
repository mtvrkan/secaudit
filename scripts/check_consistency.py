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
        for attr, pat in (("pattern", d.pattern), ("suppress_if", d.suppress_if),
                          ("requires_in_file", d.requires_in_file)):
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
    be loaded, so it is documentation pretending to be behavior.

    Iterates every skill rather than the one it used to hard-code. Sibling skills were added on
    2026-08-14 (`exploitation-watch`, `compliance-pack`) and a check that knows about one skill
    would have let their content ship ungated — which is the same shape as a reference nothing
    routes to: present, plausible, and never reached.
    """
    fails = []
    for skill_dir in _skill_dirs():
        name = os.path.basename(skill_dir)
        skill_md = os.path.join(skill_dir, "SKILL.md")
        if not os.path.isfile(skill_md):
            fails.append(f"check 06: skills/{name}/ has no SKILL.md")
            continue
        skill = read(skill_md)
        # A skill is routed by its frontmatter. Without both fields it is invisible to the
        # model's own routing, which makes shipping it the same as not shipping it.
        for field in ("name:", "description:"):
            if field not in skill[:1200]:
                fails.append(f"check 06: skills/{name}/SKILL.md has no `{field}` in its "
                             f"frontmatter — a skill without one is never routed to")
        refs = os.path.join(skill_dir, "references")
        if not os.path.isdir(refs):
            continue
        routed = set(re.findall(r"references/([a-z0-9-]+\.md)", skill))
        for orphan in sorted(set(md_files(refs)) - routed):
            fails.append(f"check 06: skills/{name}/references/{orphan} is shipped but never "
                         f"routed from its SKILL.md")
    return fails


def _skill_dirs() -> list[str]:
    root = os.path.join(PLUGIN, "skills")
    if not os.path.isdir(root):
        return []
    return sorted(os.path.join(root, n) for n in os.listdir(root)
                  if os.path.isdir(os.path.join(root, n)))


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
    the derived value — outside a dated snapshot block, which is history, not a claim.

    The list is every file that *states* a count, not every file that is documentation. That
    distinction is why `action.yml` was missing from it and spent six detectors' worth of drift
    saying 79: it is a manifest, nobody reads it as prose, and its `description` is the copy
    GitHub Marketplace shows next to the install button — the most-read sentence in the
    repository and the least-edited one. A count is a count wherever it is typed."""
    n = f["detectors"]
    fails = []
    for rel in ("README.md", "kit/README.md", "ROADMAP.md", "action.yml", "kit/action.yml"):
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
    from secaudit_core.backends import LOGIC_CLASSES
    from secaudit_core.compliance import CWE_TO_ASVS, UNMAPPED_CWES, ASVS_CHAPTERS
    from secaudit_core.taint import PY_SINKS, JS_SINKS, JS_ASSIGN_SINKS

    emitted = {d.cwe for d in DETECTORS}
    emitted |= {s.cwe for s in PY_SINKS.values()}
    emitted |= {s.cwe for _, s in JS_SINKS + JS_ASSIGN_SINKS}
    # The business-logic pass emits its own weaknesses, from its own table. Keying on that table
    # is what makes a class added there a decision about compliance mapping rather than a silent
    # omission — the same reason this check reads the detector pack instead of the ASVS map.
    emitted |= {spec.cwe for spec in LOGIC_CLASSES.values()}
    emitted.add("CWE-1395")     # dependency advisories, emitted by scan_dependencies

    fails = [f"check 24: `{cwe}` is emitted by the engine but has no ASVS chapter "
             f"(add it to CWE_TO_ASVS, or to UNMAPPED_CWES with a reason)"
             for cwe in sorted(emitted - set(CWE_TO_ASVS) - set(UNMAPPED_CWES))]
    fails += [f"check 24: CWE_TO_ASVS maps `{cwe}` to `{chapter}`, which is not an ASVS chapter"
              for cwe, chapter in sorted(CWE_TO_ASVS.items()) if chapter not in ASVS_CHAPTERS]

    # PCI DSS, same rule and the same reason. The refusal list carries weight here that it does
    # not carry for ASVS: an unmapped CWE must be a stated decision about what a source scan can
    # assert to an assessor, never a row somebody forgot.
    from secaudit_core.compliance import CWE_TO_PCI, PCI_NOT_ASSERTABLE, PCI_REQUIREMENTS
    fails += [f"check 24: `{cwe}` is emitted by the engine but has no PCI DSS requirement "
              f"(add it to CWE_TO_PCI, or to PCI_NOT_ASSERTABLE with the reason a source scan "
              f"cannot assert one)"
              for cwe in sorted(emitted - set(CWE_TO_PCI) - set(PCI_NOT_ASSERTABLE))]
    fails += [f"check 24: CWE_TO_PCI maps `{cwe}` to `{req}`, which is not in PCI_REQUIREMENTS — "
              f"every requirement id this project states is one whose text was read, and an id "
              f"that is not in that table has not been"
              for cwe, req in sorted(CWE_TO_PCI.items()) if req not in PCI_REQUIREMENTS]
    overlap = sorted(set(CWE_TO_PCI) & set(PCI_NOT_ASSERTABLE))
    fails += [f"check 24: `{cwe}` is both mapped to a PCI requirement and listed as not "
              f"assertable — one of the two is wrong" for cwe in overlap]
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
    "kit/tests/test_provenance.py":
        "pytest-only, and deliberately: every case needs a `tmp_path` directory tree, which is "
        "what makes the directory-level question answerable at all. Covered by the coverage "
        "gate, which runs pytest over the whole suite.",
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
        # docs/launch-checklist.md was outside this list until 2026-08-14 and had kept 26.0
        # through two rounds — a page whose whole job is to be the thing you work through at
        # launch, quoting a figure two runs old, with every gate green. Prose is only gated
        # where it is anchored, so a page naming the current result must be named here.
        (os.path.join(".claude", "LAUNCH-CHECKLIST.md"), "the deterministic-tier comparison",
         r"not\s+with\s+the\s+([\d.]+)\s+the\s+deterministic\s+tier\s+scores", f3, 1),
        # The Turkish README states the same three figures. A translated page is the one nobody
        # re-reads when a number moves, so it is anchored from the day it is added rather than
        # after it has already drifted — which is what happened to the launch checklist.
        # Anchored from `RealVuln` forward, not on the first `F3 **N**` in the file: the row
        # above it states the OWN-corpus F3 (0.986), and an anchor that cannot tell the two
        # apart either fails on correct prose or gets loosened until it proves nothing. Same
        # trap check 27 already documents for the English README.
        ("README.tr.md", "the Turkish README's RealVuln row",
         r"RealVuln.*?\|.*?\|\s*F3\s+\*\*([\d.]+)\*\*", f3, 1),
        ("README.tr.md", "the Turkish README's precision",
         r"RealVuln.*?F3\s+\*\*[\d.]+\*\*,\s*precision\s+\*\*([\d.]+)\*\*", prec, 3),
        ("README.tr.md", "the Turkish README's recall",
         r"RealVuln.*?precision\s+\*\*[\d.]+\*\*,\s*recall\s+\*\*([\d.]+)\*\*", rec, 3),
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
        # `+{delta}` reads as `**+-1**` when a round gives one back, which is how a real
        # cell looked the first time a family went down. Signed properly instead.
        want_prev = f"{prev_tp} / {total}" + (f" **{tp - prev_tp:+d}**" if tp != prev_tp else "")
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
                8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen",
                14: "fourteen", 15: "fifteen", 16: "sixteen", 17: "seventeen",
                18: "eighteen", 19: "nineteen", 20: "twenty", 21: "twenty-one",
                22: "twenty-two", 23: "twenty-three", 24: "twenty-four", 25: "twenty-five", 26: "twenty-six",
                27: "twenty-seven", 28: "twenty-eight", 29: "twenty-nine", 30: "thirty"}


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
        # `[\w-]` rather than `\w`: the count passed twenty and the words are hyphenated from
        # there on, and a gate that stops matching is a gate that stops checking.
        m = re.search(r"all ([\w-]+) runs", read(os.path.join(REPO, rel)))
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


def check_31_every_finding_source_is_ranked(f: dict) -> list[str]:
    """Every `source=` a Finding is constructed with must have a rank in `engine._SOURCE_RANK`.

    `_dedupe` resolves a collision at one (file, line, cwe) by keeping only the findings whose
    source ranks highest, and it reads that rank with `.get(f.source, 0)`. A source the map has
    never heard of therefore does not error and does not rank last on purpose — it ranks below
    `builtin`, the weakest evidence in the engine, and loses every group it collides with, in
    silence.

    That is not hypothetical. `structural/authz.py` shipped emitting `source="authz"` while every
    other structural analysis emits `source="structural"`, so the two analyses that exist to
    report broken access control and missing authentication were the only ones a plain regex
    match could evict. No gate could see it: the fixtures produce zero authz findings through the
    engine, and `test_authz.py` calls `analyze_file` directly, so dedup never ran on one.

    A rank is a deliberate ordering decision, so the fix is not a default — it is that adding a
    source without ranking it fails the build.

    Its bound, stated rather than left to be discovered: it reads string literals. Every producer
    in the package writes one today, and a source assembled from a variable would pass this check
    unseen. If that ever changes, this check has to change with it.
    """
    from secaudit_core.engine import _SOURCE_RANK  # noqa: PLC0415

    core = os.path.join(KIT, "secaudit_core")
    emitted: dict[str, list[str]] = {}
    for dirpath, dirnames, filenames in os.walk(core):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            path = os.path.join(dirpath, name)
            for src in set(re.findall(r"""source=["']([\w-]+)["']""", read(path))):
                emitted.setdefault(src, []).append(os.path.relpath(path, REPO))

    return [f"check 31: {', '.join(sorted(where))} constructs findings with "
            f"`source=\"{src}\"`, which `engine._SOURCE_RANK` does not rank — dedup would score "
            f"it 0 and drop it behind every other source at the same file/line/CWE"
            for src, where in sorted(emitted.items()) if src not in _SOURCE_RANK]


# The digest, the module list and the reason each module is on or off it now live in
# `scripts/engine_digest.py`. They moved the day `eval/secbenchjs/run.py` needed the same
# answer to decide whether a cached scan result still describes this engine — two definitions
# of "the engine that produced this figure" is one more than a repository can be held to.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine_digest import engine_digest as _engine_digest        # noqa: E402


def check_32_result_json_matches_the_engine_that_produced_it(f: dict) -> list[str]:
    """`eval/realvuln/result.json` must record the engine it was measured with.

    Check 27 gates the prose against `result.json`. Nothing gated `result.json` against the
    *code*, and that gap is not hypothetical — it shipped. The JavaScript structural analysis
    landed in `c96c914`, one commit after `8fc17e1` wrote the 31.5 figures, and `result.json` was
    never rewritten. The published precision described an engine that no longer existed: measured
    on 2026-08-14 the shipped engine returned 595 false positives where the committed file said
    448, and every gate was green the whole time, because every gate was comparing prose to a file
    rather than either to the engine.

    A digest cannot re-run a 62-repository benchmark in CI, and it does not try to. What it does
    is make the staleness *loud*: change anything that decides a finding and the build says the
    published number no longer describes this code, which is the sentence nobody wrote for four
    commits.
    """
    digest, unlisted = _engine_digest()
    fails = [f"check 32: `secaudit_core/{rel}` is in neither the measured set nor "
             f"`NOT_IN_MEASURED_PATH` in scripts/engine_digest.py — decide which, with a reason, so the engine digest "
             f"cannot silently stop covering it" for rel in sorted(unlisted)]

    # Both external numbers, not just the first one. The SecBench.js figures are published in the
    # README, the Turkish README, the roadmap and the site, and for two rounds nothing tied them
    # to the code — the exact gap this check was written for, sitting one directory over from it.
    for rel, rerun in (("eval/realvuln/result.json", "eval/realvuln/run.py"),
                       ("eval/secbenchjs/result.json",
                        "eval/secbenchjs/run.py, then score.py"),
                       ("eval/noisefloor/result.json",
                        "eval/noisefloor/run.py, then score.py"),
                       # Listed in the same change that first published a CVEfixes figure. A
                       # published number this loop does not name is a number free to outlive
                       # its engine, which is the defect described above wearing a new
                       # directory name.
                       ("eval/cvefixes/result.json",
                        "eval/cvefixes/run.py, then score.py --run-date …")):
        path = os.path.join(REPO, *rel.split("/"))
        if not os.path.isfile(path):
            continue                              # check 27 / 35 already fail on a missing file
        with open(path, encoding="utf-8") as fh:
            result = json.load(fh)
        recorded = result.get("engine_digest")
        if not recorded:
            fails.append(f"check 32: {rel} has no `engine_digest`, so nothing ties its published "
                         f"figures to the code that produced them. Re-run and record: {digest}")
        elif recorded != digest:
            fails.append(
                f"check 32: {rel} was measured with engine {recorded}, and the engine in this "
                f"tree is {digest}. Something that decides a finding has changed since the "
                f"published figures were measured, so they no longer describe this code. Re-run "
                f"`{rerun}`, then update the figures and this digest together — never the digest "
                f"alone.")
    return fails


# Suites that legitimately have no `main()` of their own, with the reason.
_MAIN_LESS_SUITES = {
    "kit/tests/test_zz_suite_mains.py":
        "It IS the pytest wrapper that calls every other suite's main(); having one of its own "
        "would be circular. Already exempted from the gate list for the same reason.",
}


def check_33_every_test_function_is_actually_called(f: dict) -> list[str]:
    """A `test_*` function a suite's `main()` never calls is dead, and it is dead invisibly.

    Every suite here is a script whose verdict is `main()`'s exit code, and `main()` calls its
    tests by name. That is a deliberate design — it is what makes the suites runnable without
    pytest — but it has one failure mode, and this repository has now hit it twice. The first
    time, `pytest kit/tests` reported 75 passed with the flagship JS SQL-injection sink deleted,
    because the collected `test_*` functions were never run by the collector in a way that could
    fail. This is the other half of the same shape: on 2026-08-14 a `test_pci_mapping` was added
    to `test_compliance.py` and not added to its `main()`. The suite printed PASSED, the gate was
    green, and every assertion in it — including the ones about what the tool must refuse to tell
    an auditor — had never executed. It was found by mutation, not by the suite.

    So: a test function must be reachable from the `main()` of the file that defines it, **or**
    contain an `assert` so pytest can fail on it. Either route ends in a red build; a function
    with neither is collected, reported as passed, and proves nothing. Checked by reading the
    source rather than by importing, because importing a suite runs it.

    Its bound: a function called only from another dead function still counts as called. Closing
    that would mean building a call graph over a test file, and the shape this has actually
    caught twice is a name that appears exactly once.
    """
    fails = []
    for directory in (os.path.join(KIT, "tests"), os.path.join(REPO, "tests")):
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            if not (name.startswith("test_") and name.endswith(".py")):
                continue
            rel = os.path.relpath(os.path.join(directory, name), REPO).replace("\\", "/")
            if rel in _MAIN_LESS_SUITES:
                continue
            source = read(os.path.join(directory, name))
            defined = set(re.findall(r"^def (test_\w+)", source, re.M))
            if not defined:
                continue
            # A wrapper that asserts can go red under pytest, which is a real verdict route and
            # the pattern `test_engine.py` deliberately uses. Bodies are sliced from one `def`
            # at column 0 to the next, so an `assert` in a neighbouring function is not credited.
            bodies = dict(zip(re.findall(r"^def (\w+)", source, re.M),
                              re.split(r"^def \w+", source, flags=re.M)[1:]))
            asserting = {n for n in defined if re.search(r"^\s+assert\b", bodies.get(n, ""),
                                                         re.M)}
            defined -= asserting
            main_body = re.search(r"^def main\(.*?(?=^\S|\Z)", source, re.M | re.S)
            if not defined:
                # Every test in the file asserts, so pytest is a real verdict route for all of
                # them and there is nothing left for a `main()` to rescue. The check used to
                # demand one anyway, and the demand was incoherent with the exemption three
                # lines above it: a suite whose every function can already fail the build was
                # reported as "defines 0 test function(s) and has no main()", which names a
                # problem it had just finished proving does not exist.
                continue
            if not main_body:
                fails.append(f"check 33: {rel} defines {len(defined)} test function(s) and has "
                             f"no `main()` — nothing runs them")
                continue
            called = set(re.findall(r"\b(test_\w+)\s*\(", main_body.group(0)))
            # A loop over `globals()` picking up every test_ name counts as calling all of them.
            if re.search(r"globals\(\)|getmembers|vars\(\)", main_body.group(0)):
                continue
            for orphan in sorted(defined - called):
                fails.append(f"check 33: {rel} defines `{orphan}` but its `main()` never calls "
                             f"it — the suite reports PASSED without running those assertions")
    return fails


def check_34_language_families_are_claimed_whole(f: dict) -> list[str]:
    """A tier that analyses one member of a language family must analyse all of it.

    Written after the disagreement it gates cost two live defects. Four places independently
    listed which extensions are JavaScript or TypeScript and gave three different answers:
    `detectors.py` said `.js` and `.ts`, the lexical model added `.jsx/.tsx/.mjs/.cjs`, and
    `structural/js.py` added `.mts/.cts` on top. The consequences were invisible in both
    directions — a React codebase received **zero** pattern detectors (the same file scanned as
    `vuln.ts` and not as `vuln.tsx`), and `.mts`/`.cts` were published as analysed while
    `code_view` had no group for them, so every structural analysis returned nothing for a file
    type the generated language matrix promised.

    Neither showed up as a failure. Both showed up as silence, which is the only failure mode a
    security scanner has that matters: a clean report on a file nobody looked at.

    `langs.py` now holds the families and every tier derives from it. This check is what keeps
    that true — including for a detector added later, which is the case a one-time fix does not
    cover. `.tsx` is TypeScript with markup in it; a rule about `createHash('md5')` does not stop
    applying because the file also renders a component. Naming half a family is never a decision.
    """
    sys.path.insert(0, KIT)
    from secaudit_core import langs                                     # noqa: E402
    from secaudit_core.structural import js as structural_js            # noqa: E402
    from secaudit_core.taint import TAINT_DEPTH                         # noqa: E402
    from secaudit_core.taint.lexical import _EXT_GROUP                  # noqa: E402

    fails = []
    for det in DETECTORS:
        claimed = {e.lower() for e in det.exts}
        for family, exts in langs.FAMILIES.items():
            whole = set(exts)
            if claimed & whole and not whole <= claimed:
                missing = ", ".join(sorted(whole - claimed))
                fails.append(f"check 34: detector {det.id} names part of the {family} family "
                             f"but not {missing} — a rule that is right for one member is right "
                             f"for all of them, and the files it skips are reported as clean")

    # The three tiers that decide *which files exist* for an analysis. A file claimed by one and
    # not another is analysed by half the engine while the docs describe the whole of it.
    tiers = {
        "taint depth table": {e for name in ("JavaScript", "TypeScript")
                              for e in TAINT_DEPTH[name]["exts"]},
        "structural route scanner": set(structural_js.JS_EXTS),
        "lexical code view": {e for e, group in _EXT_GROUP.items() if group == "js"},
    }
    for tier, claimed in tiers.items():
        if claimed != set(langs.JSTS_EXTS):
            missing = ", ".join(sorted(set(langs.JSTS_EXTS) - claimed)) or "none"
            extra = ", ".join(sorted(claimed - set(langs.JSTS_EXTS))) or "none"
            fails.append(f"check 34: the {tier} disagrees with langs.JSTS_EXTS — "
                         f"missing: {missing}; unexpected: {extra}")
    return fails


def check_44_cvefixes_claims_match_the_scorer(f: dict) -> list[str]:
    """Every stated CVEfixes figure must equal what `eval/cvefixes/score.py` wrote.

    The same job as check 27, one corpus over, and written in the change that first published the
    figure rather than after it had already drifted — which is what happened to the launch
    checklist, and is the reason check 27 says prose is only gated where it is anchored.

    This corpus has a second reason to be gated and it is the one that matters more. Its headline
    is **bad**, and a bad number is exactly the kind a later edit rounds, softens or quietly drops
    while every other gate stays green. The sealed/unsealed pair is anchored for the same reason
    in reverse: those two figures are the entire evidence that the held-out mechanism works, and
    an unchecked claim about a seal is the sort of promise `eval/HELDOUT.md` exists to refuse.
    """
    path = os.path.join(REPO, "eval", "cvefixes", "result.json")
    if not os.path.isfile(path):
        return ["check 44: eval/cvefixes/result.json is missing — it is the committed output of "
                "eval/cvefixes/score.py and the source for every stated CVEfixes figure"]
    with open(path, encoding="utf-8") as fh:
        result = json.load(fh)
    head, seal = result["headline"], result["headline_by_seal"]
    cve_pct = round(head["cve_recall"] * 100, 1)
    file_pct = round(head["recall"] * 100, 1)
    sealed_pct = round(seal["sealed"]["recall"] * 100, 2)
    unsealed_pct = round(seal["unsealed"]["recall"] * 100, 2)

    # `\s+` between every word, never a literal space: these sentences get reflowed whenever a
    # figure changes width, and an anchor a reflow can break is an anchor that goes missing in
    # exactly the edit it exists to police. Check 27 learned that the expensive way.
    anchors = [
        ("README.md", "the blind-number CVE figure",
         r"finds\s+\*\*([\d.]+)%\*\*\s+of\s+the\s+CVEs", cve_pct, 1),
        ("README.md", "the blind-number file figure",
         r"of\s+the\s+CVEs\s+and\s+\*\*([\d.]+)%\*\*\s+of\s+the\s+vulnerable\s+files",
         file_pct, 1),
        ("README.md", "the sealed-slice figure",
         r"sealed\s+slice\s+scores\s+\*\*([\d.]+)%\*\*", sealed_pct, 2),
        ("README.md", "the unsealed-slice figure",
         r"scores\s+\*\*[\d.]+%\*\*\s+against\s+\*\*([\d.]+)%\*\*\s+unsealed", unsealed_pct, 2),
        (os.path.join("eval", "HELDOUT.md"), "the seal-works evidence",
         r"\*\*sealed\s+([\d.]+)%,\s+unsealed\s+[\d.]+%\.\*\*", sealed_pct, 2),
        (os.path.join("eval", "HELDOUT.md"), "the seal-works comparison",
         r"\*\*sealed\s+[\d.]+%,\s+unsealed\s+([\d.]+)%\.\*\*", unsealed_pct, 2),
        (os.path.join("eval", "cvefixes", "README.md"), "the headline CVE row",
         r"one\s+file\s+detected\*\*\s*\|\s*\*\*([\d.]+)%\*\*", cve_pct, 1),
        (os.path.join("eval", "cvefixes", "README.md"), "the headline file row",
         r"fired\s+at\s+a\s+fixed\s+hunk\*\*\s*\|\s*\*\*([\d.]+)%\*\*", file_pct, 1),
        (os.path.join("eval", "cvefixes", "README.md"), "the sealed-slice sentence",
         r"Sealed\s+slice\s+\*\*([\d.]+)%\*\*", sealed_pct, 2),
        (os.path.join("eval", "cvefixes", "README.md"), "the unsealed-slice sentence",
         r"unsealed\s+\*\*([\d.]+)%\*\*", unsealed_pct, 2),
        # The Turkish README states the same figures, and is anchored from the day it states
        # them for the reason check 27 records: a translated page is the one nobody re-reads
        # when a number moves.
        ("README.tr.md", "the Turkish CVE-level row",
         r"CVE\s+bazında\s+\*\*([\d.]+)%\*\*", cve_pct, 1),
        ("README.tr.md", "the Turkish file-level row",
         r"dosya\s+bazında\s+\*\*([\d.]+)%\*\*", file_pct, 1),
        ("README.tr.md", "the Turkish sealed-slice figure",
         r"Mühürlü\s+dilim\s+\*\*([\d.]+)%\*\*", sealed_pct, 2),
        ("README.tr.md", "the Turkish unsealed-slice figure",
         r"mühürsüz\s*\n?\s*\*\*([\d.]+)%\*\*", unsealed_pct, 2),
    ]

    fails = []
    for name, what, pattern, actual, places in anchors:
        m = re.search(pattern, read(os.path.join(REPO, name)))
        if not m:
            fails.append(f"check 44: {name} lost {what} — the CVEfixes figure it carried is no "
                         f"longer checked against eval/cvefixes/result.json")
        elif round(float(m.group(1)), places) != round(actual, places):
            fails.append(f"check 44: {name} states {m.group(1)} in {what}, the committed scorer "
                         f"output says {round(actual, places)}")
    return fails


def check_41_the_held_out_slice_is_still_sealed(f: dict) -> list[str]:
    """No sealed corpus entry may be named anywhere in the tree except the register.

    The policy is in `eval/HELDOUT.md`; this is the half that makes it more than a promise.

    It works on how corpus-informed tuning actually happens rather than on intent. You cannot
    diagnose against a package without writing its name down somewhere — a commit message, a
    comment explaining why a rule was narrowed, a test fixture, a CHANGELOG entry, a line in a
    README. All of those are in the tree, and all of them fail this check. Nobody in this
    repository's four corpus-informed rounds set out to overfit; they read the misses because the
    misses were right there. This removes "right there".

    Not airtight, and `HELDOUT.md` says so: a determined person can read a sealed package, form a
    hypothesis, and write it up citing only unsealed ones. What this removes is the casual path.

    The register itself is exempt, obviously, and so is the scan-results tree, which is generated
    output rather than something anyone wrote.
    """
    path = os.path.join(REPO, "eval", "heldout.json")
    if not os.path.exists(path):
        return []                                  # no seal declared, nothing to enforce
    with open(path, encoding="utf-8") as fh:
        register = json.load(fh)
    sealed = {name for corpus in register.get("corpora", {}).values()
              for name in corpus.get("packages", [])}
    if not sealed:
        return ["check 41: eval/heldout.json declares no sealed entries — either seal a slice or "
                "delete the register, because an empty seal reads as a policy that is in force"]

    # Version strings make package dirs like `<name>_1.2.3`; the bare name is far too common a
    # word to search for (`express`, `got`, `chalk`), so the underscore-joined form is what is
    # searched. That is also the form anybody would paste.
    fails, checked = [], 0
    skip_dirs = {".git", "node_modules", "__pycache__", "scan-results", ".venv", "venv"}
    for dirpath, dirnames, filenames in os.walk(REPO):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in filenames:
            rel = os.path.relpath(os.path.join(dirpath, name), REPO).replace("\\", "/")
            if rel in ("eval/heldout.json", "eval/HELDOUT.md"):
                continue
            if not name.endswith((".md", ".py", ".json", ".yml", ".yaml", ".txt", ".toml",
                                  ".js", ".ts", ".html", ".css")):
                continue
            try:
                text = read(os.path.join(dirpath, name))
            except (OSError, UnicodeDecodeError):
                continue
            checked += 1
            for entry in sealed:
                # Bounded on the right, because a substring match is wrong in exactly the
                # direction that costs a real round: a four-digit sealed identifier is a PREFIX
                # of a five-digit unsealed one from the same year, so a plain `in` reported a
                # seal break on a file that named the other CVE entirely. Caught the first time
                # this repository published a table of CVE identifiers — and this comment names
                # neither of them, because naming the sealed one here would be the very thing
                # the check exists to stop.
                if re.search(re.escape(entry) + r"(?![\w-])", text):
                    fails.append(
                        f"check 41: `{rel}` names the sealed corpus entry `{entry}`. It is in "
                        f"the held-out slice (eval/HELDOUT.md), which means no decision in this "
                        f"repository may be taken by looking at it. If this is an accident, "
                        f"rename it; if it is not, the seal is broken and that corpus stops "
                        f"being able to make a blind claim.")
    return fails


def check_42_the_result_files_agree_with_themselves(f: dict) -> list[str]:
    """A published headline must equal the per-part table published beside it.

    `eval/realvuln/result.json` is assembled from two of the benchmark's own outputs —
    `reports/dashboard.json` for `overall`, and the per-repository scorecards for `by_repo` — and
    on 2026-08-16 they disagreed. The headline said 271 false positives and the table in the same
    file summed to 273. Re-running that engine on that clone in 2026-08-17 reproduced the scan
    byte for byte and the scorer said 273 twice over: `dashboard.py` had not been re-run after
    that round's scoring, so the file published the *previous* engine's headline (which was
    genuinely 271 — the earlier engines were re-run too, and they emit it) over this engine's
    table. Precision 0.7086 rather than 0.7071, F3 across a rounding boundary, and a round whose
    stated argument leaned on the false positives not having moved when they had.

    Nothing caught it, and the reason is worth stating because it generalises past this file.
    Check 27 holds the prose to `result.json`. Check 32 holds `result.json` to the engine that
    produced it. **Neither holds `result.json` to itself** — and a file assembled from two
    sources will eventually be assembled from two moments. The same applies to the class table in
    `eval/secbenchjs/result.json`, gated here for the same reason on the same day rather than
    after its own version of this.

    `collect_result.py` now refuses to write a file that fails this. The gate stays because a
    refusal in the collector only protects the files the collector writes.
    """
    fails = []

    rv = os.path.join(REPO, "eval", "realvuln", "result.json")
    if os.path.exists(rv):
        with open(rv, encoding="utf-8") as fh:
            result = json.load(fh)
        by_repo = dict(result.get("by_repo") or {})
        if by_repo:
            for key in ("tp", "fp", "fn"):
                summed = sum(r.get(key) or 0 for r in by_repo.values())
                stated = result["overall"].get(key)
                if summed != stated:
                    fails.append(
                        f"check 42: eval/realvuln/result.json states overall {key} = {stated} "
                        f"and its own by_repo table sums to {summed} over {len(by_repo)} "
                        f"repositories — one of the two was written from a different run")
        # The families partition the labels, so their totals have to add up to the labels the
        # headline was computed over. This is the invariant that catches the doubling described
        # in `collect_result.read_scorecards`: a table summed over two dated scorecards per
        # repository is exactly twice as large and otherwise looks perfectly ordinary.
        families = result.get("by_family") or {}
        labelled = result["overall"].get("tp", 0) + result["overall"].get("fn", 0)
        summed = sum(fam.get("total") or 0 for fam in families.values())
        if families and summed != labelled:
            fails.append(
                f"check 42: eval/realvuln/result.json's by_family table covers {summed} labels "
                f"and its headline was computed over {labelled} ({result['overall']['tp']} TP + "
                f"{result['overall']['fn']} FN) — the families partition the labels, so a total "
                f"that is a multiple of the right one means the same scorecards were counted "
                f"more than once")

        # Every earlier round is a published figure too: the README's history table reads them.
        for run in result.get("previous_runs") or []:
            o = run.get("overall") or {}
            if not all(k in o for k in ("tp", "fp", "precision")):
                continue
            denominator = (o["tp"] + o["fp"]) or 1
            if abs(round(o["tp"] / denominator, 4) - o["precision"]) > 0.0002:
                fails.append(
                    f"check 42: the {run.get('run_date')} run in previous_runs states precision "
                    f"{o['precision']} and its own {o['tp']} TP / {o['fp']} FP give "
                    f"{o['tp'] / denominator:.4f}")

    sb = os.path.join(REPO, "eval", "secbenchjs", "result.json")
    if os.path.exists(sb):
        with open(sb, encoding="utf-8") as fh:
            result = json.load(fh)
        classes = result.get("by_class") or {}
        for key in ("tp", "fn"):
            summed = sum(c.get(key) or 0 for c in classes.values())
            stated = result["overall"].get(key)
            if classes and summed != stated:
                fails.append(f"check 42: eval/secbenchjs/result.json states overall {key} = "
                             f"{stated} and its by_class table sums to {summed}")
        seal = result.get("by_seal") or {}
        if seal:
            summed = sum(s.get("tp") or 0 for s in seal.values())
            if summed != result["overall"]["tp"]:
                fails.append(f"check 42: eval/secbenchjs/result.json's sealed and unsealed slices "
                             f"hold {summed} true positives and the headline claims "
                             f"{result['overall']['tp']} — every label is in exactly one slice")
    return fails


def check_40_noise_floor_claims_match_the_scorer(f: dict) -> list[str]:
    """`eval/noisefloor/README.md` must say what `eval/noisefloor/result.json` says.

    Third benchmark, same gate on the day it lands rather than after its first figure goes stale.
    This one earns it twice over, because its numbers are the smallest on the site and the
    easiest to round in prose: 0.21 reads the same as 0.2 to a writer and not to a reader
    deciding whether to adopt the tool.

    The per-repository table is gated by its total rather than row by row. A row is a fact about
    one checkout; the sum is the claim — and the failure that matters is the table quietly
    ceasing to add up to the headline, which is exactly what a hand-edited row does. This check
    exists because the first version of that table was typed from the run's console output and
    had four of its eight `High+Crit` cells wrong.
    """
    path = os.path.join(REPO, "eval", "noisefloor", "result.json")
    page = os.path.join(REPO, "eval", "noisefloor", "README.md")
    if not os.path.exists(path):
        return ["check 40: eval/noisefloor/result.json is missing — it is the committed output "
                "of the scorer and every figure on the page is read from it"]
    with open(path, encoding="utf-8") as fh:
        result = json.load(fh)
    text = read(page)
    fails = []

    # The top-level README quotes the headline too, and a figure published in two places drifts
    # in exactly one of them. Same reason check 35 reaches past `eval/secbenchjs/README.md`.
    o0 = result["overall"]
    readme = read(os.path.join(REPO, "README.md"))
    for value, what in ((o0["per_1k_lines"], "findings per 1,000 lines"),
                        (o0["actionable_per_1k_lines"], "High+Critical per 1,000 lines")):
        if f"{value:.2f}" not in readme:
            fails.append(f"check 40: README.md does not state {value:.2f} — the noise floor is "
                         f"published there ({what}) and nothing was holding it to result.json")

    o = result["overall"]
    for value, what in ((o["per_1k_lines"], "findings per 1,000 lines"),
                        (o["actionable_per_1k_lines"], "High+Critical per 1,000 lines"),
                        (o["high_confidence_per_1k_lines"], "HIGH-confidence per 1,000 lines")):
        if f"{value:.2f}" not in text:
            fails.append(f"check 40: the page never states {value:.2f} as the {what}")
    if f"{result['total_lines']:,}" not in text:
        fails.append(f"check 40: the page never states {result['total_lines']:,} as the total "
                     f"lines scanned — the denominator is half the claim")
    if f"{result['repos_scored']} " not in text and f"{result['repos_scored']} " not in text:
        fails.append(f"check 40: the page never states {result['repos_scored']} as the number "
                     f"of repositories")

    # The table has to add up to the headline. Summing the rows is what catches a hand-edited
    # cell; checking each row against the file would catch it too and would also fail on a row
    # legitimately reordered, which is noise.
    rows = re.findall(r"^\|\s*`([^`]+)`\s*\|\s*\w+\s*\|\s*([\d,]+)\s*\|\s*(\d+)\s*\|"
                      r"\s*[\d.]+\s*\|\s*(\d+)\s*\|$", text, re.M)
    if len(rows) != len(result["by_repo"]):
        fails.append(f"check 40: the per-repository table has {len(rows)} rows and result.json "
                     f"has {len(result['by_repo'])} repositories")
    else:
        for name, lines, findings, actionable in rows:
            entry = result["by_repo"].get(name)
            if entry is None:
                fails.append(f"check 40: the table names `{name}`, which result.json does not")
            elif (int(lines.replace(",", "")) != entry["lines"]
                    or int(findings) != entry["findings"]
                    or int(actionable) != entry["actionable"]):
                fails.append(
                    f"check 40: the table row for `{name}` reads "
                    f"{lines} lines / {findings} findings / {actionable} High+Crit; result.json "
                    f"gives {entry['lines']:,} / {entry['findings']} / {entry['actionable']}")
    return fails


def check_35_secbenchjs_claims_match_the_scorer(f: dict) -> list[str]:
    """`eval/secbenchjs/README.md` must say what `eval/secbenchjs/result.json` says.

    The same rule as check 27 and for the same reason, applied to the second benchmark on the day
    it lands rather than after its first figure has gone stale. Check 27 exists because four
    sentences kept a previous round's F3 through a green build; the lesson does not need learning
    twice, and a page that is not gated is a page that will drift.

    The per-class table is the part worth gating hardest: it is where the results this benchmark
    was built to expose live — the blind run's ReDoS 0/87 and prototype pollution 9/185, and what
    the engine scores now — and a table row is exactly the shape that gets edited for readability
    and quietly stops matching.
    """
    path = os.path.join(REPO, "eval", "secbenchjs", "result.json")
    page = os.path.join(REPO, "eval", "secbenchjs", "README.md")
    if not os.path.exists(path):
        return ["check 35: eval/secbenchjs/result.json is missing — it is the committed output "
                "of the scorer and every figure on the page is read from it"]
    if not os.path.exists(page):
        return ["check 35: eval/secbenchjs/README.md is missing"]
    with open(path, encoding="utf-8") as fh:
        result = json.load(fh)
    text = read(page)
    fails = []

    overall = result["overall"]
    recall = f"{overall['recall']}"
    if recall not in text:
        fails.append(f"check 35: the page never states the scored recall {recall}")
    headline = f"{overall['tp']} of {result['labels_scored']}"
    if headline not in text:
        fails.append(f"check 35: the page never states '{headline}' as the headline count")
    lower = f"{overall['precision_lower_bound']}"
    if lower not in text:
        fails.append(f"check 35: the page never states the unmatched-finding ratio {lower}, "
                     f"which it must name in order to say it is not a precision")
    if "precision_lower_bound" not in text:
        fails.append("check 35: the page must name the `precision_lower_bound` field, so a "
                     "reader who opens result.json sees the same disclaimer the page makes")

    for cls, stats in result["by_class"].items():
        row = f"| `{cls}` | {stats['tp']} / {stats['labels']} |"
        if row not in text:
            fails.append(f"check 35: the per-class table has no row `{row}` — result.json says "
                         f"{cls} scored {stats['tp']} of {stats['labels']}")
    for cause, n in result["misses_by_cause"].items():
        if f"| {n} |" not in text:
            fails.append(f"check 35: the misses-by-cause table never states {n} for "
                         f"'{cause}'")

    # The figure travels: it is on the benchmark page above, in both READMEs and on the site.
    # Check 27 learned this the expensive way about the other benchmark — four sentences kept a
    # previous round's F3 through a green build — so the second number is anchored everywhere it
    # is stated on the day it starts being stated, rather than after the first drift.
    elsewhere = {
        "README.md": (recall, f"{overall['tp']} of {result['labels_scored']}"),
        "README.tr.md": (recall,),
    }
    for rel, needles in elsewhere.items():
        page_text = read(os.path.join(REPO, rel))
        for needle in needles:
            if needle not in page_text:
                fails.append(f"check 35: {rel} does not state `{needle}` — the SecBench.js "
                             f"figure is published there and nothing was holding it to "
                             f"eval/secbenchjs/result.json")
    # Both READMEs, not just the English one. The Turkish page stated these classes as inline
    # prose, which a row-shaped check cannot see, and two of them went stale exactly that way:
    # it said prototype-pollution 62/185 and redos 26/87 while the scorer said 72 and 28. A
    # translated page is the one nobody re-reads when a number moves, so it now carries the same
    # table in the same shape — which is the only reason this check can hold it.
    for rel in ("README.md", "README.tr.md"):
        page_text = read(os.path.join(REPO, rel))
        for cls, stats in result["by_class"].items():
            row = f"| `{cls}` | {stats['tp']} / {stats['labels']} |"
            if row not in page_text:
                fails.append(f"check 35: {rel}'s per-class table has no row `{row}` — "
                             f"result.json says {cls} scored {stats['tp']} of {stats['labels']}")
    return fails


def check_36_the_install_command_matches_the_manifest(f: dict) -> list[str]:
    """Every `/plugin install` in the documentation must name the ids Claude Code will resolve.

    Found by installing the kit into an empty virtualenv and following the README from the top —
    the first line a new user types said `/plugin install secaudit` while the walkthrough forty
    lines down said `/plugin install secaudit@secaudit-kit`, and `docs/getting-started.md`
    agreed with the second. One of them had to be the wrong one to type first.

    Both identifiers live in `.claude-plugin/marketplace.json` and nowhere else, so this reads
    them from there. It is the same argument `gen_site.plugin_ids()` makes about the site, which
    is exactly why the site was right about this and the READMEs were not: the site derived it.
    """
    fails = []
    manifest = json.loads(read(os.path.join(REPO, ".claude-plugin", "marketplace.json")))
    plugins = manifest.get("plugins") or []
    if len(plugins) != 1:
        return [f"check 36: marketplace.json declares {len(plugins)} plugins; the documented "
                f"install command is written for exactly one"]
    expected = f"/plugin install {plugins[0]['name']}@{manifest['name']}"

    # Every markdown file that ships to a reader. The site is not in this list because it does
    # not type the command at all any more — it builds it from the same manifest.
    for rel in ("README.md", "README.tr.md", "docs/getting-started.md"):
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            continue
        for i, line in enumerate(read(path).splitlines(), 1):
            if "/plugin install" not in line or expected in line:
                continue
            fails.append(f"check 36: {rel}:{i} says `{line.strip()}` — the manifest names "
                         f"marketplace `{manifest['name']}` and plugin `{plugins[0]['name']}`, "
                         f"so the command a reader can paste is `{expected}`")
    return fails


def check_37_the_strict_reading_is_actually_stricter(f: dict) -> list[str]:
    """`strict_micro` in the RealVuln result must count the repositories that were not scanned.

    The published figure is a range — **33.4 – 35.9** — and the low end is the whole reason it is
    honest: four benchmark repositories are gone from GitHub, all four are dense teaching apps,
    and `strict_micro` is the reading where their 141 labels count as misses rather than as
    nothing. It is computed by the benchmark's own dashboard from the directories under
    `scan-results/`, which means it is destroyed by deleting them: the grid loses the four, every
    label they carry leaves the denominator, and `strict_micro` silently becomes a copy of
    `micro`. Nothing errors. The number that survives is the flattering one.

    That happened here, in the middle of a measurement round, from a `rm -rf scan-results/`
    between two runs. It is caught now rather than trusted to a note in a README, because the
    failure produces a *plausible* file — same shape, same keys, better score.
    """
    result = json.loads(read(os.path.join(REPO, "eval", "realvuln", "result.json")))
    micro, strict = result["overall"], result["strict_micro"]
    missing = len(result.get("repos_missing") or [])
    fails = []
    if result.get("repos_total") != result.get("repos_scored", 0) + missing:
        fails.append(
            f"check 37: result.json says {result.get('repos_total')} repositories total and "
            f"{result.get('repos_scored')} scored with {missing} named as missing — the three "
            f"do not add up, so the grid the strict reading was computed over is not the corpus")
    if missing and strict["fn"] <= micro["fn"]:
        fails.append(
            f"check 37: `strict_micro` counts {strict['fn']} misses and `overall` counts "
            f"{micro['fn']}, so the strict reading is not stricter. {missing} repositories were "
            f"never scanned and their labels have left the denominator — recreate their "
            f"directories under `scan-results/` and re-run `dashboard.py` (see "
            f"eval/realvuln/README.md, note 5). Publishing this file would drop the low end of "
            f"the published range and raise the headline for no reason but a deleted directory.")
    return fails


def check_39_the_run_history_holds_rounds_not_save_points(f: dict) -> list[str]:
    """No label may appear twice in the RealVuln run history.

    `collect_result.py` pushes the current figures into `previous_runs` every time it is called,
    which is right once per round and wrong the second time inside one. Collecting a round twice
    — because a rule was adjusted after the first measurement, which is the ordinary way a round
    goes — leaves the intermediate state in the history as if it had been a published result,
    and `--previous-label` stamps it with the *previous* round's name, so it is wrong twice: a
    save point, wearing someone else's label.

    This has now happened three times (an intermediate 34.4 during the structural round, and
    twice during the JavaScript one), each time caught by reading the file rather than by
    anything failing. Duplicate figures are not the signal — two consecutive rounds legitimately
    scored 35.9 — so the check is on the label, which is the one thing a round has to itself.
    """
    result = json.loads(read(os.path.join(REPO, "eval", "realvuln", "result.json")))
    labels = [r.get("label") for r in result.get("previous_runs", []) if r.get("label")]
    labels.append(result.get("run_label"))
    seen, fails = set(), []
    for label in labels:
        if label in seen:
            fails.append(
                f"check 39: the run history holds two rounds labelled {label!r}. A round appears "
                f"once; a second entry is a save point from collecting the same round twice, and "
                f"it carries the previous round's label rather than its own. Drop it from "
                f"`previous_runs` — the history is the argument that every delta is attributable "
                f"to one change, and a save point breaks that argument silently.")
        seen.add(label)
    return fails


def check_38_one_version_number(f: dict) -> list[str]:
    """`secaudit_core.__version__` and `pyproject.toml`'s `version` must agree.

    Two literals for one fact, with nothing holding them together and only one of them enforced:
    `release.yml` fails the build when the pushed tag does not match `pyproject.toml`, so a
    drifted `__version__` ships without anything noticing — and `__version__` is what a running
    installation reports about itself. The tag would be right, the package would be right, and
    the thing the user can actually read would be a release behind.
    """
    version = ""
    for line in read(os.path.join(KIT, "pyproject.toml")).splitlines():
        stripped = line.strip()
        if stripped.startswith("version") and "=" in stripped:
            version = stripped.split("=", 1)[1].strip().strip('"').strip("'")
            break
    module = ""
    for line in read(os.path.join(KIT, "secaudit_core", "__init__.py")).splitlines():
        if line.startswith("__version__"):
            module = line.split("=", 1)[1].strip().strip('"').strip("'")
            break
    if not version or not module:
        return [f"check 38: could not read both version literals "
                f"(pyproject {version!r}, __init__ {module!r})"]
    if version != module:
        return [f"check 38: `kit/pyproject.toml` says version {version} and "
                f"`secaudit_core.__version__` says {module}. The release workflow checks the tag "
                f"against the first and nothing checks the second, so `secaudit --version` would "
                f"report a number no release ever had."]
    return []


def check_43_the_strict_reading_is_derived_too(f: dict) -> list[str]:
    """The unflattering half of the RealVuln range has to come from the file as well.

    `eval/realvuln/README.md` publishes a *range* — `strict_micro` to `micro` — because four
    benchmark repositories are gone from GitHub and the strict aggregate is the reading in which
    their 141 labels count as misses. That paragraph exists so the lower number cannot be quietly
    dropped, and check 27 covered every other figure on the page except the one in it.

    It drifted the first round after that gap appeared: the range was updated to the new run and
    the sentence four lines above it kept the *previous* round's strict F3, recall and counts.
    Two disagreeing numbers in the same paragraph, in the passage whose whole job is honesty about
    the worse reading. A page that derives 95% of its figures grows its typed one exactly here —
    in the paragraph nobody thinks to doubt, because it is the self-critical one.
    """
    path = os.path.join(REPO, "eval", "realvuln", "result.json")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        result = json.load(fh)
    strict, micro = result.get("strict_micro"), result.get("overall")
    if not strict or not micro:
        return ["check 43: eval/realvuln/result.json has no `strict_micro` — the published range "
                "has nothing behind it"]
    rel = "eval/realvuln/README.md"
    text = read(os.path.join(REPO, *rel.split("/")))
    fails = []

    delta = round(micro["f3_score"] - strict["f3_score"], 1)
    m = re.search(r"stricter reading of this run, and it is ([\d.]+) points lower", text)
    if not m:
        fails.append(f"check 43: {rel} no longer states how far below the headline the strict "
                     f"reading sits")
    elif abs(float(m.group(1)) - delta) > 0.05:
        fails.append(f"check 43: {rel} says the strict reading is {m.group(1)} points lower; "
                     f"result.json makes it {delta}")

    for label, pattern, want in (
            ("strict F3", r"counts 141 further labels as missed — F3 \*\*([\d.]+)\*\*",
             f"{strict['f3_score']}"),
            ("strict recall", r"F3 \*\*[\d.]+\*\*, recall \*\*([\d.]+)\*\*",
             f"{strict['recall']:.4f}"),
            ("the range", r"the honest range for this run is \*\*([\d.]+) – [\d.]+\*\*",
             f"{strict['f3_score']}"),
            ("the range's upper bound", r"the honest range for this run is \*\*[\d.]+ – ([\d.]+)\*\*",
             f"{micro['f3_score']}"),
            ("the figure to quote", r"and ([\d.]+) is the one to use for any", f"{strict['f3_score']}"),
            ("the shared TP count", r"on\s+the identical (\d+) true positives", f"{micro['tp']}"),
            ("the shared FP count", r"true positives and (\d+) false ones", f"{micro['fp']}")):
        got = re.search(pattern, text)
        if not got:
            fails.append(f"check 43: {rel} no longer states {label} where check 43 reads it")
        elif got.group(1) != want:
            fails.append(f"check 43: {rel} states {got.group(1)} as {label}, result.json gives "
                         f"{want}")
    return fails


_FAMILY_SCORE_RE = re.compile(r"`(\w+)`\s*\((\d+)\s*(?:/|of)\s*(\d+)\)")

# Prose that cites a family score, and the files where such a citation is a live claim. CHANGELOG
# and the plan documents are excluded because a dated entry saying a family stood at 1/76 is a
# record of that day and stays true; `eval/realvuln/README.md` is excluded because check 27 holds
# its table cell by cell in a different shape.
_FAMILY_PROSE_FILES = ("README.md", "README.tr.md", "docs")


def check_45_a_family_score_in_prose_matches_the_scorer(f: dict) -> list[str]:
    """Any `family` (N/M) written into prose must be what `by_family` says today.

    This check exists because the front page was wrong for two days and nothing could see it.
    README.md's "what still does not move" sentence read `broken_access_control` (1/76),
    `missing_auth` (4/74), `path_traversal` (3/39) — the scorer said 2, 7 and **23**. The last
    one is the instructive number: path traversal had gone from 3 to 23 of 39, so the sentence
    was not merely stale, it was understating the tool by twenty labels on the page every
    reader starts at, in a paragraph headed by a claim that the class had not moved.

    Check 27 already holds `eval/realvuln/README.md`'s table this way. Nothing held the prose,
    and prose is where a number is quoted to somebody who will not open the table.
    """
    path = os.path.join(REPO, "eval", "realvuln", "result.json")
    if not os.path.exists(path):
        return ["check 45: eval/realvuln/result.json is missing — the family scores quoted in "
                "prose have nothing to be held against"]
    with open(path, encoding="utf-8") as fh:
        by_family = json.load(fh)["by_family"]

    fails = []
    for rel in _family_prose_paths():
        for m in _FAMILY_SCORE_RE.finditer(read(os.path.join(REPO, rel))):
            family, tp, total = m.group(1), int(m.group(2)), int(m.group(3))
            if family not in by_family:
                continue          # `codeview` (2/3) and the like — not a family claim.
            cell = by_family[family]
            if (tp, total) != (cell["tp"], cell["total"]):
                fails.append(f"check 45: {rel} states `{family}` ({tp}/{total}), result.json "
                             f"gives ({cell['tp']}/{cell['total']})")
    return fails


def _family_prose_paths() -> list[str]:
    """The markdown a reader meets before they meet a table."""
    out = []
    for entry in _FAMILY_PROSE_FILES:
        full = os.path.join(REPO, entry)
        if os.path.isdir(full):
            out.extend(os.path.join(entry, n) for n in sorted(os.listdir(full))
                       if n.endswith(".md"))
        elif os.path.exists(full):
            out.append(entry)
    return out


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
    check_31_every_finding_source_is_ranked,
    check_32_result_json_matches_the_engine_that_produced_it,
    check_33_every_test_function_is_actually_called,
    check_34_language_families_are_claimed_whole,
    check_35_secbenchjs_claims_match_the_scorer,
    check_40_noise_floor_claims_match_the_scorer,
    check_41_the_held_out_slice_is_still_sealed,
    check_42_the_result_files_agree_with_themselves,
    check_43_the_strict_reading_is_derived_too,
    check_44_cvefixes_claims_match_the_scorer,
    check_36_the_install_command_matches_the_manifest,
    check_37_the_strict_reading_is_actually_stricter,
    check_38_one_version_number,
    check_39_the_run_history_holds_rounds_not_save_points,
    check_45_a_family_score_in_prose_matches_the_scorer,
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
