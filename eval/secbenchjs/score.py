#!/usr/bin/env python3
"""Score this engine against SecBench.js, and be explicit about what the score can mean.

    python3 eval/secbenchjs/run.py   --packages ../secbench-pkgs
    python3 eval/secbenchjs/score.py --packages ../secbench-pkgs

WHY THIS EXISTS. Every published figure in `eval/realvuln/` describes Python. The JavaScript and
TypeScript side of this engine — 32 pattern rules, four structural analyses and a taint tier —
has never been scored by anyone outside this repository, and that gap has widened three times.
SecBench.js closes it, and closes it *blind*: no rule here was written or selected by reading its
labels, which is the one property RealVuln can no longer offer at any price.

WHAT THE TWO NUMBERS MEAN, because they do not mean the same thing.

**Recall is sound.** Each entry is one npm package at one pinned version with one labelled sink
at `file:line`. Either the scan reported something of the right class within tolerance of that
line or it did not. That is a fair question and the answer is comparable across tools.

**Precision is a LOWER BOUND and is not comparable to the RealVuln figure.** SecBench.js labels
*one* vulnerability per package and says nothing about the rest of the code. A finding elsewhere
in the package is counted here as a false positive even when it is a real flaw the benchmark
simply never labelled — and these are unaudited npm packages, so some of them are. RealVuln
labels many findings per repository and publishes false-positive traps, which is what makes a
precision number mean something there. Quoting this one beside it would be comparing two
different measurements that share a name.

MATCHING. File path, then class, then line within ±10 — the same tolerance RealVuln's own scorer
uses, adopted so the two runs are at least internally consistent. The class map below is the
benchmark's five categories expressed as the CWEs this engine emits; it is stated rather than
derived because it is a claim about SecBench.js's taxonomy, not about this repository's code.

**The label's path is not always a path in the package, and comparing the two literally made this
scorer count misses it had caused itself.** SecBench.js records a sink as `util.js:143` or
`merge/dist/lib/merge.js:12` — sometimes a bare basename, sometimes carrying a monorepo or
package-name prefix that the published tarball does not have (`ajv`'s `util.js` is
`lib/compile/util.js` on disk; `viking04-merge`'s `merge/index.js` is `index.js`). The old
comparison filed every one of those under *"no rule fired at the sink"*, which is the same mistake
this file already made once with `dist/` and wrote up under [What the first run's three findings
turned into] — a miss attributed to the wrong cause aims the next round at the wrong thing, and
here it was aiming at detection for labels that were never being looked up at all. The count is
in `misses_by_cause` and in `README.md`, from the run rather than from this sentence.

`_resolve_sink` therefore resolves the label against the files actually present: the stated path
if it exists, else the unique file whose path matches it on component boundaries in either
direction (the label may be missing leading components, or carrying extra ones). Three guards,
because a resolver that guesses is worse than one that declines:

* **unique or nothing** — several candidates and the label is reported unresolved, never picked
  between. `dist/`, `src/` and `lib/` copies of one file are the normal case in this corpus.
* **the file has to be long enough to contain the line** — a candidate with 40 lines is not where
  `:143` lives, whatever its name.
* **the two remaining causes are named in the output** rather than folded back into "no rule
  fired": a label whose file is not in the published package at all (a TypeScript source, a
  `build/` the tarball omits), and a label that resolves ambiguously.

It is worth being explicit that this change moves the published recall **up** on an unchanged
engine, which is the direction that deserves the most scepticism. Most of what it resolves stays a
miss and merely gets counted under a truthful cause; only a handful become hits. That ratio is the
argument that this is a fidelity fix rather than a flattering one — the exact figures are in
`README.md` next to the run that produced them. `blind_run` below was re-measured through the same
matcher, on the same engine that produced it, so the two figures stay comparable.

MISSES ARE BROKEN OUT BY CAUSE, because "the rule did not fire" and "the file was never opened"
are different problems with different fixes and only one of them is about detection. The second
category is not hypothetical here and it is the sharpest thing this benchmark has said about the
engine so far: **36 labelled sinks live under `build/` or `dist/`**, which the scanner skips as
build output. That is the right default for an application repository, where `dist/` is generated
and the source beside it is what a developer edits — and it is exactly wrong for a *published npm
package*, where `dist/` is not a by-product but the artifact that actually runs on the installing
machine. They are counted as misses, because from the installer's point of view they are, and
they are counted separately, because fixing them is a scoping decision rather than a rule.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "kit"))

from secaudit_core.engine import SKIP_DIRS, _published_build_dirs   # noqa: E402
from secaudit_core.langs import JSTS_EXTS                           # noqa: E402

LINE_TOLERANCE = 10

# What a label that could not be resolved to a file is counted as. Three different problems, and
# none of them is "the rule did not fire" — which is what all three used to be reported as.
_UNRESOLVED_CAUSE = {
    "absent": "labelled file is not in the published package",
    "ambiguous": "labelled file is ambiguous — the package holds more than one of that name",
    "too_short": "labelled file is too short to contain the labelled line",
}

# The first run of this benchmark, recorded because it is the only one that will ever be blind.
#
# **It used to say "the engine that produced it is gone, so recomputing it is impossible", and
# that was wrong in a way worth keeping.** The engine was not gone; it was a `git worktree add`
# away. Believing otherwise cost something concrete: when the scorer's path matcher was fixed on
# 2026-08-17, the blind figure could not be corrected with it, and the table would have compared
# a run measured one way against a run measured another.
#
# So it was re-measured: worktree at 8ac20f4, `eval/secbenchjs/run.py --engine-kit <that>/kit`,
# 594 packages freshly scanned, 0 reused. Scored with the matcher of the day it was published it
# returns **128 / 573, recall 0.2234, and every per-class figure identical** — the reproduction
# is exact and the procedure is now proven rather than asserted. The numbers below are that same
# run scored with the current matcher, which is the like-for-like comparison the table needs.
# (One number did not reproduce: the unmatched count came back 2,030 against the 1,966 recorded,
# +64. `react-native@0.63.0-rc.0` accounts for 66 of them on its own — the earlier run abandoned
# it at the old 120-second bound and this one finishes it at 300s — so the corpus was 593
# packages then and 594 now, and two findings elsewhere move the other way for a reason nobody
# has established. Recall is identical either way, which is exactly why a corpus that changes
# size between runs can sit unnoticed; it is the same defect the timeout note in README.md
# describes.)
#
# It stays a literal because it is a historical fact rather than a derivation, and because every
# later run is corpus-informed — this is the figure to quote when the question is *how does this
# engine do on code it has never seen*.
BLIND_RUN = {
    "run_date": "2026-08-16",
    "remeasured": "2026-08-17",
    "note": "The only blind run. No rule in this engine had been written or selected by reading "
            "a SecBench.js label when this was measured. Re-measured on 2026-08-17 from a "
            "worktree at the commit that produced it, so that the scorer's corrected path "
            "matcher applies to it as well: with the original matcher it reproduces 128 / 573 "
            "and recall 0.2234 exactly, and the figures here are that run scored the way every "
            "figure in this file is scored now.",
    "engine_digest": "sha256:e4ee787354b0e91a60d1214abb64841e0b6f8475233f1d0634f932c2bd6952cb",
    "overall": {"tp": 131, "fn": 442, "fp_unmatched": 2030,
                "recall": 0.2286, "precision_lower_bound": 0.0606},
    "overall_as_first_published": {"tp": 128, "fn": 445, "fp_unmatched": 1966,
                                   "recall": 0.2234, "precision_lower_bound": 0.0611},
    "by_class": {
        "code-injection": {"tp": 19, "labels": 33},
        "command-injection": {"tp": 41, "labels": 101},
        "path-traversal": {"tp": 61, "labels": 167},
        "prototype-pollution": {"tp": 10, "labels": 185},
        "redos": {"tp": 0, "labels": 87},
    },
    "misses_by_cause": {
        "no rule fired at the sink": 396,
        "labelled file is not in the published package": 32,
        "labelled file is ambiguous — the package holds more than one of that name": 4,
        "sink is in a file type no detector claims": 2,
        "sink is under build/, which the scanner skips as build output": 1,
        "sink is under dist/, which the scanner skips as build output": 1,
    },
}

# SecBench.js's five categories, as the CWEs this engine emits for them. `ace_breakout` is the
# benchmark's name for sandbox escapes that end in arbitrary code execution, which is what its
# `code-injection` directory holds.
CLASS_CWES: dict[str, tuple[str, ...]] = {
    "command-injection": ("CWE-78",),
    "path-traversal": ("CWE-22",),
    "prototype-pollution": ("CWE-1321", "CWE-915"),
    "redos": ("CWE-1333", "CWE-400"),
    "code-injection": ("CWE-94", "CWE-95"),
}


def norm(path: str) -> str:
    return path.replace("\\", "/").lstrip("./").lower()


def load_entries(packages: str) -> list[dict]:
    with open(os.path.join(packages, "entries.json"), encoding="utf-8") as fh:
        return json.load(fh)


def sink_of(entry: dict) -> tuple[str, int] | None:
    """`index.js:18:3` -> ("index.js", 18). Column is recorded by the benchmark and ignored
    here: this engine reports a line, and inventing a column to compare against would be a
    precision the finding does not have."""
    raw = entry.get("sink") or ""
    if not raw or raw in ("n/a",):
        return None
    parts = raw.split(":")
    if len(parts) < 2:
        return None
    try:
        return norm(parts[0]), int(parts[1])
    except ValueError:
        return None


def results_path(packages: str, entry: dict) -> str:
    return os.path.join(packages, "scan-results", entry["class"], entry["dir"] + ".json")


def package_files(pkg_dir: str) -> list[str]:
    """Every file in the package, as the engine would spell it: relative, `/`, lower-case."""
    out: list[str] = []
    for root, _dirs, files in os.walk(pkg_dir):
        for name in files:
            out.append(norm(os.path.relpath(os.path.join(root, name), pkg_dir)))
    return out


def _long_enough(pkg_dir: str, rel: str, line: int) -> bool:
    """Whether `rel` even has a line `line`. A 40-line file is not where `:143` is."""
    try:
        with open(os.path.join(pkg_dir, rel.replace("/", os.sep)), "rb") as fh:
            return sum(1 for _ in fh) >= line
    except OSError:
        return False


def _resolve_sink(pkg_dir: str, files: list[str], label: str, line: int) -> tuple[str, str]:
    """Where the labelled sink actually lives, and how that was decided.

    Returns `(path, status)` with status one of `exact`, `resolved`, `ambiguous`, `too_short`,
    `absent`. See the module docstring for why this is not simply a string comparison. The two
    directions are both real in this corpus and they are not the same mistake:

        label `util.js`               file `lib/compile/util.js`   — label missing its directory
        label `merge/dist/lib.js`     file `dist/lib.js`           — label carrying a package prefix

    so a candidate qualifies when either path is a suffix of the other **on component
    boundaries**. `lib.js` and `sub/mylib.js` do not match; `lib.js` and `sub/lib.js` do.
    """
    if label in files:
        return label, "exact"
    want = label.split("/")
    named = []
    for f in files:
        have = f.split("/")
        if have[-len(want):] == want or want[-len(have):] == have:
            named.append(f)
    candidates = [c for c in named if _long_enough(pkg_dir, c, line)]
    if len(candidates) == 1:
        return candidates[0], "resolved"
    if candidates:
        return "", "ambiguous"
    return "", "too_short" if named else "absent"


def _sealed_packages() -> set[str]:
    """The held-out slice, from `eval/heldout.json`. Empty when no seal is declared.

    Read here rather than recomputed from the hash, even though the rule is deterministic: the
    register is the artefact check 41 enforces against, so the scorer and the gate must be
    looking at the same list. Two implementations of one rule is how they stop agreeing.
    """
    path = os.path.join(REPO, "eval", "heldout.json")
    if not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as fh:
        register = json.load(fh)
    return {name for corpus in register.get("corpora", {}).values()
            for name in corpus.get("packages", [])}


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--packages", required=True, help="output directory of fetch_packages.py")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                  "result.json"))
    ap.add_argument("--run-date", required=True, help="date of the run, YYYY-MM-DD")
    args = ap.parse_args(argv)

    packages = os.path.abspath(args.packages)
    entries = load_entries(packages)

    per_class = collections.defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "labels": 0})
    unlabelled = unfetched = unscanned = 0
    # Why a miss was a miss. Derived from the engine's own scope rules rather than a second copy
    # of them, so a change to SKIP_DIRS shows up here instead of quietly making this wrong.
    causes = collections.Counter()
    # How each label's path was turned into a path in the package. Published because a matcher
    # that silently resolves is a matcher nobody audits: `exact` falling is the signal that the
    # corpus changed shape, and `resolved` rising is the signal to re-read this scorer.
    resolutions: collections.Counter[str] = collections.Counter()
    tp = fn = fp = 0
    missed_samples = collections.defaultdict(list)
    digests: set[str] = set()
    # The held-out slice (eval/HELDOUT.md). Sealed packages are scored exactly like the rest —
    # the headline recall covers the whole corpus — but they are reported as their own column and
    # never named in the output. A committed file that lists which sealed packages were missed is
    # a diagnosis aid, which is the one thing the seal exists to withhold; check 41 caught this
    # file doing it the first time it ran.
    sealed = _sealed_packages()
    by_seal = {"sealed": {"tp": 0, "labels": 0}, "unsealed": {"tp": 0, "labels": 0}}

    for entry in entries:
        cls = entry["class"]
        sink = sink_of(entry)
        if sink is None:
            unlabelled += 1
            continue
        per_class[cls]["labels"] += 1
        slice_ = "sealed" if entry["dir"] in sealed else "unsealed"
        by_seal[slice_]["labels"] += 1
        pkg_dir = os.path.join(packages, cls, entry["dir"])
        if not os.path.isdir(pkg_dir) or not os.listdir(pkg_dir):
            unfetched += 1
            per_class[cls]["fn"] += 1
            fn += 1
            continue
        rpath = results_path(packages, entry)
        if not os.path.exists(rpath):
            unscanned += 1
            per_class[cls]["fn"] += 1
            fn += 1
            continue
        with open(rpath, encoding="utf-8") as fh:
            payload = json.load(fh)
        findings = payload.get("findings", [])
        # Which engine produced this scan. Collected per package rather than read off the current
        # tree, because those are different questions: the tree says what the code is *now*, and
        # this says what actually emitted the findings being scored. A mixed set is refused below.
        digests.add(payload.get("engine_digest") or "")

        want = CLASS_CWES[cls]
        label_file, sink_line = sink
        # The label's path, resolved against the files that are actually in the package. Every
        # question below — did a finding land on it, was it skipped as build output, is it a file
        # type no detector claims — is asked of the resolved path, because asking it of a path
        # that does not exist answers about nothing. `sink_file` is empty when the label could not
        # be resolved, and the loop below reports that as its own cause rather than as detection.
        sink_file, resolution = _resolve_sink(pkg_dir, package_files(pkg_dir), label_file,
                                              sink_line)
        resolutions[resolution] += 1
        parts = sink_file.split("/")
        # "Skipped as build output" has to be asked of the engine, not of the path. A sink under
        # `dist/` in a package whose own `package.json` publishes `dist/` IS scanned, and calling
        # its miss a scoping decision would file a detection failure under the wrong cause —
        # flattering, and in the direction of "we could find this if we looked", which is exactly
        # what this table exists to test. So the manifest decides here the same way it decides in
        # the engine, by calling the engine's own function.
        published = _published_build_dirs(pkg_dir, os.listdir(pkg_dir))
        out_of_scope = next(
            (p for p in parts[:-1] if p in SKIP_DIRS and p not in published), "")
        wrong_type = os.path.splitext(sink_file)[1] not in JSTS_EXTS
        hit = False
        for f in findings:
            same_file = norm(f.get("file", "")) == sink_file
            same_class = f.get("cwe") in want
            close = abs(int(f.get("line", 0)) - sink_line) <= LINE_TOLERANCE
            if same_file and same_class and close:
                hit = True
                break
        if hit:
            tp += 1
            per_class[cls]["tp"] += 1
            by_seal[slice_]["tp"] += 1
        else:
            fn += 1
            per_class[cls]["fn"] += 1
            if resolution in _UNRESOLVED_CAUSE:
                # Not a detection failure and not a scoping one: the scan never had this file to
                # look at, or the label names a file the package holds more than one of. Counted
                # as a miss all the same — a label this run cannot check is a label it did not
                # find — but named, so nobody spends a round writing rules for it.
                causes[_UNRESOLVED_CAUSE[resolution]] += 1
            elif out_of_scope:
                causes[f"sink is under {out_of_scope}/, which the scanner skips as build output"] += 1
            elif wrong_type:
                causes["sink is in a file type no detector claims"] += 1
            else:
                causes["no rule fired at the sink"] += 1
                if len(missed_samples[cls]) < 5 and entry["dir"] not in sealed:
                    missed_samples[cls].append(f"{entry['dir']} :: {entry['sink']}")
        # Everything else the scan reported in this package is unmatched. See the module
        # docstring: this is a lower bound on precision, not a comparable precision.
        for f in findings:
            same_file = norm(f.get("file", "")) == sink_file
            same_class = f.get("cwe") in want
            close = abs(int(f.get("line", 0)) - sink_line) <= LINE_TOLERANCE
            if not (same_file and same_class and close):
                fp += 1
                per_class[cls]["fp"] += 1

    labels = tp + fn
    recall = round(tp / labels, 4) if labels else 0.0
    precision_lb = round(tp / (tp + fp), 4) if (tp + fp) else 0.0

    # One engine, or no figure. `run.py` keys its cache on the digest so a stale result is
    # rescanned rather than served — but nothing stopped *scoring* a directory holding scans from
    # two engines, and the aggregate of those is a number no engine ever produced. The same
    # defect as the cache bug one step later: it does not look wrong, it looks like a result.
    if len(digests) > 1:
        raise SystemExit(
            "REFUSING TO SCORE — the scan results were produced by more than one engine:\n"
            + "\n".join(f"  - {d or '(no digest recorded)'}" for d in sorted(digests))
            + "\nRe-run eval/secbenchjs/run.py so every package is scanned by one engine.")
    digest = next(iter(digests), "")

    result = {
        "note": "Scored by eval/secbenchjs/score.py against SecBench.js sink locations. "
                "Recall is the sound metric; precision is a LOWER BOUND and is not comparable "
                "to the RealVuln figure — see the module docstring and README.md.",
        "benchmark": "SecBench.js (github.com/cristianstaicu/SecBench.js, ISC)",
        "run_date": args.run_date,
        "engine_digest": digest,
        "engine_digest_note": "sha256 over every secaudit_core module that can change what the "
                              "measured run emits, taken from the scan results themselves rather "
                              "than from the working tree — this records the engine that produced "
                              "these findings. Check 32 recomputes it and fails the build when it "
                              "moves, because the figures then describe an engine that no longer "
                              "exists. RealVuln's result.json had this from the round where a "
                              "published precision of 0.5419 turned out to describe an engine "
                              "that actually returned 0.4711; the SecBench figures are published "
                              "in four documents and had nothing holding them to the code.",
        "line_tolerance": LINE_TOLERANCE,
        "blind": False,
        "blind_note": "This run is NOT blind. The engine has since been changed in response to "
                      "what the blind run below reported, which is corpus-informed selection in "
                      "exactly the way RealVuln's figure has been since its third run. Quote "
                      "`blind_run` when the question is how this engine does on unseen code.",
        "blind_run": BLIND_RUN,
        "entries_total": len(entries),
        "packages_scanned": len(entries) - unfetched - unscanned,
        "labels_scored": labels,
        "labels_without_a_sink_location": unlabelled,
        "packages_not_fetched": unfetched,
        "packages_not_scanned": unscanned,
        "overall": {"tp": tp, "fn": fn, "fp_unmatched": fp,
                    "recall": recall, "precision_lower_bound": precision_lb},
        "misses_by_cause": dict(causes.most_common()),
        "sink_resolution": dict(resolutions.most_common()),
        "sink_resolution_note": "How each label's stated path was matched to a file in the "
                                "package: `exact` it was already one, `resolved` a unique file "
                                "matched it on component boundaries in one direction or the "
                                "other, and the rest could not be resolved and are counted as "
                                "misses under their own causes. See the module docstring.",
        "by_class": {k: dict(v, recall=round(v["tp"] / v["labels"], 4) if v["labels"] else 0.0)
                     for k, v in sorted(per_class.items())},
        "by_seal": {k: dict(v, recall=round(v["tp"] / v["labels"], 4) if v["labels"] else 0.0)
                    for k, v in by_seal.items()},
        "by_seal_note": "The held-out slice, per eval/HELDOUT.md. Sealed packages are scored "
                        "but never inspected, and their names never appear in this file. Today "
                        "this is a BASELINE and not a blind figure — they were in the corpus for "
                        "the blind run and both tuned rounds. Its value is the next round: if "
                        "`unsealed` moves and `sealed` does not, that round bought corpus fit "
                        "rather than detection.",
        "missed_samples": dict(sorted(missed_samples.items())),
    }
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print(f"SecBench.js — {labels} labelled sinks scored, {tp} found.")
    print(f"  recall {recall}  |  precision (lower bound) {precision_lb}")
    for cls, v in sorted(per_class.items()):
        print(f"    {cls:<22} {v['tp']:>3} / {v['labels']:<4} "
              f"({100 * v['tp'] / v['labels'] if v['labels'] else 0:.1f}%)")
    print("  sink paths: " + " · ".join(f"{k} {v}" for k, v in resolutions.most_common()))
    if causes:
        print("  misses by cause:")
        for cause, n in causes.most_common():
            print(f"    {n:>4}  {cause}")
    if unlabelled or unfetched or unscanned:
        print(f"  no sink location: {unlabelled} · not fetched: {unfetched} · "
              f"not scanned: {unscanned}")
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
