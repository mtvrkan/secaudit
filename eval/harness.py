#!/usr/bin/env python3
"""Score SecAudit against a labelled corpus, and write the scorecard.

    python3 eval/harness.py                 # score the shipped fixtures, write eval/scorecard.*
    python3 eval/harness.py --check         # fail if the committed scorecard is stale (CI)
    python3 eval/harness.py --gate          # fail if a metric regressed past eval/thresholds.json
    python3 eval/harness.py --results R.json --ground-truth G.json   # score an external corpus

Why this exists: the README used to say "19/19 target sink classes", which is a real number
about a corpus the detectors were tuned against — useful as a regression floor, useless as a
claim about anyone else's code. This harness computes the metrics that are comparable
(precision, recall, F1, F3, per class and per language) in the same shape the
[RealVuln](https://github.com/kolega-ai/Real-Vuln-Benchmark) benchmark uses, so the number we
publish about ourselves and the number a third party publishes about us mean the same thing.

**Scoring rules — read these before quoting a number.**

* A result *matches* a labelled region when the file matches, the reported line falls inside
  `[start_line, end_line]`, and the result's CWE is in the label's `acceptable_cwes`.
* **TP** — a `is_vulnerable: true` region with at least one matching result.
* **FN** — a `is_vulnerable: true` region with none.
* **FP** — a result landing inside a `is_vulnerable: false` region: a *false-positive trap*,
  the safe implementation of the same feature. This is the strictest kind of trap there is.
* **Unlabelled** — a result inside no labelled region at all. Counted and reported, but
  **not** scored as a false positive, because our ground truth only labels planted flaws and
  an unlabelled hit may well be a real finding nobody planted. Folding those into precision
  would be inventing data in our own favour or against it, depending on the corpus.

That last rule means **precision here is an upper bound**, and the scorecard says so. A
corpus that labels every line (RealVuln does not either) would remove the caveat; until then,
the honest move is to state the bound rather than round it away.

F-beta weights recall β× as heavily as precision: `F3` (β=3, recall 9×) is RealVuln's primary
metric, on the reasoning that a missed vulnerability costs more than a triaged false alarm.
Both F1 and F3 are reported, because which one matters depends on whether a human or a gate
reads the output.
"""
from __future__ import annotations

import json
import os
import sys
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KIT = os.path.join(REPO, "kit")
EVAL = os.path.join(REPO, "eval")
GROUND_TRUTH = os.path.join(EVAL, "ground-truth", "secaudit-fixtures", "ground-truth.json")
SCORECARD_MD = os.path.join(EVAL, "scorecard.md")
SCORECARD_JSON = os.path.join(EVAL, "scorecard.json")
THRESHOLDS = os.path.join(EVAL, "thresholds.json")

sys.path.insert(0, KIT)


# --------------------------------------------------------------------------- metrics

def fbeta(precision: float, recall: float, beta: float) -> float:
    """F-beta. Returns 0.0 when both inputs are 0 — an undefined score is not a perfect one."""
    b2 = beta * beta
    denominator = b2 * precision + recall
    return 0.0 if denominator == 0 else (1 + b2) * precision * recall / denominator


class Tally:
    __slots__ = ("tp", "fn", "fp")

    def __init__(self) -> None:
        self.tp = self.fn = self.fp = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    def as_dict(self) -> dict:
        return {
            "tp": self.tp, "fn": self.fn, "fp": self.fp,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(fbeta(self.precision, self.recall, 1), 4),
            "f3": round(fbeta(self.precision, self.recall, 3), 4),
        }


# --------------------------------------------------------------------------- scoring

def result_cwes(result: dict) -> set[str]:
    meta = result.get("extra", {}).get("metadata", {}) or {}
    cwes = meta.get("cwe") or []
    if isinstance(cwes, str):
        cwes = [cwes]
    out = set()
    for entry in cwes:
        # Semgrep writes "CWE-89: Improper Neutralization…"; take the identifier.
        out.add(str(entry).split(":")[0].strip())
    return out


def same_file(result_path: str, label_path: str) -> bool:
    """Whether two paths name the same file, tolerating different roots but not different dirs.

    Comparing basenames would be simpler and wrong: the two fixture corpora contain files with
    identical names (`auth.js`, `util.js`, `py_app.py`), so a basename match scores every
    vulnerable-app detection as a false positive on the secure-app trap of the same name — the
    exact opposite of the truth. Suffix matching on whole path components keeps that apart
    while still tolerating a scanner that reports absolute paths against relative labels."""
    a = result_path.replace("\\", "/").lstrip("./")
    b = label_path.replace("\\", "/").lstrip("./")
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def matches(result: dict, label: dict) -> bool:
    if not same_file(result.get("path", ""), label["file"]):
        return False
    line = (result.get("start") or {}).get("line", 0)
    location = label["location"]
    if not (location["start_line"] <= line <= location["end_line"]):
        return False
    acceptable = set(label.get("acceptable_cwes") or [label.get("primary_cwe")])
    return bool(result_cwes(result) & acceptable)


def score(results: list[dict], labels: list[dict]) -> dict:
    overall = Tally()
    by_class: dict[str, Tally] = defaultdict(Tally)
    by_language: dict[str, Tally] = defaultdict(Tally)
    by_cwe: dict[str, Tally] = defaultdict(Tally)
    matched_results: set[int] = set()
    misses: list[str] = []
    trap_hits: list[str] = []

    for label in labels:
        hits = [i for i, r in enumerate(results) if matches(r, label)]
        matched_results.update(hits)
        buckets = (overall, by_class[label["vulnerability_class"]],
                   by_language[label.get("language", "other")],
                   by_cwe[label.get("primary_cwe", "unclassified")])
        if label["is_vulnerable"]:
            if hits:
                for b in buckets:
                    b.tp += 1
            else:
                for b in buckets:
                    b.fn += 1
                misses.append(f"{label['id']} — {label['vulnerability_class']} "
                              f"({label['file']}:{label['location']['start_line']})")
        elif hits:
            for b in buckets:
                b.fp += 1
            checks = sorted({results[i].get("check_id", "?") for i in hits})
            trap_hits.append(f"{label['id']} — {label['vulnerability_class']} "
                             f"({label['file']}) hit by {', '.join(checks)}")

    unlabelled = [r for i, r in enumerate(results) if i not in matched_results]
    return {
        "overall": overall.as_dict(),
        "by_class": {k: v.as_dict() for k, v in sorted(by_class.items())},
        "by_language": {k: v.as_dict() for k, v in sorted(by_language.items())},
        # Keyed by CWE as well as by our own class names: a class name is ours to rename, a
        # CWE is the identifier every other tool, benchmark and compliance mapping speaks. A
        # breakdown only in local vocabulary cannot be compared with anyone.
        "by_cwe": {k: v.as_dict() for k, v in sorted(by_cwe.items())},
        "misses": misses,
        "trap_hits": trap_hits,
        "unlabelled_results": len(unlabelled),
        "labelled_vulnerabilities": sum(1 for l in labels if l["is_vulnerable"]),
        "false_positive_traps": sum(1 for l in labels if not l["is_vulnerable"]),
        "total_results": len(results),
    }


# --------------------------------------------------------------------------- running

def scan_fixtures() -> list[dict]:
    """Run the engine over both fixture corpora and return Semgrep-shaped results.

    Dependency scanning is off: `npm audit` needs a network and a registry, and a score that
    changes with the weather is not a regression gate."""
    from secaudit_core import engine, report

    results: list[dict] = []
    for corpus in ("vulnerable-app", "secure-app"):
        root = os.path.join(REPO, "tests", "fixtures", corpus)
        scan = engine.scan(root, run_deps=False, use_scanners=False)
        payload = json.loads(report.to_semgrep_json(scan))
        for r in payload["results"]:
            r["path"] = f"{corpus}/{r['path']}"
            results.append(r)
    return results


def labels_for(results: list[dict], all_labels: list[dict]) -> list[dict]:
    """Scope labels to the corpus a result set covers, so scoring one corpus does not count
    the other's labels as misses."""
    corpora = {r["path"].split("/")[0] for r in results if "/" in r["path"]}
    scoped = [l for l in all_labels if l.get("corpus", "") in corpora] if corpora else all_labels
    return scoped or all_labels


def qualify(labels: list[dict]) -> list[dict]:
    """Prefix each label's file with its corpus, matching how `scan_fixtures` qualifies paths."""
    out = []
    for label in labels:
        copy = dict(label)
        if label.get("corpus"):
            copy["file"] = f"{label['corpus']}/{label['file']}"
        out.append(copy)
    return out


# --------------------------------------------------------------------------- rendering

def render_markdown(data: dict) -> str:
    o = data["overall"]
    lines = [
        "# SecAudit — measured detection quality",
        "",
        "<!-- Generated by `python3 eval/harness.py`. Do not edit by hand; CI fails on drift. -->",
        "",
        f"Corpus: **{data['corpus']}** · {data['labelled_vulnerabilities']} labelled "
        f"vulnerabilities · {data['false_positive_traps']} false-positive traps "
        f"(safe implementations of the same features) · Tier 0 only, no LLM, no external "
        f"scanners, no network.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Recall | **{o['recall']:.1%}** ({o['tp']}/{o['tp'] + o['fn']}) |",
        f"| Precision (upper bound — see below) | **{o['precision']:.1%}** |",
        f"| F1 | **{o['f1']:.3f}** |",
        f"| F3 (recall-weighted, RealVuln's primary metric) | **{o['f3']:.3f}** |",
        f"| False positives on traps | **{o['fp']}** / {data['false_positive_traps']} |",
        f"| Results in no labelled region | {data['unlabelled_results']} (not scored — see below) |",
        "",
        "## By language",
        "",
        "| Language | TP | FN | FP | Recall | Precision | F3 |",
        "|---|---|---|---|---|---|---|",
    ]
    for language, m in data["by_language"].items():
        lines.append(f"| {language} | {m['tp']} | {m['fn']} | {m['fp']} | {m['recall']:.0%} "
                     f"| {m['precision']:.0%} | {m['f3']:.3f} |")

    lines += ["", "## By vulnerability class", "",
              "| Class | TP | FN | FP | Recall |", "|---|---|---|---|---|"]
    for vclass, m in data["by_class"].items():
        lines.append(f"| {vclass} | {m['tp']} | {m['fn']} | {m['fp']} | {m['recall']:.0%} |")

    lines += ["",
              "## By CWE",
              "",
              "The same results keyed by CWE rather than by this project's own class names, "
              "so they can be compared against another tool's or a benchmark's breakdown.",
              "",
              "| CWE | TP | FN | FP | Recall |",
              "|---|---|---|---|---|"]
    for cwe, m in data["by_cwe"].items():
        lines.append(f"| `{cwe}` | {m['tp']} | {m['fn']} | {m['fp']} | {m['recall']:.0%} |")

    lines += ["", "## What was missed", ""]
    lines += [f"- {m}" for m in data["misses"]] or ["_Nothing — every labelled vulnerability "
                                                   "was detected._"]
    if data["trap_hits"]:
        lines += ["", "## False positives on the safe fixture", ""]
        lines += [f"- {t}" for t in data["trap_hits"]]

    lines += [
        "",
        "## How to read this",
        "",
        "- **These fixtures were written alongside the detectors**, so this is a regression "
        "floor, not a prediction of performance on your code. Published external numbers are "
        "the ones to compare against — see [`realvuln/`](realvuln/).",
        "- **Precision is an upper bound.** Results landing outside any labelled region are "
        "counted and reported but not scored as false positives, because the ground truth "
        "only labels planted flaws and an unlabelled hit may be a real finding. See the "
        "scoring rules in `eval/harness.py`.",
        "- The traps are the hard part: each is a *safe implementation of the same feature* as "
        "its vulnerable twin, not unrelated clean code.",
        "- Tier 1 (LLM triage and logic-bug discovery) is excluded on purpose. It is not "
        "reproducible, so it does not belong in a regression gate.",
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- entry point

def load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    def flag(name: str) -> str | None:
        return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else None

    gt_path = flag("--ground-truth") or GROUND_TRUTH
    ground_truth = load(gt_path)

    results_path = flag("--results")
    if results_path:
        payload = load(results_path)
        results = payload.get("results", payload if isinstance(payload, list) else [])
        labels = ground_truth["findings"]
    else:
        results = scan_fixtures()
        labels = qualify(labels_for(results, ground_truth["findings"]))

    data = score(results, labels)
    data["corpus"] = ground_truth.get("repo_id", os.path.basename(gt_path))
    data["ground_truth_schema"] = ground_truth.get("schema_version", "unknown")

    rendered_md = render_markdown(data)
    rendered_json = json.dumps(data, indent=2, ensure_ascii=False) + "\n"

    if "--check" in argv:
        stale = []
        for path, rendered in ((SCORECARD_MD, rendered_md), (SCORECARD_JSON, rendered_json)):
            try:
                with open(path, encoding="utf-8") as f:
                    if f.read() != rendered:
                        stale.append(os.path.relpath(path, REPO))
            except OSError:
                stale.append(os.path.relpath(path, REPO))
        if stale:
            print("FAIL — the committed scorecard no longer matches what the engine measures: "
                  + ", ".join(stale) + "\n  Run: python3 eval/harness.py")
            return 1
        print("Scorecard is current.")
        return 0

    if "--gate" in argv:
        thresholds = load(THRESHOLDS)
        o = data["overall"]
        failures = []
        # Compare at the precision the floor is stated and the scorecard is rendered at.
        # Comparing a raw float against a 3-decimal floor fails on a value that displays as
        # exactly the floor (0.9569… vs 0.957) — an off-by-epsilon trap that would bite every
        # future contributor and teach them to lower the floor to make it go away.
        def at(value: float) -> float:
            return round(value, 3)

        if at(o["recall"]) < thresholds["min_recall"]:
            failures.append(f"recall {at(o['recall']):.3f} < floor {thresholds['min_recall']}")
        if at(o["f3"]) < thresholds["min_f3"]:
            failures.append(f"F3 {at(o['f3']):.3f} < floor {thresholds['min_f3']}")
        if o["fp"] > thresholds["max_trap_false_positives"]:
            failures.append(f"{o['fp']} false positives on safe-implementation traps "
                            f"> limit {thresholds['max_trap_false_positives']}")
        # Per-class and per-CWE loss. An aggregate can improve while a whole class stops
        # being detected — add three fixtures of one kind, lose the only fixture of another,
        # and overall recall goes UP. That is the regression this catches, and the floors are
        # not typed anywhere: they are read from the committed scorecard, so "was detected
        # before, is not now" is the whole rule. Inventing per-class thresholds would be worse
        # than nothing at this corpus size, where most classes have a single fixture.
        previous = load(SCORECARD_JSON) if os.path.exists(SCORECARD_JSON) else {}
        for dimension in ("by_class", "by_cwe", "by_language"):
            for key, was in (previous.get(dimension) or {}).items():
                now = (data.get(dimension) or {}).get(key)
                if was.get("tp", 0) > 0 and (now is None or now.get("tp", 0) == 0):
                    failures.append(
                        f"{dimension[3:]} `{key}` was detected ({was['tp']} true positive(s)) "
                        f"and is now not detected at all"
                        + ("" if now else " (the class has no labelled fixture any more)")
                        + ". Overall recall can rise while a whole class goes dark; say which "
                          "class and why in the PR, or fix it")

        if failures:
            print("EVAL GATE FAILED:")
            print("\n".join("  - " + f for f in failures))
            return 1
        print(f"EVAL GATE PASSED — recall {o['recall']:.1%}, F3 {o['f3']:.3f}, "
              f"{o['fp']} trap false positive(s).")
        return 0

    with open(SCORECARD_MD, "w", encoding="utf-8") as f:
        f.write(rendered_md)
    with open(SCORECARD_JSON, "w", encoding="utf-8") as f:
        f.write(rendered_json)
    o = data["overall"]
    print(f"Wrote eval/scorecard.md + eval/scorecard.json — recall {o['recall']:.1%}, "
          f"precision {o['precision']:.1%}, F1 {o['f1']:.3f}, F3 {o['f3']:.3f}, "
          f"{o['fp']} trap false positive(s), {data['unlabelled_results']} unlabelled result(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
