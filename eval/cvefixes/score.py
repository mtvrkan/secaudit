#!/usr/bin/env python3
"""Score the CVEfixes run: recall overall, and the sealed slice reported separately.

    python3 eval/cvefixes/score.py --corpus ../corpora/cvefixes

**Recall is the sound metric. Precision is a lower bound and is not comparable to RealVuln's.**
Only the lines a fix deleted are labelled, so a finding elsewhere in a file that genuinely
carried a CVE is not evidence of a false positive — it may be a second real issue, or the same
issue at the line the fix did not touch. The unmatched count is printed because hiding it would
be worse, and it is named `unmatched` rather than `false positives` for the same reason
`eval/secbenchjs/` does: a number is not a false positive because it is inconvenient.

**The sealed slice is the reason this corpus exists.** Per `eval/HELDOUT.md`, the fifth of the
CVEs whose identifier hashes into the bottom of the space was sealed by `build_corpus.py` before
this engine had scored a single entry, and is never inspected. Its recall is reported beside the
unsealed slice every round. A round that moves the unsealed number and not the sealed one has
bought corpus fit rather than detection, and this output is where that shows up rather than in
somebody's judgement afterwards.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "scripts"))

from engine_digest import engine_digest                                       # noqa: E402

# A finding within this many lines of the labelled region counts. The label is a deleted hunk,
# and a scanner legitimately reports the call two lines below the guard that was added — the same
# tolerance SecBench.js's scorer uses here, chosen once and not tuned since.
LINE_TOLERANCE = 10


def load_findings(corpus_dir: str) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    results = os.path.join(corpus_dir, "scan-results")
    if not os.path.isdir(results):
        raise SystemExit(f"no scan results in {results} — run eval/cvefixes/run.py first")
    for name in sorted(os.listdir(results)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(results, name), encoding="utf-8") as fh:
            out[name[:-5]] = json.load(fh).get("findings", [])
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default=os.path.join(REPO, "..", "corpora", "cvefixes"))
    ap.add_argument("--out", default=os.path.join(HERE, "result.json"))
    ap.add_argument("--run-date", required=True,
                    help="YYYY-MM-DD; passed in rather than read from the clock so the same "
                         "inputs always produce the same file")
    args = ap.parse_args()

    with open(os.path.join(args.corpus, "ground-truth.json"), encoding="utf-8") as fh:
        gt = json.load(fh)
    findings_by_cve = load_findings(args.corpus)

    # Index findings by (cve, file) once; the label loop is otherwise quadratic on a big corpus.
    index: dict[tuple[str, str], list[int]] = collections.defaultdict(list)
    unmatched_pool: dict[str, set[tuple[str, int]]] = collections.defaultdict(set)
    for cve, findings in findings_by_cve.items():
        for f in findings:
            rel = (f.get("file") or "").replace("\\", "/")
            # `run.py` scans `corpus/<cve>/`, so a finding's path is relative to that directory
            # while a label's path carries the CVE in front of it.
            key = f"{cve}/{rel}" if not rel.startswith(cve + "/") else rel
            index[(cve, key)].append((int(f.get("line") or 0), f.get("cwe") or ""))
            unmatched_pool[cve].add((key, int(f.get("line") or 0)))

    # How concentrated each (language, CWE) cell is in a single CVE. Computed from the labels
    # themselves rather than from the scan, so it describes the corpus and not the engine.
    per_cell: dict[tuple[str, str], collections.Counter] = collections.defaultdict(
        collections.Counter)
    sealed_cves = {label["cve_id"] for label in gt["findings"] if label.get("sealed")}
    for label in gt["findings"]:
        per_cell[(label.get("language", "?"), label["primary_cwe"])][label["cve_id"]] += 1
    concentration = {}
    for (language, cwe), counter in per_cell.items():
        total = sum(counter.values())
        if total < 40:                 # too small for the question to mean anything
            continue
        cve, biggest = counter.most_common(1)[0]
        share = round(biggest / total, 3)
        if share >= 0.3:
            concentration[f"{language} {cwe}"] = {
                "labels": total, "cves": len(counter),
                # A sealed entry is scored and never named. This block is a fact about the
                # CORPUS rather than about any entry's contents, so it is publishable — but the
                # identifier is not, and check 41 caught exactly that the first time this table
                # was written. The shape of the distortion survives the redaction; the thing
                # somebody could go and read does not.
                "top_cve": "(sealed entry — see eval/HELDOUT.md)" if cve in sealed_cves else cve,
                "top_labels": biggest, "top_share": share}
    concentration = dict(sorted(concentration.items(), key=lambda kv: -kv[1]["top_share"]))

    by_seal = {True: collections.Counter(), False: collections.Counter()}
    by_lang = collections.defaultdict(collections.Counter)
    by_cwe = collections.defaultdict(collections.Counter)
    matched_findings: set[tuple[str, str, int]] = set()
    total, strict = collections.Counter(), collections.Counter()
    strict_by_seal = {True: collections.Counter(), False: collections.Counter()}

    # Per-hunk counting is not what the other two corpora measure, and reporting it as "recall"
    # would put a number next to RealVuln's that means something else. A fix that rewrites every
    # query in a file deletes twenty hunks and describes ONE vulnerability; scoring each hunk
    # separately turns finding that vulnerability into 1/20. So the primary reading is per
    # (CVE, file) — did anything fire at any fixed hunk in the vulnerable file — with the CVE
    # level beside it, and the per-hunk figure kept as the strict floor.
    entry_hits: dict[tuple[str, str], bool] = {}
    entry_strict: dict[tuple[str, str], bool] = {}
    entry_meta: dict[tuple[str, str], dict] = {}

    for label in gt["findings"]:
        cve, rel = label["cve_id"], label["file"]
        start = label["location"]["start_line"] - LINE_TOLERANCE
        end = label["location"]["end_line"] + LINE_TOLERANCE
        near = [f for f in index.get((cve, rel), []) if start <= f[0] <= end]
        sealed = bool(label.get("sealed"))
        got = bool(near)
        # The strict reading additionally asks whether the finding is about the same KIND of
        # vulnerability. It matters more here than the tolerance suggests: a fixture written to
        # test this scorer scored a command-injection label with a SQL-injection finding nine
        # lines away, and both readings called that a detection. A vulnerable file usually holds
        # more than one issue, so location alone credits the engine for finding a different bug.
        accept = set(label.get("acceptable_cwes") or [label["primary_cwe"]])
        got_strict = any(cwe in accept for _, cwe in near)
        total["tp" if got else "fn"] += 1
        strict["tp" if got_strict else "fn"] += 1
        strict_by_seal[sealed]["tp" if got_strict else "fn"] += 1
        by_seal[sealed]["tp" if got else "fn"] += 1
        by_lang[label.get("language", "?")]["tp" if got else "fn"] += 1
        by_cwe[label["primary_cwe"]]["tp" if got else "fn"] += 1
        key = (cve, rel)
        entry_hits[key] = entry_hits.get(key, False) or got
        entry_strict[key] = entry_strict.get(key, False) or got_strict
        entry_meta.setdefault(key, {"language": label.get("language", "?"), "sealed": sealed})
        for ln, _cwe in near:
            matched_findings.add((cve, rel, ln))

    unmatched = sum(len({(k, ln) for (k, ln) in pool if (cve, k, ln) not in matched_findings})
                    for cve, pool in unmatched_pool.items())
    scanned = sum(len(v) for v in findings_by_cve.values())

    def recall(c: collections.Counter) -> float:
        n = c["tp"] + c["fn"]
        return round(c["tp"] / n, 4) if n else 0.0

    entry = collections.Counter()
    entry_strict_c = collections.Counter()
    entry_by_lang = collections.defaultdict(collections.Counter)
    entry_by_seal = {True: collections.Counter(), False: collections.Counter()}
    cve_found: dict[str, bool] = {}
    for key, got in entry_hits.items():
        meta = entry_meta[key]
        entry["tp" if got else "fn"] += 1
        entry_strict_c["tp" if entry_strict[key] else "fn"] += 1
        entry_by_lang[meta["language"]]["tp" if got else "fn"] += 1
        entry_by_seal[meta["sealed"]]["tp" if got else "fn"] += 1
        cve_found[key[0]] = cve_found.get(key[0], False) or got
    cves_found = sum(1 for v in cve_found.values() if v)

    digest, _ = engine_digest(os.path.join(REPO, "kit"))
    result = {
        "note": "Scored by eval/cvefixes/score.py against lines deleted by each CVE's fix "
                "commit. Recall is the sound metric; precision is a LOWER BOUND and is not "
                "comparable to the RealVuln figure — see the module docstring.",
        "benchmark": "CVEfixes v1.0.8 (DOI 10.5281/zenodo.13118970), CC-BY-4.0",
        "citation": "Bhandari, Naseer & Moonen, PROMISE 2021",
        "run_date": args.run_date,
        "engine_digest": digest,
        "line_tolerance": LINE_TOLERANCE,
        "labels_scored": total["tp"] + total["fn"],
        "cves_scanned": len(findings_by_cve),
        "findings_total": scanned,
        "headline": {
            "what": "One label per vulnerable FILE — did anything fire at any hunk the fix "
                    "touched. This is the reading comparable to how RealVuln and SecBench.js "
                    "count, and the one to quote.",
            "files": entry["tp"] + entry["fn"], "tp": entry["tp"],
            "recall": recall(entry),
            "strict_recall": recall(entry_strict_c),
            "cves": len(cve_found), "cves_found": cves_found,
            "cve_recall": round(cves_found / len(cve_found), 4) if cve_found else 0.0,
        },
        "headline_by_language": {k: {"files": v["tp"] + v["fn"], "tp": v["tp"],
                                     "recall": recall(v)}
                                 for k, v in sorted(entry_by_lang.items())},
        "headline_by_seal": {
            "sealed": {"files": entry_by_seal[True]["tp"] + entry_by_seal[True]["fn"],
                       "tp": entry_by_seal[True]["tp"], "recall": recall(entry_by_seal[True])},
            "unsealed": {"files": entry_by_seal[False]["tp"] + entry_by_seal[False]["fn"],
                         "tp": entry_by_seal[False]["tp"], "recall": recall(entry_by_seal[False])},
        },
        "overall": {"tp": total["tp"], "fn": total["fn"],
                    "recall": recall(total), "unmatched": unmatched,
                    "precision_lower_bound": round(total["tp"] / scanned, 4) if scanned else 0.0,
                    "$comment": "Per-HUNK, kept as the strict floor. A fix that rewrites every "
                                "query in a file deletes many hunks and describes one "
                                "vulnerability, so this reading understates by however many "
                                "hunks a fix happened to have. Do not compare it to RealVuln."},
        "strict": {"tp": strict["tp"], "fn": strict["fn"], "recall": recall(strict)},
        "strict_note": "`overall.recall` asks only whether a finding landed within "
                       f"{LINE_TOLERANCE} lines of the fixed hunk; `strict.recall` also requires "
                       "the finding's CWE to be one the label accepts. Quote the strict figure. "
                       "The loose one is kept beside it because the gap between them is itself "
                       "the measurement — it is how much credit location alone was handing out.",
        "by_seal": {
            "sealed": {"tp": by_seal[True]["tp"], "labels": by_seal[True]["tp"] + by_seal[True]["fn"],
                       "recall": recall(by_seal[True]),
                       "strict_recall": recall(strict_by_seal[True])},
            "unsealed": {"tp": by_seal[False]["tp"],
                         "labels": by_seal[False]["tp"] + by_seal[False]["fn"],
                         "recall": recall(by_seal[False]),
                         "strict_recall": recall(strict_by_seal[False])},
        },
        "by_seal_note": "The held-out slice, per eval/HELDOUT.md. Sealed on adoption, before "
                        "this engine had scored one entry, so unlike the secbenchjs slice this "
                        "one is a genuinely blind figure on its first run.",
        "by_language": {k: {"tp": v["tp"], "labels": v["tp"] + v["fn"], "recall": recall(v)}
                        for k, v in sorted(by_lang.items())},
        "by_cwe": {k: {"tp": v["tp"], "labels": v["tp"] + v["fn"], "recall": recall(v)}
                   for k, v in sorted(by_cwe.items(), key=lambda kv: -(kv[1]["tp"] + kv[1]["fn"]))},
        "concentration": concentration,
        "concentration_note":
            "How much of a language/CWE cell comes from ONE fix commit. A CVE fixed by a "
            "repository-wide refactor deletes lines in hundreds of files, and every one of them "
            "becomes a labelled entry here — so a cell can look like a broad detection failure "
            "while being three commits wearing many filenames. Reported because it changes how "
            "a reader should weigh the per-language table above, and because the direction it "
            "distorts in is not predictable: a huge commit can just as easily be caught by one "
            "rule and inflate a figure. `top_share` is the largest single CVE's share of that "
            "cell's labels; anything above 0.5 is one commit and should be read as one.",
    }
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(result, fh, indent=1)
        fh.write("\n")

    o = result["overall"]
    h = result["headline"]
    print(f"HEADLINE  files {h['files']}  tp {h['tp']}  recall {h['recall']}  "
          f"(strict {h['strict_recall']})")
    print(f"          CVEs  {h['cves']}  found {h['cves_found']}  recall {h['cve_recall']}")
    print(f"sealed    {result['headline_by_seal']['sealed']}")
    print(f"unsealed  {result['headline_by_seal']['unsealed']}")
    print(f"per-hunk floor: labels {result['labels_scored']}  tp {o['tp']}  recall {o['recall']}")
    print(f"sealed   {result['by_seal']['sealed']}")
    print(f"unsealed {result['by_seal']['unsealed']}")
    print(f"unmatched findings (NOT false positives — read the docstring): {unmatched}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
