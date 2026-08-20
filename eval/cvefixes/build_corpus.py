#!/usr/bin/env python3
"""Build a scannable corpus, and its labels, out of the CVEfixes database.

CVEfixes is a third-party dataset of real CVEs joined to the commits that fixed them
(Bhandari, Naseer & Moonen, PROMISE 2021; CC-BY-4.0, DOI 10.5281/zenodo.13118970). Two of its
columns are what make it usable here without inventing anything:

* `file_change.code_before` is the **whole vulnerable file**, as it stood before the fix. So the
  corpus does not have to be reconstructed by cloning every project at every commit — it can be
  materialised from the dataset itself, which is also what makes the run reproducible by anyone
  who downloads the same archive.
* `file_change.diff_parsed` carries the deleted lines **with their line numbers in that before
  file**. Those numbers are the label.

**What the label is, stated before any number is quoted from it.** A line removed by a security
fix is evidence about where the vulnerability was, not a definition of it. Three ways it is
wrong, all of them left in rather than cleaned away, because the cleaning would be this
repository deciding what its own corpus says:

1. A fix commit also refactors, renames and reformats. Some deleted lines are not the bug.
2. A CVE's fix can touch files that were never vulnerable — a test, a changelog, a version pin.
   Non-production paths are dropped (the engine's own `is_production_source`), the rest stay.
3. NVD's CWE for the CVE is the CWE for the *vulnerability*, not necessarily for the line.

So **recall is the sound metric here and precision is a lower bound**, exactly as on SecBench.js
and for the same reason: only the fixed lines are labelled, and a finding elsewhere in a file
that genuinely had a CVE is not evidence of a false positive. `score.py` says so in its output.

**The seal comes first.** Per `eval/HELDOUT.md`, a slice is sealed *before* the corpus is
diagnosed, by a rule that is a function of the entry name and nothing else, so the slice cannot
have been chosen for how it scores. This script writes that slice into `eval/heldout.json` as
part of building the corpus — not as a later step someone could take after a first look.

    python3 eval/cvefixes/fetch.py                 # download + verify the archive
    python3 eval/cvefixes/build_corpus.py          # corpus/ + ground-truth.json + the seal
    python3 eval/cvefixes/run.py                   # scan (cached on the engine digest)
    python3 eval/cvefixes/score.py                 # recall, sealed slice reported separately
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "kit"))

from secaudit_core.structural.routes import is_production_source            # noqa: E402

# Every language this engine has a front end for, which is the honest line to draw — not "the
# languages the published figures already cover". A corpus entry in a language with no analysis
# behind it would depress a number without saying anything ("we score badly on C" is not a
# finding when there is no C front end to score), but PHP has a detector pack here and is also
# this corpus's single largest slice, so leaving it out would be choosing the languages we are
# good at. `score.py` reports recall per language, so a weak one cannot hide inside the total.
LANGUAGES = {"Python": ".py", "JavaScript": ".js", "TypeScript": ".ts", "PHP": ".php"}

# PyDriller writes the enum's repr into this column, so the value is `ModificationType.MODIFY`
# rather than `MODIFY`. Both spellings are accepted so a dump written by either convention loads.
# Worth the two entries: the first run against the real database matched zero rows and reported
# a corpus of zero files without complaining, which is the shape of failure this repository
# spends its gates on — a measurement that silently does not measure.
MODIFY_VALUES = ("MODIFY", "ModificationType.MODIFY")

# A fix whose before-file is enormous is usually a vendored bundle or a generated artefact, and a
# fix that deletes most of a file is a rewrite rather than a repair — in both the deleted lines
# stop being a pointer at a vulnerability.
MAX_BEFORE_BYTES = 400_000
MAX_DELETED_LINES = 200

SEAL_FRACTION = 5          # the bottom fifth of the hash space, as for secbenchjs


def is_sealed(name: str) -> bool:
    """The seal rule, identical to the one already in `eval/heldout.json`.

    A function of the name alone, so anybody with the corpus can recompute the slice and confirm
    it was not chosen for how it scores.
    """
    return int(hashlib.sha256(name.encode("utf-8")).hexdigest()[:8], 16) < 2 ** 32 // SEAL_FRACTION


def _deleted_lines(diff_parsed: str) -> list[int]:
    """Line numbers deleted by the fix, in the before-file's numbering."""
    try:
        parsed = ast.literal_eval(diff_parsed) if diff_parsed else {}
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return []
    out = []
    for entry in (parsed or {}).get("deleted", []):
        # PyDriller writes (lineno, text); defend against either order of surprise rather than
        # trusting a field that is a repr of a tuple inside a text column.
        if isinstance(entry, (list, tuple)) and entry and isinstance(entry[0], int):
            out.append(entry[0])
    return sorted(set(out))


def _hunks(lines: list[int], gap: int = 3) -> list[tuple[int, int]]:
    """Group deleted line numbers into contiguous regions.

    One label per hunk rather than per line: a fix that deletes six consecutive lines describes
    one vulnerability, and six labels would let a single finding score six times.
    """
    if not lines:
        return []
    out, start, prev = [], lines[0], lines[0]
    for n in lines[1:]:
        if n - prev > gap:
            out.append((start, prev))
            start = n
        prev = n
    out.append((start, prev))
    return out


def _rows(db: str, limit: int | None):
    # The placeholder list is built from LANGUAGES rather than written out, so adding a language
    # is one edit; the values are still bound, never interpolated.
    placeholders = ",".join("?" for _ in LANGUAGES)
    modify = ",".join("?" for _ in MODIFY_VALUES)
    sql = f"""
        SELECT f.cve_id, fc.filename, fc.old_path, fc.code_before, fc.diff_parsed,
               fc.programming_language, fc.change_type, c.hash
        FROM file_change fc
        JOIN commits c  ON fc.hash = c.hash
        JOIN fixes   f  ON c.hash  = f.hash
        WHERE fc.programming_language IN ({placeholders})
          AND fc.code_before IS NOT NULL
          AND fc.code_before != 'None'
          AND fc.change_type IN ({modify})
        ORDER BY f.cve_id, fc.filename
    """
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        conn.text_factory = lambda b: b.decode("utf-8", errors="replace")
        cur = conn.execute(sql, tuple(LANGUAGES) + MODIFY_VALUES)
        seen = 0
        while True:
            row = cur.fetchone()
            if row is None:
                return
            yield row
            seen += 1
            if limit and seen >= limit:
                return
    finally:
        conn.close()


def _cwes(db: str) -> dict[str, list[str]]:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        conn.text_factory = lambda b: b.decode("utf-8", errors="replace")
        out: dict[str, list[str]] = {}
        for cve, cwe in conn.execute("SELECT cve_id, cwe_id FROM cwe_classification"):
            if cwe and str(cwe).startswith("CWE-"):
                out.setdefault(cve, []).append(str(cwe))
        return out
    finally:
        conn.close()


def build(db: str, out_dir: str, limit: int | None = None) -> dict:
    cwe_of = _cwes(db)
    corpus = os.path.join(out_dir, "corpus")
    os.makedirs(corpus, exist_ok=True)

    findings, skipped = [], {"non_production": 0, "no_deleted_lines": 0, "too_large": 0,
                             "too_many_deleted": 0, "no_cwe": 0}
    written = 0
    for cve, filename, old_path, code_before, diff_parsed, lang, _change, commit in _rows(db, limit):
        rel_src = (old_path or filename or "").replace("\\", "/")
        if not rel_src or not is_production_source(rel_src):
            skipped["non_production"] += 1
            continue
        if len(code_before) > MAX_BEFORE_BYTES:
            skipped["too_large"] += 1
            continue
        deleted = _deleted_lines(diff_parsed)
        if not deleted:
            skipped["no_deleted_lines"] += 1
            continue
        if len(deleted) > MAX_DELETED_LINES:
            skipped["too_many_deleted"] += 1
            continue
        cwes = sorted(set(cwe_of.get(cve, [])))
        if not cwes:
            skipped["no_cwe"] += 1
            continue

        # One directory per (CVE, commit, file) so two files from one fix cannot collide and a
        # path in the report is enough to find the entry again.
        stem = hashlib.sha256(f"{cve}/{commit}/{rel_src}".encode()).hexdigest()[:12]
        rel_out = f"{cve}/{stem}/{os.path.basename(rel_src)}"
        dest = os.path.join(corpus, rel_out.replace("/", os.sep))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(code_before)
        written += 1

        for start, end in _hunks(deleted):
            findings.append({
                "id": f"{cve}-{stem}-{start}",
                "cve_id": cve,
                "is_vulnerable": True,
                "vulnerability_class": "cve_fix",
                "primary_cwe": cwes[0],
                "acceptable_cwes": cwes,
                "file": rel_out,
                "location": {"start_line": start, "end_line": end},
                "language": lang,
                "sealed": is_sealed(cve),
            })

    ground_truth = {
        "schema_version": "1.0",
        "repo_id": "cvefixes",
        "source": "CVEfixes v1.0.8 (DOI 10.5281/zenodo.13118970), CC-BY-4.0",
        "label_meaning": "A labelled region is a contiguous run of lines DELETED by the commit "
                         "that fixed the CVE, numbered in the pre-fix file. It is evidence about "
                         "where the vulnerability was, not a definition of it — see the module "
                         "docstring of build_corpus.py before quoting anything measured here.",
        "files_written": written,
        "skipped": skipped,
        "findings": findings,
    }
    with open(os.path.join(out_dir, "ground-truth.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump(ground_truth, fh, indent=1, sort_keys=False)
        fh.write("\n")
    return ground_truth


def register_seal(ground_truth: dict) -> tuple[int, int]:
    """Write the sealed slice into `eval/heldout.json`, before anything is diagnosed.

    The register is what check 41 enforces: from here on, naming one of these CVEs anywhere in
    the tree fails the build. That is the whole mechanism — you cannot tune against an entry
    without writing its identifier down, and every place you could write it is in the tree.
    """
    path = os.path.join(REPO, "eval", "heldout.json")
    with open(path, encoding="utf-8") as fh:
        register = json.load(fh)

    cves = sorted({f["cve_id"] for f in ground_truth["findings"]})
    sealed = sorted(c for c in cves if is_sealed(c))
    register.setdefault("corpora", {})["cvefixes"] = {
        "sealed_on": "2026-08-18",
        "of_total": len(cves),
        "sealed": len(sealed),
        "blind": "Sealed BEFORE the corpus was first scored, which is what the policy asks for "
                 "and what the secbenchjs slice could not be. No rule in this engine has been "
                 "written or selected by reading any entry here.",
        "packages": sealed,
    }
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(register, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return len(sealed), len(cves)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default=os.path.join(REPO, "..", "corpora", "CVEfixes.db"),
                    help="path to the CVEfixes sqlite database")
    ap.add_argument("--out", default=os.path.join(REPO, "..", "corpora", "cvefixes"),
                    help="where to materialise the corpus and its ground truth")
    ap.add_argument("--limit", type=int, default=None,
                    help="stop after N file_change rows (for a smoke run)")
    ap.add_argument("--no-register", action="store_true",
                    help="do not touch eval/heldout.json (smoke runs)")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"no database at {args.db} — run eval/cvefixes/fetch.py first", file=sys.stderr)
        return 2
    os.makedirs(args.out, exist_ok=True)
    gt = build(args.db, args.out, args.limit)
    print(f"files written : {gt['files_written']}")
    print(f"labels        : {len(gt['findings'])}")
    print(f"skipped       : {gt['skipped']}")
    if not args.no_register:
        sealed, total = register_seal(gt)
        print(f"sealed slice  : {sealed} of {total} CVEs registered in eval/heldout.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
