#!/usr/bin/env python3
"""One command that re-measures every published figure, against one frozen engine.

    python3 scripts/measure_all.py --run-date 2026-08-20 --label "what changed" \
        --previous-label "what the last round was called"
    python3 scripts/measure_all.py --run-date 2026-08-20 --label "…" --amend   # re-run a round

Four corpora, four harnesses, eight commands, and until this file existed they were typed by
hand in the right order. Two things went wrong on 2026-08-20 doing exactly that, and both are
what this script exists to make impossible:

* **The engine moved mid-measurement.** `engine_digest` is a sha256 over every module that can
  change what a scan emits — *including its comments*, because the digest hashes bytes and a
  comment is a byte. A one-word comment fix landed between the RealVuln run and the CVEfixes
  run, and check 32 then failed the build with four result files describing three different
  engines. The digest is frozen here before the first scan and re-checked after the last one; if
  it moved, the figures are void and the script says so instead of writing them.
* **Two scans raced the same cache.** The CVEfixes harness caches one result file per CVE keyed
  on the engine digest. Two runs of it were alive at once, writing the same files, and which
  engine each entry described came down to which process finished last. A lock file makes the
  second run refuse rather than interleave.

Corpora that are not on this machine are **skipped out loud**. A contributor with RealVuln and
nothing else gets three lines saying so, which is the difference between a partial measurement
and a silently narrower one.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCK = os.path.join(REPO, ".measure.lock")

sys.path.insert(0, os.path.join(REPO, "scripts"))
from engine_digest import engine_digest                                     # noqa: E402

# (name, corpus path flag default, the file the figure is published in)
CORPORA = ("realvuln", "noisefloor", "secbenchjs", "cvefixes")


def result_path(name: str) -> str:
    return os.path.join(REPO, "eval", name, "result.json")


def published(name: str) -> dict:
    """The committed figures, read before anything overwrites them."""
    try:
        with open(result_path(name), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def headline(name: str, doc: dict) -> str:
    """One line per corpus, in that corpus's own terms. Deliberately not a single metric: an F3
    and a recall and a rate per thousand lines are three different questions, and averaging them
    into a score is the move this repository refuses everywhere else."""
    if not doc:
        return "—"
    if name == "realvuln":
        o = doc.get("overall", {})
        return (f"F3 {o.get('f3_score')} · P {o.get('precision')} · R {o.get('recall')} "
                f"({o.get('tp')}/{o.get('fp')}/{o.get('fn')})")
    if name == "noisefloor":
        o = doc.get("overall", {})
        return (f"{o.get('findings')} findings · {o.get('per_1k_lines')} per 1k · "
                f"{o.get('actionable')} actionable")
    if name == "secbenchjs":
        o = doc.get("overall", doc)
        return (f"recall {o.get('recall')} "
                f"({o.get('tp')} of {(o.get('tp') or 0) + (o.get('fn') or 0)} sinks)")
    if name == "cvefixes":
        h = doc.get("headline", {})
        return f"files {h.get('recall')} · CVEs {h.get('cve_recall')} · {doc.get('findings_total')} findings"
    return "—"


def run(cmd: list[str], cwd: str) -> None:
    print(f"    $ {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=cwd)
    if proc.returncode != 0:
        raise SystemExit(f"measure-all: {cmd[1] if len(cmd) > 1 else cmd[0]} failed "
                         f"({proc.returncode}) — nothing after this point was measured")


def py() -> str:
    return sys.executable or "python3"


def measure_realvuln(bench: str, args: argparse.Namespace) -> None:
    run([py(), "eval/realvuln/run.py", "--benchmark", bench], REPO)
    repos = os.path.join(bench, "repos")
    names = sorted(d for d in os.listdir(repos) if os.path.isdir(os.path.join(repos, d)))
    print(f"    scoring {len(names)} repositories with the benchmark's own scorer")
    for name in names:
        subprocess.run([py(), "score.py", "--repo", name, "--scanner", "secaudit"],
                       cwd=bench, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run([py(), "dashboard.py", "--scanners", "secaudit"], bench)
    collect = [py(), "eval/realvuln/collect_result.py", "--benchmark", bench,
               "--run-date", args.run_date, "--label", args.label]
    collect += ["--amend"] if args.amend else ["--previous-label", args.previous_label]
    run(collect, REPO)


def measure_noisefloor(workdir: str, args: argparse.Namespace) -> None:
    run([py(), "eval/noisefloor/run.py", "--workdir", workdir], REPO)
    run([py(), "eval/noisefloor/score.py", "--workdir", workdir,
         "--run-date", args.run_date], REPO)


def measure_secbenchjs(packages: str, args: argparse.Namespace) -> None:
    run([py(), "eval/secbenchjs/run.py", "--packages", packages], REPO)
    run([py(), "eval/secbenchjs/score.py", "--packages", packages,
         "--run-date", args.run_date], REPO)


def measure_cvefixes(corpus: str, args: argparse.Namespace) -> None:
    run([py(), "eval/cvefixes/run.py", "--corpus", corpus], REPO)
    run([py(), "eval/cvefixes/score.py", "--corpus", corpus,
         "--run-date", args.run_date], REPO)


def selftest() -> int:
    """The three things that make this script worth having, asserted without a corpus.

    A measurement runner nobody can test is a measurement runner that breaks quietly and is
    discovered on the day somebody needed it. This runs in well under a second and is a gate.
    """
    fails: list[str] = []

    # 1. The lock is exclusive. This is the whole reason it is `O_EXCL` rather than a check.
    if os.path.exists(LOCK):
        fails.append(f"{LOCK} already exists — a real run may be in progress")
    else:
        fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
        try:
            os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            fails.append("a second acquisition of the lock succeeded")
        except FileExistsError:
            pass
        os.unlink(LOCK)
        if os.path.exists(LOCK):
            fails.append("the lock survived its own release")

    # 2. Every committed result file renders. A reader added for a key that a scorer renamed
    #    would otherwise print `None` in the delta table and nobody would read it as a defect.
    for corpus in CORPORA:
        doc = published(corpus)
        if not doc:
            fails.append(f"eval/{corpus}/result.json is missing or unreadable")
            continue
        line = headline(corpus, doc)
        if "None" in line or line == "—":
            fails.append(f"{corpus}: the delta table would print `{line}`")

    # 3. The digest is readable and nothing in `secaudit_core` is unclassified — the condition
    #    the run refuses to start under.
    _, unlisted = engine_digest()
    if unlisted:
        fails.append(f"unclassified modules in engine_digest: {unlisted}")

    if fails:
        print("MEASURE-ALL SELFTEST FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("MEASURE-ALL SELFTEST PASSED — the lock is exclusive, all four result files render, "
          "and the engine digest is complete.")
    return 0


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    if "--selftest" in argv:
        return selftest()

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true",
                    help="assert the lock, the result readers and the digest, then exit")
    ap.add_argument("--run-date", required=True, help="date of the run, YYYY-MM-DD")
    ap.add_argument("--label", required=True, help="what this round changed")
    ap.add_argument("--previous-label", help="how to name the run being pushed into history; "
                                             "required unless --amend")
    ap.add_argument("--amend", action="store_true",
                    help="replace the current head instead of pushing it into previous_runs — "
                         "for re-measuring a round that has not been committed yet")
    ap.add_argument("--benchmark", default=os.path.join(REPO, "..", "Real-Vuln-Benchmark"))
    ap.add_argument("--noisefloor", default=os.path.join(REPO, "..", "noisefloor-work"))
    ap.add_argument("--secbench", default=os.path.join(REPO, "..", "secbench-pkgs"))
    ap.add_argument("--cvefixes", default=os.path.join(REPO, "..", "corpora", "cvefixes"))
    ap.add_argument("--only", default="", help="comma-separated subset of "
                                               f"{','.join(CORPORA)} (default: all present)")
    args = ap.parse_args(argv)
    if not args.amend and not args.previous_label:
        ap.error("--previous-label is required unless --amend is given")

    wanted = [c.strip() for c in args.only.split(",") if c.strip()] or list(CORPORA)
    unknown = [c for c in wanted if c not in CORPORA]
    if unknown:
        ap.error(f"--only: unknown corpus {unknown} — choose from {', '.join(CORPORA)}")

    paths = {"realvuln": os.path.abspath(args.benchmark),
             "noisefloor": os.path.abspath(args.noisefloor),
             "secbenchjs": os.path.abspath(args.secbench),
             "cvefixes": os.path.abspath(args.cvefixes)}
    runners = {"realvuln": measure_realvuln, "noisefloor": measure_noisefloor,
               "secbenchjs": measure_secbenchjs, "cvefixes": measure_cvefixes}

    # The lock is `O_EXCL`, not a check-then-create: two runs started a second apart would both
    # pass a `os.path.exists` and both proceed, which is the race this is here to stop.
    try:
        fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        with open(LOCK, encoding="utf-8") as f:
            who = f.read().strip() or "an earlier run"
        raise SystemExit(
            f"measure-all: {LOCK} exists — {who}.\n"
            f"  A second measurement would write the same per-entry caches as the first and the "
            f"figures would describe whichever process finished last. Wait for it, or delete the "
            f"lock if you are certain nothing is running.") from None
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(f"pid {os.getpid()} started {time.strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        frozen, unlisted = engine_digest()
        if unlisted:
            raise SystemExit(f"measure-all: {unlisted} is not classified in `engine_digest` — "
                             f"a module nobody has decided about cannot be measured against")
        print(f"engine {frozen}")
        before = {c: published(c) for c in CORPORA}

        for corpus in wanted:
            where = paths[corpus]
            if not os.path.exists(where):
                print(f"\nSKIPPED {corpus} — {where} is not on this machine")
                continue
            print(f"\n=== {corpus} · {where}")
            runners[corpus](where, args)

        moved, _ = engine_digest()
        if moved != frozen:
            raise SystemExit(
                f"measure-all: the engine moved while it was being measured.\n"
                f"  started {frozen}\n"
                f"  ended   {moved}\n"
                f"  The result files now describe more than one engine. `engine_digest` hashes "
                f"module bytes, so a comment is enough to move it. Re-run this script against a "
                f"tree that is not being edited.")

        print("\n" + "=" * 78)
        print(f"{'corpus':12} {'before':52} after")
        for corpus in CORPORA:
            if corpus not in wanted or not os.path.exists(paths[corpus]):
                continue
            print(f"{corpus:12} {headline(corpus, before[corpus]):52} "
                  f"{headline(corpus, published(corpus))}")
        print("\nEvery figure above was produced by one engine. Update the pages that quote them, "
              "then `python3 scripts/run_checks.py`.")
    finally:
        try:
            os.unlink(LOCK)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
