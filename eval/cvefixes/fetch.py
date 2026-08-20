#!/usr/bin/env python3
"""Download and verify the CVEfixes archive, then restore its database out of it.

12.7 GB over one HTTP connection, so this resumes rather than restarts: an interrupted download
that has to begin again is a download that never finishes on a domestic link. The MD5 is the one
Zenodo publishes for the record and is checked before anything is unpacked — a truncated archive
that unzips far enough to produce a smaller database would otherwise become a smaller corpus and
a *better looking* recall, which is the failure mode worth spending a checksum on.

Nothing here is committed. The archive and the database live outside the repository (default
`../corpora/`), because a corpus this repository ships is a corpus this repository owns, and the
whole point of an external number is that somebody else owns the labels.

    python3 eval/cvefixes/fetch.py                 # download, verify, restore the database
    python3 eval/cvefixes/fetch.py --verify        # just re-check the archive already on disk
    python3 eval/cvefixes/fetch.py --restore-only  # rebuild the database from that archive
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import urllib.request
import zipfile

RECORD = "13118970"
ARCHIVE = "CVEfixes_v1.0.8.zip"
URL = f"https://zenodo.org/api/records/{RECORD}/files/{ARCHIVE}/content"
MD5 = "4586a358977acfa4c60b1a2cdd096221"
CITATION = ("CVEfixes: Bhandari, Naseer & Moonen, PROMISE 2021. "
            "CC-BY-4.0, DOI 10.5281/zenodo.13118970")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DEFAULT_DIR = os.path.join(REPO, "..", "corpora")


def md5_of(path: str, chunk: int = 8 << 20) -> str:
    h = hashlib.md5()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                return h.hexdigest()
            h.update(block)


def download(dest: str) -> None:
    """Resume `dest` from wherever it stopped."""
    have = os.path.getsize(dest) if os.path.exists(dest) else 0
    req = urllib.request.Request(URL)
    if have:
        req.add_header("Range", f"bytes={have}-")
    try:
        resp_cm = urllib.request.urlopen(req, timeout=120)
    except urllib.error.HTTPError as exc:
        # 416 means the range starts past the end — i.e. the file on disk is already the whole
        # thing. A resumable downloader that crashes once the download has succeeded is a
        # downloader nobody can run twice, and running it twice is the normal case here.
        if exc.code == 416 and have:
            print(f"  already complete ({have / 1e9:.2f} GB)", file=sys.stderr)
            return
        raise
    with resp_cm as resp:
        # A server that ignores Range answers 200 and sends the whole file; appending to what is
        # already there would corrupt it silently, so start over in that case.
        mode = "ab" if (have and resp.status == 206) else "wb"
        if mode == "wb":
            have = 0
        total = int(resp.headers.get("Content-Length") or 0) + have
        with open(dest, mode) as fh:
            done = have
            while True:
                block = resp.read(8 << 20)
                if not block:
                    break
                fh.write(block)
                done += len(block)
                if total:
                    pct = 100.0 * done / total
                    print(f"\r  {done / 1e9:.2f} / {total / 1e9:.2f} GB  ({pct:.1f}%)",
                          end="", file=sys.stderr, flush=True)
    print(file=sys.stderr)


# The archive ships a SQL dump, not a database — upstream's own restore step is
# `gzcat CVEfixes.sql.gz | sqlite3 CVEfixes.db`. There is no `sqlite3` binary on every machine
# that can run the rest of this repository (there is none on the one that wrote this), so the
# restore is done here instead, and only for the tables the corpus actually needs.
#
# That filter is not a micro-optimisation. The dump is 12.7 GB and most of it is `method_change`,
# which carries a copy of every method's source before and after every fix — data this corpus
# never reads, because the labels are file-level line numbers. Importing it would cost an hour
# and tens of gigabytes to build a table nothing queries.
NEEDED_TABLES = ("file_change", "commits", "fixes", "cwe_classification")


def _wanted(statement: str) -> bool:
    head = statement.lstrip()[:400].lower()
    if head.startswith(("pragma", "begin", "commit", "end")):
        return True
    for verb in ("create table", "create index", "create unique index", "insert into"):
        if head.startswith(verb):
            return any(t in head for t in NEEDED_TABLES)
    return False


def restore(archive: str, out_dir: str) -> str:
    """Stream the SQL dump out of the zip and into a SQLite file.

    Statements are split with `sqlite3.complete_statement`, not on `;`, because the dump's
    payload is source code: a semicolon inside a string literal is the common case here rather
    than the edge one, and splitting on it produces a database that is subtly short of rows.
    """
    import gzip
    import sqlite3

    with zipfile.ZipFile(archive) as z:
        names = [n for n in z.namelist() if n.lower().endswith(".sql.gz")]
        if not names:
            raise SystemExit(f"{archive} contains no .sql.gz member: {z.namelist()[:10]}")
        member = max(names, key=lambda n: z.getinfo(n).file_size)
        dest = os.path.join(out_dir, "CVEfixes.db")
        if os.path.exists(dest):
            os.remove(dest)                 # a half-restored database is worse than none
        print(f"restoring {member} -> {dest}", file=sys.stderr)

        conn = sqlite3.connect(dest)
        # Import-time only. The database is a derived artefact rebuildable from the archive, so
        # durability during the build buys nothing and costs hours.
        conn.executescript("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; "
                           "PRAGMA cache_size=-200000; PRAGMA locking_mode=EXCLUSIVE;")
        done = kept = skipped = 0
        buf = ""
        with z.open(member) as raw, gzip.open(raw, "rt", encoding="utf-8",
                                              errors="replace") as fh:
            for line in fh:
                buf += line
                if not sqlite3.complete_statement(buf):
                    continue
                statement, buf = buf, ""
                done += 1
                if _wanted(statement):
                    try:
                        conn.execute(statement)
                        kept += 1
                    except sqlite3.Error as exc:
                        # A dump written by a newer sqlite can carry syntax this one refuses.
                        # Say so and keep going rather than losing the whole import to one row.
                        if kept < 5 or done % 100000 == 0:
                            print(f"\n  skipped a statement: {exc}", file=sys.stderr)
                        skipped += 1
                else:
                    skipped += 1
                if done % 200000 == 0:
                    conn.commit()
                    print(f"\r  {done:,} statements  kept {kept:,}", end="",
                          file=sys.stderr, flush=True)
        conn.commit()
        print(f"\n  {done:,} statements, kept {kept:,}, skipped {skipped:,}", file=sys.stderr)
        for table in NEEDED_TABLES:
            try:
                n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except sqlite3.Error as exc:
                raise SystemExit(f"restore produced no usable `{table}`: {exc}") from exc
            print(f"  {table}: {n:,} rows", file=sys.stderr)
        conn.close()
        return dest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", default=DEFAULT_DIR, help="where the archive and database live")
    ap.add_argument("--verify", action="store_true", help="only check the archive already there")
    ap.add_argument("--restore-only", action="store_true",
                    help="skip download and md5, restore the database from the archive on disk")
    args = ap.parse_args()

    os.makedirs(args.dir, exist_ok=True)
    archive = os.path.join(args.dir, ARCHIVE)

    if args.restore_only:
        if not os.path.exists(archive):
            print(f"no archive at {archive}", file=sys.stderr)
            return 2
        restore(archive, args.dir)
        return 0

    if not args.verify:
        print(f"{CITATION}\ndownloading {URL}", file=sys.stderr)
        download(archive)

    if not os.path.exists(archive):
        print(f"no archive at {archive}", file=sys.stderr)
        return 2
    print("checking md5 …", file=sys.stderr)
    got = md5_of(archive)
    if got != MD5:
        print(f"MD5 MISMATCH: expected {MD5}, got {got}. The archive is incomplete or corrupt; "
              f"re-run to resume. Nothing was unpacked.", file=sys.stderr)
        return 1
    print("md5 ok", file=sys.stderr)
    if args.verify:
        return 0
    restore(archive, args.dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
