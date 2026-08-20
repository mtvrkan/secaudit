"""Materialise a git ref into a temporary directory, so it can be scanned like any other tree.

Used by diff mode (`--since <ref>`). The baseline has to be a real directory rather than a set
of blobs, because the analysis is whole-tree: cross-module taint resolves an import edge by
looking the target file up in the scanned set, so handing it a partial checkout would change
the answer for reasons that have nothing to do with the diff.

`git archive | tarfile` rather than `git worktree` or a second clone: no working-tree state is
touched, nothing is left behind if the process dies, and the tar is read through the standard
library instead of shelling out to a `tar` binary that Windows did not always ship.
"""
from __future__ import annotations

import io
import os
import shutil
import subprocess
import tarfile
import tempfile


class GitError(RuntimeError):
    """Anything that stops us producing the baseline tree, phrased for the person running it."""


def _git_bytes(args: list[str], cwd: str) -> bytes:
    """Raw stdout from git, or GitError phrased for the person running it.

    Split from `_git` (which returned `bytes | str` depending on a flag) because every caller
    already knew which one it wanted, and the union meant each of them handed a value that
    might be `str` to something that only accepts `bytes` — `io.BytesIO(blob)` below being the
    one where that would surface as a TypeError at scan time rather than at the call site.
    """
    try:
        done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=False)
    except FileNotFoundError:
        raise GitError("`git` is not on PATH, so there is no baseline to compare against.") from None
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace").strip().splitlines()
        raise GitError(detail[-1] if detail else f"git {args[0]} failed ({done.returncode}).")
    return done.stdout


def _git(args: list[str], cwd: str) -> str:
    return _git_bytes(args, cwd).decode("utf-8", "replace").strip()


def repo_root(target: str) -> str:
    """The work tree containing `target`, or GitError explaining why there isn't one.

    `realpath`, not `normpath`: git always answers with the fully-resolved path, and the caller
    may have been handed any other spelling of the same directory — an 8.3 short name, a
    junction, a symlink. Two spellings of one tree are what `__enter__` used to compute a
    relative path *between*, and the result was not a wrong answer but a silent one. Normalising
    both sides here is half the fix; the containment check below is the half that does not
    depend on `realpath` reconciling every case.
    """
    start = target if os.path.isdir(target) else os.path.dirname(os.path.abspath(target))
    root = _git(["rev-parse", "--show-toplevel"], start or ".")
    if not root:
        raise GitError(f"{target} is not inside a git repository, so `--since` has no baseline.")
    return os.path.realpath(root)


def resolve(ref: str, root: str) -> str:
    """Full commit sha for `ref`. Resolving up front means a typo fails before a scan runs."""
    try:
        sha = _git(["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], root)
    except GitError:
        sha = ""
    if not sha:
        raise GitError(
            f"`{ref}` is not a commit in this repository. Use a branch, tag or sha that "
            f"exists locally — `--since` reads the baseline from your own object store and "
            f"does not fetch.")
    return sha


def extract(ref: str, root: str, dest: str) -> None:
    """Write the tree at `ref` into `dest`."""
    blob = _git_bytes(["archive", "--format=tar", ref], root)
    # `filter="data"` arrived in 3.12 and was backported to 3.9.17 — not to every 3.9 this
    # package claims to support, and passing it where it does not exist is a TypeError at the
    # worst moment. Feature-detected rather than assumed, and the manual checks below hold on
    # their own either way; the filter is the second lock, not the only one.
    extra = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r|") as tar:
        # A tar from `git archive` cannot contain absolute paths, `..`, symlinks out of the
        # tree, or device nodes — git refuses to record them. Checked anyway: this function
        # writes to the filesystem from an archive, and "the producer is trustworthy" is the
        # assumption behind every tar-extraction CVE. Cheap to verify, expensive to assume.
        root_real = os.path.realpath(dest)
        for member in tar:
            target_path = os.path.realpath(os.path.join(dest, member.name))
            if target_path != root_real and not target_path.startswith(root_real + os.sep):
                raise GitError(f"refusing to extract `{member.name}` outside the baseline dir")
            if member.issym() or member.islnk() or member.isdev():
                continue                       # nothing we analyse lives behind a link
            tar.extract(member, dest, **extra)   # type: ignore[arg-type]  # see `extra`


class baseline_tree:
    """Context manager yielding a directory holding `ref`'s content. Cleans up on the way out."""

    def __init__(self, ref: str, target: str):
        self.ref = ref
        self.target = target
        self.root = repo_root(target)
        self.sha = resolve(ref, self.root)
        self._dir = ""

    def __enter__(self) -> str:
        self._dir = tempfile.mkdtemp(prefix="secaudit-baseline-")
        try:
            extract(self.sha, self.root, self._dir)
        except BaseException:
            shutil.rmtree(self._dir, ignore_errors=True)
            raise
        # Scan the same subtree that was asked for, not the whole repo: `secaudit src --since
        # main` has to compare src against src, or every finding outside src reads as fixed.
        #
        # `realpath` on both sides, because `self.root` came from git already resolved. Mixing
        # spellings here was a real bug and the worst-shaped one this feature can have: on a
        # GitHub Windows runner `TEMP` is an 8.3 short name (`C:\Users\RUNNER~1\...`), git
        # answered with the long name, and `relpath` between them produced `..\..\RUNNER~1\<repo>`
        # — a path that climbs out of the baseline directory and lands back on the LIVE WORKING
        # TREE. `os.path.exists` said yes, so the baseline scanned was the current code. Every
        # finding compared equal to itself, `--since` reported "Nothing new", and a pull request
        # introducing a Critical passed its own gate in silence.
        relative = os.path.relpath(os.path.realpath(self.target), self.root)
        if relative in (".", ""):
            return self._dir
        scoped = os.path.realpath(os.path.join(self._dir, relative))
        # The containment check `extract()` already applies to every tar member, applied to the
        # scoping step too — that asymmetry is exactly where the bug lived. Anything `realpath`
        # cannot reconcile now fails loudly instead of scanning some other directory: a baseline
        # is only a baseline if it came out of the archive.
        inside = os.path.realpath(self._dir)
        if scoped != inside and not scoped.startswith(inside + os.sep):
            raise GitError(
                f"the baseline path for `{self.target}` resolved outside the extracted tree "
                f"({scoped!r}). That means the target and `git rev-parse --show-toplevel` "
                f"disagree about how this directory is spelled, and comparing against the wrong "
                f"tree would report a clean diff for a change that is not clean. Pass the "
                f"target as its resolved path.")
        # A path that did not exist at the baseline is an empty baseline, not an error: every
        # finding in a newly added directory is genuinely new.
        return scoped if os.path.exists(scoped) else os.path.join(self._dir, "__absent__")

    def __exit__(self, *exc) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)
