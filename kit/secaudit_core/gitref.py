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
    """The work tree containing `target`, or GitError explaining why there isn't one."""
    start = target if os.path.isdir(target) else os.path.dirname(os.path.abspath(target))
    root = _git(["rev-parse", "--show-toplevel"], start or ".")
    if not root:
        raise GitError(f"{target} is not inside a git repository, so `--since` has no baseline.")
    return os.path.normpath(root)


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
        relative = os.path.relpath(os.path.abspath(self.target), self.root)
        if relative in (".", ""):
            return self._dir
        scoped = os.path.join(self._dir, relative)
        # A path that did not exist at the baseline is an empty baseline, not an error: every
        # finding in a newly added directory is genuinely new.
        return scoped if os.path.exists(scoped) else os.path.join(self._dir, "__absent__")

    def __exit__(self, *exc) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)
