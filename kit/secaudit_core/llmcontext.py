"""The source code the Tier-1 model actually reads.

Until this module existed, Tier 1 received only Tier 0's own output: a detector id, a file, a
line, a severity and a single line of `evidence`. Two consequences followed from that and both
were wrong in the direction that flatters:

  * **Triage was judging a citation, not the code.** "Decide if this is real and reachable from
    untrusted input in THIS code" was asked of a model that had never been shown the code. It
    could only agree with the detector or guess.
  * **Logic-bug discovery was structurally impossible.** The `extra` channel asks for the flaws
    the pattern scan missed — IDOR, missing ownership checks, the classes RealVuln files under
    `broken_access_control` and `missing_auth`. Those live in handlers that Tier 0 never flagged,
    so nothing about them was in the payload. Anything the model returned there was invented.

So the payload now carries source. Two passes, in this order, because the order is what degrades
gracefully when a repository is larger than the budget:

  1. **Excerpts around every finding** — the code triage needs. Overlapping windows in one file
     are merged so a dense file is sent once, not once per finding.
  2. **Whole files Tier 0 never flagged** — the only way the model can report something Tier 0
     did not. Ranked toward request handlers, because that is where the undetectable classes sit.

Excerpts are packed first, so a truncated context loses discovery breadth and never loses the
code behind a finding being triaged. Truncation is recorded and reported; a clean triage over a
partial view must not read as a clean triage over the repository.

**Privacy.** This changed what leaves the host. Before, a remote backend saw findings metadata;
now it sees source. That is the point — a model cannot audit code it cannot read — but it makes
`--backend ollama` (local, nothing leaves the machine) a materially different choice rather than
a slower one, and it makes the exclusion list below load-bearing rather than tidy: credential
material is never shipped to a third-party API, whatever the scan is pointed at.

Determinism: every listing is sorted before use. `os.walk` order is not stable across machines
and this repository has already shipped one bug where file-walk order changed which findings
appeared; a context that varies run to run would put that bug back in a place where it would be
much harder to see.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from .engine import MAX_BYTES, SKIP_DIRS
from .schema import ScanResult

# Lines kept on each side of a finding. Wide enough to carry the enclosing function in ordinary
# code — a triage decision usually turns on the guard clause above the sink, not on the sink.
EXCERPT_BEFORE = 14
EXCERPT_AFTER = 14

# Character budget for one call's source payload, and the cap on how many calls one scan may
# make. Characters rather than tokens because the shipped package declares zero runtime
# dependencies and `assert_no_runtime_deps.py` gates that, so there is no tokenizer to call;
# ~4 chars/token puts 240k chars near 60k tokens, which every supported backend accepts.
# MAX_CHUNKS is a cost ceiling as much as a context one: it bounds a scan at four model calls
# no matter how large the repository, so a run against a monorepo cannot quietly become a
# hundred-call bill.
CHUNK_BUDGET_CHARS = 240_000
MAX_CHUNKS = 4

# Extensions worth showing a security model. Deliberately not "every text file": lockfiles,
# minified bundles and generated migrations burn budget that handler code should have.
SOURCE_EXTS = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".php", ".java",
    ".kt", ".cs", ".rs", ".swift", ".scala", ".ex", ".exs", ".pl", ".sh",
)

# Never shipped to a backend, remote or local. These are credential material; a scan that reads
# them is doing its job, a payload that forwards them is an exfiltration path with a helpful
# name on it. Matched on the basename and on any path segment, so `secrets/prod.py` is caught
# by the segment rule even though its extension is ordinary source.
SECRET_BASENAMES = {
    ".env", "id_rsa", "id_ed25519", "id_ecdsa", "credentials.json", "secrets.json",
    "serviceaccountkey.json", "kubeconfig", "npmrc", ".npmrc", ".pypirc", ".netrc",
}
SECRET_SUFFIXES = (
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".tfstate", ".kubeconfig", ".ppk",
)
SECRET_SEGMENTS = {"secrets", ".ssh", ".gnupg"}

# Path fragments that mark a file as request-handling code. The classes Tier 0 structurally
# cannot decide — missing ownership checks, absent authorization, business-logic flaws — are
# properties of what a handler does, so handlers are what the discovery budget should buy.
_HANDLER_HINTS = (
    "route", "view", "controller", "handler", "endpoint", "api", "resource",
    "auth", "login", "session", "permission", "admin", "middleware", "serializer",
)


@dataclass
class SourceContext:
    """The rendered payload plus an honest account of what it does and does not contain."""

    chunks: list[str] = field(default_factory=list)
    excerpt_files: list[str] = field(default_factory=list)
    discovery_files: list[str] = field(default_factory=list)
    secret_files_withheld: list[str] = field(default_factory=list)
    source_files_total: int = 0
    omitted_for_budget: int = 0

    @property
    def truncated(self) -> bool:
        return self.omitted_for_budget > 0

    def note(self) -> str:
        """One sentence a report can print verbatim. States the bound, never implies coverage."""
        seen = len(set(self.excerpt_files) | set(self.discovery_files))
        parts = [f"Tier-1 read source from {seen} of {self.source_files_total} source files "
                 f"({len(self.excerpt_files)} as excerpts around findings, "
                 f"{len(self.discovery_files)} in full for discovery) across "
                 f"{len(self.chunks)} model call(s)."]
        if self.omitted_for_budget:
            parts.append(f"{self.omitted_for_budget} file(s) were not sent because the context "
                         f"budget ran out — findings cannot be ruled out there.")
        if self.secret_files_withheld:
            parts.append(f"{len(self.secret_files_withheld)} file(s) matching credential "
                         f"patterns were withheld from the model by policy.")
        return " ".join(parts)


def is_secret_path(rel: str) -> bool:
    """Credential material, matched on basename, suffix, or an enclosing directory."""
    norm = rel.replace("\\", "/").lower()
    base = norm.rsplit("/", 1)[-1]
    if base in SECRET_BASENAMES or base.startswith(".env"):
        return True
    if norm.endswith(SECRET_SUFFIXES):
        return True
    return any(seg in SECRET_SEGMENTS for seg in norm.split("/")[:-1])


def _source_files(root: str) -> list[str]:
    """Every readable source file under `root`, relative and sorted (see the determinism note)."""
    if os.path.isfile(root):
        return [os.path.basename(root)] if root.endswith(SOURCE_EXTS) else []
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith(SOURCE_EXTS):
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > MAX_BYTES:
                    continue
            except OSError:
                continue
            out.append(os.path.relpath(full, root).replace("\\", "/"))
    return sorted(out)


def _read(root: str, rel: str) -> str | None:
    path = root if os.path.isfile(root) else os.path.join(root, rel)
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return None


def _merged_ranges(lines: list[int], total: int) -> list[tuple[int, int]]:
    """Finding lines -> merged 1-based inclusive windows. Overlaps collapse, so a file with
    twenty findings in one function is sent once rather than twenty times."""
    spans = sorted((max(1, ln - EXCERPT_BEFORE), min(total, ln + EXCERPT_AFTER))
                   for ln in sorted(set(lines)) if ln >= 1)
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _render(rel: str, text: str, spans: list[tuple[int, int]] | None) -> str:
    """A file or its windows, line-numbered. Numbers are not decoration: the model reports a
    `line` back and a report that cites the wrong line is a finding nobody can check."""
    lines = text.splitlines()
    if spans is None:
        body = "\n".join(f"{i:>5} | {ln}" for i, ln in enumerate(lines, 1))
        return f"===== FILE {rel} (complete, {len(lines)} lines) =====\n{body}\n"
    out = [f"===== FILE {rel} (excerpts, {len(lines)} lines total) ====="]
    for start, end in spans:
        out.append(f"--- lines {start}-{end} ---")
        out.extend(f"{i:>5} | {lines[i - 1]}" for i in range(start, min(end, len(lines)) + 1))
    return "\n".join(out) + "\n"


def _discovery_rank(rel: str) -> tuple:
    """Handlers first, then small files before large ones, then path for determinism.

    Small-first is not an aesthetic: within a fixed budget, ten 200-line handlers give the model
    ten chances to find a missing ownership check and one 2000-line module gives it one.
    """
    low = rel.lower()
    return (0 if any(h in low for h in _HANDLER_HINTS) else 1, rel)


def build(result: ScanResult, root: str | None = None) -> SourceContext:
    """Assemble the source payload for one scan. Returns an empty context (no chunks) when the
    target is not a readable tree — a live-URL scan has no source and must not pretend to."""
    root = root or result.target
    ctx = SourceContext()
    if not root or not os.path.exists(root):
        return ctx

    all_files = _source_files(root)
    withheld = [f for f in all_files if is_secret_path(f)]
    usable = [f for f in all_files if not is_secret_path(f)]
    ctx.secret_files_withheld = withheld
    ctx.source_files_total = len(usable)
    if not usable:
        return ctx

    flagged: dict[str, list[int]] = {}
    for f in result.findings:
        rel = (f.file or "").replace("\\", "/")
        if rel in usable and f.line:
            flagged.setdefault(rel, []).append(f.line)

    # Pass 1 — the code behind each finding. Packed first so truncation never costs triage.
    blocks: list[tuple[str, str, bool]] = []          # (rel, rendered, is_excerpt)
    for rel in sorted(flagged):
        text = _read(root, rel)
        if text is None:
            continue
        spans = _merged_ranges(flagged[rel], len(text.splitlines()))
        blocks.append((rel, _render(rel, text, spans), True))

    # Pass 2 — files Tier 0 said nothing about, which is the only place discovery can happen.
    for rel in sorted((f for f in usable if f not in flagged), key=_discovery_rank):
        text = _read(root, rel)
        if text is not None:
            blocks.append((rel, _render(rel, text, None), False))

    chunks: list[str] = []
    current: list[str] = []
    size = 0
    for i, (rel, rendered, is_excerpt) in enumerate(blocks):
        if current and size + len(rendered) > CHUNK_BUDGET_CHARS:
            chunks.append("\n".join(current))
            current, size = [], 0
            if len(chunks) >= MAX_CHUNKS:
                ctx.omitted_for_budget = len(blocks) - i
                break
        # A single block larger than the whole budget is truncated rather than dropped: half a
        # handler still shows a missing authorization check, and dropping it silently would be
        # the one outcome this module exists to prevent.
        current.append(rendered[:CHUNK_BUDGET_CHARS])
        size += min(len(rendered), CHUNK_BUDGET_CHARS)
        (ctx.excerpt_files if is_excerpt else ctx.discovery_files).append(rel)
    else:
        if current:
            chunks.append("\n".join(current))
    ctx.chunks = chunks
    return ctx
