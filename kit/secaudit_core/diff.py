"""Compare two scans: what a change introduced, what it fixed, what it left alone.

This is what makes a security gate usable on a pull request. Gating on the absolute count fails
every PR forever the moment a repo has any pre-existing debt, so teams turn the gate off; gating
on what the change *added* is a bar a PR can actually clear.

Two decisions carry the correctness of this module.

**Both trees are scanned whole.** The obvious optimisation — scan only the files git says
changed — is wrong here, and quietly so. Taint analysis resolves across import edges, so editing
a route can create a finding whose sink sits in a file the commit never touched; that finding
would never be reported, and the diff would call the PR clean. Scanning both trees costs a second
pass and removes the entire class of miss.

**Findings are matched by content, not by line.** A finding's line number is the least stable
thing about it: adding an import at the top of a file moves every finding below it, and a
line-keyed diff would then report all of them as fixed and re-introduced at once — a diff that
cries wolf on a no-op commit is a diff people stop reading. Identity here is the rule, the file,
and the matched line's text, with an occurrence index to keep repeated identical lines apart.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .schema import Finding, ScanResult, Severity


def fingerprint(finding: Finding, seen: dict[tuple, int]) -> tuple:
    """Identity that survives line drift. `seen` counts collisions and must be reused per scan.

    Whitespace is normalised because a reformat is not a new vulnerability. Everything else in
    the evidence line is kept: two calls that differ only in the variable passed are two
    findings, and collapsing them would hide one behind the other.
    """
    body = " ".join(finding.evidence.split())
    base = (finding.detector_id, finding.file, body)
    index = seen.get(base, 0)
    seen[base] = index + 1
    return (*base, index)


def _index(findings: list[Finding]) -> dict[tuple, Finding]:
    seen: dict[tuple, int] = {}
    return {fingerprint(f, seen): f for f in findings}


def _comparable(f: Finding) -> bool:
    """Whether this finding can be compared against a git baseline at all.

    Dependency findings cannot. They come from the *installed* tree — `npm audit` reads
    `node_modules`, which git does not carry — so a baseline checkout has nothing to reproduce
    them from, and every one of them would read as newly introduced. They are carried into the
    report under their own heading instead of being silently dropped: a PR that adds a
    vulnerable package is exactly the case a security diff must not stay quiet about.
    """
    return not f.package


@dataclass
class DiffResult:
    ref: str
    sha: str
    target: str
    introduced: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    moved: list[tuple[Finding, int]] = field(default_factory=list)   # (current, baseline line)
    not_compared: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    baseline_absent: bool = False

    def worst_introduced(self) -> int:
        return max((f.severity.rank for f in self.introduced), default=0)

    def counts(self) -> dict[str, int]:
        return {"introduced": len(self.introduced), "resolved": len(self.resolved),
                "unchanged": len(self.unchanged), "moved": len(self.moved),
                "not_compared": len(self.not_compared)}


def compare(baseline: ScanResult, current: ScanResult, ref: str, sha: str) -> DiffResult:
    """What `current` has that `baseline` did not, and the other way round."""
    out = DiffResult(ref=ref, sha=sha, target=current.target)

    out.not_compared = [f for f in current.findings if not _comparable(f)]
    base_index = _index([f for f in baseline.findings if _comparable(f)])
    curr_index = _index([f for f in current.findings if _comparable(f)])

    for key, finding in curr_index.items():
        was = base_index.get(key)
        if was is None:
            out.introduced.append(finding)
        elif was.line != finding.line:
            out.moved.append((finding, was.line))
            out.unchanged.append(finding)
        else:
            out.unchanged.append(finding)

    out.resolved = [f for key, f in base_index.items() if key not in curr_index]

    order = lambda f: (-f.severity.rank, f.file, f.line)          # noqa: E731
    out.introduced.sort(key=order)
    out.resolved.sort(key=order)
    out.unchanged.sort(key=order)
    out.not_compared.sort(key=order)

    if out.not_compared:
        out.notes.append(
            f"{len(out.not_compared)} dependency finding(s) are reported in full but not "
            f"diffed: they are derived from the installed tree (node_modules), which a git "
            f"baseline does not contain, so there is nothing to compare them against.")
    if out.moved:
        out.notes.append(
            f"{len(out.moved)} finding(s) moved to a different line without changing. They "
            f"count as unchanged — a finding that shifts because an import was added above it "
            f"was not fixed and was not introduced.")
    return out


def gate(diff: DiffResult, minimum: int) -> bool:
    """True when the diff should fail CI: it *introduced* something at or above `minimum`.

    Deliberately blind to `unchanged`. A gate that fails on pre-existing findings fails every
    PR in any repo with history, and a gate that always fails is a gate that gets disabled —
    at which point it stops catching the new Critical too.
    """
    return diff.worst_introduced() >= minimum


def to_markdown(diff: DiffResult) -> str:
    # Show the resolved sha next to a symbolic ref, but not next to a sha the caller already
    # typed: `since abc123 (abc123)` reads like two different things that happen to match.
    named = diff.sha and not diff.sha.startswith(diff.ref)
    label = f"`{diff.ref}`" + (f" ({diff.sha[:10]})" if named else "")
    counts = diff.counts()
    lines = [
        f"# Security diff — {diff.target} since {label}",
        "",
        f"**{counts['introduced']} introduced · {counts['resolved']} resolved · "
        f"{counts['unchanged']} unchanged**",
        "",
    ]

    if diff.baseline_absent:
        lines += ["> This path did not exist at the baseline, so everything in it is new.", ""]

    def block(title: str, findings: list[Finding], empty: str) -> list[str]:
        out = [f"## {title}", ""]
        if not findings:
            return [*out, empty, ""]
        out += ["| Severity | Rule | Location | Finding |", "|---|---|---|---|"]
        for f in findings:
            title_cell = f.title.replace("|", "\\|")
            out.append(f"| {f.severity.value} | `{f.detector_id}` | "
                       f"`{f.file}:{f.line}` | {title_cell} |")
        return [*out, ""]

    lines += block("Introduced", diff.introduced,
                   "Nothing new. This change did not add a finding.")
    lines += block("Resolved", diff.resolved,
                   "Nothing resolved by this change.")

    if diff.not_compared:
        lines += block("Dependency findings (not diffed)", diff.not_compared, "")

    if diff.unchanged:
        worst = max(f.severity.rank for f in diff.unchanged)
        name = next(s.value for s in Severity if s.rank == worst)
        lines += [
            "## Pre-existing", "",
            f"{len(diff.unchanged)} finding(s) carried over unchanged, the most severe being "
            f"{name}. They are not this change's doing and do not fail the gate — but they are "
            f"still open, and a diff that mentions them only in a count is how they stay open.",
            "",
        ]

    if diff.notes:
        lines += ["## Notes", ""] + [f"- {n}" for n in diff.notes] + [""]

    return "\n".join(lines)


def to_json(diff: DiffResult) -> str:
    import json
    return json.dumps({
        "since": {"ref": diff.ref, "sha": diff.sha},
        "target": diff.target,
        "counts": diff.counts(),
        "introduced": [f.to_dict() for f in diff.introduced],
        "resolved": [f.to_dict() for f in diff.resolved],
        "unchanged": [f.to_dict() for f in diff.unchanged],
        "not_compared": [f.to_dict() for f in diff.not_compared],
        "notes": diff.notes,
    }, indent=2)
