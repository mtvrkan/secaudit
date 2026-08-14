"""Continuous monitoring — the EU CRA's 24-hour clock, in practice.

A source scan answers "what is wrong with this code now". It cannot answer the question the CRA
attaches a deadline to, because that question is about the world and not about the code: *a
dependency you already ship became actively exploited overnight, and nothing in your repository
changed.* From 2026-09-11 that event starts a 24-hour early-warning obligation to ENISA and the
relevant CSIRT, and the only way to notice it is to keep asking.

`--watch` is that loop. It records the advisories a scan found, each with the reachability verdict
`deps.py` gave it, and on every later run re-asks the exploitation feeds about exactly those CVE
ids and reports the **transitions**. It is a diff over the world rather than over the source, which
is what makes it different from `--since`.

DESIGN RULES

1. **A feed that could not be reached is never "no change".** This is the rule the module exists
   to hold, and it is the one that separates monitoring from the appearance of monitoring: a loop
   that prints a clean report when it failed to check manufactures the belief that somebody is
   watching. When the catalog is unusable `compare()` refuses to produce a comparison at all —
   it returns a report whose only content is that it could not be produced, the stored state is
   left untouched so the next successful run still compares against real data, and the exit code
   is non-zero. "Nothing changed" and "I could not look" must never render the same.

2. **Recorded status is a high-water mark.** Once an advisory has been seen `exploited` it stays
   `exploited` in the state even if a later fetch does not say so. KEV membership is a statement
   that exploitation *happened*; a feed that stops listing it has not un-happened it, and the
   alternative lets one bad fetch silently close a finding that started a legal clock. Same rule
   as `exploitation.apply`, which raises severity and never lowers it.

3. **Reachability ranks, it never filters.** An advisory `deps.py` called `not_affected` is still
   watched and still reported when it becomes exploited — just below the reachable ones. The
   classification is an import-level inference that can be wrong, and the obligation attaches to
   the product rather than to our confidence about it.

4. **The comparison is pure.** `compare()` takes a state and a catalog and returns a report. It
   fetches nothing, writes nothing and reads no clock, so the alerting logic is tested offline
   against constructed catalogs rather than against whatever CISA published this morning.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from . import compliance, deps, exploitation

SCHEMA = 1

# Ordered worst-first. Used for the high-water mark in rule 2 and to rank the report.
_RANK = {"exploited": 3, "elevated": 2, "listed": 1, "unknown": 0, "": 0}

# Reachability, worst first. `affected` means first-party code imports the package.
_REACH_RANK = {deps.STATUS_AFFECTED: 2, deps.STATUS_UNDER_INVESTIGATION: 1,
               deps.STATUS_NOT_AFFECTED: 0, "": 1}


@dataclass
class Watched:
    """One advisory being kept an eye on."""
    cve: str
    package: str = ""
    vex_status: str = ""
    severity: str = ""
    exploitation: str = "unknown"
    first_seen: str = ""
    exploited_since: str = ""

    @property
    def reachable(self) -> bool:
        return self.vex_status != deps.STATUS_NOT_AFFECTED

    def to_dict(self) -> dict:
        return {"cve": self.cve, "package": self.package, "vex_status": self.vex_status,
                "severity": self.severity, "exploitation": self.exploitation,
                "first_seen": self.first_seen, "exploited_since": self.exploited_since}

    @classmethod
    def from_dict(cls, raw: dict) -> Watched:
        return cls(cve=raw.get("cve", ""), package=raw.get("package", ""),
                   vex_status=raw.get("vex_status", ""), severity=raw.get("severity", ""),
                   exploitation=raw.get("exploitation", "unknown"),
                   first_seen=raw.get("first_seen", ""),
                   exploited_since=raw.get("exploited_since", ""))


@dataclass
class Transition:
    """An advisory whose exploitation status moved, and which way."""
    watched: Watched
    previous: str
    current: str
    note: str = ""

    @property
    def is_trigger(self) -> bool:
        """Whether this is the class the CRA's 24-hour early warning attaches to."""
        return self.current == "exploited" and self.previous != "exploited"


@dataclass
class Report:
    """What changed in the world since the last run — or why that could not be established."""
    target: str = ""
    blocked: str = ""                       # non-empty means no comparison was made at all
    feed_errors: list[str] = field(default_factory=list)
    triggered: list[Transition] = field(default_factory=list)
    escalated: list[Transition] = field(default_factory=list)
    unchanged: int = 0
    watched_total: int = 0
    still_exploited: list[Watched] = field(default_factory=list)

    @property
    def alerting(self) -> bool:
        """Whether this run should wake somebody up.

        A blocked run alerts. That is rule 1: the caller must not be able to tell a quiet night
        from an unreachable feed by looking at the exit code.
        """
        return bool(self.blocked) or bool(self.triggered)


def watchlist_from(findings: list, target: str, at: str) -> dict:
    """The state a first `--watch` run records, built from a scan's dependency findings.

    Only findings that already name a CVE are watched — the same bound as
    `exploitation.apply`, for the same reason: this tracks known vulnerabilities and never
    invents one.
    """
    seen: dict[str, Watched] = {}
    for finding in findings:
        cve = exploitation._cve_of(finding)
        if not cve or cve in seen:
            continue
        seen[cve] = Watched(
            cve=cve,
            package=getattr(finding, "dependency", "") or "",
            vex_status=getattr(finding, "vex_status", "") or "",
            severity=getattr(getattr(finding, "severity", None), "value", "") or "",
            exploitation=getattr(finding, "exploitation", "") or "unknown",
            first_seen=at,
            exploited_since=at if getattr(finding, "exploitation", "") == "exploited" else "")
    return {"schema": SCHEMA, "target": target, "recorded": at,
            "watched": [w.to_dict() for w in _ranked(seen.values())]}


def _ranked(items) -> list[Watched]:
    return sorted(items, key=lambda w: (-_RANK.get(w.exploitation, 0),
                                        -_REACH_RANK.get(w.vex_status, 1), w.cve))


def compare(state: dict, catalog: exploitation.Catalog) -> Report:
    """What the feeds say now versus what the state recorded. Pure — see rule 4."""
    watched = [Watched.from_dict(raw) for raw in state.get("watched", [])]
    report = Report(target=state.get("target", ""), watched_total=len(watched),
                    feed_errors=list(catalog.errors))

    if not catalog.usable:
        report.blocked = (
            "No comparison was made: neither exploitation feed could be read, so this run "
            "established nothing about whether anything changed. This is reported as a failure "
            "rather than as a quiet night on purpose — an unreachable feed and no news are the "
            "same silence, and only one of them means you are covered.")
        return report

    for item in watched:
        current = catalog.status_for(item.cve)
        previous = item.exploitation or "unknown"
        # Rule 2: the recorded status is a high-water mark, so a lower reading does not move it.
        if _RANK.get(current, 0) <= _RANK.get(previous, 0):
            if previous == "exploited":
                report.still_exploited.append(item)
            else:
                report.unchanged += 1
            continue
        transition = Transition(watched=item, previous=previous, current=current,
                                note=catalog.note_for(item.cve))
        (report.triggered if transition.is_trigger else report.escalated).append(transition)

    report.triggered.sort(key=lambda t: (-_REACH_RANK.get(t.watched.vex_status, 1),
                                         t.watched.cve))
    return report


def advance(state: dict, report: Report, at: str) -> dict:
    """The state to store after a comparison. A blocked run does not move it — see rule 1."""
    if report.blocked:
        return state
    moved = {t.watched.cve: t for t in report.triggered + report.escalated}
    out = []
    for raw in state.get("watched", []):
        item = Watched.from_dict(raw)
        transition = moved.get(item.cve)
        if transition:
            item.exploitation = transition.current
            if transition.is_trigger:
                item.exploited_since = at
        out.append(item)
    return {**state, "schema": SCHEMA, "recorded": at,
            "watched": [w.to_dict() for w in _ranked(out)]}


def load(path: str) -> dict | None:
    """The stored state, or None when there is not one yet. A file that cannot be parsed is an
    error rather than an empty baseline: silently starting over would erase the history that the
    first alert depends on."""
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        state = json.load(fh)
    if state.get("schema") != SCHEMA:
        raise ValueError(f"{path} was written by schema {state.get('schema')!r}, this build "
                         f"reads schema {SCHEMA}. Delete it to start a new baseline — and know "
                         f"that doing so resets every `exploited_since` date in it.")
    return state


def save(path: str, state: dict) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=1, sort_keys=False)
        fh.write("\n")


def to_markdown(report: Report) -> str:
    lines = [f"# Exploitation watch — {report.target or 'target'}", ""]

    if report.blocked:
        lines += ["## Could not be established", "", report.blocked, ""]
        lines += [f"- {e}" for e in report.feed_errors]
        return "\n".join(lines) + "\n"

    if report.triggered:
        lines += [f"## {len(report.triggered)} advisory(ies) became actively exploited", "",
                  "Under the EU Cyber Resilience Act this is the class that starts the "
                  "**24-hour early-warning** clock to ENISA and your CSIRT "
                  f"(obligation live from {compliance.CRA_REPORTING_STARTS}). "
                  "Reachable ones are listed first; an advisory called `not_affected` is still "
                  "here because that verdict is an import-level inference and the obligation is "
                  "about the product.", ""]
        lines += ["| CVE | Package | Reachability | Was | Now |", "|---|---|---|---|---|"]
        for t in report.triggered:
            lines.append(f"| `{t.watched.cve}` | {t.watched.package or '—'} | "
                         f"{t.watched.vex_status or 'unknown'} | {t.previous} | **{t.current}** |")
        lines.append("")
        for t in report.triggered:
            if t.note:
                lines += [f"- `{t.watched.cve}` — {t.note}"]
        lines.append("")
    else:
        lines += ["## Nothing became actively exploited since the last run", "",
                  "Both feeds answered, which is what makes this sentence mean anything.", ""]

    if report.escalated:
        lines += [f"### {len(report.escalated)} rose without reaching KEV", ""]
        lines += ["| CVE | Package | Was | Now |", "|---|---|---|---|"]
        for t in report.escalated:
            lines.append(f"| `{t.watched.cve}` | {t.watched.package or '—'} | {t.previous} | "
                         f"{t.current} |")
        lines.append("")

    if report.still_exploited:
        lines += [f"### {len(report.still_exploited)} still exploited, already reported", "",
                  "Carried rather than repeated as new: the clock on these started when they "
                  "first appeared, and re-alerting would restart it.", ""]
        for w in report.still_exploited:
            since = f" since {w.exploited_since}" if w.exploited_since else ""
            lines.append(f"- `{w.cve}` — {w.package or 'unknown package'}{since}")
        lines.append("")

    lines += ["---", "",
              f"{report.watched_total} advisory(ies) watched, {report.unchanged} unchanged. "
              f"Absence from KEV means unlisted, not safe."]
    if report.feed_errors:
        lines += ["", "Partial feed errors (the comparison above used what did answer):"]
        lines += [f"- {e}" for e in report.feed_errors]
    # Printed on every run, like every other tier's bounds: a limitation stated once in a doc is
    # a limitation the person reading the alert has not read.
    lines += [""] + [f"> {line}" for line in limitations()]
    return "\n".join(lines) + "\n"


def limitations() -> list[str]:
    return [
        "Exploitation watch (`--watch`) tracks the CVE ids a scan already found; it does not "
        "discover new advisories on its own, so re-scan on the same schedule to pick up "
        "dependencies that gained one. A run where a feed could not be read reports that it "
        "established nothing and leaves the stored state untouched, rather than reporting no "
        "change.",
    ]
