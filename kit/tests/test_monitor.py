#!/usr/bin/env python3
"""Continuous mode (`--watch`) — the transitions, and the refusals that make them mean something.

The rule under test that matters more than the others: a run where the feeds could not be read
must NOT render, exit or store like a quiet night. Everything else here is ordinary diffing; that
one is the difference between monitoring and the appearance of it.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secaudit_core import deps, exploitation, monitor          # noqa: E402
from secaudit_core.schema import Finding, Severity, Confidence  # noqa: E402

FAILURES: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        FAILURES.append(message)


def advisory(cve: str, package: str, vex: str = deps.STATUS_AFFECTED,
             status: str = "unknown") -> Finding:
    f = Finding(detector_id=cve, title=f"{package}: {cve}",
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                cwe="CWE-1395", owasp="A06", file="package.json", line=1,
                evidence=cve, fix="upgrade", source="npm-audit")
    f.dependency = package
    f.vex_status = vex
    f.exploitation = status
    return f


def test_baseline_records_what_the_scan_found() -> None:
    state = monitor.watchlist_from(
        [advisory("CVE-2024-0001", "lodash"),
         advisory("CVE-2024-0002", "express", vex=deps.STATUS_NOT_AFFECTED),
         Finding(detector_id="SEC-JS-EVAL", title="eval", severity=Severity.HIGH,
                 confidence=Confidence.HIGH, cwe="CWE-95", owasp="A03", file="a.js", line=1,
                 evidence="eval(x)", fix="don't")],
        "proj", "2026-08-14")

    check(state["schema"] == monitor.SCHEMA, "baseline must stamp its schema")
    cves = [w["cve"] for w in state["watched"]]
    check(cves == ["CVE-2024-0001", "CVE-2024-0002"],
          f"only CVE-bearing findings are watched, reachable first — got {cves}")
    check(state["watched"][0]["package"] == "lodash", "the package is carried into the state")
    check(state["watched"][1]["vex_status"] == deps.STATUS_NOT_AFFECTED,
          "a not_affected advisory is still watched — reachability ranks, it does not filter")


def test_a_new_kev_entry_is_the_cra_trigger() -> None:
    state = monitor.watchlist_from([advisory("CVE-2024-0001", "lodash")], "proj", "2026-08-14")
    catalog = exploitation.catalog_from({"CVE-2024-0001"}, {})
    report = monitor.compare(state, catalog)

    check(len(report.triggered) == 1, f"a CVE entering KEV triggers — got {len(report.triggered)}")
    check(report.triggered[0].is_trigger, "entering KEV is the 24-hour class")
    check(report.alerting, "a trigger has to alert")
    md = monitor.to_markdown(report)
    check("24-hour" in md, "the report has to name the obligation it is about")
    check("CVE-2024-0001" in md, "the report has to name the advisory")

    advanced = monitor.advance(state, report, "2026-08-15")
    check(advanced["watched"][0]["exploitation"] == "exploited", "state records the new status")
    check(advanced["watched"][0]["exploited_since"] == "2026-08-15",
          "the date the clock started is recorded")


def test_an_unreachable_feed_is_not_a_quiet_night() -> None:
    """The rule this module exists for. Three ways it must not look like 'no change'."""
    state = monitor.watchlist_from([advisory("CVE-2024-0001", "lodash")], "proj", "2026-08-14")
    dead = exploitation.Catalog(errors=["KEV could not be fetched (URLError): no route to host"])
    report = monitor.compare(state, dead)

    check(bool(report.blocked), "an unusable catalog must block the comparison outright")
    check(report.alerting, "a blocked run must alert — exit code cannot read as all-clear")
    check(not report.triggered and report.unchanged == 0,
          "a blocked run must not report anything as unchanged")
    md = monitor.to_markdown(report)
    check("Could not be established" in md, f"the report must say it established nothing:\n{md}")
    check("Nothing became actively exploited" not in md,
          "a blocked run must never render the all-clear sentence")

    frozen = monitor.advance(state, report, "2026-08-15")
    check(frozen == state,
          "a blocked run must leave the stored state untouched, so the next good run still "
          "compares against real data")


def test_status_is_a_high_water_mark() -> None:
    state = monitor.watchlist_from(
        [advisory("CVE-2024-0001", "lodash", status="exploited")], "proj", "2026-08-14")
    # The feeds answer, and this CVE is no longer listed in KEV.
    catalog = exploitation.catalog_from(set(), {"CVE-2024-0001": 0.01})
    report = monitor.compare(state, catalog)

    check(not report.triggered and not report.escalated,
          "a lower reading must not be reported as a change")
    check(len(report.still_exploited) == 1,
          "an already-exploited advisory is carried, not re-alerted and not closed")
    check(not report.alerting, "carrying a known-exploited advisory is not a new alert")
    advanced = monitor.advance(state, report, "2026-08-15")
    check(advanced["watched"][0]["exploitation"] == "exploited",
          "exploitation never downgrades in the stored state")


def test_escalation_below_kev_is_reported_but_does_not_trigger() -> None:
    state = monitor.watchlist_from(
        [advisory("CVE-2024-0001", "lodash", status="listed")], "proj", "2026-08-14")
    catalog = exploitation.catalog_from(set(), {"CVE-2024-0001": 0.42})
    report = monitor.compare(state, catalog)

    check(not report.triggered, "EPSS movement is not the CRA trigger")
    check(len(report.escalated) == 1, "a rise below KEV is still worth reporting")
    check(not report.alerting, "escalation short of KEV must not page anyone")


def test_reachable_advisories_are_reported_first() -> None:
    state = monitor.watchlist_from(
        [advisory("CVE-2024-0002", "express", vex=deps.STATUS_NOT_AFFECTED),
         advisory("CVE-2024-0001", "lodash", vex=deps.STATUS_AFFECTED)], "proj", "2026-08-14")
    catalog = exploitation.catalog_from({"CVE-2024-0001", "CVE-2024-0002"}, {})
    report = monitor.compare(state, catalog)

    check(len(report.triggered) == 2, "both trigger — not_affected does not filter")
    check(report.triggered[0].watched.package == "lodash",
          "the one first-party code actually imports is ranked first")


def test_state_round_trips_and_refuses_a_foreign_schema() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "nested", "watch.json")
        state = monitor.watchlist_from([advisory("CVE-2024-0001", "lodash")], "p", "2026-08-14")
        monitor.save(path, state)
        check(monitor.load(path) == state, "state must round-trip through the file")

        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        raw["schema"] = 999
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)
        try:
            monitor.load(path)
        except ValueError as e:
            check("999" in str(e), "the refusal names the schema it found")
        else:
            FAILURES.append("a state file from another schema must be refused, not silently "
                            "treated as a fresh baseline — that erases every exploited_since")

        check(monitor.load(os.path.join(tmp, "gone.json")) is None,
              "a missing state file is a first run, not an error")


def main() -> int:
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    if FAILURES:
        print("MONITOR TESTS FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("MONITOR TESTS PASSED — CRA trigger, high-water mark, reachability ranking, and the "
          "refusal that matters: an unreachable feed blocks the comparison, alerts, and leaves "
          "the stored state alone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
