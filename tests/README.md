# Self-test / eval

A tiny, intentionally-vulnerable fixture used to sanity-check SecAudit's coverage and
catch regressions. **The fixture is not real, not deployable, and contains only
clearly-fake/example secrets.**

## Run

```
/secaudit-code tests/fixtures/vulnerable-app
```

(or, with tools installed, `npm audit`, `semgrep`, `gitleaks` will be used automatically.)

## Check

Compare the report against [`expected-findings.md`](expected-findings.md). All 20 planted
code findings (16 JavaScript + 4 Python) must appear; dependency and secret sections must be
populated (or clearly marked "tool/lookup unavailable"). Misses are regressions.

Score it mechanically instead of eyeballing — save the produced report to a file and run:

```
python3 tests/grade-report.py my-report.md
```

The grader reads the golden set from `expected-findings.md` (single source of truth) and
checks, for each finding V1–V20, whether the report cites it — by its CWE id or by a
location token unique to that finding — then reports coverage (e.g. `20/20`) and whether
the dependency + secret sections are populated. Exit code is non-zero on any shortfall, so
it doubles as a regression gate. The committed reference report is graded in CI with
`--min 20`, so it can never silently drop a finding.

The grader tests itself too — `python3 tests/grade-report.py --selftest` asserts it credits
a complete report and, crucially, does *not* credit prose that only brushes past finding
keywords (guarding against false-PASS drift). CI runs this before grading the report.

### Deterministic integrity check (runs in CI)

The full audit needs Claude, but fixture integrity is checked mechanically so the golden
set can't silently drift:

```
python3 tests/selftest.py
```

It asserts all 20 planted sinks (V1–V16 JavaScript, V17–V20 Python) and the 3 example
secrets are still present, and
that `npm audit` on the lockfile reports ≥10 vulnerabilities incl. ≥1 critical (the same
numbers the reference report cites — skipped gracefully if npm is offline). It also gates the
negative-control fixture (below). Wired into
[`.github/workflows/validate.yml`](../.github/workflows/validate.yml).

## Precision — the negative control (`fixtures/secure-app`)

Recall (finding the 20 flaws) is only half of quality; a scanner that flags everything has
perfect recall and is useless. [`fixtures/secure-app`](fixtures/secure-app) is the **precision**
corpus: the *same* features as the vulnerable fixture, each implemented **safely** (S1–S20 ↔
V1–V20). A correct audit should report **no High/Critical findings** on it.

```
/secaudit-code tests/fixtures/secure-app
```

Any High/Critical that maps to S1–S20 is a false positive; precision = 1 − (false positives / 20).
Expected result and the control neutralizing each class: [`expected-clean.md`](expected-clean.md).

`selftest.py` gates the corpus deterministically — it asserts no vulnerable sink marker has
crept back in **and** that every safe control is still present, so the negative control can't
silently drift into being vulnerable (which would make a precision run meaningless) or be
emptied out (which would make it trivially pass). The live precision number depends on the model
at run time, like all detection quality; this corpus makes it **measurable** rather than assumed.

A reference run (in **fallback mode** — no scanners installed, Claude analysis + `npm`
only) is saved at [`../examples/self-test-report.md`](../examples/self-test-report.md) as
proof the flow works end-to-end.

## Adding cases

When you add a new check to a `references/*.md`, plant a matching minimal example in the
fixture and add a row to `expected-findings.md`. Keep examples small and clearly labeled
`INTENTIONALLY VULNERABLE`.
