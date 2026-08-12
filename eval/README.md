# Evaluation

Numbers SecAudit states about its own detection quality are produced here, by a harness you
can run, against labels derived from the corpus rather than typed next to it.

```bash
python3 eval/build_ground_truth.py   # regenerate labels from the fixtures + golden set
python3 eval/harness.py              # score, write scorecard.md + scorecard.json
python3 eval/harness.py --gate       # fail if a metric dropped below eval/thresholds.json
python3 eval/harness.py --check      # fail if the committed scorecard is stale (CI)
```

Current result: **[`scorecard.md`](scorecard.md)**.

## What is measured, and what it is worth

| | |
|---|---|
| [`ground-truth/secaudit-fixtures/`](ground-truth) | 20 labelled vulnerabilities + 20 false-positive traps, **generated** by `build_ground_truth.py` from the fixture marker comments and `tests/expected-findings.md`. Never hand-edited. |
| [`harness.py`](harness.py) | Region + CWE matching, per class and per language, precision / recall / F1 / F3. Scoring rules are in its module docstring — read them before quoting a number. |
| [`thresholds.json`](thresholds.json) | The regression floors, set to measured values with the reasoning written next to each. |
| [`realvuln/`](realvuln) | The external benchmark: what to run to get a number nobody at this end computed. |

**The traps are the point.** Each `is_vulnerable: false` entry is a *safe implementation of
the same feature* as its vulnerable twin — `S1` is the parameterized version of `S1`'s
injectable query, `S12` is the same file read with the path boundary actually enforced. Staying
quiet on unrelated clean code is easy; staying quiet on the correct version of the code you
just flagged is the thing that decides whether anyone keeps reading your reports.

**This is a floor, not a forecast.** These fixtures were written alongside the detectors. A
number measured against a corpus you tuned on says "this still works", not "this will work on
your code". Published external numbers are the ones to compare against, which is why
[`realvuln/`](realvuln) exists and why the scorecard says so at the top rather than in a
footnote.

**Precision is reported as an upper bound.** Results that land outside any labelled region are
counted and shown but not scored as false positives, because the ground truth labels only what
was planted and an unlabelled hit may be a real finding. Folding them in either direction
would be inventing data.

**Tier 1 is excluded.** LLM triage and logic-bug discovery are not reproducible, so they do not
belong in a regression gate. What the LLM tier adds is demonstrated separately and
deterministically by `kit/tests/test_enrich_e2e.py`, which replays a captured model response.

## Changing a label

Widening a label and improving a scanner produce the same green build, so the rules for what
may go in an `acceptable_cwes` set are written down in
[`tests/expected-findings.md`](../tests/expected-findings.md) and a change to one needs a
reason in the PR. The two admissible reasons: a more specific child of the listed CWE is a
correct classification, or the labelled block genuinely plants several distinct issues.

## Adding a corpus

The ground-truth format is
[RealVuln's](https://github.com/kolega-ai/Real-Vuln-Benchmark), so any corpus in that shape
scores without changes:

```bash
python3 -m secaudit_core.cli /path/to/corpus --format semgrep -o results.json
python3 eval/harness.py --results results.json --ground-truth /path/to/ground-truth.json
```
