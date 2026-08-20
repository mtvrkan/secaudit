# Quality plan 2 — detection 84 → 90, engineering 87 → 90

The first plan (`QUALITY-PLAN.md`, 2026-08-18) took detection from 74 and technical debt from 70,
and it worked because it said what the number had to *mean* before anything was built. This one
holds to the same rule. A score somebody assigns can be argued into existence; a measured one
cannot.

## Exit criteria — done when these are true, not when the rounds are finished

**Detection → 90**

| Metric | Now | Target | Read from |
|---|---|---|---|
| RealVuln F3 (recall ×9) | 61.1 | **≥ 67** | `eval/realvuln/result.json`, the benchmark's own scorer |
| RealVuln recall | 0.6067 | **≥ 0.66** | same |
| RealVuln precision | 0.6562 | **≥ 0.65** (hold) | same |
| CVEfixes, files | 15.66% | **≥ 18%** | `eval/cvefixes/result.json` |
| SecBench.js recall | 0.5445 | **≥ 0.57** | `eval/secbenchjs/result.json` |
| Noise floor / 1k lines | 0.42 | **≤ 0.50** | `eval/noisefloor/result.json` |
| Sealed slice | reported | **reported separately, never merged into the headline** | `eval/heldout.json` |

Precision is a hold, not a target, and it is the honest constraint on the whole plan: recall
bought by widening a rule until it matches everything is not detection, and F3 rewards it anyway
because it weights recall nine to one. **+95 true positives at today's false-positive rate is
what recall 0.66 costs.** Every round below reports both numbers.

**Engineering → 90**

| Item | Now | Target |
|---|---|---|
| Open rows in `.claude/TECH-DEBT.md` | 1 | **0** |
| One command that re-measures all four corpora | none | **`scripts/measure_all.py`, and every published figure comes from it** |
| Two scans racing the same result cache | possible, and it happened on 2026-08-20 | **refused by a lock** |
| Measuring against a tree that moved mid-run | possible, and it happened twice on 2026-08-20 | **refused: the digest is frozen at the start and checked at the end** |
| Gates | 44 | **≥ 45** |

## What the misses actually look like — measured 2026-08-20, 693 of them

| CWE | Missed | …with **no finding of ours anywhere in the file** |
|---|---|---|
| CWE-639 IDOR | 56 | 19 |
| CWE-79 XSS | 49 | 23 |
| CWE-200 information exposure | 47 | 18 |
| CWE-312 cleartext storage | 43 | 13 |
| CWE-840 business logic | 37 | 0 |
| CWE-862 missing authorization | 34 | 9 |
| CWE-307 rate limiting | 34 | 3 |
| CWE-215 debug information | 29 | 0 |
| CWE-306 missing authentication | 27 | 5 |
| CWE-434 unrestricted upload | 27 | 11 |
| CWE-798 hardcoded credentials | 26 | 10 |
| CWE-918 SSRF | 21 | **16** |

**202 of the 693 have no finding of ours anywhere in the file.** That is the pool the last plan's
two largest gains came out of, and it is where these rounds go first.

**One thing was checked and ruled out before any of it was planned.** A miss where a finding of
ours sits within ±10 lines but carries a CWE the label does not accept would be a *taxonomy*
problem — free recall for a mapping fix. There are 288 such misses, and reading the pairs shows
they are coincidence rather than mistyping: `SEC-PY-SECRET-KEY-FALLBACK` near a `DEBUG` label in
the same settings file, `TAINT-PY-OPENREDIR` near a business-logic label in the same handler.
Different defects that happen to live near each other. There is no cheap taxonomy round.

**And a cost that constrains every mapping decision:** the benchmark's parser expands a finding
carrying two CWEs into **two findings**. Emitting a second CWE to satisfy a label costs a false
positive on every finding of that rule that does not land on one. Widening a CWE list is not free
and will not be treated as free.

## Rounds

**E1 — the measurement loop.** `scripts/measure_all.py`: freeze the engine digest, take a lock,
run RealVuln → noise floor → SecBench.js → CVEfixes, refuse to write if the tree moved, print
the delta against the committed figures. First because it makes every round below cheaper, and
because its absence cost two full re-runs on 2026-08-20 — a comment edit moves the digest, and
nothing stopped a second scan racing the first over the same cache.

**D1 — SSRF, 21 missed and 16 of them untouched.** The sink vocabulary is three names:
`requests.get`, `requests.post`, `urllib.request.urlopen`. Missing is the rest of the ordinary
outbound-HTTP surface — the other `requests` verbs and `Session`, a bare `urlopen`, `httpx`,
`aiohttp`, `http.client`. High precision by construction: the rule still requires a taint path.

**D2 — credentials and configuration.** `CWE-798` 26 with 10 untouched, plus the JWT
default-secret shape (`os.getenv("JWT_SECRET", "dev-secret")`), which is
`SEC-PY-SECRET-KEY-FALLBACK`'s exact shape for a different key. And the Flask
`app.config['DEBUG'] = True` spelling, which `SEC-PY-DEBUG` does not read.

**D3 — uploads, 27 with 11 untouched.**

**D4 — XSS, 49 with 23 untouched:** reflected XSS in Python handlers, and the template half in
`.html` and `.jinja2`.

**D5 — the authorization pool, 107 across CWE-639/862/863.** Last plan measured a widening of
`AUTHZ-PY-IDOR` and **rejected it** (+3 true positives for +7 false ones). Nothing here repeats
that; if a shape cannot be reached without spending precision, it stays missed and stays
documented.

**R — re-measure and re-stamp.** All four corpora through `measure_all.py`, the engine digest,
every published figure, `docs/what-we-miss.md`, and the launch drafts nothing gates.

## The rule that governs every round

An engine change moves `engine_digest`, and check 32 then fails the build until every published
figure has been re-measured. That is not an obstacle to work around; it is why the numbers in
this repository are worth anything.

---

## Outcome so far — measured 2026-08-20

**E1 shipped and is a gate.** `scripts/measure_all.py` freezes the digest, takes an `O_EXCL`
lock, runs all four corpora and prints the delta; `--selftest` is check 45. It was used for both
measurements below, which is the only evidence that matters for a tool like this.

**D1 and D2 shipped, and between them they moved the headline by one tenth.**

| | Before | After |
|---|---|---|
| RealVuln F3 | 61.1 | **61.2** |
| TP / FP / FN | 1069 / 560 / 693 | **1070 / 561 / 692** |
| Precision | 0.6562 | 0.6560 |
| Noise floor | 0.42 / 1k | **0.42 / 1k, unchanged to the digit** |
| SecBench.js | 0.5445 | unchanged |
| CVEfixes | 0.1566 files | 0.1567 files (+24 findings) |

**+1 true positive for +1 false one, and the reason is the finding.** The SSRF widening was
built on a correct reading — 16 of 21 missed labels had no finding of ours in the file — and a
wrong conclusion about *why*. Fourteen of those sixteen are in one file, `vulnpy/trigger/ssrf.py`,
and every call there is **higher-order**: `_urlopen(urlopen, user_input)` passes the sink
*function* as an argument, so no amount of sink-name vocabulary reaches it. The vocabulary was
genuinely thin and is now genuinely complete; it simply was not the binding constraint. Kept, and
labelled for what it is: an unmeasured improvement on this corpus (0 findings across 2,674,253
lines of noise floor), the same standing the vendored-asset signal has.

**And one architectural trap, which is worth more than the tenth of a point.** Code-shape rules
are matched against `code_view`, where the *contents of every string literal are blanked*. A
pattern naming a key inside brackets — `config['DEBUG']` — is therefore **dead text**, matching
in a unit test and never in a scan. The same trap took the client-decision rule in an earlier
round. `SEC-PY-DEBUG-CONFIG` is a separate `literal=True` rule with a comment-line suppressor,
and it is the +1.

## What the next rounds have to be, given that

The remaining recall is not in vocabulary. It is in two shapes:

1. **Higher-order and cross-function taint.** A sink passed as an argument, a wrapper that
   forwards its parameter. This is what swallowed the SSRF pool and it is a real capability, not
   a list.
2. **The authorization pool — 107 labels across CWE-639/862/863**, which the previous plan
   measured a widening of and rejected for precision.

D3 (uploads) and D4 (XSS) are still worth running and are unchanged in scope. But **F3 ≥ 67 is
not reachable by widening vocabularies**, and this page says so now rather than after four more
rounds of tenths.
