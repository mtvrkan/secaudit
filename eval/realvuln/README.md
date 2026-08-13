# RealVuln — the external number

**Result: F3 26.0 on 62 of 66 repositories, Tier 0.**
Run 2026-08-13. Scored by the benchmark's own scorer; the raw output is committed as
[`result.json`](result.json) and every figure below is read from it.

| | Now | Config + crypto hygiene | Targeted at the first diagnosis | First run |
|---|---|---|---|---|
| F3 (recall weighted 9x — RealVuln's primary metric) | **26.0** | 24.6 | 13.3 | 12.5 |
| F2 | 27.5 | 26.1 | 14.4 | 13.5 |
| Precision | 0.511 | 0.504 | 0.393 | 0.407 |
| Recall | 0.246 | 0.233 | 0.124 | 0.116 |
| TP / FP / FN | 434 / 416 / 1328 | 410 / 404 / 1352 | 219 / 339 / 1543 | 204 / 297 / 1558 |

Every column is the same corpus, the same scorer and the same clone. The corpus was re-cloned
for this round and its ground-truth digest recomputed: `sha256:af5901bf…`, identical to the one
the earlier columns were measured against, so nothing moved underneath the comparison. The
previous engine was re-scored on this checkout first and reproduced 24.6 / 0.5037 / 0.2327
digit for digit, which is what makes the movement attributable to the engine and not to the
corpus.

## The number stopped being blind, and that matters more than its size

**12.5 and 13.3 were blind measurements.** The engine had never seen this corpus; the score
said what it did on unseen code.

**Neither 24.6 nor 26.0 is.** The rules added between 13.3 and 24.6 were chosen by reading
this benchmark's own false negatives — *which* standard rules were missing was learned from its
labels. The two analyses added between 24.6 and 26.0 were chosen the same way, and this round
went further: the labelled code itself was read to work out what shape the misses had. Every
rule added is one any SAST ships (weak PRNG for tokens, cookie flags, CSRF exemptions, a
committed fallback signing key, debug-on-by-default, open redirect, NoSQL injection,
credentials in logs, catastrophic backtracking, unauthenticated state-changing endpoints), so
none of them is a pattern reverse-engineered from a particular fixture — but the *selection*
was informed by the corpus, twice now. That is the same category of advantage
`eval/scorecard.md` has always disclosed about the fixture corpus, and it applies here with
more force each round.

So read 26.0 as "what the engine does on a corpus it has been tuned against across two rounds",
and read 12.5 as "what it did on a corpus it had not". The honest successor to a blind number
is a run against a benchmark this repository has not read; until there is one, the blind figure
in the right-hand column is the more conservative claim about your code. **The gap between 12.5
and 26.0 is the size of the advantage this disclosure is about.**

Against the published baselines:

| Category | Best reported | F3 | Precision | Recall |
|---|---|---|---|---|
| Security-specialized | Kolega.Dev | 73.0 | 0.388 | 0.809 |
| General-purpose LLM | Claude Sonnet 4.6 | 51.7 | 0.785 | 0.498 |
| Rule-based SAST | Semgrep | 17.7 | 0.205 | 0.175 |
| **Rule-based SAST + taint + structural** | **SecAudit Tier 0** | **26.0** | **0.511** | **0.246** |

**The deterministic tier scores above rule-based SAST's published 17.7, on both metrics** —
1.4x the recall and 2.5x the precision — having been below it on the two earliest runs. Read
that against the section above: the earlier comparison was blind and this one is not, so the
right claim is "above Semgrep on a corpus we have since read", not "better than Semgrep".

It remains far below both a general-purpose LLM (51.7) and the purpose-built system (73.0), and
those two were measured the way ours no longer is.

Three things this does *not* say. It is not a measurement of the LLM tier, which is the tier
meant to reach the classes below that Tier 0 structurally cannot. It is not a measurement of the
JavaScript engine — the corpus is Python-only. And it is not a claim about your repository: the
half of this corpus labelled `other`, `broken_access_control` and `missing_auth` is still where
most of the misses are, and no pattern added here touches them.

## Where the recall goes

Per CWE family, summed across every scored repository (families with fewer than 10 labelled
findings omitted; the full set is in `result.json`):

| Family | Found / labelled | Recall | Previous run | First run |
|---|---|---|---|---|
| `other` | 133 / 831 | 16.0% | 131 / 831 **+2** | 35 / 831 |
| `sensitive_data_exposure` | 31 / 141 | 22.0% | 31 / 141 | 0 / 141 |
| `security_misconfiguration` | 39 / 108 | 36.1% | 39 / 108 | 17 / 108 |
| `xss` | 11 / 98 | 11.2% | 11 / 98 | 1 / 98 |
| `broken_access_control` | 1 / 76 | 1.3% | 0 / 76 **+1** | 0 / 76 |
| `missing_auth` | 4 / 74 | 5.4% | 0 / 74 **+4** | 0 / 74 |
| `sql_injection` | 11 / 71 | 15.5% | 11 / 71 | 2 / 71 |
| `hardcoded_credentials` | 6 / 52 | 11.5% | 6 / 52 | 5 / 52 |
| `command_injection` | 39 / 46 | 84.8% | 39 / 46 | 39 / 46 |
| `denial_of_service` | 16 / 44 | 36.4% | 0 / 44 **+16** | 0 / 44 |
| `open_redirect` | 37 / 40 | 92.5% | 37 / 40 | 0 / 40 |
| `path_traversal` | 3 / 39 | 7.7% | 3 / 39 | 3 / 39 |
| `ssrf` | 16 / 37 | 43.2% | 16 / 37 | 16 / 37 |
| `xxe` | 32 / 36 | 88.9% | 31 / 36 **+1** | 31 / 36 |
| `insecure_deserialization` | 27 / 34 | 79.4% | 27 / 34 | 27 / 34 |
| `code_injection` | 28 / 30 | 93.3% | 28 / 30 | 28 / 30 |

The shape has changed again. Two families that had never produced a single true positive
now do, and one of them moved a long way — but the two that were supposed to be the point of
this round barely moved at all, which is the part worth reading first.

### Round three — the two structural classes, and what actually happened

The three families stuck at exactly zero across every previous run were
`broken_access_control` (0/76), `missing_auth` (0/74) and `denial_of_service` (0/44). The
previous round's conclusion about them was that *"more patterns will not fix it"* — that
deciding them needs to know what the application intends. That was half right, and the half it
got wrong is the interesting one: these classes are not decidable from a **line**, but two of
the three are partly decidable from a handler's **structure**, which a parser can see and a
regex cannot. Two analyses were built on that basis (`secaudit_core/authz.py`,
`secaudit_core/redos.py`), and the results split sharply.

- **`denial_of_service` 0 → 16 of 44** (36.4%), every one of them from the ReDoS analysis, at
  **17 true positives and 0 false positives** measured against the labels. Catastrophic
  backtracking is decided from the regex's parse tree — star height above one, and repeated
  groups whose alternatives overlap — and `docs/what-we-miss.md` was wrong to file it as out of
  reach: an automaton decides it *exactly*, but the shapes that actually blow up are structural
  and cheap. This is the round's real result.
- **`missing_auth` 0 → 4 of 74** and **`broken_access_control` 0 → 1 of 76.** Off zero, and
  that is close to all that can be said for it. The IDOR rule contributes a single true
  positive across the whole corpus.
- **`xxe` 31 → 32** and **`other` 131 → 133** are incidental.

**Precision went up again while recall rose: 0.504 → 0.511.** Twenty-four more true positives
against twelve more false ones. That is the signal these are rules rather than curve-fitting,
and it is the second round in a row it has held.

### What the authorization analysis cost to get right, since the failures are the lesson

The first working version of the IDOR rule scored **6 true positives against 48 false ones** —
a rule that would have made the report worse. Nearly every false positive was one shape: the
handler fetches the row by id and *then* authorizes it through a helper —
`dispute = db.get(Dispute, dispute_id)` followed by `_require_view(current_user, dispute)`.
That is the **correct** idiom, and the rule was punishing the codebases that had factored their
authorization out properly. Counting a delegated call as a check dropped the false positives to
zero — and took five of the six true positives with them, which is why the rule now finds one.

A refinement that tried to keep both — count a delegated call only when the callee *looks* like
a check, by name or by containing a comparison — was built and measured, and it recovered
**none** of the lost true positives while adding nine false ones. It was reverted. The
conservative reading is in the engine and the refinement is not, because a rule that reports the
*absence* of a check has to be sure of the absence.

The missing-authentication rule failed the other way first: **0 true positives against 7 false
ones**, because it required the handler to touch a database. The endpoints that actually get
labelled unauthenticated do not touch a database — they evaluate an expression, shell out, or
parse XML straight from the request body. The bar had to be "acts on what the caller sent", not
"reaches a row".

The benchmark's 42 `missing_authentication_false_positive` traps are all one shape: a handler
with no auth decorator that reaches a small local helper comparing a header to an environment
token. A decorator-based rule reports all 42. Following module-local calls clears them — and
the FastAPI variant, where the same gate is injected as a parameter default
(`gate: None = Depends(_wrk_gate)`) and never called in the body at all, needed the analysis to
follow *references* rather than call targets. Every one of these shapes is now a test in
`kit/tests/test_authz.py`, asserted in both directions, so the fixes cannot be undone silently.

### What did not move, again

`path_traversal` stayed at **3/39**. It was not attempted this round, and that is a deliberate
decision rather than an oversight: nine filesystem sinks were added across the two previous
rounds, the class was predicted to move twice, and it did not move either time. The evidence
says its misses are about which values are believed attacker-controlled, not which call is
dangerous, and a third round of sinks would be the same experiment run a third time. It is
recorded here as untouched rather than quietly re-attempted.

`other` at 133/831 remains the ceiling on the whole score — 831 labels in one bucket, of which
this engine finds one in six.

## Per repository

Best five of 62 scored:

| Repo | F3 | Precision | Recall | TP | FP | FN |
|---|---|---|---|---|---|---|
| `intentionally-vulnerable-python-app` | 45.5 | 1.000 | 0.429 | 3 | 0 | 4 |
| `vc-codex-high-seeded-v2-property-management-fastapi` | 24.6 | 0.600 | 0.231 | 6 | 4 | 20 |
| `dvblab` | 24.3 | 0.625 | 0.227 | 5 | 3 | 17 |
| `damn-vulnerable-flask-app` | 21.7 | 1.000 | 0.200 | 3 | 0 | 12 |
| `vc-kimi-code-seeded-v2-logistics-dispatch-fastapi` | 20.8 | 0.667 | 0.194 | 6 | 3 | 25 |

**4 of 62 repositories scored 0.0** — nothing labelled was found in any of
them. The full per-repo table is in [`result.json`](result.json).

## What was not scored, and why it matters

62 of 66 repositories. The four missing ones —
`realvuln-owasp-web-playground`, `realvuln-pygoat`, `realvuln-python-app`, `realvuln-vulnerable-api` — could not be cloned:
Upstream repositories are gone - `git clone` returns 'Repository not found' for all four. Not a choice made here, and not a random sample: all four are deliberately vulnerable teaching apps, the densest and most pattern-obvious repos in the corpus, so their absence works against this score rather than for it.

Stated the other way round: the repositories most likely to flatter this score are the ones that
could not be included. The number is not a best case.

## Reproduce it

```bash
git clone https://github.com/kolega-ai/Real-Vuln-Benchmark
cd Real-Vuln-Benchmark && python3 clone_repos.py && cd -

python3 eval/realvuln/run.py --benchmark ../Real-Vuln-Benchmark

cd ../Real-Vuln-Benchmark
for r in repos/*/; do python3 score.py --repo "$(basename "$r")" --scanner secaudit; done
python3 dashboard.py --scanners secaudit
```

Four practical notes, so the next run does not rediscover them:

1. `score.py` takes `--repo` and scores one repository at a time. The `--all-repos` flag this
   file used to document does not exist.
2. On Windows it aborts writing its own markdown report under a non-UTF-8 console codepage —
   `PYTHONUTF8=1` in front of the command is enough.
3. **Scoring a second scanner overwrites the per-repo scorecards** for the same date. Capture
   what you need from `reports/` before scoring the next one, or score them in the order you
   intend to read them.
4. **`compute_gt_hash.py` disagrees with the published digest on Windows, for an identical
   corpus.** It hashes raw file bytes and joins paths with `os.sep`, so a CRLF checkout and
   backslash separators each change the result. Normalise line endings to LF and use forward
   slashes and it reproduces `sha256:af5901bf…` exactly. This matters more than it looks: the
   first reading says the ground truth moved, which would mean no run is comparable to any
   other.

`run.py` only writes `scan-results/{repo}/{scanner}/results.json` in Semgrep JSON, which
RealVuln ingests without a custom parser. It computes nothing: **the benchmark's own scorer is
the authority.** A tool that grades itself against someone else's corpus has reintroduced
exactly the problem the corpus was there to solve.

## The LLM tier has no number, and here is the command that would produce one

Every figure on this page is Tier 0. That is not an oversight and it is not modesty — Tier 0 is
the part that reproduces: same corpus, same engine, same number, on any machine, with no key.
A model run is not that.

But "not reproducible" has been doing too much work as an excuse. The LLM tier is the front
page's headline claim — triage, verification, the logic bugs the deterministic tier structurally
cannot reach — and a headline claim with no measurement behind it is exactly the kind of thing
this repository refuses to accept from anyone else. So the measurement is now one command:

```bash
python3 eval/realvuln/run.py --benchmark ../Real-Vuln-Benchmark     --backend anthropic --scanner secaudit-tier1
cd ../Real-Vuln-Benchmark
for r in repos/*/; do python3 score.py --repo "$(basename "$r")" --scanner secaudit-tier1; done
python3 dashboard.py --scanners secaudit-tier1
```

Two guardrails are built into that path. `--backend` refuses to write under the plain `secaudit`
slug, because that slug is what `result.json` and every published figure mean and a model run
must never be mistaken for them. And the run prints its own caveat before it starts.

**It has not been run.** No key was available on the machine that built this, and rather than
publish a number from a model nobody can re-query, or quietly leave the tier unmeasured, the
harness ships unrun and this paragraph says so. When it is run, the result belongs on this page
labelled as a single observation — the honest shape for a number that cannot be a floor.

Two things to expect when someone does run it. It costs real money across 62 repositories. And
the comparison it invites is with the published general-purpose-LLM baseline (F3 51.7), which is
the row this tier exists to compete with — not with the 26.0 above.

## Reading the result honestly

- **RealVuln v1 is Python-only** (Flask, Django, FastAPI and friends). SecAudit's Python taint
  analysis runs on a real AST; its JavaScript/TypeScript analysis is a hand-rolled scanner.
  A Python score does not transfer to the JS side, in either direction.
- **Tier 0 only.** `run.py` passes `--no-deps --no-scanners`, so the number describes the
  deterministic, dependency-free engine — the part that is reproducible. If a Tier 1 number is
  ever published it will be labelled as a separate, non-reproducible run.
- **Several of the corpora are deliberately vulnerable teaching apps** (DVPWA, VAmPI and
  friends). They are denser in planted flaws than production code, which flatters recall and
  punishes precision relative to a real repository.
- **The committed 0.986 F3 on our own fixtures and the 12.5 here are not in
  conflict, and neither one is the lie.** The first is a regression floor over a corpus written
  alongside the detectors; the second is what that engine does on code nobody here has seen.
  A repo that publishes only the first is marketing; a repo that publishes only the second has
  thrown away its regression gate.
