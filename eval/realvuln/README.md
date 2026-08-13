# RealVuln — the external number

**Result: F3 31.5 on 62 of 66 repositories, Tier 0.**
Run 2026-08-13. Scored by the benchmark's own scorer; the raw output is committed as
[`result.json`](result.json) and every figure below is read from it.

| | Now | Structural | Authorization + ReDoS | Config + crypto hygiene | First diagnosis | First run |
|---|---|---|---|---|---|---|
| F3 (recall weighted 9x — RealVuln's primary metric) | **31.5** | 30.9 | 26.0 | 24.6 | 13.3 | 12.5 |
| F2 | 33.0 | 32.5 | 27.5 | 26.1 | 14.4 | 13.5 |
| Precision | 0.542 | 0.540 | 0.511 | 0.504 | 0.393 | 0.407 |
| Recall | 0.301 | 0.295 | 0.246 | 0.233 | 0.124 | 0.116 |
| TP / FP / FN | 530 / 448 / 1232 | 520 / 442 / 1242 | 434 / 416 / 1328 | 410 / 404 / 1352 | 219 / 339 / 1543 | 204 / 297 / 1558 |

**The same scorer also reports a stricter reading of this run, and it is 2.2 points lower.**
`result.json` has carried both from the first round: the `micro` aggregate above, and a
`strict_micro` one that counts 141 further labels as missed — F3 **29.3**, recall **0.2785**, on
the identical 530 true positives and 448 false ones. `micro` is what is quoted here because it is
the aggregate RealVuln's own published baselines are quoted in, and comparing against them in a
different metric would be comparing two different things. But a stricter figure sitting in the
committed raw output and named nowhere in the prose is exactly the omission this page exists to
prevent. So: the honest range for this run is **29.3 – 31.5**, and 29.3 is the one to use for any
purpose other than comparing against the baselines below.

Every column is the same corpus, the same scorer and the same clone. The corpus was re-cloned
for this round and its ground-truth digest recomputed: `sha256:af5901bf…`, identical to the one
the earlier columns were measured against, so nothing moved underneath the comparison. The
previous engine was re-scored on this checkout first and reproduced 30.9 / 0.5405 / 0.2951
digit for digit — 520 TP / 442 FP / 1242 FN, every figure identical to the committed result —
which is what makes the movement attributable to the engine and not to the corpus.

**This round added no rule.** It narrowed one, and the defect it removed was found by asking why
the rate-limit rule's *suppression* branches had no test coverage rather than by reading more
labels. `_module_has_limiter` walked the whole file, so any mention of a limiter anywhere
silenced every route in it — a single `@limiter.limit` on `/login` silenced an unlimited
`/admin-login` beside it, and `attempt` being a limiter marker meant a handler that recorded
failed passwords silenced itself, which is the wrong half of the problem: writing the break-in
down is what an unprotected endpoint does *instead* of bounding it. Module-level now means
module-level, and an attempt count is evidence of a limit only where something is compared
against it. +10 TP for +6 FP, entirely inside the `other` family where this benchmark files
CWE-307. Precision rose, which is the only reason it was kept.

## The number stopped being blind, and that matters more than its size

**12.5 and 13.3 were blind measurements.** The engine had never seen this corpus; the score
said what it did on unseen code.

**Neither 24.6, 26.0, 30.9 nor 31.5 is.** The rules added between 13.3 and 24.6 were chosen by
reading this benchmark's own false negatives — *which* standard rules were missing was learned
from its labels. The two analyses added between 24.6 and 26.0 were chosen the same way, and the
round after went further: the labelled code itself was read to work out what shape the misses
had. Every rule added is one any SAST ships (weak PRNG for tokens, cookie flags, CSRF
exemptions, a committed fallback signing key, debug-on-by-default, open redirect, NoSQL
injection, credentials in logs, catastrophic backtracking, unauthenticated state-changing
endpoints), so none of them is a pattern reverse-engineered from a particular fixture — but the
*selection* was informed by the corpus, three times now. That is the same category of advantage
`eval/scorecard.md` has always disclosed about the fixture corpus, and it applies here with
more force each round.

The 30.9 → 31.5 round is the one exception and it is worth stating precisely, because it is the
only movement here that a blind run would also have produced: it added no rule and read no
label. It removed a bug in an existing rule, found by noticing that the branches which suppress
a finding had no test coverage. That does not make the cumulative number blind again — every
rule underneath it was still selected against this corpus.

So read 31.5 as "what the engine does on a corpus it has been tuned against across three
rounds", and read 12.5 as "what it did on a corpus it had not". The honest successor to a blind
number is a run against a benchmark this repository has not read; until there is one, the blind
figure in the right-hand column is the more conservative claim about your code. **The gap
between 12.5 and 31.5 is the size of the advantage this disclosure is about, and it has widened
every round.**

Against the published baselines:

| Category | Best reported | F3 | Precision | Recall |
|---|---|---|---|---|
| Security-specialized | Kolega.Dev | 73.0 | 0.388 | 0.809 |
| General-purpose LLM | Claude Sonnet 4.6 | 51.7 | 0.785 | 0.498 |
| Rule-based SAST | Semgrep | 17.7 | 0.205 | 0.175 |
| **Rule-based SAST + taint + structural** | **SecAudit Tier 0** | **31.5** | **0.542** | **0.301** |

**The deterministic tier scores above rule-based SAST's published 17.7, on both metrics** —
1.7x the recall and 2.6x the precision — having been below it on the two earliest runs. Read
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
| `other` | 229 / 831 | 27.6% | 219 / 831 **+10** | 35 / 831 |
| `sensitive_data_exposure` | 31 / 141 | 22.0% | 31 / 141 | 0 / 141 |
| `security_misconfiguration` | 39 / 108 | 36.1% | 39 / 108 | 17 / 108 |
| `xss` | 11 / 98 | 11.2% | 11 / 98 | 1 / 98 |
| `broken_access_control` | 1 / 76 | 1.3% | 1 / 76 | 0 / 76 |
| `missing_auth` | 4 / 74 | 5.4% | 4 / 74 | 0 / 74 |
| `sql_injection` | 11 / 71 | 15.5% | 11 / 71 | 2 / 71 |
| `hardcoded_credentials` | 6 / 52 | 11.5% | 6 / 52 | 5 / 52 |
| `command_injection` | 39 / 46 | 84.8% | 39 / 46 | 39 / 46 |
| `denial_of_service` | 16 / 44 | 36.4% | 16 / 44 | 0 / 44 |
| `open_redirect` | 37 / 40 | 92.5% | 37 / 40 | 0 / 40 |
| `path_traversal` | 3 / 39 | 7.7% | 3 / 39 | 3 / 39 |
| `ssrf` | 16 / 37 | 43.2% | 16 / 37 | 16 / 37 |
| `xxe` | 32 / 36 | 88.9% | 32 / 36 | 31 / 36 |
| `insecure_deserialization` | 27 / 34 | 79.4% | 27 / 34 | 27 / 34 |
| `code_injection` | 28 / 30 | 93.3% | 28 / 30 | 28 / 30 |

Every movement in the last two rounds has landed in one bucket: `other`, which the round before
last called "the ceiling on the whole score", went 35 → 133 → 219 → **229 of 831**. That bucket
is where the scorer files rate limiting, unrestricted upload and mass assignment — three classes
that had produced **zero** true positives between them across every earlier run. The latest
+10 is the narrowing described at the top of this page, not a new rule.

### Round five — no new rule, one rule made honest

The previous four rounds all worked the same way: read the labelled misses, find the shape they
share, build the smallest thing that decides it. This one did not read a label. It came from
asking a question about the *tests* instead — why did the rate-limit rule's suppression branches
have no coverage? — and the answer was that they were wrong, in three ways that all pointed the
same direction: the rule was silent on code it existed to report.

- **A limiter anywhere silenced everywhere.** `_module_has_limiter` walked the whole tree, so
  one `@limiter.limit("5/minute")` on `/login` protected an unlimited `/admin-login` in the same
  file. "Most endpoints are limited and one was forgotten" is the realistic shape of this bug and
  the rule could not see it. Module-level now means module-level: imports, and statements written
  at module scope including the `if not settings.TESTING:` that real app setup is guarded by —
  not function bodies.
- **`attempt` was matching the wrong half of the problem.** It was a limiter marker on its own,
  so `db.record_attempt(email)` in a failure branch read as protection. Writing the break-in down
  is what an unprotected endpoint does *instead* of bounding it. An attempt count is now evidence
  of a limit only where something is compared against it — `attempts_for(ip) > 5` and
  `if too_many_attempts(email)` still silence the rule, `log.warning("failed login attempt")`
  no longer does.
- **+10 TP for +6 FP, precision 0.5405 → 0.5419.** Small, contained entirely in `other`, and
  accepted only because precision rose. The same edit with precision falling would have been
  reverted under the rule the round before last established.

### Round four — three more structural rules, and one of them is the largest single gain yet

The method was the same one that worked in round three: read the labelled misses, notice what
shape they share, and build the smallest thing that decides it. What the labels showed was that
three of the biggest untouched pools are not judgement calls at all — they are properties of a
handler that a parser can check.

- **Missing rate limiting: 0 → 85 true positives at 0.842 precision.** The largest single-rule
  gain in the project. 99 labels across four related classes named a missing rate limit and the
  engine found none of them, because "this endpoint has no limiter" describes almost every
  endpoint in almost every application. The labels are narrower than that: the flaw is that a
  **credential-testing** endpoint accepts unlimited attempts. So the rule fires only where the
  path or handler names an authentication action *and* the handler actually reaches a credential
  check — and it looks for a limiter in the decorators, the dependencies, module-local helpers,
  and anything registered on the app, because a limiter installed as middleware protects handlers
  that never mention it.
- **Unrestricted upload: 0 → 8, at 0.800 precision after one correction.** An upload is read, a
  write happens, and no check stands between them. The first version scored 8 TP against 14 FP;
  twelve of those false positives were not handlers at all — a test module, a password-list
  generator — matched because `.filename` is an attribute plenty of objects have. Anchoring the
  attribute to a request read removed all twelve.
- **Mass assignment: 0 → 1.** Effectively unmoved, and the reason is worth stating: the corpus's
  mass-assignment labels mostly pass the body through a helper that *is* named like a validator
  (`validate_update_form`) while not actually restricting fields. This rule judges whether a field
  allowlist is present, never whether it is adequate, so those are outside what it decides. That
  is a bound, not a bug, and it is in `limitations()`.

**Precision rose with recall for the third consecutive round: 0.511 → 0.540.** Eighty-six more
true positives against twenty-six more false ones.

### What the rules cost to get right

Two corrections were measured rather than reasoned about, and both are now tests:

**`splitext` is not validation.** Treating extension *extraction* as an extension *check*
silenced the one handler that splits the extension off precisely so it can keep it on the file it
writes. Removing `splitext` and `suffix` from the validation markers recovered that finding.

**The structural rules are scoped to production sources.** Every rule in the package describes
something a *deployed handler* fails to do, so a test module, a fixture, a migration or a
one-off script is out of scope by construction. The detector pack still scans those files — a
committed secret in a test is a real secret — but "this endpoint has no rate limit" is not a
question a test file can answer.

### An honest ceiling on all four rules

They are AST-based, so a **Python 2 source does not parse and produces nothing**. The corpus
contains such files, and at least one labelled upload lives in one. Nothing is guessed there.

### What still does not move

`broken_access_control` (1/76), `missing_auth` (4/74) and `path_traversal` (3/39) are unchanged.
`sensitive_data_exposure` (31/141) and `security_misconfiguration` (39/108) are unchanged too, and
reading their misses explains why: about 130 of those labels sit on a `def` line, meaning the flaw
is a property of what the whole handler returns or configures rather than of anything in it. That
is the same shape as broken access control, and the same answer applies — it needs the
business-logic pass, not another rule.

## Per repository

Best five of 62 scored:

| Repo | F3 | Precision | Recall | TP | FP | FN |
|---|---|---|---|---|---|---|
| `intentionally-vulnerable-python-app` | 58.8 | 0.800 | 0.571 | 4 | 1 | 3 |
| `vc-codex-high-seeded-v2-marketplace-commerce-fastapi` | 53.5 | 0.722 | 0.520 | 13 | 5 | 12 |
| `vc-codex-high-seeded-v2-property-management-fastapi` | 51.6 | 0.722 | 0.500 | 13 | 5 | 13 |
| `vc-codex-high-seeded-v2-fintech-lending-fastapi` | 50.5 | 0.875 | 0.483 | 14 | 2 | 15 |
| `damn-vulnerable-flask-app` | 48.6 | 0.778 | 0.467 | 7 | 2 | 8 |

**2 of 62 repositories scored 0.0** — nothing labelled was found in either of
them. The full per-repo table is in [`result.json`](result.json).

This table had never been tied to `result.json` and was two rounds stale when that was noticed —
it still showed a top repo at 45.5 after the engine had moved it to 58.8. Check 27 now
reproduces every cell from the committed scorer output, including which repositories are in the
top five and how many scored zero, so the ranking cannot flatter itself by going unmaintained.

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
the row this tier exists to compete with — not with the 31.5 above.

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
