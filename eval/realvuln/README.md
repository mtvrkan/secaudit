# RealVuln — the external number

**Result: F3 12.5 on 62 of 66 repositories, Tier 0.**
Run 2026-08-12. Scored by the benchmark's own scorer; the raw output is committed as
[`result.json`](result.json) and every figure below is read from it.

| | SecAudit (Tier 0) |
|---|---|
| F3 (recall weighted 9x — RealVuln's primary metric) | **12.5** |
| F2 | 13.5 |
| Precision | 0.407 |
| Recall | 0.116 |
| TP / FP / FN | 204 / 297 / 1558 |

Against the published baselines:

| Category | Best reported | F3 | Precision | Recall |
|---|---|---|---|---|
| Security-specialized | Kolega.Dev | 73.0 | 0.388 | 0.809 |
| General-purpose LLM | Claude Sonnet 4.6 | 51.7 | 0.785 | 0.498 |
| Rule-based SAST | Semgrep | 17.7 | 0.205 | 0.175 |
| **Rule-based SAST + taint** | **SecAudit Tier 0** | **12.5** | **0.407** | **0.116** |

**SecAudit's deterministic tier scores below Semgrep on this corpus.** It finds roughly two
thirds as many of the labelled flaws and is roughly twice as precise about the ones it reports —
and F3 weights recall nine times as heavily as precision, so being right more often does not pay
for finding less. That is the whole result, stated the way the ROADMAP promised it would be:
whatever the number is, it goes in unedited.

Two things this does *not* say. It is not a measurement of the LLM tier, which is the tier meant
to reach the classes below that Tier 0 structurally cannot. And it is not a measurement of the
JavaScript engine — the corpus is Python-only.

## Where the recall goes

Per CWE family, summed across every scored repository (families with fewer than 10 labelled
findings omitted; the full set is in `result.json`):

| Family | Found / labelled | Recall |
|---|---|---|
| `other` | 35 / 831 | 4.2% |
| `sensitive_data_exposure` | 0 / 141 | 0.0% |
| `security_misconfiguration` | 17 / 108 | 15.7% |
| `xss` | 1 / 98 | 1.0% |
| `broken_access_control` | 0 / 76 | 0.0% |
| `missing_auth` | 0 / 74 | 0.0% |
| `sql_injection` | 2 / 71 | 2.8% |
| `hardcoded_credentials` | 5 / 52 | 9.6% |
| `command_injection` | 39 / 46 | 84.8% |
| `denial_of_service` | 0 / 44 | 0.0% |
| `open_redirect` | 0 / 40 | 0.0% |
| `path_traversal` | 3 / 39 | 7.7% |
| `ssrf` | 16 / 37 | 43.2% |
| `xxe` | 31 / 36 | 86.1% |
| `insecure_deserialization` | 27 / 34 | 79.4% |
| `code_injection` | 28 / 30 | 93.3% |

The pattern is sharp and worth stating plainly: **the engine is good at the classes that have a
syntactic sink and blind to the classes that do not.** Command injection, XXE, deserialization
and code injection are 80-90%; access control, missing authentication, sensitive-data exposure,
open redirect and denial of service are zero. `what-we-miss.md` predicted exactly this set, so
the failure is documented rather than surprising — but "documented" and "absent" are the same
thing to a user whose bug is in the second list.

Two numbers deserve separate attention because they were *not* predicted:

- **`sql_injection` 2 / 71.** This is the flagship class and the taint tier's headline
  capability, and on real Django and FastAPI code it fires almost never. Our fixtures test raw
  cursor execution with string building; these corpora reach SQL through ORM escapes
  (`.raw()`, `.extra()`, `session.execute(text(...))`) and through helpers our source list does
  not treat as request-rooted. The fixtures were passing a test the real corpus does not ask.
- **`other` 35 / 831.** Just under half of all labelled findings sit in a family the engine does
  not target at all. Nothing here is a bug; it is scope, and it caps recall before any detector
  runs.

## Per repository

Best five of 62 scored:

| Repo | F3 | Precision | Recall | TP | FP | FN |
|---|---|---|---|---|---|---|
| `realvuln-intentionally-vulnerable-python-application` | 45.5 | 1.000 | 0.429 | 3 | 0 | 4 |
| `vc-codex-high-seeded-v2-property-management-fastapi` | 25.0 | 1.000 | 0.231 | 6 | 0 | 20 |
| `realvuln-damn-vulnerable-flask-application` | 21.7 | 1.000 | 0.200 | 3 | 0 | 12 |
| `vc-codex-seeded-v2-property-management-fastapi` | 20.9 | 0.750 | 0.194 | 6 | 2 | 25 |
| `vc-kimi-code-seeded-v2-logistics-dispatch-fastapi` | 20.8 | 0.667 | 0.194 | 6 | 3 | 25 |

**5 of 62 repositories scored 0.0** — nothing labelled was found in any of
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

Two practical notes from the first run, so the next one does not rediscover them: `score.py`
takes `--repo` and scores one repository at a time (the `--all-repos` flag this file used to
document does not exist), and on Windows it aborts writing its own markdown report under a
non-UTF-8 console codepage — `PYTHONUTF8=1` in front of the command is enough.

`run.py` only writes `scan-results/{repo}/secaudit/results.json` in Semgrep JSON, which
RealVuln ingests without a custom parser. It computes nothing: **the benchmark's own scorer is
the authority.** A tool that grades itself against someone else's corpus has reintroduced
exactly the problem the corpus was there to solve.

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
