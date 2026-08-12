# RealVuln — the external number

**Status: not yet run.** This directory holds everything needed to run it; the result will be
published here and in the top-level README verbatim, whatever it is.

## Why

Every number in [`../scorecard.md`](../scorecard.md) is measured against fixtures written
alongside the detectors. That makes it a regression floor and nothing more — it cannot tell you
how SecAudit behaves on code nobody here has seen.

[RealVuln](https://github.com/kolega-ai/Real-Vuln-Benchmark) (CC BY 4.0) is 66 real vulnerable
repositories with hand-labelled findings **and false-positive traps**, scored by code we did not
write. Its published baselines, under F3 (recall weighted 9×):

| Category | Best reported | F3 | Precision | Recall |
|---|---|---|---|---|
| Security-specialized | Kolega.Dev | 73.0 | 0.388 | 0.809 |
| General-purpose LLM | Claude Sonnet 4.6 | 51.7 | 0.785 | 0.498 |
| Rule-based SAST | Semgrep | 17.7 | 0.205 | 0.175 |

That bottom row is the reason the taint tier exists. A pattern pack scores 17.7 on real code no
matter how many rules it has, because the rules are not what is missing — reachability is.

## Run it

```bash
git clone https://github.com/kolega-ai/Real-Vuln-Benchmark
cd Real-Vuln-Benchmark && python3 clone_repos.py && cd -

python3 eval/realvuln/run.py --benchmark ../Real-Vuln-Benchmark

cd ../Real-Vuln-Benchmark
python3 score.py --scanner secaudit --all-repos
```

`run.py` only writes `scan-results/{repo}/secaudit/results.json` in Semgrep JSON, which
RealVuln ingests without a custom parser. It computes nothing: **the benchmark's own `score.py`
is the authority.** A tool that grades itself against someone else's corpus has reintroduced
exactly the problem the corpus was there to solve.

## Reading the result honestly

Three things to state alongside whatever number comes back, so it is not quietly oversold:

- **RealVuln v1 is Python-only** (Flask, Django, FastAPI and friends). SecAudit's Python taint
  analysis runs on a real AST; its JavaScript/TypeScript analysis is a hand-rolled scanner.
  A Python score does not transfer to the JS side, in either direction.
- **Tier 0 only.** `run.py` passes `--no-deps --no-scanners`, so the number describes the
  deterministic, dependency-free engine — the part that is reproducible. If a Tier 1 number is
  ever published it will be labelled as a separate, non-reproducible run.
- **Several of the corpora are deliberately vulnerable teaching apps** (PyGoat, DVPWA, VAmPI).
  They are denser in planted flaws than production code, which flatters recall and punishes
  precision relative to a real repository.

When the run happens, the result goes here in full — per-repo table, the classes missed, and
the trap hits — not just the headline. A benchmark you only quote when it agrees with you is
marketing.
