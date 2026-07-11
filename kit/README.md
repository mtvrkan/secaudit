# SecAudit Kit — self-running, provider-agnostic core

The Claude Code plugin (in [`../plugins/secaudit`](../plugins/secaudit)) drives an audit
*inside a Claude Code session*. This `kit/` is the **standalone** counterpart: a dependency-free
Python CLI that runs on its own — in CI, cron, or a shell — and is **not tied to Claude**.

It is built in two tiers:

| Tier | Needs an LLM? | What it does |
|---|---|---|
| **0 — deterministic core** | **No** | Built-in regex detector pack + `npm audit` (and any installed scanner). Always runs, always produces a report. Reproducible. |
| **1 — enrichment (optional)** | Yes, any provider | An LLM triages each Tier-0 finding (confirm/refute/adjust severity) and surfaces logic bugs the pattern scan can't (e.g. IDOR). Backend is pluggable: `anthropic` (Claude, best default), `openai`, `ollama` (local, no key, code never leaves the host), or `none`. |

Claude remains the highest-quality default — but it is **optional**, not required.

## Install

Zero runtime dependencies (standard library only). Run it in place, or install the `secaudit`
console command:

```bash
pip install ./kit          # or: pipx install ./kit   (from the repo root)
secaudit /path/to/repo --min high
```

No install needed either — `python -m secaudit_core.cli …` works straight from `kit/`.

## Usage

```bash
# Pure Tier 0 — no LLM, no API key, runs anywhere:
python -m secaudit_core.cli /path/to/repo

# Gate a CI build (non-zero exit if any High+ finding):
python -m secaudit_core.cli /path/to/repo --min high

# JSON for pipelines; write to a file:
python -m secaudit_core.cli /path/to/repo --format json -o report.json

# Add LLM enrichment (triage + logic-bug discovery). Provider-agnostic:
ANTHROPIC_API_KEY=…  python -m secaudit_core.cli /path/to/repo --backend anthropic
OPENAI_API_KEY=…     python -m secaudit_core.cli /path/to/repo --backend openai
                     python -m secaudit_core.cli /path/to/repo --backend ollama   # local model
```

`--backend`, `--format {md,json,sarif}`, `--min {low,medium,high,critical}`, `--no-deps`, `-o FILE`.
Pick the model with `SECAUDIT_MODEL` (default `claude-opus-4-8` / `gpt-4o` / `qwen2.5-coder`).

## What the deterministic tier actually catches — measured, not claimed

`tests/test_engine.py` runs the Tier-0 engine (no LLM, no external tools) against the two
shipped corpora and prints reproducible numbers:

```
recall (vulnerable-app):  19/19 deterministic classes  (19/20 of all 20; V3/IDOR is LLM-tier by design)
precision (secure-app):   0 HIGH-confidence false positives  ·  0 medium leads
classes reserved for the LLM tier: ['V3']
```

- **Recall** — the pack finds 19 of the 20 planted sink classes. The one it does **not** is
  `V3` (IDOR / missing authorization): a *logic* flaw with no reliable static signature. That
  gap is the concrete argument for Tier 1 — it is exactly what an LLM backend adds.
- **Precision** — zero HIGH-confidence findings on the safe [negative control](../tests/fixtures/secure-app),
  because each detector clears itself when the corresponding control is present (`suppress_if`).

**Real-code precision (not fixture-tuned):** `tests/test_dogfood.py` runs the engine on the
kit's *own* ~1.5k-line production source — real code, nothing planted — and requires **0
High/Critical** findings. This is a false-positive check against genuine code, the honest
complement to the fixture numbers.

**Live two-tier proof:** `tests/test_enrich_e2e.py` runs the whole pipeline (Tier-0 scan →
LLM triage → report) in CI using a *replayed* model response (no key), asserting the LLM tier
adds the IDOR/V3 finding Tier-0 can't reach. `tests/test_live_llm.py` runs the same against a
**real** provider when `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` is set or Ollama is up, and skips
cleanly otherwise — so you can validate the live path yourself.

> **Honest bound:** the built-in detectors are regex, tuned against the shipped fixtures; on
> arbitrary real code recall is lower (precision holds up better — see the dogfood test). This
> tier is the reproducible *floor*, not a guarantee. Installed scanners (semgrep/osv/gitleaks)
> and the LLM tier raise the ceiling. The 76 built-in detectors span JS/TS, Python, Go, Java,
> PHP, Ruby, C#, Kotlin, Swift, Dart, Dockerfile, Terraform, Kubernetes, and secret patterns —
> including 2025–2026 classes: **AI/agent** sinks (LangChain `allow_dangerous_*`, exposed Python-REPL/
> shell tools, model output into `eval`/`exec`), **modern token secrets** (Anthropic `sk-ant-`,
> GitHub fine-grained PATs, Hugging Face, npm), and **software-supply-chain / CI** (mutable-branch
> GitHub Action pins — the tj-actions CVE-2025-30066 class — and `curl | sh` install piping).

## CI & GitHub code scanning

Emit SARIF and upload it so findings land in the repo's **Security → Code scanning** tab:

```bash
python -m secaudit_core.cli . --format sarif -o secaudit.sarif
```

A ready-made composite **GitHub Action** is bundled ([`action.yml`](action.yml)) — it runs the
scan, writes SARIF, and optionally gates the build on severity. A copy-paste workflow is in
[`examples/github-workflow.yml`](examples/github-workflow.yml):

```yaml
- uses: mtvrkan/secaudit/kit@main      # pin to a release SHA in production
  with: { path: '.', min-severity: 'high' }
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: secaudit.sarif }
```

A sample Tier-0 report is committed at [`examples/example-report.md`](examples/example-report.md)
(secrets redacted — the kit never prints secret values).

## Architecture

```
secaudit_core/
  schema.py      Finding / Severity / Confidence / Verdict / ScanResult
  detectors.py   built-in deterministic detector pack (regex + suppress_if controls)
  engine.py      walk target → run detectors + npm audit → dedupe → ScanResult
  backends.py    Backend ABC · NoneBackend · Anthropic/OpenAI/Ollama (urllib, no SDK)
  report.py      Markdown / JSON renderer
  cli.py         argparse entry point + CI gate exit code
tests/
  test_engine.py recall/precision measurement on the two corpora (CI-gated, LLM-free)
```

Adding a detector = one entry in `detectors.py` (id, CWE/OWASP, severity, confidence, regex,
optional `suppress_if`, fix). Adding a backend = subclass `Backend` (or `_HTTPBackend`) and
register it in `get_backend`. The LLM backends are wired end-to-end but are not exercised in
CI (no keys / no local model there); the `none` path is fully tested.
