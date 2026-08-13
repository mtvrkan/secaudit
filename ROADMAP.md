# SecAudit — Roadmap to v2.0

Status: **planning**, written 2026-08-12. This file is the plan of record. Every phase below
states what ships, why it matters competitively, and how we know it worked. Numbers quoted from
outside sources carry their source; numbers quoted about SecAudit are measured by the CI harness
or marked `TODO(measure)` — never estimated into the document.

---

## 0. Baseline — what existed when this plan was written (2026-08-12)

A dated snapshot, deliberately not updated as phases land: it is the thing later
phases are measured against. For current state see the per-phase Done sections,
[`eval/scorecard.md`](eval/scorecard.md) and `python3 scripts/run_checks.py`.

<!-- snapshot:begin -->

| Surface | At the time |
|---|---|
| Claude Code plugin | 1 skill (`security-audit`), 16 reference files, 4 commands, 1 verifier agent, 1 PreToolUse authorization hook |
| Standalone kit | `secaudit_core` — 76 regex detectors, 3 scanner adapters (semgrep/gitleaks/osv), 4 LLM backends (anthropic/openai/ollama/replay), md+json+sarif renderers, zero runtime deps |
| Eval | 2 paired fixtures (vulnerable + secure), 20 planted flaws, JS+Python, golden set, CI regression gate |
| CI | 12 gates incl. manifest strictness, allowlist-subset check, dangling-reference check, dogfood precision, hook self-test, zizmor self-lint |
| Distribution | GitHub repo only. No site, no PyPI, no directory listing, no stars |
| Size | ~7 000 lines |

<!-- snapshot:end -->

The engineering quality bar is already high. The **reach** and the **detection ceiling** are not.

---

## 1. Competitive landscape (researched 2026-08-12)

### 1.1 Anthropic ships two official security plugins

This is the single most important fact for positioning.

**`security-guidance@claude-plugins-official`** — free, all plans. Pure hooks. Three layers:
per-edit deterministic pattern match (no model call), end-of-turn background diff review, and an
agentic review on every `git commit`/`git push` Claude makes. Extensible via
`.claude/security-patterns.yaml` and `.claude/claude-security-guidance.md`.

**`claude-security@claude-plugins-official`** — paid plans. A multi-agent scan: agents map
architecture, build a threat model, hunt, and *independently verify* every finding before it
reaches the report. Writes `CLAUDE-SECURITY-<ts>/` with `RESULTS.md`, `RESULTS.jsonl`, and a
revision stamp tying the report to a commit. `Suggest patches` drafts fixes in a scratch repo,
has an independent agent review each patch and run the project's tests, and only writes
`patches/F<n>.patch` when that review vouches for it. Never auto-applies.

**What they explicitly do NOT do** — and this is our opening:

- *"the review reads the source code in your checkout, **not a running site or deployed service**"*
  → **no live-target/DAST mode at all.**
- No authorization model, no scope file, no engagement discipline — they assume it's your repo.
- No client-deliverable report: findings + patches for developers, not an executive summary,
  remediation roadmap, retest checklist, or a report you hand to a customer.
- Claude Code session required, paid plan required for the deep scan, tokens billed per scan.
  No CI-native, no local model, no air-gapped operation.
- No compliance mapping, no SBOM, no CRA/ASVS/PCI artifacts.
- No published precision/recall. Explicitly nondeterministic: *"two scans of the same code can
  surface different findings."*

Conclusion: **do not compete on "scan my repo with agents."** Anthropic owns that, for free,
inside the product. Compete on everything the sentence above rules out.

### 1.2 The Claude Code security-kit ecosystem

| Project | Stars | Shape | Gap we can exploit |
|---|---|---|---|
| [Trail of Bits `skills`](https://github.com/trailofbits/skills) | ~6.6k | 38 skills, SARIF-first, `fp-check` gate reviews, Codex support, CC-BY-SA | Auditor-expert oriented, no turnkey end-to-end engagement, no live target, no report deliverable |
| [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) | ~3.4k | 82 skills, 15 commands, 681 curated HackerOne report patterns, 4 harnesses, MIT+CC-BY | **Offensive** bug-bounty framing. No automated tests, no CI, no measured precision. Explicitly excludes defensive/compliance work |
| [Transilience communitytools](https://github.com/transilienceai/communitytools) | — | 23 skills, 8 agents; claims 100% (104/104) on a published CTF benchmark | CTF-shaped, not product-shaped |
| [z-audit](https://github.com/zm2231/z-audit) | ~9 | 7-phase, stack detection, live URL | Closest in *shape* to SecAudit and far behind in depth |
| SecSkills, claude-bug-bounty, public-skills-builder | small | bug-bounty skill packs | — |

Lessons taken from the two winners: **skill breadth wins discovery** (82 and 38 vs. our 16
references), **cross-harness support multiplies reach**, and **a named, credible empirical
foundation** ("681 disclosed reports") is what the README sells. Neither has a test suite —
that is ours to own.

### 1.3 Outside the Claude Code ecosystem

- **[Strix](https://github.com/usestrix/strix)** — OSS AI pentester. Proves every finding with a
  working PoC (proxy, browser, exploit runtime). One of only two tools reported to produce
  actionable results against real banking apps. *PoC-or-it-didn't-happen is its moat.*
- **VulnHuntr** — LLM call-chain tracing, Python-only, 7 classes, 12+ real zero-days.
- **ZeroPath / XBOW / Horizon3 / Pentera** — commercial, heavily funded ($237M+ for XBOW alone).
- **CAI** — 300+ model backends, self-hosted/air-gapped. Privacy-first is a real differentiator.
- **DARPA AIxCC** open-sourced systems (Atlantis, Trail of Bits' Buttercup) — the state of the art.

Documented market gaps ([AppSec Santa, 2026](https://appsecsanta.com/research/ai-pentesting-agents-2026)):
**business-logic flaws (≈70% of critical web vulns) remain the top unmet need**; multi-step
chains, GUI-dependent bugs, and real zero-day discovery are still weak across the board. The
lab-to-real gap is stark — GPT-4 exploits 87% of one-day CVEs *with an advisory in hand*, but
agents solve ~13% of real CVEs in CVE-Bench and ~0% of hard HackTheBox challenges.

### 1.4 There is now an open benchmark, and it is brutal

**[RealVuln](https://github.com/kolega-ai/Real-Vuln-Benchmark)** (2026, CC BY 4.0) — real
vulnerable Python repositories with hand-labeled findings **and false-positive traps**
(v1.0 published 26 repos / 796 labels / 120 traps across 18 CWE families and 5 frameworks;
the benchmark has since grown to 66 repos). Headline F3 scores (recall weighted 9×):

| Category | Best | F3 | Precision | Recall |
|---|---|---|---|---|
| Security-specialized | Kolega.Dev | 73.0 | 0.388 | 0.809 |
| General LLM | Claude Sonnet 4.6 | 51.7 | 0.785 | 0.498 |
| Rule-based SAST | Semgrep | 17.7 | 0.205 | 0.175 |

Two conclusions. One: **regex/rule packs are near-worthless on real code** — our Tier-0 pack
scores well on our own fixtures because it was tuned against them, and `detectors.py` already
says so honestly. Two: **there is a public leaderboard we can appear on.** Almost nobody in the
Claude-plugin ecosystem publishes a number. Appearing on RealVuln with an honest score is the
single highest-credibility move available to us.

### 1.5 Regulatory tailwind — the timing is unusually good

The **EU Cyber Resilience Act** vulnerability/incident reporting obligation starts
**2026-09-11 — four weeks from now**. Manufacturers get 24h for an early warning to ENISA/CSIRT,
72h for full notification, 14 days for a final report. It triggers on **actively exploited**
vulnerabilities (→ CISA KEV / EPSS, not every CVE). Machine-readable **SBOM** is formally due
Dec 2027 but is a practical prerequisite for the 24h clock. Penalties reach €15M / 2.5% of
global turnover. Full conformity (CE marking) lands 2027-12-11.

Also current: **OWASP ASVS 5.0** (May 2025) — ~350 requirements across 17 chapters, with stable
`v5.0.0-3.2.1`-style identifiers that are ideal to map findings onto.

No competitor in the Claude-plugin space produces a CRA-shaped artifact. Nobody.

---

## 2. Positioning

> **SecAudit is the audit you can hand to someone else.**
> Anthropic's plugin secures the code Claude is writing. SecAudit answers *"is this product
> secure, can I prove it, and what do I owe a regulator?"* — for a running target as well as a
> repo, with or without Claude Code, with a measured detection floor and a deliverable at the end.

Three pillars, one roof (per decision 2026-08-12):

1. **Authorized live-target audit** — passive recon → attack surface → OWASP web/API tests, gated
   by a deterministic authorization hook and a `scope.yaml`. *Nobody official does this.*
2. **Standalone measured engine** — runs in CI, cron, a plain shell, or an air-gapped box with a
   local model. Published precision/recall. On the RealVuln leaderboard.
3. **Compliance-grade output** — ASVS 5.0 / CWE / OWASP / PCI / CRA mapping, CycloneDX SBOM,
   KEV+EPSS exploitability, executive + technical + machine-readable reports in EN and TR.

Reach: Claude Code plugin **plus an MCP server**, so Codex, Cursor, OpenCode, Copilot CLI and any
other MCP client can call the same engine.

Fix loop: verified patch generation — draft in a scratch tree, independent review agent, run the
project's tests, write `patches/F<n>.patch` only if it vouches. Never auto-apply.

### What we will NOT do

Stating this is a maturity signal (BugHunter's README does it and it works):

- No offensive tooling, weaponized exploits, C2, evasion, or post-exploitation.
- No mass targeting, no unauthorized scanning — the authorization gate is not negotiable.
- No competing with the in-session review layer. We recommend installing Anthropic's
  `security-guidance` plugin *alongside* SecAudit and say so in the README.
- No claimed completeness. Every report states its own bound.

---

## 3. Gap analysis — what has to change

| # | Gap | Severity | Phase |
|---|---|---|---|
| G1 | Tier-0 is regex-only; RealVuln shows rule-based SAST at F3 17.7 on real code | **Critical** | P1 |
| G2 | No taint/dataflow analysis → no reachability, no logic bugs | **Critical** | P1 |
| G3 | Fixtures are self-tuned; no external benchmark number | **Critical** | P2 |
| G4 | Dependency findings have no reachability/VEX → CVE noise | High | P1 |
| G5 | No SBOM, no compliance mapping, no CRA artifact | High | P3 |
| G6 | Report is one shape; no exec/technical split, no HTML/PDF, no diff-mode | High | P3 |
| G7 | No MCP server → invisible to every non-Claude agent | High | P4 |
| G8 | No patch generation | High | P5 |
| G9 | 16 references vs. competitors' 38–82 skills → weak discovery | Medium | P1/P6 |
| G10 | No website, no PyPI, no directory listing, no demo | Medium | P6 |
| G11 | Live-target track has no browser/DOM capability (auth flows, SPA, DOM XSS) | Medium | P4 |
| G12 | No continuous/monitoring mode → no CRA 24h clock support | Medium | P4 |
| G13 | 2 fixture languages; multi-language detectors are unmeasured | Medium | P2 |
| G14 | Repo hygiene: `__pycache__`/`.pytest_cache` committed, uncommitted work on disk | Low | P0 |

---

## 4. Phases

Each phase is independently shippable and ends at a tagged release. Exit criteria are gates in
CI, not opinions.

### P0 — Foundation (short)

Clear the runway before touching the engine.

- Commit the pending methodology work; purge `__pycache__`/`.pytest_cache` from the tree and
  `.gitignore` them.
- **Licensing: stay single-license MIT.** Considered and rejected the ecosystem's MIT-code /
  CC-BY-content split (Claude-BugHunter, Trail of Bits). In a Claude Code plugin the Markdown
  *is* the program — `SKILL.md` and the references are executed instructions, not documentation
  about a program — so a split creates a real "which license governs this file" ambiguity for
  every downstream user, on top of CC's own guidance against licensing software with it. MIT
  already compels attribution, and it is strictly more permissive, which matters for adoption.
  Add a short `LICENSING.md` note recording this decision so it isn't re-litigated.
- Adopt the senior-dev-kit check harness shape: `package.json` scripts driving TypeScript
  validators — `validate-skills`, `check-links`, `check-consistency`, `gen-docs --check`,
  `check-plugin`, `run-checks`. Every number stated in a README must be derived, not typed.
- Decide and reserve the public identity: repo name, `secaudit.mtvrkan.com`, PyPI name `secaudit`.

**Exit:** clean tree, green CI, `npm run check` passes, consistency checker fails on a typed count.

### P1 — Detection depth (the engineering moat)

The current pack cannot survive an honest external benchmark. Rebuild the floor.

**Done (2026-08-12):**

- ✅ **Taint engine** (`secaudit_core/taint/`) — Python via `ast`, JS/TS via a brace-aware
  statement scanner. Propagation, block scope, sanitizers, validate-then-exit guards, and
  per-argument taint so a bound query parameter is not mistaken for injection. 13 paths on
  the vulnerable corpus covering 11 golden classes; 0 high-confidence paths on the negative
  control. Every finding carries the followable path.
- ✅ **Confidence is earned** — request-rooted paths are HIGH, parameter-rooted paths are
  MEDIUM and drop a severity rung, because whether a parameter carries untrusted data is
  caller knowledge the analysis does not have.
- ✅ **Code-shape rules stop matching inside literals and comments** — 42 of 85 detectors now
  scan a blanked view. Found by the dogfood gate on the kit's own new sink catalog. This is
  the exact weakness behind rule-based SAST's 17.7 F3 on RealVuln.
- ✅ **Reachability + VEX for dependency CVEs** (`secaudit_core/deps.py`) — import-level
  classification into OpenVEX statuses with stated evidence, `--format openvex`, and explicit
  refusal to conclude `not_affected` for transitive or unindexable cases.

**Remaining:**

- ✅ **Taint engine — depth.** All three levels landed 2026-08-12 and each is measured by
  its own golden finding, so no level can be claimed on another's evidence: **V21** crosses a
  function boundary in Python, **V22** crosses a function boundary in JavaScript, **V23**
  crosses a *module* boundary. Cross-module summaries iterate to a fixed point over the import
  graph, so a chain laundering through several modules resolves and the sink is attributed to
  the file it actually lives in. Remaining: JS helpers defined as object properties or class
  methods (no delimitable body, so no summary); `await`/promise chains; a helper in a file
  outside the scanned set.
- **Symbol-level dependency reachability.** Import-level is where the current VEX pass stops,
  because neither npm audit nor OSV publishes the affected symbol in a machine-usable form.
  Closing this means resolving advisory → fixed-version diff → changed symbols, then checking
  whether those symbols are called. It converts `affected` from "reachable enough to take
  seriously" into a real claim.
- ✅ **Semgrep rule pack** — [`rules/secaudit/`](rules/secaudit/), generated from the
  detector table with a `--check` gate. 43 of 85 detectors exported; the other 42 are
  withheld with published reasons, because `pattern-regex` cannot reproduce a blanked
  code view or a file-level suppression and a noisier rule under the same name would
  invalidate the precision numbers this project publishes. Equivalence is measured
  (`kit/tests/test_semgrep_pack.py`), not asserted.
- **Business-logic pass.** The documented #1 market gap. A structured prompt track over
  route→handler→authz maps: missing ownership checks, IDOR, state-machine skips, price/quantity
  trust, race windows on writes. Deterministic scaffolding (extract the route table, extract the
  authz calls), model reasoning over the extract.
- ✅ **Language coverage matrix**, published and generated: [`docs/language-coverage.md`](docs/language-coverage.md),
  derived from the taint dispatch table, the detector pack's extension tuples and the lexical
  models `code_view` knows. Generating it exposed its first gap immediately — Rust had zero
  detectors, now three. Gated by `scripts/gen_language_matrix.py --check`.
- Grow the reference library toward the ecosystem's bar (G9): split the monolithic references into
  per-class skills with real trigger descriptions so they surface in the model's skill routing.

**Exit:** taint engine finds every planted taint-path flaw in the fixtures with zero HIGH-confidence
hits on the secure fixture; VEX output validates; per-language matrix generated from code, not typed.

### P2 — Measurement & credibility

Make the claims falsifiable, then publish them.

**Done (2026-08-12):**

- ✅ **Eval harness** (`eval/`) — precision, recall, F1, F3, per class and per language, with
  the scoring rules written down and precision reported as the upper bound it is. Labels are
  generated from the fixtures in RealVuln's ground-truth schema. Measured: 95% recall, 100%
  precision, F3 0.955, 0 false positives on 20 safe-implementation traps.
- ✅ **Regression gates** — `--check` (committed scorecard must match what the engine
  measures) and `--gate` (floors in `eval/thresholds.json`), both in CI. Plus consistency
  check 23: the README's numbers must equal the scorecard's.
- ✅ **Semgrep JSON output** — the interchange format external benchmarks and SAST tooling
  ingest.
- ✅ **RealVuln runner** (`eval/realvuln/`) — reproduction steps and an honest reading guide.
- ✅ **RealVuln, run and published: F3 26.0** on 62 of 66 repositories (four are gone from
  GitHub), Tier 0, scored by the benchmark's own scorer. **Above** rule-based SAST's published
  17.7 on both metrics — precision (0.511 vs 0.205) and recall (0.246 vs 0.175) — and far below a
  general-purpose LLM (51.7) and the purpose-built system (73.0). Full result in
  [`eval/realvuln/README.md`](eval/realvuln/README.md); the scorer's raw output is committed as
  `result.json` and consistency check 27 fails the build if any stated figure stops matching it.
- ⚠️ **The number is no longer blind, and that is disclosed everywhere it appears.** 12.5 and
  13.3 were measured on a corpus the engine had never seen. 24.6 and then 26.0 were measured
  after its false negatives were read and the missing rules implemented — twice. Every rule
  added is one any SAST ships, so nothing is fitted to a fixture, but the selection was
  corpus-informed in both rounds and the advantage compounds. The honest successor is a
  benchmark this repository has not read.
- ✅ **Four runs, one corpus, one variable.** 12.5 → 13.3 → 24.6 → 26.0, each re-scored on the
  same clone; the previous engine is re-run on it every round and has reproduced its committed
  figures digit for digit each time, so every delta is the engine and not corpus drift. The
  ground-truth digest is recomputed per round and has not moved (`sha256:af5901bf…`).
  `eval/realvuln/run.py --scanner` and `eval/realvuln/collect_result.py` exist for that.

**Remaining:**

- **The classes that are still zero are not a pattern problem.** `broken_access_control`
  (0/76), `missing_auth` (0/74), `denial_of_service` (0/44) and the bulk of `other` (131/831)
  need to know what the application intends. That is the business-logic pass (G-series below),
  not more catalog entries. `path_traversal` stayed at 3/39 across nine added filesystem sinks
  in two rounds, which says its misses are about which values are believed attacker-controlled.

- ✅ **Fixture expansion** — 61 planted flaws across 15 languages, each with a paired
  safe twin implementing the same feature. Ten languages had detectors and no fixtures
  before this; one of those detectors (`SEC-RS-CMDI`) turned out to have never been able
  to fire. Original note below:
- **Fixture expansion:** 20 → 60+ planted flaws across 5+ languages, each with a paired safe
- ✅ **Eval harness v2** — per class, per language and per CWE, plus a gate that fails when a
  previously-detected class drops to zero (the regression an improving aggregate hides).
  Original note below:
- **Eval harness v2:** precision, recall, F1 and F3 **per CWE class and per language**, not one
  aggregate. Regression-gated in CI: a drop fails the build.
- **Run RealVuln.** Publish the score honestly, including where we lose. Submit results to the
  benchmark repo. Ship the runner (`eval/realvuln/`) so anyone can reproduce it.
- ✅ **"What we miss" page**, generated: [`docs/what-we-miss.md`](docs/what-we-miss.md) —
  measured misses from the committed scorecard, classes with no deterministic coverage, the
  taint tier's own bounds, language and compliance gaps. Generated rather than written because
  a hand-maintained limitations page is accurate for one release and then silently becomes an
  understatement. Gated by `scripts/gen_what_we_miss.py --check`.
- **Determinism statement.** Tier 0 is reproducible; Tier 1 is not. Say which findings came from
  which tier in the report, per finding.
  - ✅ **Tier 0 reproducibility is now tested, not assumed.** Cross-module analysis used to
    depend on the order files were walked in — the same repo could produce two different
    answers, and the unlucky one dropped the chain's entry point. Fixed by running the module
    graph to convergence instead of for a fixed number of passes, and locked in by a test that
    demands four walk orders agree *and* that what they agree on is correct. Worth recording as
    a roadmap item rather than a bug line: this repo criticises competitors for nondeterminism
    on the comparison table, so "same code, same result" is a claim we owe a test, not prose.

**Exit:** a public benchmark number with a reproducible runner; CI fails on a precision/recall regression.

### P3 — Report & compliance (the deliverable moat)

**Done (2026-08-12):**

- ✅ **ASVS 5.0 mapping** at chapter level (V1–V17), complete over every CWE the engine emits
  (34/34), gated by consistency check 24. Requirement-level deliberately not attempted: ASVS
  5.0 moved external cross-references to OWASP's CRE project, so there is no crosswalk to copy.
- ✅ **EU CRA mapping** at clause level, with `--format cra` emitting the evidence pack:
  CycloneDX SBOM + vulnerability register (VEX, reachability, ASVS chapter, remediation) +
  clause coverage + a disclaimer that it is input to a compliance process, not a certificate.
- ✅ **CycloneDX 1.6 SBOM** (`--format cyclonedx`), deterministic, with unresolved versions
  flagged rather than inferred from a range.
- ⛔ **PCI DSS / SOC 2 / ISO 27001 deliberately not mapped** — each needs a citable source per
  control, and a plausible guess for a standard an auditor checks is worse than nothing. This
  is the next compliance item, and it is research work before it is code.


- ✅ **HTML report (`--format html`)** — self-contained (no external stylesheet, script, font
  or image), printable, executive summary and technical body as separate sections, escaping
  tested against hostile input. PDF is the browser's print-to-PDF over this file rather than a
  rendering dependency to ship and pin. **Remaining:** a SARIF integration test that actually
  uploads to GitHub code scanning, rather than asserting the document shape.
- **Compliance mapping layer.** One mapping table, many outputs: CWE → OWASP Top 10 (Web/API/LLM/
  Mobile) → **ASVS 5.0 requirement id** → PCI DSS 4.0.1 → SOC 2 CC → ISO 27001 Annex A → CRA
  Annex I essential requirement. Findings inherit the mapping; reports render whichever the user
  asks for.
- ✅ **CycloneDX + SPDX SBOM generation** — `--format cyclonedx` and `--format spdx`, sharing
  one component derivation so the two documents cannot disagree (gated). Signing/attestation
  is still open and belongs with the release pipeline.
- ✅ **KEV + EPSS enrichment** (`--exploitation`) — the "actively exploited" flag, which is
  precisely the class the CRA's 24-hour clock triggers on. Off by default (network), reports
  `unknown` rather than a clean bill when a feed is unreachable, raises severity but never
  lowers it, and has no `not_exploited` value by design. Original note below:
- **KEV + EPSS enrichment** on every CVE → an "actively exploited" flag, which is precisely the
  CRA reporting trigger.
- **CRA evidence pack** (`--profile cra`): SBOM + vulnerability register + exploitation status +
  a pre-filled 24h early-warning / 72h notification template. Nothing else in this ecosystem
  produces this, and the obligation starts 2026-09-11.
- ✅ **Diff mode:** `--since <ref>` — what's new, fixed, or still open since the last audit
  ([docs/diff-mode.md](docs/diff-mode.md)). With `--min` the gate fires on *introduced*
  findings only, which is what makes it survivable on a repo with history; pre-existing
  findings are still printed. Both trees are scanned in full rather than just the changed
  files, because taint crosses import edges and a changed-files scan would call a PR clean
  while it introduced a Critical in a file it never touched. Gated by `kit/tests/test_diff.py`
  against real git repositories.
- ✅ **i18n as data** — `i18n/en.json` + `i18n/tr.json`, `--lang tr`, gated for key and
  placeholder completeness. Report chrome is translated; finding titles and fix text stay
  in English on purpose, because they change with the engine and a stale translated fix
  is not visibly wrong. Original note below:
- **i18n as data:** report strings in `i18n/en.json` + `i18n/tr.json`, not prose forked per
- ✅ **MCP server** (`kit/secaudit_mcp/`, `python3 -m secaudit_mcp`) exposing `scan_source`,
  `scan_dependencies`, `generate_sbom`, `compliance_pack`, `explain_finding` and `coverage`.
  Per-client config in [`docs/mcp.md`](docs/mcp.md). Two planned tools were deliberately not
  shipped: `passive_recon`, because no MCP tool should touch a network target — consent to
  probe a running system is a human decision and a tool call carries no evidence of one, so
  live mode stays behind the plugin's `scope.yaml` gate and the test suite asserts no tool
  schema accepts a `url`/`host`/`endpoint`; and `suggest_patch`, until P5's review agent exists
  to vouch for a patch. `coverage` was added and is the one that matters: a model that gets
  findings but cannot ask for the bounds reports an empty result as "no security issues found".
- ✅ **PyPI package** `secaudit-kit` — build, wheel smoke test in a clean venv, tag/version
  agreement check and trusted publishing (OIDC, no stored token) in
  [`.github/workflows/release.yml`](.github/workflows/release.yml). The zero-runtime-dependency
  invariant is asserted against the built artefact, not the manifest, by
  `scripts/assert_no_runtime_deps.py`. **Publishing itself is the maintainer's step** — it
  needs the PyPI trusted publisher configured once and a tag pushed.
  Packaging is ready — `secaudit` and `secaudit-mcp` console scripts, both packages declared —
  the remaining work is the release itself.
- ✅ **Hardened GitHub Action** ([`action.yml`](action.yml)) — SARIF, PR comment (opt-in),
  severity gate on *introduced* findings, SBOM artifact. Runs the code in the checkout rather
  than installing itself. Original scope note kept below:
- **Hardened GitHub Action** — SARIF upload, PR comment summary, severity gate, SBOM artifact,
  CRA profile. Plus a reusable workflow and a `pre-commit` hook.
- ✅ **Docker image** ([`Dockerfile`](Dockerfile)) — multi-stage, non-root (UID 10001),
  read-only source mount, `git` included so `--since` works. Base pinned to a minor version
  tag with the digest-pinning command documented: a digest has to be *resolved* to be real,
  and one typed from memory is unverifiable and fails at build time.
- **Live-target depth (G11):** browser-driven checks for SPA/DOM XSS, auth-flow walking, and
  post-login surface discovery — still behind the authorization gate, still passive-by-default.
- **Continuous mode (G12):** scheduled re-scan + KEV/EPSS watch on the last SBOM; alert when a
  dependency you actually reach becomes actively exploited. This is the CRA 24h clock in practice.

**Exit:** the MCP server drives a full audit from a non-Claude client; the Action posts SARIF to
code scanning on a test repo; `pip install secaudit` works.

### P5 — Verified fix loop

- Patch generation per finding, drafted in a scratch worktree; source files untouched.
- ✅ **Verified patch loop** (`--suggest-patches`) — a model proposes, the deterministic
  engine vouches: patch applied to a throwaway copy, copy re-scanned, the two scans
  compared with the `--since` machinery. The independent reviewer has a veto only and
  never sees the author's reasoning. Out-of-scope edits, feature deletion, traded
  vulnerabilities and failing tests are all refusals. Nothing is ever applied.
  Original requirement below:
- **Independent review agent** — different context from the author. It must vouch that the patch
- Output `patches/F<n>.patch` + `patches/F<n>.md`. **Never auto-applied.** One patch, one PR.
- Retest integration: after applying, re-run only the finding's retest step.

**Exit:** on the vulnerable fixture, every patchable finding produces a patch that applies cleanly,
passes the secure fixture's test expectations, and does not reintroduce another planted flaw.

### P6 — Site, docs & launch

**Done (2026-08-12):**

- ✅ **Bilingual landing page**, generated from repository facts, gated so a typed number fails
  the build. Self-contained, theme-aware, canonical + hreflang, ~11 KB per page. Published to
  GitHub Pages by `site.yml` on every push to main.
  *Revised from the plan:* the site source lives on `main`, not a separate `site-src` branch.
  The branch split exists in senior-dev-kit to keep ~360 KB of images out of every clone; here
  the whole page is 11 KB of generated HTML from one 6 KB template, and the branch dance would
  cost more in confusion than it saves in bytes.
- ✅ **README comparison against the official Anthropic plugins** — the single thing a visitor
  needs to decide between them, stated generously and with their docs quoted.

**Remaining:**

- ✅ **Favicon** — an inline SVG shield, data-URI'd into the page so it stays a single self-contained file.
- ✅ **OG image** — `site/og.png`, generated by `scripts/gen_og_image.py` from the scorecard and
  the gate list, gated byte for byte. Headless Chrome turned out not to be needed here either:
  the repo carries a small PNG encoder (`pngwriter.py`) and a stroke font (`strokefont.py`), so
  the card is regenerable by anyone who can run Python — which is the point, because it carries
  the recall figure and would otherwise go stale the moment that figure moved. **Nothing on the
  site is a manual step any more.**
- Pages: what it is · live demo (asciinema) · **benchmark page with the RealVuln number** ·
  what we miss · CRA guide · install per harness · docs · comparison table.
- **README v2** — lead with the one sentence, the differentiator against the official plugin, the
  benchmark number, and a 15-second install. Bilingual (`README.tr.md`).
- **Docs site content**: getting started, authorization, live mode, source mode, compliance
  profiles, MCP, CI, methodology, FAQ, security policy, threat model.
- Launch: plugin directories (claudemarketplaces.com, skillsllm), Show HN, r/netsec,
  OWASP Slack, the RealVuln leaderboard PR, and a written launch post on the CRA angle timed to
  the 2026-09-11 deadline.

**Exit:** site live on a custom domain, all numbers derived, both languages complete, listed in at
least two directories.

---

## 5. Sequencing note

P1 and P2 are the only phases that are strictly ordered — you cannot publish a benchmark number
before the engine that earns it. P3 can start in parallel with P1 (the mapping layer is data
work). P6's site generator can be built early and fed by whatever numbers exist at the time,
since it derives them.

If time is short, the minimum credible v2.0 is **P0 + P1 + P2 + P6**: a measurably better engine
with a published number and a place to point people at. P3–P5 are what make it defensible.

---

## 6. Sources

- Anthropic — [security-guidance plugin](https://code.claude.com/docs/en/security-guidance) ·
  [Claude Security plugin](https://code.claude.com/docs/en/claude-security)
- [Trail of Bits skills](https://github.com/trailofbits/skills) ·
  [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) ·
  [Transilience communitytools](https://github.com/transilienceai/communitytools) ·
  [z-audit](https://github.com/zm2231/z-audit)
- [Strix](https://github.com/usestrix/strix) ·
  [AppSec Santa: AI Pentesting Agents 2026](https://appsecsanta.com/research/ai-pentesting-agents-2026)
- [RealVuln benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark) ·
  [paper](https://arxiv.org/abs/2604.13764) · [dashboard](https://realvuln.kolega.dev/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) ·
  [OWASP Benchmark](https://owasp.org/www-project-benchmark/)
- EU CRA — [OpenSSF policy hub](https://openssf.org/category/policy/cra/) ·
  [Mend compliance guide](https://www.mend.io/blog/eu-cyber-resilience-act-compliance-guide/)
