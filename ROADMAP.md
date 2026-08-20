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
- ✅ **Code-shape rules stop matching inside literals and comments** — 46 of 115 detectors now
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
- ⛔ **Symbol-level dependency reachability — blocked on data, not on analysis, and the earlier
  framing of this item was wrong.** It said "neither npm audit nor OSV publishes the affected
  symbol in a machine-usable form." OSV *does*, for some ecosystems: Go advisories carry
  `affected[].ecosystem_specific.imports[].symbols` and RustSec carries affected function lists.
  What is true is narrower and decides the item: **the two ecosystems this dependency scan
  indexes — npm and PyPI — have no such field**, so there is nothing to match a call against.
  The fallback of deriving symbols from each advisory's fix commit was considered and rejected on
  2026-08-14: a fix commit also touches tests, docs and refactors, so picking the vulnerable
  function out of the diff is a guess, and a guess that downgrades an advisory to `not_affected`
  is the most dangerous output the VEX pass can produce. This unblocks when the scan indexes Go —
  which is the real prerequisite and now the item to schedule instead of this one.
- ✅ **Semgrep rule pack** — [`rules/secaudit/`](rules/secaudit/), generated from the
  detector table with a `--check` gate. 61 of 115 detectors exported; the other 54 are
  withheld with published reasons, because `pattern-regex` cannot reproduce a blanked
  code view, a file-level suppression or a file-level precondition, and a noisier rule
  under the same name would
  invalidate the precision numbers this project publishes. Equivalence is measured
  (`kit/tests/test_semgrep_pack.py`), not asserted.
- ✅ **Business-logic pass** — shipped 2026-08-13, in the shape this plan specified: deterministic
  scaffolding plus model reasoning over the extract, never over the repository.
  `secaudit_core/structural/handlermap.py` extracts per handler what authorization evidence it
  carries, which identifiers the caller chose, which data operations the principal did or did not
  narrow, which state fields are written versus checked, and which money-shaped values come from
  the request body; `backends.LOGIC_CLASSES` accepts exactly four verdicts over that shortlist —
  missing ownership (CWE-639), missing authorization (CWE-862), workflow skip (CWE-841), trusted
  client value (CWE-602). Four refusals bound it, each counted in the report: an undefined class,
  an unshown file, a line outside every handler span, and a weakness Tier 0 already reported in
  that handler. The reserved model call is taken from inside the four-call ceiling rather than
  added to it.
  **Three things it does not claim.** The map emits no finding and is not in `_RULES`, so Tier 0
  is byte-identical and every figure on this page is unchanged and still Tier 0. The pass itself
  has **no measured precision or recall** — it is gated offline against a recorded reply, which
  proves the merge and the refusals and proves nothing about detection — so
  [`docs/what-we-miss.md`](docs/what-we-miss.md) still lists these classes as gaps. And
  `race_window` (CWE-367) was deliberately left out: whether a read-then-write is exploitable
  depends on transaction isolation the extract does not carry, and a guess in a channel whose
  only defence is narrowness is what would sink it.
- ✅ **Language coverage matrix**, published and generated: [`docs/language-coverage.md`](docs/language-coverage.md),
  derived from the taint dispatch table, the detector pack's extension tuples and the lexical
  models `code_view` knows. Generating it exposed its first gap immediately — Rust had zero
  detectors, now three. Gated by `scripts/gen_language_matrix.py --check`.
- **A vendored library does not arrive as one file.** `is_vendored_asset` decides file by file, so
  a drop like `static/js/foundation/foundation.*.js` is classified correctly for `foundation.js`,
  which carries the release banner, and as application source for the eleven siblings that do not.
  Measured, on the round that added `SEC-JS-HTML-CONCAT`: 20 of that rule's 22 RealVuln findings
  are those siblings. The fix is the same move `_is_own_release` already made for manifests —
  answer per directory, not per file — and it needs measuring on all four corpora, because
  widening a silencing predicate is the one kind of change that can only ever remove findings.
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
- ✅ **RealVuln, run and published: F3 61.2** on 62 of 66 repositories (four are gone from
  GitHub), Tier 0, scored by the benchmark's own scorer. **Above** rule-based SAST's published
  17.7 on both metrics — precision (0.6560 vs 0.205) and recall (0.6073 vs 0.175) — and now above
  the general-purpose LLM row (51.7) as well, though that comparison cuts the other way: the LLM
  baseline was measured blind and this figure was not. Still below the purpose-built system
  (73.0). Full result in
  [`eval/realvuln/README.md`](eval/realvuln/README.md); the scorer's raw output is committed as
  `result.json` and consistency check 27 fails the build if any stated figure stops matching it.
- ⚠️ **The number is no longer blind, and that is disclosed everywhere it appears.** 12.5 and
  13.3 were measured on a corpus the engine had never seen. 24.6, then 26.0, then 30.9, then the
  recall half of 35.8 were measured after its false negatives were read and the missing rules
  implemented. Every rule added is one any SAST ships, so nothing is fitted to a fixture, but the
  selection was corpus-informed in each round and the advantage compounds. Two exceptions are
  worth naming: the 30.9 → 31.5 round added no rule and read no label, and the largest component
  of 31.5 → 35.8 — 143 false positives removed because a vendored bundle is not application
  source — is true of any corpus, not this one. The honest successor is still a benchmark this
  repository has not read.
- ✅ **Fourteen runs, one corpus, one variable.** 12.5 → 13.3 → 24.6 → 26.0 → 30.9 → 31.5 → 35.8 →
  35.9 → 35.9 → 35.9 → 39.3 → 39.3 → 39.2 → 39.2, each re-scored on the same clone; the previous
  engine is re-run on it every round, so every delta is the engine and not corpus drift. The
  ground-truth digest is recomputed per round and has not moved
  (`sha256:af5901bf…`). `eval/realvuln/run.py --scanner` and
  `eval/realvuln/collect_result.py` exist for that, and the latter now **stamps the engine digest
  itself** — leaving that to whoever remembers is how the figures and the digest come apart.

  **The thirteenth entry is not an engine change: it is the twelfth, re-measured.** That
  reproduction step had reported "digit for digit" every round until 2026-08-17, when it did not.
  The engine reproduced exactly (932 findings, no repository differing); the *published* figure
  did not, because the round that shipped it changed the engine and then republished the previous
  engine's headline — `dashboard.py` had not been re-run after its own `score.py`, and its own
  per-repository table in the same file already said 273 rather than 271. Corrected to 39.2 /
  0.7071, with check 42 and a refusal in `collect_result.py` so a file whose two halves disagree
  cannot be written again, and `run.py` now records the engine digest beside the results so the
  stamp describes the run rather than the tree at collection time.

  The ninth held at 35.9 exactly: a JavaScript round measured on a Python corpus. Not inert,
  though, and the per-repo table is why that is worth saying — three repositories moved and netted
  to zero (`lets-be-bad-guys` **−3 FP** as the retired `SEC-JS-PROTO` stopped firing,
  `fintech-lending` +1 and `vulnerable-tornado-app` +2 from the rules that replaced it). An
  aggregate that does not move is not the same as an engine that did nothing.
- ⚠️ **Precision rose seven rounds running** (0.504 → 0.511 → 0.540 → 0.542 → 0.660 → 0.708 →
  0.707) **and fell in the eighth, to 0.704.** That series is this repository's own acceptance
  test for a detection change, and the rule attached to it says the round where it stops holding
  is the round to stop and narrow rather than publish. It stopped holding. The round was kept and
  the reasoning is on [`eval/secbenchjs/README.md`](eval/secbenchjs/README.md) rather than here:
  the four new false positives are one correctly-read quadratic regex in four seeded
  applications, the labelled false-positive traps did not move (248 either way), and the held-out
  slice moved *further* than the slice whose labels were read. A reader who weighs the precision
  series above those three is entitled to reject the round, which is why all four numbers are
  published together.

**Remaining:**

- ✅ **The second benchmark is run five times: [SecBench.js](https://github.com/cristianstaicu/SecBench.js),
  blind recall 0.2286, then 0.3839, 0.4136, 0.4887 and 0.5410 after acting on what the blind run
  said.** 131 → 220 → 237 → 280 → 310 of 573 labelled sinks across 594 npm packages, full result and every caveat in
  [`eval/secbenchjs/README.md`](eval/secbenchjs/README.md). The blind figure is the one to quote
  when the question is how the engine does on unseen code, and it does not improve; the second is
  corpus-informed in exactly the way RealVuln's has been since its third run. Precision is
  deliberately **not** published as a precision: the benchmark labels one vulnerability per
  package, so the unmatched-finding ratio is a lower bound on noise and is not comparable to the
  RealVuln figure. It is worth watching across runs of the same corpus, and it went
  **0.0606 → 0.1006 → 0.0903 → 0.0895 → 0.0910 → 0.0919 → 0.0918**: down in two rounds while recall rose,
  which is this page's stop signal and is argued rather than smoothed over in both cases, and
  **up** in the two rounds after them, which is the only shape that means a rule got better
  rather than louder.

  **The path matcher was wrong for every run before 2026-08-17, and the correction is why the
  figures above differ from the ones this file used to state.** Eighty-two of the 573 labels name
  a file that does not exist at the stated path — a bare basename, or a monorepo prefix the
  published tarball does not carry — and the scorer compared strings, so it filed every one under
  *"no rule fired at the sink"*. It resolves them now (unique component-boundary match, long
  enough to hold the labelled line) and reports the unresolvable ones under their own causes.
  Worth +6 true positives on an unchanged engine; worth more as a diagnosis, since 36 misses left
  a cause that had been aiming rounds at detection. The blind run was re-measured through the
  same matcher, from a worktree at the commit that produced it — reproducing 128/573 exactly under
  the old matcher, which is what makes 131/573 a like-for-like column rather than a second
  instrument.

  **Both predictions written here before the blind run arrived.** ReDoS scored **0 of 87** because
  `redos.py` was Python-only — stated in advance precisely so it could not afterwards be presented
  as a discovery. The three things the blind run diagnosed, and what each turned into:

  * **ReDoS 0 → 8 → 28 of 87.** `redos.py` gained a JavaScript front end (regex-literal lexer plus
    the string argument to `new RegExp`) feeding the *unchanged* criteria, and eight was the honest
    size of those criteria: they catch **exponential** blowup and most published ReDoS advisories
    are **polynomial**. That widening is done and it was separate work with its own cost, exactly
    as predicted. Reading all 79 remaining labels gave two changes — a **quadratic** criterion
    (two unbounded repeats over overlapping characters, followed by something that can fail) and
    reporting a JavaScript pattern on the line where it *runs* rather than only where it is
    declared. Worth +11 and +1 alone, **+19 together**. It cost 12 findings per 382,057 lines on
    the noise floor (0.21 → 0.24, none of them High) and 4 false positives on RealVuln.
  * **Command injection 41 → 62 of 101 and code injection 19 → 23 of 33, the two classes nobody
    had read.** Reading all 44 unsealed command-injection misses says the taint tier follows every
    *value* shape these libraries use — concatenation, template literal, local, `.join(' ')`, a
    call into a helper — and could not **recognise the call**: `exec` is whatever the file
    imported, and `cp.exec` / `childProcess.exec` / `child_process_1.exec` / a promisified alias /
    `shell.exec` were 14 of the 44. Receivers are resolved from the file's own imports now, which
    is the only way to be right in both directions (`re.exec` in a file that imported nothing is
    still a regular expression). Two more: a method in an object literal binds parameters, and so
    does `function(a)` written without a space — the header regex required one. And two sink
    families were simply absent: the `Function` constructor without `new`, and Node's `vm`, which
    is marketed as a sandbox and says in its own documentation that it is not one. Cost: **no
    change at all on RealVuln** and one additional Medium finding on the noise floor.
  * **Prototype pollution 9 → 13 → 25 → 68 of 185, and `SEC-JS-PROTO` is retired.** It matched
    `for (… in …)` and produced roughly 950 findings for those 9. `structural/protopollution.py`
    (`PROTO-JS-WRITE`) reports the *write* instead. The three rounds after that each answered a
    different question, and only the last one was about the rule:
    **the guard list** (`hasOwnProperty` is not a guard), then **reading all 113 unsealed misses**,
    which found that 35 of them were in a function `structural/js._functions` could not delimit at
    all — a default parameter value, a brace on the next line, an export assignment, an
    object-literal method — so every JavaScript structural analysis had been skipping them. The
    rule itself gained two things from the same reading: a callback's parameters carry what the
    iterated value carries (which retires the `js-extend@0.0.1` limitation this module had
    documented as permanent), and a **walk** — `cur = cur[part]` then a caller-chosen key at the
    end of it — which is the `set(obj, 'a.b.__proto__', v)` half of the CWE that no iteration
    binder can see. Cost: one false positive on RealVuln, three on the noise floor, and the
    unmatched-finding ratio went **up** (0.0895 → 0.0910), which is the only combination this
    project treats as unambiguously good.
  * **`dist/`/`build/`: the diagnosis was wrong, and that is the useful result.** This file called
    those 35 sinks "a scoping decision, not a detection failure". The engine now reads a build
    directory when the package's own `package.json` publishes it, which made **29 of the 35
    reachable** — and two became true positives. The other 27 were two problems stacked; removing
    the scoping one revealed the rules would not have fired anyway. The scorer was wrong in the
    same direction (it decided "skipped" from the path) and now asks the engine.

  ✅ **The follow-up recorded here is done, and it is the smallest measured round in the
  project.** `PROTO-JS-WRITE` fired when the iterated object was a **local literal** rather than
  a parameter — `Object.keys(filters)` over component state, `AdminAudit.tsx:18`, its only false
  positive on RealVuln. The rule's own title says *attacker-named key*, so it now requires the
  iterated object to trace back to a parameter. Not a single-hop check: a query-string parser is
  two bindings from its argument (`str.split('&')`, then `p.split('=')`) and is the real shape of
  a `qs`-family bug, so it is a bounded fixpoint over local bindings. **RealVuln precision
  0.7075 → 0.7084, one false positive removed, no true positive lost.** A rule that does not do
  what its title says is a defect whether or not the aggregate notices.

  *Kept because deleting it was the right call:* the first version also inherited the parameter
  lists of enclosing functions, for the recursive-merge-in-a-closure case. No mutation of that
  code could be made to fail a test — the enclosing function's span already contains the inner
  body, so its own pass reports the same write — and four lines that nothing can falsify are four
  lines that do not belong in a measured engine.

  *The plan that produced it, kept for the record:*

  *What it is:* 600 real npm vulnerabilities from Snyk / GitHub Advisories / huntr, ICSE 2023,
  five classes — prototype pollution (192), path traversal (169), command injection (101), ReDoS
  (98), arbitrary code injection (40). Each entry carries a `sinkLocation` of the form
  `lodash.js:2573:21`, so there is file-and-line ground truth to score against rather than a
  package-level verdict.

  *Why this one.* **It would be blind.** Every JS/TS rule in this engine was written against this
  repository's own fixtures; none was selected by reading SecBench.js labels, and that is the one
  property RealVuln can no longer offer at any price. It also lands exactly on the largest
  unmeasured surface — 32 pattern rules, four structural analyses and a taint tier on JS/TS that
  nobody outside this repository has ever scored — and its five classes map onto rules that
  already exist (`SEC-JS-PROTO`, `SEC-JS-PATHTRAV`, `SEC-JS-CMDI`, `SEC-JS-EVAL`, `TAINT-JS-*`),
  so the run measures the engine rather than its absence.

  *What it will cost, stated before rather than after.* There is **no scorer** — RealVuln shipped
  one and this does not, so `eval/secbenchjs/` needs a matcher and an aggregate of its own, and
  the honest way to build it is against the same `micro`/`strict_micro` shape already published,
  so the two numbers can sit beside each other without being compared. The corpus is 600 pinned
  npm package versions, which is a fetch step closer to `clone_repos.py` than to a git clone.
  The licence is not stated in the repository's own documentation and must be established before
  a single figure is published — this is a hard prerequisite, not a formality.

  *One outcome is predictable and must be published either way:* **ReDoS is 98 of the 600 labels
  and `redos.py` is Python-only**, so that sixth of the benchmark scores zero on arrival. That is
  a real gap the number will expose, and it is written down here first so the run cannot later be
  framed as having discovered it.

- **The classes that are still zero are not a pattern problem.** `broken_access_control`
  (0/76), `missing_auth` (0/74), `denial_of_service` (0/44) and the bulk of `other` (131/831)
  need to know what the application intends. That is the business-logic pass (G-series below),
  not more catalog entries.

  **`path_traversal` was on this list and did not belong here, and the wrong reason it was given
  is why it stayed at 3/39 for two rounds.** This bullet used to end: *"stayed at 3/39 across
  nine added filesystem sinks in two rounds, which says its misses are about which values are
  believed attacker-controlled."* That conclusion was wrong, and it was load-bearing — it pointed
  every later attempt at the source list. Reading the 36 labelled misses line by line says the
  opposite: the sources were **already** modelled, and the engine proves it by reporting SSRF,
  SSTI, XSS and open-redirect in the very same handlers from the very same route parameters.
  What was missing was `pathlib`. The catalog modelled the whole standard library's filesystem
  surface as one entry — the builtin `open` — and the code under test writes
  `(BASE / name).read_text()`. Nine added sinks in two rounds moved nothing because all nine were
  more ways to spell `open`, and nobody checked whether the misses spelled it at all. Modelling
  the `pathlib` read/write family (taint through the **receiver**, which no sink here had needed
  before) took it to **22 of 39**, and `other` from 228 to 268, for +24 false positives and a
  precision that did not move. **Generalises: a conclusion about why a class misses is a claim,
  and an unread one costs more than the misses — it aims the next two rounds.**

- **The tier that was supposed to reach them could not see the code (fixed 2026-08-13).** The
  enrichment prompt carried Tier-0's finding list and nothing else, so the `extra` channel — the
  one meant to report exactly `broken_access_control` and `missing_auth` — was asking a model to
  find flaws in handlers it had never been shown. `secaudit_core/llmcontext.py` now sends
  finding excerpts plus unflagged handler files, bounded at four calls per scan, and a cited file
  outside that context is refused rather than merged. **This changes nothing about the numbers
  above and must not be read as if it did:** every figure on this page is Tier 0, and the
  enrichment tier is still unmeasured. It moves the tier from *cannot* to *untested*, which is a
  smaller claim than it sounds like and the honest one.

- 🚫 **Measuring the LLM tier is out of scope — a decision, not a backlog item (2026-08-14).**
  It needs paid inference across 62 repositories and this project does not carry that cost, so
  it is not "not yet": it is not planned, and no session should re-open it as debt. Three things
  follow and all three are already done. **One:** the tier is off by default and the README now
  says in its own section that every published figure is Tier 0 and that the tier will stay
  unmeasured. **Two:** the positioning moved off it — a general-purpose model scores 51.7 on this
  same corpus with no harness at all, 20 points above this engine, so "we find more" was never
  the claim to make; reproducible, offline, consent-bounded and auditable is. **Three:** the
  harness still ships and runs in one command, so a contributor with a key can produce the number
  and it goes on the page with their name on it. Reconsider only if someone funds it or brings a
  measured result — never because the gap looks untidy.

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
- ✅ **PCI DSS 4.0.1 mapped, at requirement level** across the four requirements whose text was
  read and cross-checked; weaknesses whose applicable requirement depends on whether the data is
  account data, or the component in the cardholder data environment, are refused by name in
  `PCI_NOT_ASSERTABLE` rather than guessed.
- ⛔ **SOC 2 and ISO 27001 stay unmapped, and this is now a decision rather than a backlog item.**
  The AICPA Trust Services Criteria and ISO/IEC 27001 Annex A control texts are both behind
  copyright, so a mapping could only name control *numbers* whose text this project cannot quote
  and no reader could check. PCI is mapped and these are not for exactly one reason: PCI SSC
  publishes its standard for free. When a citable source exists, map; when it does not, say so —
  `compliance.py`, `docs/compliance.md` and `docs/what-we-miss.md` all carry the refusal, and it
  is a feature of the pack rather than a hole in it. Re-open only if the control text becomes
  citable, not because a competitor lists the acronym.


- ✅ **HTML report (`--format html`)** — self-contained (no external stylesheet, script, font
  or image), printable, executive summary and technical body as separate sections, escaping
  tested against hostile input. PDF is the browser's print-to-PDF over this file rather than a
  rendering dependency to ship and pin. **Remaining:** a SARIF integration test that actually
  uploads to GitHub code scanning, rather than asserting the document shape.
- **Compliance mapping layer.** One mapping table, many outputs: CWE → OWASP Top 10 (Web/API/LLM/
  Mobile) → ASVS chapter → PCI DSS 4.0.1 → CRA Annex I essential requirement. Findings inherit
  the mapping; reports render whichever the user asks for.
  *Revised from the plan:* ASVS is mapped at **chapter** rather than requirement level (5.0 moved
  cross-references out to OWASP CRE, so there is no authoritative CWE→requirement crosswalk to
  copy), and SOC 2 CC / ISO 27001 Annex A are **not** mapped at all — see the refusal above. The
  original scope line is kept here because it is what the plan promised and the difference is the
  point.
- ✅ **CycloneDX + SPDX SBOM generation** — `--format cyclonedx` and `--format spdx`, sharing
  one component derivation so the two documents cannot disagree (gated). **Signing/attestation
  landed with the release pipeline and this line said otherwise for two rounds:**
  `release.yml`'s `attest` job writes SLSA build provenance and an SBOM attestation
  (`actions/attest-build-provenance` + `actions/attest-sbom`, both SHA-pinned) over the wheel and
  the sdist, signed by OIDC rather than a stored key. It is a separate job from `build` for the
  same reason `pages: write` moved out of `site.yml`'s build job — the step that produces an
  artefact and the step that vouches for it should not share a credential. The SBOM it signs is
  produced by the tool being released, against its own source. **Unproven until the first `v*`
  tag**, like everything else in that workflow.
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
- ✅ **i18n as data** — `kit/secaudit_core/locales/en.json` + `tr.json`, `--lang tr`, gated for key and
  placeholder completeness. Report chrome is translated; finding titles and fix text stay
  in English on purpose, because they change with the engine and a stale translated fix
  is not visibly wrong. Original note below:
- **i18n as data:** report strings in `i18n/en.json` + `i18n/tr.json`, not prose forked per

### P4 — Distribution (G7, G10-partial, G11, G12)

Reach the harnesses and pipelines that are not a Claude Code session. The gap table routes G7,
G11 and G12 here; this heading was missing while its items sat under P3, which made three rows of
that table point at a phase the document did not contain.

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
- ✅ **Live-target depth (G11)** — phase P10 of the audit skill, with
  [`references/browser-driven.md`](plugins/secaudit/skills/security-audit/references/browser-driven.md):
  SPA/DOM XSS, auth-flow walking, post-login surface discovery and the two-role replay that
  decides broken access control, all behind the same authorization gate and passive by default.
  *Revised from the plan:* the browser comes from the harness, not from the package. Shipping
  Playwright to reach the DOM would trade the kit's zero-dependency property — the one thing that
  makes `secaudit_core` installable anywhere — for one phase, so this is a reference the model
  follows rather than a library the package installs. P10 is also declared non-optional where it
  matters: if P2 finds a document with no content, the earlier phases were testing a shell, and
  the report must either run P10 or say the real surface was never examined.
- ✅ **Continuous mode (G12)** — `--watch STATE` ([`monitor.py`](kit/secaudit_core/monitor.py)):
  records every advisory a scan found with the reachability verdict `deps.py` gave it, re-asks
  the exploitation feeds about exactly those CVE ids on each later run, and reports the
  *transitions*. A diff over the world rather than over the source, which is what makes it a
  different question from `--since` — the two are refused in combination for that reason. Its
  governing rule is that an unreachable feed established **nothing**: `compare()` refuses to
  produce a comparison, leaves the stored state untouched and exits non-zero, because a loop that
  prints a clean report when it failed to check manufactures the belief that somebody is watching.

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
- ✅ **OG image** — `site/og.png` and `og.tr.png`, rasterised from `site/og.html` by
  `scripts/gen_og_image.py`. This was drawn in pure Python for a while, on the argument that a
  build step needing a browser fails for a contributor who has done nothing wrong. That was right
  about the *gate* and wrong about the *asset*: it bought a card with no lowercase, no serif, no
  italic and no gradient, which is a design constraint nobody chose. The two are separated now —
  the PNGs are committed and redrawn by hand with Chrome, while `site/og.facts.json` records the
  figures they were drawn from and `--check` holds that against the repository **without opening
  a browser**. A card cannot outlive its number, and nobody needs Chrome to run the gates.
- ✅ **Benchmark page** — `/benchmark/` and `/tr/benchmark/`, the whole external result rather
  than the landing page's summary of it: the confusion matrix behind the aggregates, every run
  with what each round cost, the published baselines, every CWE family ordered by labelled pool
  size, all 62 repositories rather than a top five, both digests, the reproduction sequence, and
  the blindness disclosure given its own section instead of a footnote. Every figure is read from
  `result.json`; the baselines table and the reproduction commands are parsed out of
  `eval/realvuln/README.md`, which check 27 already holds against the scorer output, so the two
  documents cannot disagree. Adding it split the template into one shell plus a body per page —
  the alternative was a second copy of 470 lines of CSS, which does not stay a copy.
- ✅ **Install page** — `/install/` and `/tr/install/`, the six surfaces at full size with every
  command read out of the file that defines it: the plugin ids from the manifest Claude Code
  loads, the package metadata from `kit/pyproject.toml`, the Action's seven inputs from
  `action.yml`, the hook ids and flags from `.pre-commit-hooks.yaml`, the client configs and tool
  descriptions from `docs/mcp.md`, the build and run lines from `docs/ci.md`, the base digest and
  uid from the `Dockerfile`. Three cross-file gates came with it (marketplace version = package
  version, the hooks example's `rev:` = the tag the release would cut, the documented MCP tools =
  the served ones), and a release-state section that says which three surfaces need the first
  `v*` tag and which three do not. Writing it found `action.yml` advertising a detector count six
  rules out of date in the copy GitHub Marketplace prints beside the install button — check 08
  now covers manifests, not only prose. (It also caught the first draft of *this* bullet, which
  quoted the stale figure in the shape the check looks for.)
- ✅ **Landing page cut to eight sections from twelve** — the four removed were the four the menu
  never listed, which is what gave them away. `Capabilities` was four cards restating the hero
  demo, the dependency section, the evidence section and the gate, in shorter form, right after
  each had been made; the OpenVEX register duplicated the evidence section. `--since` and the
  comparison against the official plugins are real but they are a feature detail and a
  positioning argument, and the lede carries the positioning already. The comparison now lives
  only in the README until the page below is written, which is the right place for a table that
  makes factual claims about someone else's product.
- ✅ **Social cards per language, and a home-screen icon** — `site/og.png`, `site/og.tr.png` and
  `site/apple-touch-icon.png`, all three drawn by `gen_og_image.py` from `gen_site.facts()` rather
  than a second reading of the scorecard, and byte-checked together. The card used to lead with
  recall 98.4% and F3 0.986 — the *internal fixture* figures, the ones the site gives a section to
  saying they are not a claim about anyone else's code — so the first thing a reader saw made the
  flattering claim the rest of the page walks back. It leads with the external F3 now. Six Turkish
  letters had to be added to the stroke font (Ç Ğ İ Ö Ş Ü, each composed from its base glyph plus
  a mark rather than redrawn), and `draw` now raises on an unknown one: it used to skip, which was
  right while there was one card in one language and somebody looked at it, and would have shipped
  GÜVENLİK as GVENLK with every gate green the moment there were two.
- ✅ **Full-site audit — SEO, accessibility, structure, print, assets.** Findings worth recording:
  the landing page's two panels reported on two different scales (RealVuln's scorer emits
  F-scores on 0–100 and precision/recall as fractions, this repository's scorecard emits all
  three as fractions), so the section built to invite a comparison showed F3 31.5 beside F3 0.986
  — the landing page states every ratio as a percentage now, and the benchmark page keeps the
  scorer's units because it mirrors their published tables and says so. One figure on the site
  was still typed rather than derived (a published SAST baseline, quoted three hundred lines from
  the table it came from) and now comes from the same parse. Six meta descriptions and two titles
  were longer than a search result shows. Printing produced a mostly blank document, because the
  reveal system leaves unseen sections at `opacity: 0` and browsers drop background colours.
  Four gates came out of it, each proven by mutation, plus a container-query clamp on the stat
  figures so a measurement gaining a digit cannot run into its neighbour again.
- ✅ **Comparison page** (`/compare/`) — the capability table the landing page stopped carrying,
  the two sentences Anthropic's own documentation uses about its scope (quoted and dated, because
  their product changes and this page cannot), and four things SecAudit deliberately is not. Two
  cells state a figure rather than a tick, gated by `FIGURES` — a tick a reader cannot check is a
  tick this project has no business drawing. It also shipped orphaned, which is how the build
  gained a reachability walk: every check in the generator asked whether a link goes somewhere and
  none asked whether a page can be arrived at.
- ⛔ **CRA guide** (`/cra/`) — **removed 2026-08-20.** Built, shipped, then cut: the site's job is to say what the engine finds and how it was measured, and a page arguing a regulation is a second subject that a reader of a scanner did not come for. The date the duty starts is still on the landing page and still read from `compliance.py`; the evidence pack itself is unchanged and is produced by `--format cra`. Originally: the three reporting deadlines with the trigger that decides whether
  any of them run, the seven Annex I clauses, the one command, and four things the pack cannot
  establish. Dates and article number read from `compliance.py`, never typed onto the page.
- ⛔ **Documentation on the site** — **removed 2026-08-20**, along with the ~300-line markdown renderer that existed only to serve it. `docs/*.md` is read on GitHub, where it is versioned beside the code it describes, rather than at a second URL that has to be kept in step. Originally: `/docs/` plus one page per file in `docs/`, rendered by a
  ~300-line markdown renderer written rather than installed (zero runtime dependencies is a
  property of the build too). Strict on purpose: it raises on any construct it does not
  implement, because a document that renders *almost* right ships and nobody re-reads it.
- ⛔ **Demo page** (`/demo/`) — **removed 2026-08-20.** The landing page's hero already shows one finding in full, which is the same argument in the place a first-time reader actually reaches. Originally: one command against the shipped fixture, showing the output
  *this build* produced. **Not asciinema, and the reason is the reason for the rest of the
  site:** a recording is correct on the day it is made and silently wrong afterwards, it needs
  an external host and a player script, and this site's CSP is `default-src 'none'` because it
  fetches nothing from anywhere. A demo that required loosening that would be advertising a
  property the page then stopped having. The transcript is regenerated from a real Tier-0 run on
  every build, so it cannot show output the tool no longer produces.
- ⛔ **"What it is" as a separate page — closed, not deferred.** It was on this list from before
  the landing page was cut from twelve sections to eight; the landing page *is* the what-it-is
  page, and a second one would be the same content at a second URL, which is the thing the cut
  was for. Re-open only if the landing page stops answering it.
- ✅ **README v2** — done in `f52e654` and confirmed against this line on 2026-08-16 rather than
  rewritten again: it leads with the one sentence, the differentiator against the official
  plugins, the benchmark number with its caveat before it, and a 15-second install, in both
  languages. What it was missing was the *second* number — both READMEs published one external
  figure while two existed, and both now state which language each describes, with the
  SecBench.js per-class table anchored by check 35 so it cannot drift the way the first one did.
- ⛔ **Docs site content** — **removed from the site 2026-08-20**; every document still exists in `docs/`. Originally: all seventeen, at `/docs/`: getting started, source mode, live mode,
  authorization, methodology, diff mode, continuous mode, supply chain, compliance, MCP, CI,
  optional scanners, language coverage, what this misses, FAQ, launch checklist, and the
  **threat model**. The last one was the only genuinely missing item on this line and it was
  worth the delay: writing it found that evidence lines and file paths — strings the *scanned
  repository* authors — reached the terminal and the markdown report unsanitised, which the HTML
  renderer had reasoned through for itself and nobody had carried across. The security policy
  lives at `.github/SECURITY.md`, where GitHub reads it, rather than as a docs page.
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
