<div align="center">

# 🛡️ SecAudit — Authorized Security Audit Kit for Claude Code

**Point Claude at a URL or a codebase. Get a prioritized, remediation-focused security report.**

Find known (CVE / dependency) **and** unknown (logic / code) vulnerabilities across the
OWASP Web, API, LLM, and Mobile Top 10 and the CWE Top 25 — using industry scanners when
you have them, and Claude's analysis when you don't.

[![Validate plugin](https://github.com/mtvrkan/secaudit/actions/workflows/validate.yml/badge.svg)](https://github.com/mtvrkan/secaudit/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Claude Code Plugin](https://img.shields.io/badge/Claude%20Code-Plugin-8A2BE2)](https://docs.claude.com/en/docs/claude-code/plugins)
[![OWASP Aligned](https://img.shields.io/badge/OWASP-Top%2010%20aligned-000000)](https://owasp.org/www-project-top-ten/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

---

> ⚠️ **Defensive use only.** SecAudit is for auditing systems **you own or are explicitly
> authorized to test**. It defaults to safe/passive checks; active testing requires you to
> assert authorization. It will never produce weaponized exploits, malware, DoS payloads,
> or unauthorized-access tooling. See [Ethics & Legal](#ethics--legal).

## Why SecAudit?

Most "security scanners" give you a wall of raw findings with no context. SecAudit uses
Claude to **triage, verify, and explain** — separating real, reachable issues from noise,
chaining findings into real-world impact, and handing your developers a concrete fix and a
retest step for each one.

- 🎯 **Two modes, one command** — audit a **live URL** or a **source-code repo** (or both,
  and cross-reference them).
- 🔍 **Known + unknown vulns** — dependency/CVE scanning *and* logic/code analysis. Not
  just `npm audit`; actual OWASP-methodology testing.
- 🔗 **Reachability, not just pattern matching** — a built-in taint engine traces untrusted
  input from source to sink across lines, so `db.query(sql)` is only reported when `sql` was
  actually built from `req.query.name` — and *not* when the value is bound as a query
  parameter. Every such finding ships the path you can follow and refute:
  `L12: req.query.name (request) → L13: TAINT-JS-SQLI argument 0`.
- 📦 **Dependency advisories get a verdict, not a dump** — every CVE is classified by import
  reachability into an [OpenVEX](https://github.com/openvex/spec) status (`affected` /
  `not_affected` / `under_investigation`) with the evidence for the call. A package your code
  never loads drops two severity rungs and says why; a transitive one stays
  `under_investigation` rather than becoming a false all-clear. Nothing is deleted — a
  filtered register is not evidence. `--format openvex` emits the machine-readable document
  the [EU CRA](https://openssf.org/category/policy/cra/) reporting duty asks for.
- 🇪🇺 **EU Cyber Resilience Act evidence, from the same scan** — `--format cra` emits a
  CycloneDX 1.6 SBOM, a vulnerability register with VEX status and reachability, and each
  finding mapped to the clause it bears on (Annex I Part I (2)(a), Part II (1)/(2)/(3)).
  Vulnerability-handling obligations apply from **2026-09-11**. Findings also carry an
  **OWASP ASVS 5.0** chapter. It is input to a compliance process, not a certificate, and the
  pack says so in its own disclaimer.
- 🧰 **Hybrid engine** — auto-uses `semgrep`/`opengrep`, `trivy`, `osv-scanner`, `gitleaks`,
  `trufflehog`, `zizmor`, `testssl.sh` if installed (plus authorized-only `nuclei`/ZAP for active
  scans); falls back to Claude analysis if not. **Zero tools required to start.**
- 🧠 **Verified, not noisy** — an adversarial verifier agent tries to *refute* each
  high/critical finding before it reaches your report.
- 🌐 **OWASP Web + API + LLM + Mobile Top 10, CWE Top 25** — plus the 2025–2026 additions most
  scanners miss: **agentic-AI + MCP** risks (tool poisoning, excessive agency), **auth/identity**
  (JWT/OAuth/OIDC/SAML), **HTTP request smuggling**, **cache poisoning**, and current
  **supply-chain** attacks (self-replicating install-script worms, mutable-tag CI compromise,
  slopsquatting, provenance/SLSA).
- 📄 **Report you can act on** — severity-ranked findings, dependency/CVE register,
  positive controls, and a 24–72h / 7–14d / 30–60d remediation roadmap. English or Turkish.
- 🔒 **Safe by default** — passive recon needs no authorization; active testing is gated by a
  deterministic **PreToolUse hook** (not just model discipline) that blocks offensive scanners
  and state-changing requests until you assert authorization; no DoS, no brute-force, no data
  exfiltration, ever.

## How this differs from Claude Code's built-in security tools

Anthropic ships two official security plugins and they are good. **Install them.**
[`security-guidance`](https://code.claude.com/docs/en/security-guidance) reviews code as Claude
writes it; the [Claude Security plugin](https://code.claude.com/docs/en/claude-security) runs a
multi-agent scan of a repository and produces reviewed patches. Both read the source in your
checkout.

SecAudit is not trying to be better at that. It covers what those deliberately leave out:

| | Official plugins | SecAudit |
|---|---|---|
| Reviews code as Claude writes it | ✅ | — |
| Multi-agent repo scan → reviewed patches | ✅ | — |
| **Audit a running site or API** | — | ✅ |
| **Authorization gate + `scope.yaml` for active testing** | — | ✅ |
| **Runs without Claude Code, without a paid plan, offline** | — | ✅ |
| **Published, reproducible detection score** | — | ✅ |
| **SBOM, OpenVEX and EU CRA evidence pack** | — | ✅ |
| **Same engine from Codex, Cursor, OpenCode (MCP server)** | — | ✅ |

The official docs are explicit that their review *"reads the source code in your checkout, not
a running site or deployed service"*, and that scans are nondeterministic — *"two scans of the
same code can surface different findings"*. Neither plugin models an authorization boundary for
testing a target you must prove you own, and neither produces an artefact for an auditor.

Run them together: the in-session plugin reduces what reaches your branch, and SecAudit answers
the question you get asked afterwards.

## Install

**Requires [Claude Code](https://docs.claude.com/en/docs/claude-code).** In a Claude Code session:

```
/plugin marketplace add mtvrkan/secaudit
/plugin install secaudit@secaudit-kit
```

That's it. No tools to install to get started — SecAudit works with just Claude. For deeper
scans, optionally install the [recommended tools](docs/tooling-setup.md) (`semgrep`,
`osv-scanner`, `gitleaks`, `testssl.sh`).

<details>
<summary>Manual install (without the marketplace)</summary>

```bash
git clone https://github.com/mtvrkan/secaudit
cp -r secaudit/plugins/secaudit/skills/*   ~/.claude/skills/
cp -r secaudit/plugins/secaudit/commands/* ~/.claude/commands/
cp -r secaudit/plugins/secaudit/agents/*   ~/.claude/agents/
```

> ⚠️ Manual install copies the skill, commands, and agent — but **not** the PreToolUse
> `hooks/`, which the marketplace install wires automatically. Without the hook, the
> passive/active authorization gate falls back to model discipline only (the deterministic,
> harness-level block on active scanners and probe payloads is not active). To keep it, also
> register `plugins/secaudit/hooks/active-scan-guard.py` as a PreToolUse hook — see
> [`hooks/README.md`](plugins/secaudit/hooks/README.md).
</details>

## Usage

```bash
/secaudit https://your-site.com        # full audit of a live target (passive by default)
/secaudit ./path/to/your/repo          # static source-code + dependency + secret audit
/secaudit https://site.com ./repo      # both — code confirms live findings and vice-versa

/secaudit-code                         # source-only audit of the current directory
/secaudit-passive https://site.com     # recon only, zero authorization needed
/secaudit-deps                         # dependency + supply-chain + secret scan only

/secaudit https://site.com --active    # authorized active testing (you assert ownership)
/secaudit ./repo --lang tr             # report in Turkish
```

For active testing against a live target, fill in
[`templates/scope.example.yaml`](templates/scope.example.yaml) or assert authorization in
chat. See [Authorization](docs/authorization.md).

## Run it without Claude Code (standalone kit)

The [`kit/`](kit) directory is a dependency-free Python CLI that runs **outside** a Claude Code
session — in CI, cron, or a plain shell — and is **not tied to Claude**:

```bash
python -m secaudit_core.cli /path/to/repo --min high        # Tier 0: deterministic, no LLM, no key
python -m secaudit_core.cli /path/to/repo --format cra      # EU CRA evidence pack (SBOM + register + VEX)
python -m secaudit_core.cli /path/to/repo --format cyclonedx # CycloneDX 1.6 SBOM only
python -m secaudit_core.cli /path/to/repo --format html     # self-contained report; print to PDF
python -m secaudit_core.cli /path/to/repo --backend ollama  # optional local-model enrichment
ANTHROPIC_API_KEY=… python -m secaudit_core.cli /path/to/repo --backend anthropic   # or Claude/OpenAI
```

**Tier 0** (built-in detector pack + taint analysis + `npm audit`) always runs and is
reproducible; **Tier 1** optionally adds LLM triage + logic-bug discovery with a pluggable
backend (`anthropic` / `openai` / `ollama` / `none`).

> 🔐 **Tier 1 sends your source code.** It reads the excerpts around every Tier-0 finding *and*
> whole files Tier 0 never flagged — that second part is the only way a model can report the
> classes the pattern tier structurally cannot (missing ownership checks, unauthenticated
> endpoints), and it is why `--backend ollama` (a local model, nothing leaves the machine) is a
> different decision rather than a cheaper one. Files matching credential patterns (`.env`,
> `*.pem`, `*.key`, `secrets/`, …) are withheld from every backend. Each scan is capped at four
> model calls, and when a repository does not fit, the report says how many files were not sent
> — a triage over a partial view is never printed as a clean bill.

What the LLM-free tier actually measures
on the shipped corpora is in the generated [scorecard](eval/scorecard.md) — reproduced below,
and regenerated by CI rather than restated here.

### Measured, by a harness you can run

| Metric | Tier 0, no LLM, no external scanners |
|---|---|
| Recall | **98%** (61/62 labelled vulnerabilities, 15 languages) |
| Precision | **100%** (upper bound — see the scoring rules) |
| F1 · F3 | **0.992** · **0.986** |
| False positives on safe-implementation traps | **0** / 62 |

```bash
python3 eval/harness.py        # reproduce it
```

The one miss is IDOR / broken access control, which has no reliable static signature and is
documented as belonging to the LLM tier. Labels are **generated** from the fixtures, floors
live in [`eval/thresholds.json`](eval/thresholds.json), and CI fails if the committed
[scorecard](eval/scorecard.md) stops matching what the engine measures.

**This is a regression floor, not a forecast.** These fixtures were written alongside the
detectors, so the number says "this still works", not "this will work on your code".

### The external number: F3 31.5

Measured on the [RealVuln benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark) — 66 real
vulnerable repositories labelled by people who have never seen this code, scored by their scorer,
not ours.

| | F3 | Precision | Recall |
|---|---|---|---|
| Purpose-built (Kolega.Dev) | 73.0 | 0.388 | 0.809 |
| General-purpose LLM (Claude Sonnet 4.6) | 51.7 | 0.785 | 0.498 |
| Rule-based SAST (Semgrep) | 17.7 | 0.205 | 0.175 |
| **SecAudit Tier 0** | **31.5** | **0.542** | **0.301** |

**Read the caveat before the number.** The first two runs scored 12.5 and 13.3 and were blind —
the engine had never seen this corpus. 24.6, 26.0, 30.9 and 31.5 are not: the rules added since
were chosen by reading this benchmark's own false negatives. Every one of them is a rule any SAST
ships (weak PRNG for tokens, cookie flags, CSRF exemptions, a committed fallback signing key,
debug-on-by-default, open redirect, NoSQL injection, credentials in logs, catastrophic
backtracking), so none is a pattern fitted to a fixture — but the *selection* was informed by
the corpus, which is the same disclosure `eval/scorecard.md` has always carried about the
fixture set. 12.5 is what this engine did on a corpus it had not read; 31.5 is what it does on
one it has read repeatedly, and the gap between those two numbers is the size of the advantage.

What moved in the latest round: nothing was added. A rule was **narrowed**, and it was found by
covering the branches that suppress a finding rather than the ones that raise one. The
rate-limit rule treated any mention of a limiter *anywhere in a file* as protection, so one
`@limiter.limit` on `/login` silenced an unlimited `/admin-login` beside it, and a handler that
carefully logged every failed password silenced itself — recording an attempt read as bounding
one. Module-level now means module-level, and an attempt count counts as a limit only where
something is actually compared against it: **+10 true positives for +6 false positives**,
F3 30.9 → 31.5. Before that, missing rate limiting 0 → 85 at 0.842 precision, unrestricted
upload 0 → 8, and `denial_of_service` 0 → 16 of 44 from a ReDoS analysis with **zero** false
positives. **Precision rose with recall for the fourth consecutive round**
(0.504 → 0.511 → 0.540 → 0.542), which is the reason to read these as rules rather than as
curve-fitting.

What still does not move: `broken_access_control` (1/76), `missing_auth` (4/74) and
`path_traversal` (3/39). Reading the misses in the two largest remaining pools —
`sensitive_data_exposure` and `security_misconfiguration` — shows why: most of those labels sit
on a handler definition, so the flaw is a property of everything the handler returns rather than
of anything inside it. That needs the business-logic pass, not another rule, and the full
accounting is in [`eval/realvuln/`](eval/realvuln).

**The LLM tier has no measured number.** Every figure above is Tier 0. The enrichment tier —
triage, verification, the logic bugs the deterministic tier cannot reach — is the headline claim
of this kit and it is unmeasured, which is a gap and is named here as one. The harness that would
measure it ships in [`eval/realvuln/`](eval/realvuln) and runs in one command; it has not been
run, because no key was available and a number nobody can re-query is worse than an admitted gap.

**And until 2026-08-13 the gap was worse than "unmeasured": the tier could not have earned a
number.** Its prompt carried only Tier-0's own findings — a detector id, a file, a line and one
line of evidence — and no source. So triage was judging a citation rather than the code, and
logic-bug discovery, which is the part that reaches `broken_access_control` and `missing_auth`,
was asking a model to find flaws in handlers it had never been shown. The finding-list payload is
now a source payload; what that changed is described above, and what it is worth is still
unmeasured. This is recorded rather than quietly fixed because the claim was public for a month
and the measurement that would have caught it is the one this section says has not been run.

Full result — per-family, per-repo, all six runs, what could not be cloned and why —
[`eval/realvuln/`](eval/realvuln). The raw scorer output is committed and CI fails if these
figures stop matching it. Two numbers, both true: 0.986 is what the engine still does on the
corpus it was built against, 31.5 is what it does on 62 real repositories.

## What you get

A structured report: executive summary → scope & constraints → methodology → severity-ranked
findings (each with impact, evidence, root cause, **specific fix**, and a **retest step**) →
dependency/CVE register → positive controls you already have → a prioritized remediation
roadmap. See a [sanitized example report](examples/example-report.md).

> 🧪 **Tested on itself — recall *and* precision.** SecAudit ships two paired fixtures. The
> **vulnerable** one plants **62 code flaws** across **15 languages** (SQLi, command
> injection, SSRF, insecure deserialization, SSTI, broken-JWT, IDOR, path traversal, mass
> assignment, prototype pollution, XSS, CORS, open redirect, weak crypto, hardcoded creds,
> container misconfig, XXE, disabled TLS verification, unsafe Rust, over-broad IAM, privileged
> containers, agent tools with a shell, mutable CI action refs) + 10 dependency vulns + secrets — the
> committed [self-test report](examples/self-test-report.md) is a captured fallback-mode run
> (no scanners installed) that surfaces them all (**recall**). The **secure** fixture
> ([`secure-app`](tests/fixtures/secure-app)) implements the *same* features safely — 62
> traps, each a safe implementation of the same feature as its vulnerable twin; a correct
> audit stays quiet on it (**precision** — no crying wolf). CI gates both: `selftest.py` asserts
> every planted sink is still present *and* that the secure fixture hasn't drifted (no sink
> reappears, every control stays), and `grade-report.py` fails if the reference report drops any
> finding. See the [golden set](tests/expected-findings.md) and the
> [negative control](tests/expected-clean.md). Detection quality on your own code depends on the
> model at run time; these fixtures make it **measurable**, and every report states its own limitations.

## How it works

```
Target ──▶ Detect type (URL / source / both) & available tools
       ──▶ Authorization gate  (passive = free · active = must assert ownership)
       ──▶ Phased methodology:
             P1 Passive recon      P4 OWASP web tests    P7 Infra / cloud / IaC
             P2 Attack surface     P5 API tests          P8 Mobile (if app)
             P3 Known CVEs/deps    P6 Source review      P9 AI/LLM security (if AI)
       ──▶ Verify each finding (adversarial refutation of highs/criticals)
       ──▶ Prioritize (CISA KEV → exposure → impact)
       ──▶ Report (EN/TR) with fixes + retest checklist
```

Full methodology: [docs/methodology.md](docs/methodology.md).

## Features at a glance

| | |
|---|---|
| **Live URL audit** | headers, TLS, cookies, exposure, tech fingerprint, OWASP web/API tests |
| **Source audit (SAST)** | source→sink taint paths (Python AST + JS/TS scanner), authz gaps, injection, SSTI, deserialization, secrets, weak crypto |
| **Auth & identity** | JWT (alg confusion, `alg:none`), OAuth/OIDC (`redirect_uri`, PKCE, `state`), SAML (XSW), sessions, MFA, passkeys |
| **Modern web** | HTTP request smuggling/desync, cache poisoning/deception, prototype pollution, DOM clobbering, CSWSH, CSPT |
| **Dependency / supply chain** | multi-ecosystem CVEs with **OpenVEX reachability verdicts**, slopsquatting, install-script worms, mutable-tag CI compromise, provenance/SLSA, KEV cross-ref |
| **Secret detection** | code + git history; masked reporting, rotation guidance |
| **Infra / IaC / CI/CD** | Dockerfile, Terraform, CloudFormation, K8s, Compose, cloud IAM, GitHub Actions (`zizmor`, SHA-pinning) |
| **AI / LLM / agents** | prompt injection (direct + indirect/RAG/multimodal), output → XSS, excessive agency, MCP tool poisoning, agentic threats, cost limits |
| **Mobile** | Android / iOS / Flutter — MASVS / Mobile Top 10 |

## Ethics & Legal

SecAudit is a **defensive** tool. By using it you agree to test only assets you own or are
explicitly authorized to test. Unauthorized scanning or testing of systems is illegal in
most jurisdictions. The maintainers accept no liability for misuse. Read the full
[DISCLAIMER](DISCLAIMER.md) and [SECURITY.md](.github/SECURITY.md).

It will refuse to: run DoS/brute-force, exfiltrate real data/PII, exploit beyond minimal
proof, or produce weaponized exploit code, malware, or detection-evasion tooling.

## Use it from Codex, Cursor, OpenCode or any MCP client

Claude Code gets SecAudit as a plugin. Everything else gets the same engine over MCP:

```bash
python3 -m secaudit_mcp --tools        # verify the server, print its tool manifest
claude mcp add secaudit -- python3 -m secaudit_mcp
```

Six tools: `scan_source`, `scan_dependencies`, `generate_sbom`, `compliance_pack`,
`explain_finding` — and `coverage`, which is a tool rather than a doc page on purpose. An MCP
client that gets findings but cannot ask for the bounds will summarise an empty result as "no
security issues found", which is a claim the engine never made. Live-target scanning is
deliberately **not** exposed: consent to probe a running system is a human decision, and the
test suite asserts no tool schema accepts a `url`, `host` or `endpoint`. (The dependency tools
do reach the network to look advisories up by package name — a query about a package, not a
request aimed at a host.) Per-client config:
[docs/mcp.md](docs/mcp.md).

## Documentation

- 🌐 **[secaudit.mtvrkan.com](https://secaudit.mtvrkan.com)** — landing page (EN / TR)
- **[What we miss](docs/what-we-miss.md)** — the false negatives, generated from the engine
  itself. Read this before treating a clean report as an all-clear.
- **[Language coverage](docs/language-coverage.md)** — analysis depth per language, derived
  from the dispatch tables rather than typed.
- **[Report languages](kit/secaudit_core/locales/)** — `--lang tr`. Report chrome is translated; finding titles
  and fix instructions stay in English, and a translated report says why.
- **[Running in CI](docs/ci.md)** — GitHub Action, pip, Docker and pre-commit, with the exit
  codes and what a green build does and does not mean.
- **[Semgrep rules](rules/secaudit/README.md)** — 43 of the 85 detectors as a Semgrep pack, and
  the published list of which 42 are withheld because a regex rule cannot reproduce them.
- **[Diff mode](docs/diff-mode.md)** — `--since <ref>`: gate a pull request on what it
  introduced, not on the debt it inherited.
- [Getting started](docs/getting-started.md) · [Authorization & scope](docs/authorization.md)
- [Live URL mode](docs/live-url-mode.md) · [Source-code mode](docs/source-code-mode.md) ·
  [MCP server](docs/mcp.md)
- [Tooling setup](docs/tooling-setup.md) · [Methodology](docs/methodology.md) · [FAQ](docs/faq.md)

## Contributing

New checks, tool integrations, language coverage, and false-positive fixes are very welcome.
See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

[MIT](LICENSE) © mtvrkan

<div align="center">
<sub>Built for <a href="https://docs.claude.com/en/docs/claude-code">Claude Code</a>. Not affiliated with Anthropic or OWASP. If SecAudit helped secure your product, please ⭐ the repo.</sub>
</div>
