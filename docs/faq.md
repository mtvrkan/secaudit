# FAQ

**Is this a replacement for a professional pentest?**
No. SecAudit is a fast, thorough, best-effort assistant that catches a large class of
issues and explains fixes. For high-risk systems (finance, health, critical infra),
complement it with professional manual testing. A clean SecAudit report is not a security
certification.

**Do I need to install semgrep/trivy/etc.?**
No. SecAudit works with zero tools using Claude's analysis + `curl`. Tools add depth and
are auto-used when present. See [tooling-setup.md](tooling-setup.md).

**Can I scan any website?**
Only sites you own or are explicitly authorized to test. Passive recon is low-impact, but
active testing (probes/payloads) is gated behind an authorization step and is illegal
against systems you don't control. See [authorization.md](authorization.md) and
[DISCLAIMER](../DISCLAIMER.md).

**Will it break my production site?**
No. It's read-only and rate-limited by default; it never runs DoS, brute-force, or
destructive actions, and it stops on instability. Active testing uses harmless canaries and
your own test records only.

**Does it send my source code anywhere?**
It depends on which way you run it, and the three answers are genuinely different:

| How you run it | What leaves your machine |
|---|---|
| Claude Code plugin | Your code is processed by Claude per your Claude Code setup. |
| `secaudit_core.cli` with no `--backend` (Tier 0, the default) | **Nothing.** No network call is made about your code at all. |
| `--backend ollama` | **Nothing.** The model runs locally on `localhost:11434`. |
| `--backend anthropic` / `--backend openai` | **Your source code**, to that provider's API. |

The last row is deliberate and it is what Tier 1 is: a model cannot triage a finding or spot a
missing ownership check in code it has not been shown. It receives the excerpts around each
Tier-0 finding plus whole files Tier 0 never flagged, capped at four calls per scan. Files
matching credential patterns — `.env*`, `*.pem`, `*.key`, `*.p12`, `id_rsa`, `secrets/`,
`*.tfstate` and the rest of the list in `secaudit_core/llmcontext.py` — are withheld from every
backend, the local one included, and the report says how many were withheld.

The dependency tools do reach the network without a backend, but they send package *names* to
an advisory database, never your code. External scanners (semgrep/trivy/etc.) run locally.
SecAudit adds no telemetry in any mode.

**How does it handle secrets it finds?**
It never prints secret values — only the type, `file:line`, and a masked prefix — and
recommends rotation + moving to a secret manager + purging from git history.

**What languages/stacks are supported?**
Source review covers JS/TS, Python, Go, Rust, PHP, Ruby, Java, C#, plus IaC (Docker,
Terraform, K8s, Compose), mobile (Android/iOS/Flutter), and AI/LLM apps. Dependency
scanning covers all major package ecosystems.

**English or Turkish reports?**
Both. Reports match your language by default; force with `--lang en` or `--lang tr`.
Technical IDs (CWE/CVE/OWASP) stay canonical.

**How is this different from `npm audit` / a single scanner?**
Those find *known* dependency CVEs only. SecAudit adds the *unknown* class — logic flaws,
missing authorization, injection, XSS, secrets, misconfig — via OWASP-methodology testing
and code analysis, then triages and explains everything with fixes.

**Why did a finding say "PLAUSIBLE" instead of "CONFIRMED"?**
It was found by code review but not live-triggered (e.g. a paid endpoint, or no test
account). SecAudit is honest about what it verified vs inferred.

**Can I add my own checks?**
Yes — see [CONTRIBUTING.md](../CONTRIBUTING.md). New checks, tools, and language coverage
are welcome.
