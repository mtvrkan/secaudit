# Getting started

## 1. Install

In a [Claude Code](https://docs.claude.com/en/docs/claude-code) session:

```
/plugin marketplace add mtvrkan/secaudit
/plugin install secaudit@secaudit-kit
```

Verify it loaded: type `/secaudit` and you should see the command with its argument hint.

## 2. Your first scan (no setup, safe)

Audit your own codebase — no tools or authorization needed:

```
/secaudit-code ./
```

Or a passive recon of a site you own (read-only, no payloads):

```
/secaudit-passive https://your-site.com
```

## 3. Go deeper (optional tools)

SecAudit works with zero tools, but installing a few unlocks deeper scanning. The core four:

```
semgrep      # SAST (code)         → pipx install semgrep
osv-scanner  # dependency CVEs     → go install github.com/google/osv-scanner/cmd/osv-scanner@latest
gitleaks     # secret detection    → brew/scoop install gitleaks
testssl.sh   # TLS posture         → git clone https://github.com/drwetter/testssl.sh
```

See [tooling-setup.md](tooling-setup.md) for all supported tools. SecAudit auto-detects and
uses whatever is on your PATH; anything missing falls back to Claude analysis.

## 4. Active testing (authorized)

To let SecAudit send probes to a live target (injection canaries, IDOR checks, etc.), you
must assert authorization:

```
/secaudit https://your-site.com --active
```

SecAudit will confirm ownership/scope first. For formal engagements, copy
[`templates/scope.example.yaml`](../templates/scope.example.yaml) to `scope.yaml` and fill
it in. See [authorization.md](authorization.md).

## 5. Read the report

You get a severity-ranked report with fixes and retest steps. See a
[sanitized example](../examples/example-report.md). Ask Claude to write it to a file or
produce a shareable summary.

## Commands

| Command | Does |
|---|---|
| `/secaudit <url\|path>` | Full audit; auto-detects target type |
| `/secaudit-code [path]` | Source-only (SAST + deps + secrets), no live requests |
| `/secaudit-passive <url>` | Recon only, zero authorization needed |
| `/secaudit-deps [path]` | Dependency + supply-chain + secret scan |

Flags: `--lang tr|en`, `--passive`, `--active`, `--code`, `--deps`.
