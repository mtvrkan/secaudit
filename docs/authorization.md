# Authorization & scope

SecAudit is safe by default and gates anything that could affect a live target. This page
explains the two impact tiers and how to authorize active testing.

## The two tiers

**Passive / no authorization needed** — run freely:
- Reading and analyzing source code, manifests, configs, and IaC you give it.
- Dependency / SBOM / secret / SAST scans of local files.
- For a live URL: fetching pages a normal browser would (`GET /`, `robots.txt`,
  `sitemap.xml`, `.well-known/*`), reading response headers, TLS inspection, technology
  fingerprinting, and checking whether well-known sensitive paths exist — read-only, no
  payloads, ≤1–3 req/s.

**Active / authorization required** — gated:
- Any crafted/probe payload (injection canaries, auth-bypass attempts, IDOR enumeration,
  SSRF probes, fuzzing), authenticated testing, forced-browsing sweeps, or non-`GET`/`HEAD`
  requests that change state.

## How to authorize

Either:
- Add `--active` and confirm ownership when SecAudit asks, **or**
- Copy [`templates/scope.example.yaml`](../templates/scope.example.yaml) to `scope.yaml`,
  fill it in (set `i_am_authorized: true`), and point SecAudit at it. This is best for
  formal engagements — it records owner, approval, in-scope domains, test accounts,
  excluded paths, and rate limits.

`scope.yaml` is gitignored — don't commit a filled-in copy.

## Absolute limits (never crossed, even when authorized)

- No DoS / stress / high-volume fuzzing / resource exhaustion.
- No password/OTP/token brute-force; lockouts and rate limits respected.
- No exfiltration or display of real user data / PII / secrets — masked; canary for proof.
- No exploitation beyond minimum safe proof; no persistence, lateral movement, or privilege
  escalation beyond approved test roles; no third-party systems.
- Only in-scope assets; stop on instability.
- Never produces weaponized exploits, malware, or detection-evasion tooling.

## Legal

Testing systems you don't own or aren't authorized to test is illegal in most
jurisdictions. You are responsible for your authorization. Read the [DISCLAIMER](../DISCLAIMER.md).
