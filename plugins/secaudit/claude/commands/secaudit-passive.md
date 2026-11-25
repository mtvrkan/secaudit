---
description: Passive, zero-authorization-needed recon of a live URL (headers, TLS, cookies, public files, tech fingerprint, exposure checks). No payloads, no active probing.
argument-hint: "<url> [--lang tr|en]"
allowed-tools: Read, Grep, Glob, WebFetch, WebSearch, Bash(curl -sS*), Bash(curl -I*), Bash(command -v*), Bash(dig*), Bash(nslookup*), Bash(testssl.sh*), Bash(sslscan*)
---

Run the **security-audit** skill in **passive-only mode** against: `$ARGUMENTS`

Only low-impact, read-only checks a normal browser would make (≤1–3 req/s):

1. Passive recon (P1): security headers, TLS/cert posture, cookie flags, HTTP→HTTPS
   redirect, `robots.txt` / `sitemap.xml` / `.well-known/*`, error-page/stack-trace
   leakage, technology + version fingerprinting.
2. Attack-surface map (P2): public pages, auth flows, API endpoints discovered from
   HTML/JS bundles, third-party integrations — inventory only.
3. Known-vuln lookup (P3) for any fingerprinted versions (OSV/NVD/GHSA/CISA KEV).
4. Check whether well-known sensitive paths exist (`.git`, `.env`, backups, admin
   panels, debug endpoints) with read-only GETs — report exposure, never exploit.

Do NOT send any crafted payload, auth attempt, IDOR/enumeration, or fuzzing — that is
active testing and requires the authorization gate (`/secaudit --active`). Clearly
state the passive-only coverage limits in the report.
