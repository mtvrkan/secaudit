# Live URL mode

Audit a deployed web app / API. Passive by default; active testing is gated.

```
/secaudit https://your-site.com            # passive recon + known-CVE + surface map
/secaudit https://your-site.com --active   # + authorized OWASP web/API tests
/secaudit-passive https://your-site.com    # passive only, never probes
```

## What runs

**Passive (always):**
- **P1 Passive recon** — security headers, TLS/cert posture, cookie flags, HTTP→HTTPS
  redirect, `robots.txt`/`sitemap.xml`/`.well-known`, error-page leakage, technology +
  version fingerprinting, exposure checks (`.git`, `.env`, backups, admin, debug).
- **P2 Attack-surface map** — routes, auth flows, API endpoints (from JS bundles), third
  parties, input points.
- **P3 Known vulns** — looks up fingerprinted versions on OSV/NVD/GHSA/CISA KEV.

**Active (with authorization):**
- **P4 OWASP web tests** — access control (IDOR/BOLA, vertical/horizontal), auth/session,
  injection, XSS, CSRF/CORS, file upload, SSRF/open-redirect, misconfig, crypto, business
  logic.
- **P5 API tests** — the OWASP API Top 10 (BOLA, mass assignment, BFLA, etc.).
- **P7 Infra** — TLS/DNS/exposure for in-scope infra.

## Best results

- Provide **two test accounts** for horizontal-authz (IDOR/BOLA) testing.
- Provide the **source code** too (`/secaudit https://site.com ./repo`) — SecAudit
  cross-references, so live findings get confirmed in code and vice-versa.
- Point out excluded flows (payments, deletion, email/SMS) up front.

## Safety

Read-only and rate-limited by default; DoS, brute-force, and data exfiltration never
happen. Passive-only coverage limits are stated clearly in the report. See
[authorization.md](authorization.md).
