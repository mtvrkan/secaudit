# P1 — Passive reconnaissance (live target)

Low-impact, read-only checks a normal browser would make. No payloads. Rate ≤1–3 req/s,
`--max-time`. Requires no authorization beyond the target being publicly reachable.

## Headers & redirect

```bash
# Full headers, follow redirects, timeout
curl -sS -D - -o /dev/null -L --max-time 25 https://TARGET/
# HTTP→HTTPS behavior (want 301 + HSTS on the redirect too)
curl -sS -D - -o /dev/null --max-time 20 http://TARGET/
```

Check for and grade each **security header**:

| Header | Want | Missing → |
|---|---|---|
| `Strict-Transport-Security` | `max-age≥31536000; includeSubDomains` (+`preload` if ready) | SSL-strip/MITM window · CWE-319 |
| `Content-Security-Policy` | scoped `default-src`, no `unsafe-inline` script | weak XSS defense-in-depth · CWE-693 |
| `X-Frame-Options`/CSP `frame-ancestors` | `DENY`/`'none'` on sensitive pages | clickjacking · CWE-1021 |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | referrer leakage |
| `Permissions-Policy` | lock camera/mic/geo | feature abuse |
| `Cache-Control` (sensitive pages) | `no-store` | sensitive data cached |
| `X-Powered-By`/`Server` | absent / no version | version disclosure · CWE-200 |

Note **duplicated/conflicting** headers (e.g. proxy + app both set `X-Frame-Options`
with different values) — real-world finding.

**Grade CSP strength, not just presence.** A header that reflects into the page is worth
little if it's bypassable. Flag: `unsafe-inline`/`unsafe-eval` in `script-src`; a wildcard
`*` or `https:` source; a permissive host allowlist that includes a JSONP-capable or
user-content CDN (a known CSP-bypass vector); and **missing `object-src 'none'` and
`base-uri 'none'`** (dangling-markup / base-tag injection). `report-uri`/`report-to` without
enforcement is monitor-only. Prefer nonce/hash-based CSP with `strict-dynamic`.

## Cookies

Inspect every `Set-Cookie`. Session cookies must have `Secure`, `HttpOnly`, and an
appropriate `SameSite` (`Lax`/`Strict`). Missing `HttpOnly` + any XSS = session theft
(CWE-1004/614). Check for session rotation after login (needs auth — flag for P4).

## TLS

```bash
# Quick verification
curl -sS -o /dev/null -w "verify=%{ssl_verify_result} http=%{http_version}\n" --max-time 20 https://TARGET/
# Deep (if installed): protocols, ciphers, cert chain, known TLS vulns
testssl.sh --quiet --jsonfile tls.json TARGET
# or: sslscan TARGET   |   nmap --script ssl-enum-ciphers -p 443 TARGET
```

Flag: expired/mismatched cert, TLS 1.0/1.1 enabled, weak ciphers, no OCSP stapling.

## Public files & exposure (read-only existence checks)

Check whether these **exist** (status code), never exploit contents:

```
robots.txt  sitemap.xml  /.well-known/security.txt  /.well-known/*
/.env  /.env.bak  /.env.production  /.git/config  /.git/HEAD  /.svn/
/config.php  /wp-config.php  /appsettings.json  /application.properties
/backup.zip  /backup.sql  /db.sql  /dump.sql  /database.sql
/composer.json  /package.json  /composer.lock  /yarn.lock
/phpinfo.php  /info.php  /test.php  /debug  /server-status  /actuator
/swagger  /swagger.json  /openapi.json  /api-docs  /graphql
/.DS_Store  *.map (source maps)
```

**Crucial:** on SPAs a catch-all often returns the app `index.html` (HTTP 200) for
missing files — that is NOT exposure. Confirm real exposure by checking content-type
and body (a real `.env`/`.git/config` has recognizable content; a 200 HTML fallback of
the same byte-size for every path is the SPA router). The example reports do this well.

## Email & DNS hygiene (passive DNS lookups)

Spoofing/phishing exposure is read-only DNS — no authorization needed. Check the apex
and mail domains:

```bash
dig +short TXT TARGET                 # SPF (v=spf1 …) and other TXT
dig +short TXT _dmarc.TARGET          # DMARC policy
dig +short TXT default._domainkey.TARGET   # DKIM (selector varies)
dig +short CAA TARGET                  # who may issue certs
```

Flag:
- **No SPF**, or SPF ending `~all`/`+all` instead of `-all` (soft/no fail → spoofable).
- **No DMARC**, or `p=none` (monitor-only, doesn't block spoofed mail). Want `p=quarantine`
  or `p=reject` with `rua` reporting.
- **Missing DKIM** on a domain that sends mail.
- **No CAA record** (any CA may issue certs for the domain).
- **Dangling DNS** (CNAME → a de-provisioned cloud resource) → subdomain takeover; see
  `infra-cloud.md`.

## Error pages & tech fingerprint

- Request a nonexistent path; a verbose framework 404 (`Cannot GET /x` = Express) or a
  stack trace leaks stack/version info (CWE-200).
- Fingerprint from `Server`, `X-Powered-By`, cookie names (`PHPSESSID`, `JSESSIONID`,
  `connect.sid`, `laravel_session`), HTML meta/generator, JS bundle names
  (`vue-*`, `react-*`, `/_next/`, `index-*.js` = Vite), CDN/WAF headers (`CF-*`,
  `X-Amz-*`, `X-Vercel-*`). Record versions where visible → feed P3.
- *(Active — authorization required, NOT passive recon.)* `nuclei -t http/technologies`
  can automate fingerprinting, but even "info" templates fire many crafted probes beyond
  what a normal browser sends. Run it only after the authorization gate (see `tooling.md`).

## Deliverable

A tech-fingerprint table + headers/cookies/TLS grade + exposure results + discovered
routes/endpoints (feeds P2/P3). Mark clearly what is passive-only and cannot be
confirmed without accounts/source.
