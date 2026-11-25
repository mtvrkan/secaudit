# Authentication & identity — OAuth 2.0 / OIDC / SAML / JWT / sessions / MFA

Cross-cutting reference (not a numbered phase). Load whenever the target uses federated login,
social login, SSO, token-based sessions, or its own auth. Broken auth/authz is consistently the
highest-impact real-world class. Code review is always safe; live tests are ACTIVE (gate first,
approved test accounts only, never brute-force).

## JWT / token attacks (CWE-347/345)

- **`alg:none`** — server accepts an unsigned token. Must reject.
- **Algorithm confusion (RS256→HS256)** — server verifies an attacker-forged token using the
  **public** key as an HMAC secret. Fix: pin the expected algorithm; never let the token's `alg`
  header choose the verification method.
- **Header injection — `jku` / `jwk` / `kid` / `x5u`** — attacker points key resolution at their
  own key, or `kid` path-traverses / SQL-injects into key lookup. Fix: allowlist `jku`/`x5u`
  hosts, ignore embedded `jwk`, treat `kid` as untrusted.
- **Weak HMAC secret** — brute-forceable `HS256` secret (do NOT brute-force live; flag for
  offline review / rotate to a strong random key or asymmetric).
- **Missing claim validation** — no `exp`/`nbf` expiry, no `aud`/`iss` binding, no `jti`
  replay protection. Confirm all are validated server-side.
- **Storage** — tokens in `localStorage` are XSS-stealable; prefer `HttpOnly` cookies +
  anti-CSRF. Long-lived access tokens with no revocation is a finding.

## OAuth 2.0 / OIDC (CWE-601/352/287)

- **`redirect_uri` validation** — must be an **exact allowlist** match. Loose matching (prefix,
  substring, open subdomain, path-appended) → token/code theft via open redirect. Test benign:
  does an unregistered/mutated `redirect_uri` get accepted?
- **`state` parameter** — required, unguessable, single-use → CSRF on the callback. Missing/
  unchecked `state` is a finding.
- **PKCE** — public/mobile/SPA clients must use PKCE (`S256`, not `plain`); confirm the server
  enforces the `code_verifier`. Downgrade to `plain` or no-PKCE is a finding.
- **Implicit flow / tokens in URL fragment** — deprecated; access tokens leak via Referer/history.
  Prefer auth-code + PKCE.
- **Authorization-code injection / mix-up** — code bound to the wrong client; confirm code is
  one-time and client-bound.
- **Scope & consent** — over-broad scopes, scope not enforced server-side, silent re-consent.
- **Confused deputy** — the app trusts an ID token/userinfo without validating `aud`/`iss` and
  signature → account takeover across clients.
- **Token leakage** — tokens in logs, Referer headers, browser history, or error pages.

## SAML (CWE-347)

- **Signature wrapping (XSW)** — attacker adds a second (unsigned) assertion the app processes
  while signature validation checks the original. Fix: validate the signature covers the exact
  processed assertion; use a hardened library; reject multiple assertions.
- **Unsigned / partially-signed assertions** — require the whole assertion (and response) be
  signed; reject unsigned.
- **Comment-truncation / canonicalization** — `user@evil.com<!---->.com` parsing differences →
  identity spoofing. Fix: current library, strict XML canonicalization, no comment splitting.
- **Missing recipient/audience/`NotOnOrAfter`** — replay and cross-app reuse. Validate all.
- **XXE in the SAML parser** — disable external entities (ties to `code-review.md`).

## Sessions & cookies

- Session ID **regenerated on login** (no fixation) and **invalidated server-side on logout**.
- Cookie flags: `Secure`, `HttpOnly`, appropriate `SameSite` (`Lax`/`Strict`) — see
  `passive-recon.md`. Absolute + idle timeouts. No sensitive data in the token/cookie body.
- Concurrent-session / device-revocation controls for sensitive apps.

## Passwords, MFA & recovery (CWE-287/307/640)

- Password hashing: **argon2id** (or bcrypt/scrypt) with per-user salt — never MD5/SHA1/SHA256
  raw (see `code-review.md`).
- Rate-limit / lockout on login, MFA, and reset — observe behavior with 1–2 attempts, never
  brute-force.
- **Account enumeration** — login/reset/registration must return one generic message.
- Password reset: high-entropy, single-use, short-TTL token bound to the user; no host-header
  poisoning of the reset link (`X-Forwarded-Host` → attacker-controlled reset URL).
- **MFA** — enforced (not just enrolled), not bypassable via a parallel endpoint, remember-device
  scoped, backup codes single-use. Prefer **passkeys / WebAuthn** (phishing-resistant); verify
  the RP ID / origin binding and that a password fallback doesn't defeat the passkey.

## Deliverable

Findings mapped to CWE + OWASP A01/A07 (+ API1/API2/API5 for API auth), each with the exact
token/flow/`file:line`, a safe repro, and the specific fix (pin `alg`, exact-match
`redirect_uri`, enforce PKCE + `state`, sign the whole SAML assertion, argon2id, generic errors).
Mark live-verified vs code-review-only.
