# P4 — OWASP web application testing (ACTIVE — authorization required)

Safe tests for each class. Harmless canaries, approved test accounts, minimal proof. No
destructive payloads, no data extraction, no brute-force. Gate first (`SKILL.md` §1).

## 4.1 Access control (A01) — the #1 real-world risk

- **Horizontal (IDOR/BOLA):** user A cannot reach user B's resources. Test with numeric
  IDs, UUIDs, slugs, filenames, invoice/order/profile IDs. **Use two approved test
  accounts**; access only records you created for the audit.
- **Vertical:** low-priv user cannot reach admin functions/routes. Confirm server-side
  enforcement (a 302-to-home for unauthorized is good; a 200 with content is a finding).
- **Method authz:** try `GET/POST/PUT/PATCH/DELETE` — is each authorized server-side?
- **Forced browsing** to hidden routes (read-only).
- Object ownership must be enforced **server-side**, not just hidden in the UI.

## 4.2 Authentication & session (A07)

- Login rate-limit / lockout behavior — observe without brute-forcing (1–2 attempts).
- **Account enumeration:** does "user not found" differ from "wrong password"? (real
  finding — return one generic message). Same for password-reset and registration.
- Password reset: token entropy, expiry, one-time use; prefer emailed time-limited
  token over security questions (CWE-640).
- MFA enrollment/enforcement/reset/bypass.
- Session: rotation after login (`session_regenerate_id`), logout invalidates
  server-side, cookie flags (P1), session fixation (cookie-swap test without password).
- JWT: storage (localStorage = XSS-stealable), expiry, `alg:none` rejection, signature
  validation, issuer/audience — verify in P6 if source available.
- **CAPTCHA / anti-automation strength — don't take it at face value.** A CAPTCHA that
  *looks* effective can be trivially machine-solvable if the answer leaks through the
  challenge response itself, not just through weak entropy. Check, in order:
  1. **Does the challenge response leak its own answer?** Fetch the challenge and inspect
     the raw body/headers — an SVG/HTML challenge with the answer as literal `<text>`/DOM
     content (not rasterized to an image, not a font-outline path) is solved by a one-line
     regex, no OCR needed. Same class of bug: answer echoed in a response header, a hidden
     form field, an HTML comment, or derivable from a predictable/seeded RNG.
     Confirmed real-world finding — see the dogfood case in `examples/` where
     `<text>t</text><text>m</text>...` in the SVG body was the literal answer.
  2. If the raw response doesn't leak it, check **entropy/space** (charset size × length —
     is brute-forcing the answer itself feasible within the endpoint's own rate limit?).
  3. Confirm the challenge is actually **bound and single-use** — same `captchaId`/token
     reusable across multiple submit attempts, or accepted without ever being fetched, is
     also a finding (bypasses the control entirely regardless of #1/#2).
  - **Fix:** rasterize to an image (PNG/JPEG) with no embedded text node, or render glyphs as
    SVG `<path>` outlines (no `<text>`); bind the challenge id to one verification attempt;
    for anything beyond hobby-scale, prefer a proven third-party service (hCaptcha,
    Turnstile, reCAPTCHA) over a homegrown renderer.
  - **Severity guidance:** if login/register still has effective IP+account rate-limiting
    and lockout behind the broken CAPTCHA, this is usually **Medium** (anti-automation
    layer removed, but brute-force is still bounded) — not Critical/High by itself. If the
    rate-limiter is *also* weak or per-IP-only (trivially distributed across proxies), the
    combination escalates the severity — chain the findings.

> **OAuth 2.0 / OIDC / SAML / JWT / passkeys** have their own deep checklist — see the
> cross-cutting **`auth-identity.md`** reference and load it whenever the target uses federated
> login, social login, SSO, or token-based sessions.

## 4.3 Injection (A05)

Canaries only in search, filters, forms, headers, JSON bodies, path params, file names,
GraphQL vars. Classes: SQL/NoSQL, command, SSTI, LDAP/XML/XPath, header/log, HTML/JS.

- Prefer **error-behavior / scanner / code-review** evidence over data extraction.
- SQLi canary `test' OR '1'='1` → a raw SQL error/stack trace or auth bypass is the
  signal; parameterized queries return a literal non-match (good).
- **XXE (CWE-611):** any endpoint parsing XML (SOAP, SAML, SVG/DOCX/XLSX upload, RSS,
  `Content-Type: application/xml`) — test a **benign** external-entity that resolves to an
  owner-controlled endpoint (OOB) or an in-band error, never `file:///etc/passwd` or
  metadata. A callback/error proves the parser resolves external entities. Fix: disable
  DTD/external-entity resolution (`FEATURE_SECURE_PROCESSING`, `disallow-doctype-decl`).
- **Never** dump DB content, run OS commands, write files, or alter records.

## 4.4 XSS & content injection (A05)

- Reflected: is input echoed encoded (`&lt;script&gt;`) or raw?
- Stored: submit a clearly-labeled test-record canary (`<b>xssTESTcanary</b>`) in your
  own account; check it renders encoded. **Also check the admin/support view** — it may
  use a different template (separate stored-XSS path). Tell the owner to delete the test
  record afterward.
- DOM sinks: `innerHTML`, `document.write`, `eval`, `dangerouslySetInnerHTML`,
  unsanitized `marked.parse()`/markdown → verify in JS source.
- If a script-execution PoC is truly needed, a benign `alert`-style probe **in a test
  account/page only** — never steal cookies/tokens/storage.

## 4.5 CSRF & CORS (CSRF → A01 · CORS → A02)

- State-changing requests need anti-CSRF token (session-bound, server-validated,
  non-reusable across users) or strict `SameSite`. Test by POSTing without/with a bad
  token → expect rejection (403). Test only harmless profile/test-record changes.
- CORS: does it reflect arbitrary `Origin` with credentials? Send
  `Origin: https://evil.example` → the response must NOT echo it into
  `Access-Control-Allow-Origin` with `Allow-Credentials: true`.
- CORS error-path robustness: a rejected foreign origin should return a clean `204`/`403`,
  not throw. If the origin-validation callback `throw`s on rejection (a common `cors`
  middleware pattern: `callback(new Error(...))` instead of `callback(null, false)`), a
  foreign-origin preflight can trigger an unhandled `500` — low severity by itself (the
  rejection still holds), but a signal of uncontrolled error-path behavior worth noting.

## 4.6 File upload & handling

Server-side type enforcement (not extension/MIME only), stored outside executable paths,
safe rename, sandboxed processing, authorized direct access, sanitized filenames/metadata.
Upload **harmless test files only** — never web shells/malware/exploit files.

## 4.7 SSRF / open redirect / URL fetching (A01 — SSRF folded into Broken Access Control in 2025)

- URL-preview/import/webhook features must block internal IPs, `localhost`,
  link-local/**cloud metadata** (`169.254.169.254`), private ranges. **Use only
  owner-controlled external test endpoints; never target real metadata services.**
- Open redirect: test `redirect`/`next`/`return_to`/`url`/`goto`/`callback` params —
  do they redirect off-domain? Destinations should be allowlisted.

## 4.8 Security misconfiguration (A02)

Debug off, stack traces hidden, admin protected, no default creds, directory listing
off, backup/config files not public, restrictive CORS, appropriate CSP, no secrets in
client JS/source maps/logs/errors, sensitive pages not publicly cached.

- **Sample security headers (especially CSP) from more than one route class before
  generalizing.** Page routes (SSR/SPA HTML) and API/JSON routes are frequently served by
  different middleware stacks with *different* policies — e.g. a page-level CSP that adds
  `script-src 'unsafe-inline'` for Google Analytics/AdSense/GTM bootstrap snippets, while
  the API layer's CSP has no `unsafe-inline` at all. A single `curl -I` against one path is
  not evidence for the whole app. Check at minimum: one public page, one authenticated
  page (if applicable), and one `/api/*` JSON endpoint — report each policy separately and
  flag the weakest one as the one that actually matters for that route class's own
  injection surface.
- **Duplicate/conflicting headers from two layers (reverse proxy + app middleware) is its
  own finding**, independent of whether either value alone is secure. E.g. nginx setting
  `X-Frame-Options: SAMEORIGIN` while Express/Helmet also sets `X-Frame-Options: DENY` on
  the same response — the browser behavior when a header repeats with different values is
  under-specified/inconsistent across browsers, and it signals two uncoordinated
  configuration sources that will drift further apart over time. Fix: pick one layer as the
  single source of truth (prefer the app-level one, since it can be unit-tested) and remove
  the other.

## 4.15 Reflected-parameter encoding checks (framework-internal payloads too)

- When probing for reflected XSS, don't stop at "the raw payload doesn't render as HTML" —
  check the *actual* encoding used. Modern SSR/hydration frameworks (Next.js RSC payloads,
  Nuxt payloads, etc.) often echo query/route params back inside an embedded JSON/JS blob
  for hydration. Confirm the framework encoded it safely for *that* context (e.g.
  `<`/`>` inside a `<script>`-embedded JSON string is inert; a literal `<`/`>` or
  an HTML-entity-decoded value re-inserted into the DOM without a corresponding
  encode/escape step is not). Grep the raw response for the exact injected string and read
  20–30 bytes of surrounding context before concluding either way — a substring match alone
  (e.g. finding `alert(1)` present) proves nothing about whether it's executable.

## 4.9 Crypto & sensitive data (A04)

HTTPS everywhere + HSTS, no sensitive data in URLs, modern password hashing (argon2/
bcrypt/scrypt), random long scoped expiring tokens, secrets not committed/exposed, PII
minimized + masked in logs/responses.

## 4.10 Business logic & race conditions

Scanners miss these — they need reasoning about *intended* flow vs what's *enforced*.

- **Value/quantity tampering:** negative quantities, negative/zero/overflow prices,
  currency swap, decimal precision (`0.001` rounding), applying a discount to a
  discounted item. Check server-side re-validation, not client totals.
- **Coupon/discount abuse:** stacking, reuse past limit, applying after order lock,
  guessing sequential codes.
- **Workflow-step skipping:** jump straight to the "confirmed"/"paid"/"approved" step
  by calling its endpoint directly, skipping payment/verification. Check state-machine
  enforcement server-side.
- **Quota/limit bypass:** free-tier limits enforced only in UI; resetting counters via
  a re-init endpoint; per-account limit bypassed by re-registration.
- **Role/approval abuse:** self-approving, approving your own request, promoting your
  own role via a profile-update field (mass assignment overlap, §API3).
- **Trial/subscription abuse:** re-trialing, downgrading after consuming an annual perk.
- **Race conditions (TOCTOU):** the classic gap between check and use. Examples: spending
  the same balance/coupon/gift-card twice via two near-simultaneous requests; double
  withdrawal; using a one-time token twice; over-booking a limited resource. **Safe test
  (authorized, non-prod):** send **2–3** parallel requests (not a flood — never DoS) and
  observe whether both succeed. If it can only be safely reasoned about, review the code
  for a DB-level lock / atomic decrement / unique constraint / idempotency key instead.
  Fix pattern: atomic `UPDATE ... WHERE balance >= x`, `SELECT ... FOR UPDATE`, unique
  constraints, or idempotency keys — never check-then-act in application code.

Test records only; no real payments/obligations; parallel probes capped at a handful.

## 4.11 HTTP request smuggling / desync (CWE-444)

Parser differentials between a front-end proxy/CDN and the back-end in how they interpret
`Content-Length` vs `Transfer-Encoding` (CL.TE / TE.CL / TE.TE), plus newer 2024–2025 classes:
**CL.0** (back-end ignores `Content-Length`), **client-side desync**, and **HTTP/1.1 desync
"0.CL" endgame** using `Expect`/early-response gadgets → response-queue poisoning and
cross-tenant cache/content hijack. Impact: request hijacking, credential theft, cache poisoning,
bypassing front-end auth/WAF.

- **Detection is timing/behavior-based and delicate — this is authorized-active only, low-rate.**
  Prefer Burp Repeater's "HTTP Request Smuggler" / the desync probe methodology; observe
  timing differences, never flood. On any sign of instability, stop.
- Strongest fix: **use HTTP/2 (or HTTP/3) end-to-end** and reject ambiguous/downgraded requests;
  normalize/validate `Content-Length` + `Transfer-Encoding` at the edge; disable connection reuse
  to the back-end where feasible. Ref: PortSwigger request-smuggling research (2025 "HTTP/1.1
  Must Die"). Often better confirmed by config review than live probing.

## 4.12 Web cache poisoning & cache deception (poisoning → CWE-349 · deception → CWE-524)

- **Cache poisoning (CWE-349, untrusted data accepted into a cached response):** an unkeyed
  input (a header like `X-Forwarded-Host`, `X-Forwarded-Scheme`,
  or a quirky param) influences a cached response → the poisoned response is served to others.
  Safe test: send a benign unique marker in a candidate unkeyed header to a **cacheable** path,
  confirm it reflects, then confirm (carefully, once) it's cached. Never poison a shared prod
  cache with anything harmful.
- **Cache deception (CWE-524, sensitive content stored in a shared cache):** trick the cache
  into storing a victim's *authenticated* page under a URL
  the attacker can fetch (path-confusion: `/account/profile.css`, delimiter/extension tricks).
  Confirm sensitive pages are `Cache-Control: no-store` and the CDN doesn't cache by extension
  alone. Fix: cache keys include all security-relevant inputs; never cache authenticated content;
  strict path normalization at the edge.

## 4.13 Client-side injection: prototype pollution, DOM clobbering, CSPT

- **Client-side prototype pollution** — user-controlled keys reach `Object.prototype` via unsafe
  merge/`$.extend`/`lodash.merge`/`JSON` parsing of `__proto__`/`constructor`/`prototype` →
  DOM-XSS gadget or logic bypass. Grep the bundle for recursive merges and `[key]=` assignment
  from `location`/`postMessage`. Fix: `Object.create(null)`, block those keys, `Map`, or
  `Object.freeze(Object.prototype)`.
- **DOM clobbering** — attacker HTML (`<a id=x>`, `<form name=y>`) overrides JS globals/`document`
  properties the app trusts. Fix: don't rely on named DOM lookups; sanitize with DOMPurify
  (`SANITIZE_NAMED_PROPS`).
- **Client-side path traversal (CSPT)** — attacker-controlled path segment steers a client-side
  `fetch()`/XHR to an unintended endpoint (→ CSRF, info leak, self-XSS chaining). Fix: validate/
  encode path segments; use absolute, allowlisted API paths.

## 4.14 WebSocket security (CWE-1385)

- **Cross-Site WebSocket Hijacking (CSWSH):** the WS handshake is a `GET` — if it relies only on
  cookies with **no `Origin` check and no CSRF token**, any site can open an authenticated socket
  and read/act as the victim. Check the handshake validates `Origin` and uses a per-session token.
- Also check: authz on each message (not just at connect), input validation on WS payloads
  (same injection sinks), and rate limits.
- **Live active test for room/broadcast authorization (Socket.IO and equivalents):** client-side
  room-join logic (`socket.emit('join_admin')`, `socket.emit('join_user', userId)`) is a
  strong signal the server *might* be trusting client-asserted role/identity for what gets
  broadcast to that connection — but don't flag it from source alone if the server can't be
  read, and don't assume the worst from source alone either: confirm live. Safe recipe:
  1. Connect a real Socket.IO/WS client **without any auth cookie/token**.
  2. Emit the client-observed join events for the highest-privilege room you can find in the
     bundle (e.g. `join_admin`, `join_room:*`), and any user-scoped join with an arbitrary/
     guessed id.
  3. Attach a catch-all listener (`socket.onAny(...)` or equivalent) and listen for a bounded
     window (~10-15s) while triggering an unrelated, harmless public action from another tab/
     request (e.g. a public page view) that *should* generate a broadcast if the room/event
     wiring is real.
  4. **No privileged event arriving = the room join was accepted but not wired to any
     sensitive broadcast** — note this as a confirmed-safe result, not a finding (many apps
     serve all sensitive data over authenticated REST and use sockets only for low-value
     real-time UI, in which case the missing handshake auth is a defense-in-depth gap, not an
     active data leak — say so explicitly and rate it accordingly, don't over-claim severity).
     **Any privileged event arriving = confirmed live data-leak finding**, rate by what leaked.
  5. Either way, still flag the missing handshake authentication itself (CWE-306) as a
     defense-in-depth finding — it means a *future* feature that does broadcast sensitive data
     over that same unauthenticated connection would be unprotected on day one.

## Automation (authorized, rate-limited)

`nuclei` safe templates (exposures/misconfig/CVE detection), OWASP ZAP **baseline** scan
first. Full/active scans only with explicit approval and low rate. Manual verification
still required — scanner output is leads, not findings.

## Deliverable

Per-finding evidence set (`report-template.md`). Mark verified-live vs inferred. List
what couldn't be tested (no 2nd account, cost, scope) and why.
