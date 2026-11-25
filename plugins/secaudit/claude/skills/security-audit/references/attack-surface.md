# P2 — Attack-surface mapping (live target)

Inventory everything reachable. This is discovery, not exploitation. Passive unless you
start submitting forms (that's P4/P5, gated).

## Build the inventory

- **Public pages** and routes (from HTML links, `sitemap.xml`, SPA router config in JS).
- **Auth flows**: login, registration, password reset, email verification, MFA, logout.
- **Account/profile** pages and settings.
- **File upload/download** features.
- **Search / filter / sort** endpoints (injection + IDOR surface).
- **Admin / dashboard** routes.
- **API endpoints + methods** — extract from JS bundles (grep for `/api/`, `fetch(`,
  `axios`, route tables), OpenAPI/Swagger if exposed, network calls.
- **WebSocket / SSE** endpoints (`ws://`, `wss://`, `socket.io`).
- **Third-party integrations** (analytics, payment, auth providers, CDNs, reCAPTCHA).
- **Input points**: forms, query params, path variables, JSON fields, headers,
  file names/metadata, GraphQL operations.
- **Role-based features** visible per test account (if provided).

## Extracting endpoints from JS bundles (passive)

```bash
# fetch a bundle, then grep for API paths / routes (read-only)
curl -sS --max-time 25 https://TARGET/assets/index-XXXX.js -o bundle.js
grep -oE '"/api/[a-zA-Z0-9/_-]+"' bundle.js | sort -u
# single-quoted, so the backtick is literal (matches template-literal calls, e.g. fetch(`/x`))
grep -oE '(fetch|axios\.[a-z]+)\(`?[^`")]+' bundle.js | sort -u
```

Map each endpoint: method(s), auth required?, roles, input fields, expected authz.
Note source maps (`*.map`) — if present they reveal original source (feeds P6-lite).

## Rules

- Respect exclusions (payments, deletion, email/SMS).
- Do NOT submit forms that cause payments, account deletion, emails to real users, or
  irreversible state. Mapping ≠ submitting.
- Use only harmless test data and approved test accounts when auth is needed.

## Deliverable

An endpoint/route table (method · path · auth · roles · inputs · expected authz) plus a
list of the highest-value targets for P4/P5 (auth flows, IDOR-prone ID params, upload,
admin, URL-fetch/webhook features for SSRF). This drives where authorized active
testing focuses.
