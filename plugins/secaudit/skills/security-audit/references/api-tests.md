# P5 — API security testing (OWASP API Top 10 2023) — ACTIVE, authorized

Applies when the target exposes an API (REST/GraphQL/gRPC-web). Approved test accounts
only; no real-user enumeration; no high-volume fuzzing.

## The OWASP API Top 10 (2023) checklist

| # | Risk | What to check (safely) |
|---|---|---|
| API1 | Broken Object Level Authorization (BOLA/IDOR) | swap object IDs between two test accounts; server must reject cross-owner access |
| API2 | Broken Authentication | token validation, expiry, `alg:none`, weak/absent auth on some routes, credential-stuffing resistance (don't brute-force) |
| API3 | Broken Object Property Level Authorization | mass assignment (send extra fields like `role`,`isAdmin`,`verified`); excessive data exposure in responses |
| API4 | Unrestricted Resource Consumption | missing rate limits, pagination limits, large-payload handling — observe headers, don't DoS |
| API5 | Broken Function Level Authorization | low-priv account calling admin endpoints/methods; unauthorized `PUT/PATCH/DELETE` |
| API6 | Unrestricted Access to Sensitive Business Flows | automatable flows (signup, purchase, booking) without anti-automation — reason about it, don't abuse |
| API7 | Server-Side Request Forgery | URL params/webhooks that fetch attacker-controlled URLs (`web-tests.md` §4.7 rules) |
| API8 | Security Misconfiguration | verbose errors, missing headers, permissive CORS, unauthenticated debug/actuator endpoints |
| API9 | Improper Inventory Management | old/undocumented versions (`/v1` vs `/v2`), staging/debug hosts, deprecated endpoints |
| API10 | Unsafe Consumption of APIs | trust in third-party API responses, no validation of upstream data |

## Method

- Document each endpoint: `method · path · auth required · roles tested · input fields ·
  expected authz · observed · finding?`
- Test BOLA/BFLA with **two** approved accounts + your own test records only.
- Mass assignment: add unexpected privileged fields to a normal request to your own
  test object; check if they're accepted (don't escalate a real account).
- Validate errors don't leak stack traces, secrets, internal hostnames, or SQL.
- **Token/auth** — for JWT/OAuth/OIDC-protected APIs, run the `auth-identity.md` checklist
  (`alg:none`, algorithm confusion, `kid`/`jku` injection, missing `aud`/`exp`, PKCE).

## GraphQL specifics

- **Introspection** exposed in prod → full schema map for attackers. Disable or restrict.
- **Depth / complexity / alias limits** — deeply nested or aliased queries (`a:f b:f c:f …`)
  cause resource exhaustion (API4) or bypass per-request rate limits. Confirm depth + cost limits.
- **Batching abuse** — array/aliased batching to brute-force or bypass per-request throttling
  (e.g. many `login` mutations in one request). Confirm anti-automation counts operations, not
  requests.
- **Field-level authorization** — a resolver returning a field the caller shouldn't see (BOLA/
  BFLA at field granularity). Test with two accounts.
- **Field suggestion / error leakage** — "did you mean" suggestions leak schema even with
  introspection off; verbose resolver errors leak internals.

## Rate-limit & anti-automation bypass (API4/API6)

Check limits can't be trivially evaded: rotating `X-Forwarded-For`, case/trailing-slash/
path-param variants of the same route, HTTP/2 multiplexing, GraphQL batching, or per-endpoint
limits that miss a sibling version (`/v1` vs `/v2`). Reason about it — **do not actually flood**.

**HTTP/2 Rapid Reset (CVE-2023-44487):** rapid `HEADERS`+`RST_STREAM` cycles let a client
open/cancel streams faster than the server frees them → DoS. This is an **availability**
issue — **assess by version/config, not by attacking**: confirm the server/proxy (nginx,
Envoy, Go `net/http`, etc.) is patched and caps concurrent/reset streams. Flag unpatched
edge stacks as a finding; never send the actual flood.

## gRPC / gRPC-web

Check TLS + auth on every method (not just the gateway), reflection disabled in prod, message-
size limits, and that authz is enforced per-method server-side (not only at an API gateway).

## Safe limits

Approved test accounts only · no real-user/customer enumeration · no high-volume
fuzzing · no state-changing calls on real data · minimal proof.

## Deliverable

Endpoint authz matrix + per-finding evidence (`report-template.md`), mapped to the
API Top 10 IDs above.
