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

### API3 — config/settings endpoints: the highest-value excessive-data-exposure check

A single "settings" or "site-config" DB row commonly mixes public-safe fields (site title,
social links, feature flags) with genuinely secret ones (SMTP credentials, third-party API
keys, payment provider secrets) — and it's routinely serialized wholesale, with no
field-level allowlist, to **every** endpoint that reads it. This is a recurring, high-impact,
easy-to-check real-world bug class — confirmed critical finding in a past engagement (a
public "site settings" endpoint, intentionally unauthenticated for legitimate frontend use,
leaked the newsletter SMTP password to every page load). Check specifically:

1. **Enumerate every endpoint that returns a config/settings object** — public AND admin
   (`/api/settings`, `/api/public/site-settings`, `/api/admin/site-settings`, `/config`,
   `/api/site-info`, GraphQL `settings { ... }`). Note that a bug in a *shared serializer*
   affects all of them identically — if one leaks, check the others immediately, they very
   likely share the same root cause.
2. **Diff the full response against what the UI actually consumes.** Open the same page in a
   browser / read the frontend source for what fields it reads from that response, then
   compare to the full raw JSON — every extra field the UI never touches is a candidate leak.
   Look especially for field names containing `smtp`, `key`, `secret`, `token`, `password`,
   `credential`, `api_key`, `webhook`, `dsn`, `connection_string`.
3. **Check both the intentionally-public endpoint and any admin-only sibling** — an admin
   settings endpoint that's *missing* its auth middleware (simple oversight) is just as
   likely to exist alongside a *by-design* public one that over-serializes; both routes
   often return the identical unfiltered row, so one grep of the handler/serializer code
   finds both bugs at once.
4. **Safely test the write side without ever mutating real data — the no-op replay
   technique:** to confirm whether a state-changing endpoint (`PUT`/`PATCH`/`POST` on that
   same settings object) is actually authorization-protected, `GET` the current values first,
   then replay the **exact same values** back through the write endpoint (net change: zero).
   A `401`/`403` proves write is protected without ever having risked altering real
   configuration; a `200` that echoes success is a confirmed write-side finding you obtained
   with zero risk. This same replay-only technique generalizes to any state-changing endpoint
   you need to authz-test but must not actually mutate.
- **Severity note:** even if the write side is fully protected (so defacement/injection via
  that field isn't possible), a **secret credential** leaking through the read side alone is
  still Critical — the impact (credential theft → third-party system compromise) doesn't
  depend on being able to write back through the same endpoint.

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
