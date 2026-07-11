# Negative control — expected result for `fixtures/secure-app`

`fixtures/vulnerable-app` measures **recall** (does the audit find the 20 planted flaws?).
This fixture measures the other half of quality — **precision** (does the audit stay quiet
when the code is actually safe?). It is `secure-app`: the *same* features as the vulnerable
fixture, each implemented correctly (S1–S20 ↔ V1–V20).

A good security tool must do **both**: surface real issues *and* not cry wolf. A scanner that
flags everything gets 100% recall and useless precision; this corpus catches that failure mode.

## What a correct audit should report

- **No Critical and no High findings.** Every vulnerability class from the golden set is
  neutralized here by a specific control (below). Flagging one of them is a **false positive**.
- At most a few Informational/Low notes are acceptable (e.g. "consider a digest-pinned base
  image", "add security headers") — these are hardening suggestions, not vulnerabilities.
- The dependency scan should be quiet: versions are pinned to patched releases
  (`lodash@4.17.21`, `minimist@1.2.8`, `express@4.21.2`, `marked@12`, `dompurify@3.1.7`).
- No secrets: credentials are read from the environment; nothing is hardcoded.

## The control that neutralizes each class

| ↔ | Class | Control in `secure-app` |
|---|---|---|
| S1  | SQL injection | parameterized query (`WHERE name = ?`) |
| S2  | OS command injection | `execFile` + arg array + host allowlist (no shell) |
| S3  | Broken access control | `requireAuth` + `owner_id = ?` ownership check |
| S4  | Password hashing | `scrypt` with a per-password random salt |
| S5  | Hardcoded secret | `process.env` — nothing in source |
| S6  | CORS | explicit origin allowlist, not reflected |
| S7  | SSRF | https + host allowlist + private-range block |
| S8  | Output handling / XSS | `DOMPurify.sanitize` (+ `textContent` for user input) |
| S9  | Container | pinned base, `USER node`, secret injected at runtime |
| S10 | JWT | server-pinned `alg`, constant-time HMAC verify, exp/aud checks |
| S11 | Open redirect | relative-path allowlist |
| S12 | Path traversal | resolve + containment check under `DOCS_ROOT` |
| S13 | Mass assignment | explicit field allowlist |
| S14 | Prototype pollution | `__proto__`/`constructor` blocked, null-proto target |
| S15 | Insecure deserialization | `JSON.parse`, no `eval` |
| S16 | SSTI | data-as-context interpolation, no compilation |
| S17 | XXE | entities/network/DTD disabled |
| S18 | TLS verification | `verify=True` |
| S19 | OS command injection (Py) | arg list, no `shell=True`, validated host |
| S20 | Insecure deserialization (Py) | `json.loads`, no `pickle` |

## Measuring precision (reproducible)

```
/secaudit-code tests/fixtures/secure-app
```

Count any **High/Critical** finding that maps to S1–S20 as a false positive. Precision on this
corpus = 1 − (false positives / 20). The deterministic integrity of this corpus (that it stays
genuinely safe and doesn't drift back into a vulnerable state) is gated in CI by
`selftest.py` — see [`README.md`](README.md). The live precision number itself depends on the
model at run time, like all detection quality; this fixture makes it measurable rather than
assumed.
