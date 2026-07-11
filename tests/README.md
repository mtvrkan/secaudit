# Self-test / eval

A tiny, intentionally-vulnerable fixture used to sanity-check SecAudit's coverage and
catch regressions. **The fixture is not real, not deployable, and contains only
clearly-fake/example secrets.**

## Run

```
/secaudit-code tests/fixtures/vulnerable-app
```

(or, with tools installed, `npm audit`, `semgrep`, `gitleaks` will be used automatically.)

## Check

Compare the report against [`expected-findings.md`](expected-findings.md). All 16 planted
code findings must appear; dependency and secret sections must be populated (or clearly
marked "tool/lookup unavailable"). Misses are regressions.

A reference run (in **fallback mode** — no scanners installed, Claude analysis + `npm`
only) is saved at [`../examples/self-test-report.md`](../examples/self-test-report.md) as
proof the flow works end-to-end.

## Adding cases

When you add a new check to a `references/*.md`, plant a matching minimal example in the
fixture and add a row to `expected-findings.md`. Keep examples small and clearly labeled
`INTENTIONALLY VULNERABLE`.
