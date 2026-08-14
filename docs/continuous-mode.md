# Continuous mode — `--watch`

A source scan answers *"what is wrong with this code now."* It cannot answer the question the EU
Cyber Resilience Act attaches a deadline to, because that question is not about your code:

> A dependency you already ship became **actively exploited** overnight. Nothing in your
> repository changed.

From **2026-09-11** that event starts a 24-hour early-warning obligation to ENISA and your CSIRT,
72 hours for the full notification and 14 days for the final report. The trigger is *actively
exploited*, not *has a CVE* — which is why this mode exists and why it is built on CISA KEV rather
than on advisory counts.

```bash
# First run: records what this project ships, and what is known about it today.
secaudit ./repo --watch .secaudit/watch.json

# Every run after that: re-asks the feeds about exactly those CVE ids and reports the moves.
secaudit ./repo --watch .secaudit/watch.json
```

Exit code is **non-zero when something newly became exploited — and also when a feed could not be
read.** That is deliberate, and it is the whole design (see below).

## What it actually diffs

`--since` diffs your code against an older tree. `--watch` diffs **the world** against the last
run. The state file records every advisory the dependency scan found, with the reachability
verdict [`deps.py`](../kit/secaudit_core/deps.py) gave it, and each later run compares the stored
exploitation status against a fresh CISA KEV / FIRST EPSS lookup.

| Transition | Reported as | Alerts? |
|---|---|---|
| anything → `exploited` (in KEV) | **the CRA 24-hour class** | yes |
| `listed` → `elevated` (EPSS rose) | noted, below the fold | no |
| already `exploited` | carried, with the date the clock started | no |
| a lower reading than recorded | **ignored** — see rule 2 | no |
| a feed could not be read | *no comparison was made* | yes |

## The four rules it will not bend

**1. A feed that could not be reached is never "no change."** This is the rule the module exists
to hold. A loop that prints a clean report when it failed to check is worse than no monitoring,
because it manufactures the belief that somebody is watching. When neither feed answers,
`compare()` refuses to produce a comparison at all, the report's only content is that it could not
be produced, the stored state is **left untouched** so the next good run still compares against
real data, and the exit code is non-zero. A quiet night and a failed check must not be tellable
apart by exit code alone.

**2. Recorded status is a high-water mark.** Once an advisory has been seen `exploited` it stays
`exploited` even if a later fetch does not say so. KEV membership is a statement that exploitation
*happened*; a feed that stops listing it has not un-happened it. The alternative lets one bad
fetch silently close a finding that started a legal clock.

**3. Reachability ranks, it never filters.** An advisory `deps.py` called `not_affected` is still
watched and still reported when it becomes exploited — just below the reachable ones. That verdict
is an import-level inference that can be wrong, and the obligation attaches to the product rather
than to our confidence about it.

**4. The comparison is pure.** `monitor.compare()` takes a state and a catalog and returns a
report. It fetches nothing, writes nothing and reads no clock. The alerting logic is therefore
tested offline against constructed catalogs rather than against whatever CISA published this
morning — see [`kit/tests/test_monitor.py`](../kit/tests/test_monitor.py), whose refusal cases are
proven by mutation.

## Scheduling it

```yaml
# .github/workflows/watch.yml
on:
  schedule:
    - cron: "17 6 * * *"        # daily; the CRA clock is 24h, so daily is the loosest useful loop
  workflow_dispatch:

jobs:
  watch:
    runs-on: ubuntu-latest
    permissions:
      contents: write            # to commit the updated state file
    steps:
      - uses: actions/checkout@v5
      - run: pipx install secaudit-kit
      - run: secaudit . --watch .secaudit/watch.json --summary watch.md
      - if: failure()            # newly exploited, OR a feed was unreachable
        run: gh issue create --title "Exploitation watch: action required" --body-file watch.md
        env: { GH_TOKEN: "${{ github.token }}" }
```

Commit the state file. It carries `exploited_since` per advisory, which is the date your 24-hour
clock started, and a fresh baseline erases it.

## What it does not do

It tracks the CVE ids a scan already found; it does not discover new advisories on its own. Re-run
the scan on the same schedule (the command above does both in one pass) so a dependency that
*gains* an advisory enters the watch list. And it watches dependencies — a newly published
weakness in your own code is what the scan itself is for.
