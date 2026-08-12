# Running SecAudit in CI

Four ways in, same engine behind all of them. Pick by how you already work — there is no
"real" one and no feature that only exists in one.

| | Use it when | Cost |
|---|---|---|
| [GitHub Action](#github-action) | You are on GitHub Actions | No install |
| [pip](#pip) | Any CI, any runner, air-gapped included | `pip install secaudit-kit` |
| [Docker](#docker) | You want the toolchain fixed and the scanner sandboxed | One image pull |
| [pre-commit](#pre-commit) | You want it before the commit exists | `pre-commit install` |

## GitHub Action

```yaml
permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # required — see below
      - uses: mtvrkan/secaudit@v1
        with:
          fail-on: high
```

On a `pull_request` event this gates on what the PR **introduced**, comparing against the base
branch automatically. Pre-existing findings are reported and do not fail the job. See
[diff mode](diff-mode.md) for why that distinction is the whole point.

**`fetch-depth: 0` is not optional if you want the diff gate.** `actions/checkout` clones one
commit by default, so the base commit is not in the checkout and there is nothing to compare
against. The action does not fail in that case — it emits a warning and audits the whole tree,
which is a stricter gate than you asked for rather than a weaker one.

### Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | File or directory to audit |
| `since` | auto | Git ref for the baseline. Empty = the PR base branch. `off` = audit the whole tree |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, or `none` to never fail |
| `sarif` | — | Also write SARIF here, for `github/codeql-action/upload-sarif` |
| `sbom` | — | Also write a CycloneDX 1.6 SBOM here |
| `comment` | `false` | Post the report as a PR comment. Needs `pull-requests: write` and `token` |

`comment` is off by default deliberately: a security workflow should not acquire write access
to your pull requests as a side effect of being installed.

### Outputs

`introduced`, `total`, `report` (path to the Markdown).

### With code scanning

```yaml
      - uses: mtvrkan/secaudit@v1
        with:
          fail-on: high
          sarif: secaudit.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()          # upload even when the gate failed — that is when you want it most
        with:
          sarif_file: secaudit.sarif
```

## pip

```bash
pip install secaudit-kit

secaudit .                      --min high
secaudit . --since origin/main  --min high     # gate on what this branch introduced
secaudit . --format sarif -o secaudit.sarif
secaudit . --format cyclonedx -o sbom.cdx.json    # vulnerability correlation
secaudit . --format spdx      -o sbom.spdx.json   # licence / procurement review
secaudit . --exploitation                          # mark CVEs confirmed exploited in the wild
```

`--exploitation` is the only part of Tier 0 that reaches the network. It sends CVE ids and
nothing else — no path, no package version, no hostname — and if a feed is unreachable it
reports `unknown` rather than treating "could not check" as "not exploited".

Zero runtime dependencies — the wheel declares none, and the release pipeline fails if it ever
does ([`scripts/assert_no_runtime_deps.py`](../scripts/assert_no_runtime_deps.py)). It installs
and runs on a machine with no network.

Both shapes of one scan, without scanning twice:

```bash
secaudit . --format json -o result.json --summary report.md
```

## Docker

```bash
docker build -t secaudit .
docker run --rm -v "$PWD:/src:ro" secaudit /src --min high
```

The mount is read-only and the container runs as UID 10001. A scanner has no reason to write to
what it is scanning, so it cannot.

For `--since`, the `.git` directory has to be inside the mount — it already is if you mount the
repository root.

## pre-commit

```yaml
repos:
  - repo: https://github.com/mtvrkan/secaudit
    rev: v1.0.0
    hooks:
      - id: secaudit
```

Or, if the full pass is too slow to survive on your repository, the narrow one:

```yaml
      - id: secaudit-secrets
```

**Budget is the design constraint here.** A hook that takes ten seconds gets `--no-verify`'d
within a week, and a bypassed hook catches nothing. Both hooks run deterministic checks over the
staged files only, with dependency scanning and external scanners off. The full audit belongs in
CI, where it can afford to be slow.

`secaudit-secrets` uses `--only secret`, which is worth having as the fallback because a
committed credential is the least recoverable finding there is: once it is in the history,
removing it is not the fix — rotating it is.

Detector groups come from the detector ids themselves. `secaudit --only ?` lists them.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing at or above the threshold |
| `1` | Something at or above the threshold (with `--since`: something **introduced**) |
| `2` | The audit could not be run — bad ref, not a git repository, unknown `--only` group, incompatible `--format` |

Treat `2` as a broken build, not a security finding. *"This change is unsafe"* and *"I could not
tell you whether this change is safe"* should never reach a reviewer as the same signal.

## What a green build means

That these rules did not fire, in [these languages](language-coverage.md), across the files that
were scanned. Not that the code is safe. [What we miss](what-we-miss.md) is generated from the
engine itself and is the page to read before treating a clean run as an all-clear.
