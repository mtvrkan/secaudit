# P3 — Known vulnerabilities & dependency research

Match detected technologies/versions against trusted vulnerability sources. This is the
"known vulnerabilities" half of the job (the "unknown" half is P4–P6).

## Inputs

- Versions fingerprinted in P1 (server, framework, JS libs, CDN).
- If source available, dependency manifests + **lockfiles** (lockfiles give the exact
  resolved version — always prefer them over manifest ranges):
  ```
  package.json/package-lock.json/yarn.lock/pnpm-lock.yaml
  requirements.txt/Pipfile.lock/poetry.lock   composer.json/composer.lock
  Gemfile.lock   go.mod/go.sum   Cargo.lock   *.csproj/packages.lock.json
  pom.xml/build.gradle/gradle.lockfile
  Dockerfile + base image tags   IaC (Terraform/CFN/K8s/Compose)   CI/CD workflows
  ```

## Scan (tools → fallback)

Use `references/tooling.md`. Preferred one-shot for a repo:

```bash
osv-scanner -r . --format json     # all ecosystems at once
trivy fs . --format json           # deps + secrets + misconfig
# per-ecosystem: npm audit / pip-audit / govulncheck / cargo audit / composer audit / …
```

No tools installed → read each lockfile, extract the resolved version of each dependency,
and look it up on **OSV.dev** and the **GitHub Advisory Database** via WebSearch/WebFetch.
Do not rely on training memory for whether a version is vulnerable — check live.

## Sources (query per detected component)

- **OSV.dev** — open-source package vulns (all ecosystems).
- **GitHub Advisory Database** — GHSA advisories.
- **NVD / CVE** — CVE records + CVSS.
- **CISA KEV** — actively exploited in the wild → **top priority**.
- **Vendor advisories** — for the exact framework/CMS/plugin/server/DB/CDN.

## Triage each hit (don't just paste scanner output)

For each candidate CVE:
1. Is the **installed** version actually in the affected range? (lockfile, not range)
2. Is the vulnerable code path **reachable** / the affected API actually used?
3. Is there a **fix version**? Is it a safe upgrade (semver)?
4. Is it in **CISA KEV** or does a public exploit exist? → raise priority.
5. Transitive vs direct — note which; transitive needs the parent bumped or an override.

## Supply-chain checks

- **Unpinned** CDN/script tags (`/npm/marked/` = latest) — pin to an exact version
  (+ SRI `integrity` for `<script>`). A malicious/broken upstream release auto-hits you.
- **Freshly published** packages (<7 days) — elevated typosquat/compromise risk.
- **Typosquatting / dependency confusion** — a public package shadowing an internal name, or a
  near-miss of a popular name. Verify internal scopes are reserved and registry precedence is set.
- **Slopsquatting** — packages named after **AI-hallucinated** imports. As AI coding assistants
  became mainstream (2025–2026), attackers pre-register plausible-but-nonexistent names that
  LLMs suggest. Flag any dependency that has few downloads, a very recent first-publish, and a
  name that "looks right" but you can't trace to a real project.
- **Lockfile integrity/`resolved` drift** — unexpected registry, hash, or version changes in the
  lockfile diff. Review `resolved`/`integrity` churn on every PR.
- **Malicious `postinstall`/lifecycle scripts** — the primary infection vector for npm worms.
  Grep manifests for `preinstall`/`postinstall`/`prepare` running network/exec; prefer
  `--ignore-scripts` for untrusted installs.
- **Provenance / attestation** — prefer packages published with **npm provenance** (SLSA build
  attestation via Sigstore). Verify with `npm audit signatures`. SLSA v1.2 (Nov 2025) adds a
  Source track; GitHub Artifact Attestations and npm **trusted publishing** (OIDC, no long-lived
  tokens) are the 2026 baseline.
- **GitHub Actions** not pinned to a full commit **SHA** (tag pinning is bypassable — see below).
- **`npm ci` vs `npm install`** in CI (use `ci` for reproducible, lockfile-faithful installs).

## Recent-incident awareness (what these attacks look like)

Use these as pattern templates — don't assume a specific package is still affected; **look up
current advisories**. The point is to recognize the *class*.

- **Self-replicating npm/PyPI worms — "Shai-Hulud" family (Sept 2025 → "Mini Shai-Hulud" May
  2026, first to span npm + PyPI).** A compromised package's `postinstall` steals credentials
  (often abusing secret-scanners like TruffleHog against the dev's own machine/CI), exfiltrates
  them, and **auto-republishes malware to every package the stolen npm token can reach**.
  Detection: unexpected `postinstall`, credential-harvesting code, outbound POSTs to unknown
  hosts, a maintainer's packages all bumping at once, new GitHub Actions workflows added to
  repos. Mitigation: `--ignore-scripts`, short-lived/scoped tokens + trusted publishing, MFA on
  publish, pin + verify provenance, and audit token scopes.
- **Compromised GitHub Action via mutable tags — `tj-actions/changed-files` (CVE-2025-30066,
  Mar 2025).** The attacker repointed **all** version tags to a malicious commit that dumped CI
  secrets into build logs (23k+ repos). This is exactly why **tags are not trustworthy** — pin
  every third-party Action to a full commit SHA and review the pinned code.
- **Maintainer social-engineering + obfuscated build payload — `xz-utils` backdoor
  (CVE-2024-3094).** A long-game trusted-contributor takeover hid a backdoor in **build
  scripts / test blobs**, not the source diff. When reviewing deps, don't trust "it's a
  reputable project" — scrutinize build tooling, binary test fixtures, and release-only files
  that aren't in the git tree.

## Deliverable — dependency/CVE register

```markdown
| Component | Installed | Evidence | Source checked | CVE/Advisory | In CISA KEV? | Reachable? | Fix version | Priority |
|---|---:|---|---|---|---|---|---|---|
```

Prioritize KEV-listed and reachable-with-exploit first (see `severity-cvss.md`).
