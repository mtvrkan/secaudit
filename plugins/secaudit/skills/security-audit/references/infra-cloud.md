# P7 — Infrastructure, cloud, containers & IaC

Only explicitly in-scope assets. For live infra, passive/read-only unless authorized.
For IaC/config files provided as source, static review is always safe.

## Containers & images

- `trivy image <image>` or `grype <image>` — OS + app-layer CVEs, misconfig, secrets.
- Dockerfile review: non-root `USER`, pinned base image (digest, not `:latest`),
  minimal base, no secrets in layers/`ARG`/`ENV`, `.dockerignore` excludes secrets,
  multi-stage to drop build deps, `HEALTHCHECK`, no `--privileged`.
- `syft <image> -o cyclonedx-json` for an SBOM.

## IaC misconfiguration

- `checkov -d .` or `trivy config .` or `tfsec .` (Terraform), `kube-score` (K8s).
- **Terraform/CFN:** public S3/blob buckets, open security groups (`0.0.0.0/0` on 22/
  3389/DB ports), unencrypted storage/volumes, public RDS, overbroad IAM (`*:*`),
  missing logging/versioning, hardcoded secrets.
- **Kubernetes:** no `runAsNonRoot`, privileged/`hostNetwork`/`hostPID`, missing
  resource limits, no NetworkPolicy, secrets as env vars, `latest` images, overbroad
  RBAC (`cluster-admin`), exposed dashboard/kubelet.
- **Docker Compose:** exposed DB/admin ports, `privileged`, host mounts, plaintext secrets.

## Cloud / deployment exposure (in-scope only)

- Public storage buckets, public admin panels, exposed DBs/queues/dashboards/metrics/logs.
- CDN/WAF configuration, TLS config (`passive-recon.md` §TLS), DNS exposure
  (dangling records, zone transfer — passive).
- **Subdomain takeover / dangling DNS:** a `CNAME`/`ALIAS` still pointing at a
  de-provisioned cloud resource (S3/GitHub Pages/Heroku/Azure/Netlify/Fastly, etc.) lets an
  attacker claim that resource and serve content from your subdomain (cookie theft, phishing,
  CSP/OAuth-origin bypass). Enumerate subdomains passively (cert transparency / `subfinder`),
  flag any resolving to a "NoSuchBucket"/"404 no app"/unclaimed-service fingerprint. Confirm
  by fingerprint only — **do not** register the dangling resource. Fix: remove the stale record.
- Environment variable & secret management (are secrets in a manager or in plaintext?).
- Backup exposure.

## IAM & least privilege (config review)

The highest-impact cloud misconfigs are identity ones. When policy/config is available:

- **Wildcard actions/resources:** `"Action": "*"`, `"Resource": "*"`, `iam:*`, `s3:*`,
  `sts:AssumeRole` on `*`, admin/`Owner`/`cluster-admin` handed out broadly.
- **Privilege-escalation paths (AWS):** `iam:PassRole` + `ec2:RunInstances`/`lambda:*`,
  `iam:CreatePolicyVersion`/`AttachUserPolicy`/`PutUserPolicy`, `sts:AssumeRole` chains,
  `iam:CreateAccessKey` on another user. GCP: `iam.serviceAccounts.actAs`,
  `setIamPolicy`, `serviceAccountKeys.create`. Azure: `Owner`/`User Access Administrator`,
  custom roles with `Microsoft.Authorization/*/write`.
- **Trust policies:** overly broad `Principal` (`"AWS": "*"`), missing `ExternalId` /
  condition on cross-account assume-role, OIDC trust with a wildcard `sub`.
- **Confused-deputy / SSRF-to-credential:** instance-metadata (IMDSv1) reachable →
  steal role creds (require IMDSv2). Ties to app-layer SSRF (`web-tests.md` §4.7).
- **Long-lived keys** instead of short-lived roles/OIDC federation; access keys not
  rotated; keys in code (`code-review.md` §secrets).
- **Public/anonymous grants:** S3 bucket policy `Principal:*`, `authenticated-users`
  ACL (any AWS account), public GCS/Blob, RDS/DB publicly accessible, security group
  `0.0.0.0/0` to admin/DB ports.
- **No guardrails:** missing SCP/Org policy, no CloudTrail/audit logging, no MFA on
  privileged/root, root access keys present.

Prefer least-privilege, scoped resources, condition keys, permission boundaries, and
short-lived credentials. Flag every `*` in an action or resource for justification.

## CI/CD (A03 supply chain)

CI is now a top-tier target (tj-actions `CVE-2025-30066`, an action used by 23k+ repos, leaked
CI secrets into build logs by repointing mutable tags; the Shai-Hulud worm family spreads through
CI tokens). Check:

- **Pin every third-party Action to a full commit SHA** — tags/branches are mutable and were
  the exact vector in 2025's biggest CI compromise. Run **`zizmor`** (GitHub Actions static
  auditor: unpinned actions, script injection, dangerous triggers, over-broad tokens).
- **Least-privilege `GITHUB_TOKEN`** — set a top-level `permissions:` block (default read-only);
  grant write only per-job where needed.
- **`pull_request_target` / `workflow_run`** running untrusted PR code **with secrets** — the
  classic privilege-escalation trigger. Never check out + build untrusted PR head with secrets.
- **Script injection** — untrusted `${{ github.event.* }}` (PR title/body/branch) interpolated
  into a `run:` shell block → command injection. Pass via `env:` and quote, don't inline.
- **No secrets echoed to logs**; secrets in the platform secret store, not in workflow files.
- **OIDC / trusted publishing** over long-lived cloud keys and npm tokens (short-lived, scoped).
- **Publish provenance** — npm `--provenance` / SLSA build attestation (Sigstore); consumers
  verify with `npm audit signatures`.
- **`npm ci` (not `install`)** and `--ignore-scripts` for untrusted installs; review lockfile
  `resolved`/`integrity` drift; avoid freshly-published deps (<7 days).

## Deliverable

Findings with the exact file/resource + secure config snippet. Mark severity by
exposure (internet-facing unauthenticated > internal). Note KEV-listed image CVEs first.
