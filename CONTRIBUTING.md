# Contributing to SecAudit

Thanks for helping make SecAudit better and safer! Contributions of all sizes are welcome.

## Ground rules

- SecAudit is a **defensive** tool. Contributions must not add weaponized exploits,
  malware, DoS/brute-force capability, or unauthorized-access tooling. New checks should
  help owners *find and fix* issues in *their own* systems.
- Keep the safe-by-default posture: anything active (payloads, probes, fuzzing) must be
  behind the authorization gate and documented as such.

## Good first contributions

- **New vulnerability checks** — add to the relevant `references/*.md` with the class,
  detection hint, safe verification, and fix. Map to OWASP + CWE.
- **Tool integrations** — add a scanner to `references/tooling.md` (detect → invoke →
  parse), keeping the "works without it" fallback intact.
- **Language coverage** — new source-language hotspots in `references/code-review.md`.
- **False-positive fixes** — sharpen a check that over-reports.
- **Docs & examples** — clearer guides, more sanitized example reports.
- **Report localization** — additional report languages in `references/report-template.md`.

## Run the checks locally

Every gate CI runs is a script you can run yourself. There is no check that only exists in
the workflow file:

```bash
python3 scripts/run_checks.py          # all 15 gates, same as CI
python3 scripts/run_checks.py --fast   # structure + consistency + hook guard (seconds)
python3 scripts/run_checks.py --list   # what each gate is and how to run it alone
```

Two gates deserve a note, because they fail in ways that look like a bug and are not:

- **`check_repo.py` (checks 11–20)** — manifests, plugin layout, frontmatter, the
  command-allowlist subset rule, dangling references, relative links, hook wiring, stray
  secrets.
- **`check_consistency.py` (checks 01–10)** — recomputes every number the docs state about
  the kit from the detector table, the golden set and the shipped plugin tree. **If you add a
  detector or a golden finding, a stated count somewhere will now be wrong and the gate will
  say which.** That is the gate working. Fix the document, never the derivation.
  `python3 scripts/check_consistency.py --facts` prints the current derived values.

If you add a gate to `validate.yml`, add it to `GATES` in `scripts/run_checks.py` too — the
two are kept in sync by hand.

## How to contribute

1. Fork and create a branch (`feat/…` or `fix/…`).
2. Make your change. Keep reference files tight and skimmable — they're loaded into
   Claude's context on demand, so favor signal over volume.
3. If you touch a manifest (`plugin.json`, `marketplace.json`), validate it:
   ```bash
   claude plugin validate . --strict
   claude plugin validate ./plugins/secaudit --strict
   ```
   `--strict` turns unknown-field warnings into errors. `scripts/check_repo.py` runs the same
   field-strictness rules offline, so you get the answer without the CLI.
4. Run `python3 scripts/run_checks.py` and make it green before opening the PR.
5. Test the change in a Claude Code session against a target you own.
6. Open a PR describing what class/tool it adds and why. Reference any OWASP/CWE IDs.

## Sanitized examples only

Never commit real audit output containing real target names, live session cookies/tokens,
IP addresses, or PII. Example reports must be **fully sanitized/fictional** (see
`examples/`).

## Style

- Reference files: Markdown, concrete commands, OWASP/CWE mappings, no fluff.
- Docs: English. Report *output* may be localized; keep technical IDs canonical.

By contributing you agree your work is licensed under the [MIT License](LICENSE).
