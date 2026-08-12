# SecAudit hooks

## `active-scan-guard.py` — PreToolUse authorization gate

A deterministic, harness-level guard that makes SecAudit's *passive-by-default* posture a
real gate instead of relying only on model discipline. It inspects every `Bash` command
before it runs and blocks the **active** patterns unless authorization is asserted:

- offensive scanners (`nuclei`, `nmap`, `sqlmap`, ZAP, `hydra`, `ffuf`, …),
- state-changing / payload-bearing HTTP requests (`curl -X POST`, `--data`, `-F`, `-T`, …), and
- read-only `GET`s carrying a crafted probe payload (SQLi canary, path-traversal to a system
  file, cloud-metadata SSRF, XSS/SSTI marker, CRLF/null-byte) — a probe, not passive recon.

A plain read-only `GET`/`HEAD` of a real resource, TLS/cert inspection, tech fingerprinting,
and all local static analysis (SAST / dependency / secret scanners) are never blocked — they
need no gate. The probe-payload check is high-precision (common OWASP canaries only); an
obfuscated/encoded payload or a `WebFetch`-tool GET is not shell-visible and still relies on
the skill's authorization discipline — this is defense-in-depth, not a complete WAF.
See [`../../../docs/authorization.md`](../../../docs/authorization.md).

### Asserting authorization (to allow active testing)

Either of:

- a `scope.yaml` in the working directory containing `i_am_authorized: true`, **kept untracked
  by git** (start from [`../../../templates/scope.example.yaml`](../../../templates/scope.example.yaml)), or
- the environment variable `SECAUDIT_ACTIVE=1` for the session.

A `scope.yaml` that is committed to the repository is ignored: it arrived with a clone, so it
is not an assertion this operator made, and treating it as one would let any project you open
unlock active scanning. The guard checks with `git ls-files`; if git cannot answer, the file is
refused rather than trusted.

Even when authorized, the guard's absolute limits still stand: no DoS, brute-force, or data
exfiltration.

### Interpreter resolution (cross-platform)

`hooks.json` invokes the guard as:

```
python3 <guard> || python <guard> || py <guard>
```

The fallback chain matters because no single interpreter name exists everywhere: Linux/macOS
expose `python3` (and sometimes `python`), while a python.org install on Windows provides
`python` and the `py` launcher but **not** `python3`. `${CLAUDE_PLUGIN_ROOT}` is expanded by
Claude Code, so the command is shell-agnostic (works under `sh` and `cmd.exe`).

Crucially, the guard **always exits 0** and signals a block by printing a PreToolUse `deny`
decision to stdout (not via a non-zero exit). This is what makes the `||` chain correct: a
non-zero "block" exit would make `||` treat the block as a failure and re-run the guard on an
already-consumed stdin — the re-run would read empty input and fail open, silently dropping
the block. Because both the allow and block paths exit 0, the fallback fires **only** when an
interpreter is genuinely absent (stdin still intact for the next one). The deny payload
carries both the modern `permissionDecision: deny` and the legacy `decision: block` fields so
any Claude Code version honors it.

### Fail-open is intentional (and bounded)

The guard **fails open** on a malformed/unparseable PreToolUse payload so a bad payload can
never wedge a session — this is a defense-in-depth layer *on top of* the skill's own
authorization discipline, not the only control. It blocks (emits the `deny` decision)
whenever it can parse the payload and recognizes an unauthorized active command. If no Python
interpreter is present at all, the hook cannot run and the skill's in-prompt authorization
gate remains the control; install Python (any of the three names above) to get the
deterministic layer.

### Self-test

```
python3 plugins/secaudit/hooks/active-scan-guard.py --selftest
```

Asserts the active patterns block and passive/local ones pass while unauthorized, and that
`SECAUDIT_ACTIVE=1` lets an active command through. Wired into CI
([`../../../.github/workflows/validate.yml`](../../../.github/workflows/validate.yml)).
