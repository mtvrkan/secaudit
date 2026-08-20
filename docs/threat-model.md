# Threat model

A scanner reads code written by someone else and prints it back to you. That sentence contains
the whole problem: **the input is authored by the party the tool exists to be suspicious of**, and
the output lands in a terminal, a pull request, a CI log and a browser. This document says what
crosses each boundary, what enforces it, and — the part that makes a threat model worth writing —
what each control does **not** stop.

Nothing here is aspirational. Where a control does not exist, this says so.

## What is being protected

1. **The machine the scan runs on.** A scan must not become code execution by the scanned repo.
2. **The report's integrity.** A finding must say what the file actually contains, and a repo
   must not be able to edit, hide or forge the report describing it.
3. **The confidentiality of the scanned code.** Source stays local unless you opt into a tier
   that sends it, and then you should know exactly what left.
4. **The release artifacts.** What you install is what this repository built.

Out of scope by definition: the security of the code you point it at (that is the output, not the
threat), and the correctness of findings (measured in [`eval/`](../eval/), not here).

## The scanned repository is an untrusted author

This is the boundary that carries the most weight, because it is crossed on every single run —
including the passive, offline, no-key default.

**No code from the scanned repository is executed.** The engine has zero runtime dependencies and
never imports, evaluates, builds or installs anything it reads. There is no plugin loading, no
config file from the target that changes behaviour, and no `eval`. Analysis is regex and
hand-written structural passes over text.

**Every file under the target is opened**, including credential material — `.env`, `id_rsa`,
`*.pem`. That is deliberate: a committed key is exactly the finding this tool exists to report,
and a scanner that refuses to look cannot report it. What is controlled is what comes *back out*:
the secret detectors set `mask=True` and print a redaction rather than the value, and a gate
(check 10) fails the build on a CWE-798 detector that forgets. **`.env` is scanned only by those
masked rules.**

**Evidence lines and file paths are attacker-authored strings**, and until they were fixed, three
things passed through verbatim:

| What the repo could put in a line | What it did |
|---|---|
| `\x1b[2J`, `\r` | Repainted the terminal the report was printing into |
| U+202E and friends | [Trojan Source](https://trojansource.codes/) (CVE-2021-42574) — the evidence line renders in an order the file does not have |
| A backtick | Closed the markdown code span, so `[click](https://evil.example)` after it became a live link in a report pasted into a pull request |

All three are closed at the `Finding` constructor rather than in a renderer, because every tier
builds its own findings and a rule applied in one renderer holds for one renderer. Control and
format characters (Unicode `Cc`/`Cf`) are replaced by `<U+XXXX>` — **named, not deleted**, since
for the Trojan Source case the presence of the character *is* the finding. The markdown renderer
picks a code fence longer than any backtick run in the content. The HTML renderer already escaped;
it was the reasoning in its docstring that led to looking at the other two.

**Not stopped:** a repository large or pathological enough to make a scan slow. Cost grows with
the tree, an unbounded scan of a hostile repo is a local denial of service, and the per-package
timeout in the benchmark harness exists because of exactly one 30 MB package. There is no
wall-clock bound on `secaudit` itself.

## The report's readers

The markdown report is written to be pasted somewhere. After the fixes above it contains no
control characters and no unbalanced code spans, and the HTML report escapes every
attacker-influenced string. SARIF and JSON go through `json.dumps`, which escapes control
characters by construction.

**Not stopped:** a finding's *text* is still attacker-influenced content in a document a human
reads. Nothing prevents a repository from putting a plausible-looking sentence in a comment and
having it quoted in the evidence line. Read evidence as a quotation, never as the tool's own
statement.

## External scanners run as subprocesses

`semgrep`, `gitleaks`, `osv-scanner`, `npm audit` and `trivy` are invoked when present, with
argument lists (never a shell string), and their JSON output is parsed. They are optional; a
scan without them is the default and is what every published figure measures.

**Not stopped:** these are third-party binaries running with your privileges, resolved from
`PATH`. If `PATH` is attacker-controlled, so are they. A related real bug is worth repeating:
`shutil.which` honours `PATHEXT` and `CreateProcess` does not, so a `.cmd`-shimmed scanner was
detected as present and then silently unrunnable — a false sense of coverage rather than a
compromise, but the same seam.

## The network

The engine makes **no** network requests by default. Two feeds exist and both are opt-in with
`--exploitation`:

- **CISA KEV** — the whole feed is downloaded. Nothing about your project is sent.
- **FIRST EPSS** — queried by CVE id only, batched 100 at a time. No path, no package version, no
  hostname. **This does disclose which CVEs you are looking up**, which is a statement about your
  dependency set to a third party. That is the trade for the score; it is why the feed is opt-in.

An unreachable feed reports `unknown` and never a clean bill, and never lowers a severity.
Dependency advisories themselves come from the optional external scanners, not from a call this
engine makes.

## The LLM tier sends your source code

Tier 1 is off by default. When `--backend anthropic` or `--backend openai` is passed, **source
code leaves the machine** — excerpts around findings, then unflagged handler-ranked files, up to
240k characters across four calls. `--backend ollama` keeps it local; that makes the backend
choice a privacy decision rather than only a cost one.

Files matching credential patterns are withheld from **every** backend, local included
(`llmcontext.SECRET_BASENAMES` / `SECRET_SUFFIXES` / `SECRET_SEGMENTS`), and the count of
withheld files is stated in the context rather than dropped silently.

**Not stopped, and this is the sharp one: prompt injection from the scanned code.** The model is
shown attacker-authored source, so a comment can address the model directly. The mitigations are
narrow and worth stating exactly: a citation the model cannot ground in a real finding is
refused, the tier only annotates and re-ranks findings rather than creating scan authority, and
**every published number in this repository is Tier 0** — no measured claim depends on model
output. A triage note is a suggestion from something that read hostile input.

**Withholding is a Tier-1 boundary, not a Tier-0 one.** `is_secret_path` governs what is sent to
a backend. It does not govern what the local scan reads, which is the paragraph above.

## The MCP server

The server speaks JSON-RPC over stdio and is driven by whatever client you connect (Codex,
Cursor, OpenCode). It runs with your privileges. Tool arguments are validated for type and
existence — and **that is the whole path check: there is no workspace confinement.** A client can
ask it to scan any path the user can read, and `scan_dependencies` will additionally run the
external scanners against it.

This is stated rather than fixed because it is the same authority the client already has, and a
scanner that cannot be pointed at an arbitrary checkout is not usable. But the consequence is
real: **a prompt-injected MCP client can direct a scan at a path you did not intend**, and the
report it gets back contains evidence lines from those files. Treat the MCP server as being as
trusted as the client driving it.

## Active testing against a live target

Everything above is passive. The live-target track can send requests, and that is gated
deterministically rather than by model discipline: a `PreToolUse` hook
(`plugins/secaudit/hooks/active-scan-guard.py`) blocks offensive scanners, state-changing HTTP
methods, and read-only requests carrying probe payloads, unless authorization is asserted by an
untracked `scope.yaml` with `i_am_authorized: true` or `SECAUDIT_ACTIVE=1`.

**Not stopped**, and documented in [`authorization.md`](authorization.md) rather than implied
away: a sufficiently obfuscated payload, and anything sent through the `WebFetch` tool rather
than a shell command. The hook is defense in depth, not a WAF. The absolute limits — no DoS, no
brute force, no exfiltration of real user data, no persistence or lateral movement — are skill
discipline, not hook-enforced, and they hold even once authorized.

## The release pipeline

Actions are pinned by commit SHA, resolved through the API rather than typed. Publishing uses
OIDC with no stored key. `release.yml` builds in one job and attests in another, so the step that
produces an artifact and the step that vouches for it do not share a credential; SLSA build
provenance and an SBOM attestation are written over the wheel and the sdist. The SBOM is produced
by the tool being released, against its own source.

**Not stopped:** none of it has run yet. It fires only on a `v*` tag and there has not been one,
so this paragraph describes a configuration, not an observation. The `pypi` environment has **no
required reviewers configured** — naming an environment in a workflow does not by itself require
approval, and GitHub creates a missing one with no protection on first use.

## Suggested patches

Patches are written to `patches/` and **never applied**. An independent review agent with a
separate context has to vouch for one, and the finding's retest is re-run after you apply it. A
patch is a proposal from a process that read attacker-authored code; the review step exists
because of that, not as ceremony.

## Reporting a problem here

Vulnerabilities in SecAudit itself go through
[the security policy](https://github.com/mtvrkan/secaudit/security/policy) — private disclosure,
no exploit details in a public issue. Findings *about the code you scanned* are not this tool's
vulnerabilities; they are its output.
