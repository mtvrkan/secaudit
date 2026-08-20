# SecAudit over MCP

Claude Code gets SecAudit as a plugin. Everything else gets it through the Model Context
Protocol server: Codex, Cursor, OpenCode, Copilot CLI, Zed, or anything that speaks MCP.

One engine behind all of them. The numbers in [`eval/scorecard.md`](../eval/scorecard.md)
describe the plugin, the CLI and this server, because they are the same code — a second
implementation per harness is how two clients end up disagreeing about whether a file is safe.

## What every client needs

Whatever the config file looks like, every MCP client needs the same three facts:

| | |
|---|---|
| **Command** | `python3` (or `python` on Windows) |
| **Arguments** | `-m`, `secaudit_mcp` |
| **Transport** | stdio |

After `pip install secaudit-kit` the console script `secaudit-mcp` works as the command with no
arguments at all. From a checkout, set `PYTHONPATH` to the `kit/` directory instead.

Verify it before wiring anything up:

```bash
python3 -m secaudit_mcp --tools        # prints the tool manifest and exits
```

## Per-client configuration

Config formats move; the command above does not. If a snippet below has drifted from what your
client documents, trust the client and keep the command.

**Claude Code** — the plugin is the better path here, but the server works too:

```bash
claude mcp add secaudit -- python3 -m secaudit_mcp
```

**Codex CLI** — `~/.codex/config.toml`:

```toml
[mcp_servers.secaudit]
command = "python3"
args = ["-m", "secaudit_mcp"]
```

**Cursor** — `.cursor/mcp.json` in the project, or the global equivalent:

```json
{ "mcpServers": { "secaudit": { "command": "python3", "args": ["-m", "secaudit_mcp"] } } }
```

**VS Code / Copilot CLI** — `.mcp.json` or `.vscode/mcp.json`:

```json
{ "servers": { "secaudit": { "command": "python3", "args": ["-m", "secaudit_mcp"] } } }
```

**OpenCode** — `opencode.json`:

```json
{ "mcp": { "secaudit": { "type": "local", "command": ["python3", "-m", "secaudit_mcp"] } } }
```

## Tools

| Tool | What it does |
|---|---|
| `scan_source` | Deterministic Tier-0 audit of local source: pattern detectors plus source→sink taint analysis. Markdown, JSON or SARIF. |
| `scan_dependencies` | Advisories for declared dependencies, each classified by whether the code actually imports the package (OpenVEX `affected` / `not_affected` / `under_investigation`) with the evidence for the call. |
| `generate_sbom` | CycloneDX 1.6 SBOM. Unresolvable versions are flagged, never guessed from a range. |
| `compliance_pack` | EU CRA evidence pack: SBOM + vulnerability register + ASVS chapter mapping + clause coverage. |
| `explain_finding` | What a detector or taint sink matches, its CWE and ASVS chapter, the fix, and how much the rule actually claims. |
| `coverage` | What the engine cannot see — depth per language, documented false-negative sources, classes with no deterministic coverage. |

## Two deliberate omissions

**No live-target tools.** No tool here probes a system. `scan_dependencies` and
`compliance_pack` do reach the network — they look advisories up by package name through an
installed scanner — which is a different thing from a request aimed at someone's host, and
worth saying precisely rather than rounding to "offline". SecAudit's live mode is real and
stays in the Claude Code plugin behind its
[`scope.yaml` authorization gate](authorization.md), because consent to probe a running system
is a human decision. An MCP `tools/call` carries no evidence that anyone gave it — and a tool
that scans whatever URL it is handed is a tool that scans whatever a prompt injection puts in
front of it. The test suite asserts no tool schema accepts a `url`, `host` or `endpoint`, so
this cannot be reintroduced quietly.

**No `suggest_patch` yet.** Patch generation is on the roadmap with an independent review agent
that has to vouch for the patch before it is written out. Until that exists, a tool that emits
a security patch nothing verified is worse than no tool.

## Why `coverage` is a tool and not a README section

An MCP tool is called by a model, not a person. A model that receives findings but has no way
to ask for the bounds will summarise an empty result as "no security issues found", which is a
claim the engine never made. So the same generated limitations the reports carry are callable,
the server's `initialize` instructions tell the client to call it before summarising, and every
scanning tool's description points at it.

A clean result means these rules did not fire, in these languages, across the files that
were scanned. The
full version is in [what we miss](what-we-miss.md).
