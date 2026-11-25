# SecAudit under Codex

This folder is the Codex plugin. It is generated from the Claude Code plugin in
[`../claude/`](../claude), which is where the kit is written.

## Install

```bash
codex plugin marketplace add mtvrkan/secaudit
codex plugin add secaudit@secaudit-kit
```

Then, once:

1. In a Codex session, open `/hooks` and review the plugin's hook (`active-scan-guard.py`).
   Codex does not run a plugin hook until it has been trusted, and until then the
   passive-by-default posture rests on the skill's own authorization gate alone.
2. Install the verifier agent — a plugin cannot carry one:

   ```bash
   python3 install.py                  # $CODEX_HOME/agents, default ~/.codex/agents
   python3 install.py --project DIR    # or one project only: DIR/.codex/agents
   ```

   Run it from this folder in a clone of the repository, or from the installed copy under
   `~/.codex/plugins/cache/secaudit-kit/secaudit/<version>/`. `--check` reports drift,
   `--uninstall` removes it. Skipping this step loses nothing but the named role: the skills
   fall back to a default agent given the verifier's instructions.

## What maps to what

| Claude Code (`../claude/`) | Codex (this folder) |
| --- | --- |
| `skills/*` | `skills/*`, copied unchanged (`secaudit:security-audit`, `secaudit:compliance-pack`, `secaudit:exploitation-watch`) |
| `commands/*.md` (`/secaudit`, `/secaudit-code`, `/secaudit-deps`, `/secaudit-passive`) | `skills/<name>/SKILL.md`, invoked as `$secaudit`, `$secaudit-code`, `$secaudit-deps`, `$secaudit-passive` |
| a command runs when the user types it | `agents/openai.yaml` beside each of those skills, with `allow_implicit_invocation: false` |
| a command's `allowed-tools` | the same list inside the skill, stated as a rule — Codex has no per-skill allowlist |
| `agents/secaudit-verifier.md` | `agents/secaudit-verifier.toml`, installed by `install.py`; read-only by sandbox, not only by instruction |
| `hooks/hooks.json` | `hooks/hooks.json`, with `${PLUGIN_ROOT}` in place of `${CLAUDE_PLUGIN_ROOT}` |
| `hooks/active-scan-guard.py` | `hooks/active-scan-guard.py`, copied unchanged — Codex speaks the same PreToolUse contract |
| `.claude-plugin/plugin.json` | `.codex-plugin/plugin.json` |
| `/.claude-plugin/marketplace.json` | `/.agents/plugins/marketplace.json` |

Not carried over: the agent's Claude model name. Under Codex an agent inherits the session's
model and keeps its reasoning effort.

## Authorizing active testing

Exactly as in Claude Code: an untracked `scope.yaml` with `i_am_authorized: true` in the working
directory, or `SECAUDIT_ACTIVE=1` in the environment Codex was started from. See
[`../claude/hooks/README.md`](../claude/hooks/README.md).

## Do not edit the generated files

Everything here except this file and `install.py` is written by `scripts/gen_codex.py`, and so
is `.agents/plugins/marketplace.json` at the repository root. Change the source under
`../claude/` and regenerate:

```bash
python3 scripts/gen_codex.py
```

`scripts/check_repo.py` fails the build when the generated files are stale, and when a file
that was not generated is sitting where Codex would load it.
