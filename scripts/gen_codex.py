#!/usr/bin/env python3
"""Generate the Codex plugin from the Claude Code plugin.

    python3 scripts/gen_codex.py            # write the generated files
    python3 scripts/gen_codex.py --check    # exit 1 if any of them is stale; writes nothing

The kit is authored once, in Claude Code's formats, under `plugins/secaudit/claude/`. The Codex
plugin under `plugins/secaudit/codex/` is a second plugin root, and a plugin may only load what
is inside its own root — so everything Codex needs is written there by this script:

  claude/skills/**            ->  codex/skills/**                        copied byte for byte
  claude/commands/<name>.md   ->  codex/skills/<name>/SKILL.md           a skill, invoked as $<name>
                                  codex/skills/<name>/agents/openai.yaml ...and only by name
  claude/agents/<name>.md     ->  codex/agents/<name>.toml               a custom agent definition
  claude/hooks/hooks.json     ->  codex/hooks/hooks.json                 same hook, Codex's root variable
  claude/hooks/*.py           ->  codex/hooks/*.py                       copied byte for byte
  claude/.claude-plugin/plugin.json  ->  codex/.codex-plugin/plugin.json
  .claude-plugin/marketplace.json    ->  .agents/plugins/marketplace.json

Nothing under `claude/` is written, so the Claude Code plugin is exactly what its sources say,
and nothing under `codex/` is authored, so the two cannot be edited apart: `--check` is run by
`scripts/check_repo.py`, and a skill, command, agent, hook or manifest that changes without the
Codex plugin being regenerated fails the build instead of quietly disagreeing.

WHY THE COMMANDS BECOME EXPLICIT-ONLY SKILLS. Codex has no plugin commands. A skill is the only
thing a plugin can add that a user can call by name, so each command becomes one. They are
marked `allow_implicit_invocation: false` because the `security-audit` skill already carries
the trigger phrases: four more descriptions competing for the same request would make routing
worse, and a command is something a user types, in both harnesses.

WHY THE ALLOWLIST IS RESTATED AS PROSE. A command's `allowed-tools` is enforced by Claude Code.
Codex has no per-skill allowlist, so the generated skill lists the same commands and states
them as a rule. That is weaker than enforcement and the skill says so rather than implying
otherwise; the authorization hook is the deterministic layer in both harnesses.

WHY THE AGENT IS NOT LOADED FROM THE PLUGIN. Codex discovers custom agents in
`$CODEX_HOME/agents/` and in a project's `.codex/agents/`, not inside a plugin. The generated
`.toml` is therefore installed by `plugins/secaudit/codex/install.py`, and every generated skill
names the fallback for a session that does not have it.
"""
from __future__ import annotations

import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLAUDE_REL = "plugins/secaudit/claude"
CODEX_REL = "plugins/secaudit/codex"
CLAUDE = os.path.join(REPO, *CLAUDE_REL.split("/"))

SCRIPT = "scripts/gen_codex.py"

# The part of the Codex manifest that has no Claude Code source to derive from: how the plugin
# is presented in Codex's plugin list. Everything else in the manifest is read from the Claude
# manifest, so a version bump or a new keyword cannot be made in one and forgotten in the other.
DISPLAY_NAME = "SecAudit"
CATEGORY = "Coding"
CAPABILITIES = ["Interactive", "Read", "Write"]
DEFAULT_PROMPTS = [
    "Run $secaudit-code on this repository",
    "Run $secaudit-deps to check dependencies and secrets",
    "Run $secaudit-passive against a URL I own",
]

# The agent the skills delegate to. Named once so the link to its instructions in every generated
# skill is one the build can check exists.
VERIFIER = "secaudit-verifier"

# A description is where the two harnesses name themselves. Rewritten rather than duplicated so
# the Codex manifest cannot describe a different product from the Claude one.
HARNESS_NAME = (("for Claude Code", "for Codex"),)

# Claude Code and Codex each expand their own name for the plugin's root in a hook command.
# Codex also accepts Claude's, but a Codex plugin that only works through a compatibility alias
# is one release note away from not working.
PLUGIN_ROOT_VARIABLE = ("${CLAUDE_PLUGIN_ROOT}", "${PLUGIN_ROOT}")


def read(rel: str) -> str:
    # newline="" so a copied file is compared and written with the bytes it has, on any platform.
    with open(os.path.join(REPO, *rel.split("/")), encoding="utf-8", newline="") as f:
        return f.read()


def split_frontmatter(text: str, rel: str) -> tuple[dict[str, str], str]:
    """`key: value` frontmatter and the body after it.

    Deliberately not a YAML parser: commands and agents use one line per key and nothing else,
    and a construct this does not understand must stop the build rather than be half-read into
    a generated file that looks plausible.
    """
    text = text.replace("\r\n", "\n")
    if not text.startswith("---\n"):
        raise SystemExit(f"{SCRIPT}: {rel} has no frontmatter")
    head, sep, body = text[4:].partition("\n---\n")
    if not sep:
        raise SystemExit(f"{SCRIPT}: {rel} has unterminated frontmatter")
    fields: dict[str, str] = {}
    for line in head.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"([A-Za-z][\w-]*):\s*(.*)$", line)
        if not m:
            raise SystemExit(f"{SCRIPT}: {rel} frontmatter line is not `key: value`: {line!r}")
        value = m.group(2).strip()
        if value in (">", ">-", "|", "|-", ""):
            raise SystemExit(f"{SCRIPT}: {rel} uses a multi-line value for `{m.group(1)}`; "
                             f"this generator reads single-line frontmatter only")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        fields[m.group(1)] = value
    return fields, body.lstrip("\n")


def names(directory: str) -> list[str]:
    full = os.path.join(CLAUDE, directory)
    return sorted(n[:-3] for n in os.listdir(full) if n.endswith(".md"))


def tree(directory: str) -> list[str]:
    """Every file under a directory of the Claude plugin, as paths relative to that directory."""
    root = os.path.join(CLAUDE, directory)
    found = []
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        found += [os.path.relpath(os.path.join(current, name), root).replace("\\", "/")
                  for name in filenames if not name.endswith(".pyc") and name != ".DS_Store"]
    return sorted(found)


def split_tools(value: str) -> tuple[list[str], list[str]]:
    """A Claude Code tool list as (plain tool names, Bash command prefixes)."""
    plain: list[str] = []
    bash: list[str] = []
    for item in re.findall(r"[A-Za-z_]+\([^)]*\)|[A-Za-z_]+", value):
        m = re.match(r"Bash\((.*)\)$", item)
        if m:
            bash.append(m.group(1).rstrip("*").strip())
        else:
            plain.append(item)
    return plain, bash


def generated_note(source: str) -> str:
    return f"GENERATED by {SCRIPT} from {source} — do not edit."


# --------------------------------------------------------------------------- commands -> skills

def codex_body(body: str, name: str, commands: list[str]) -> str:
    """A command body in Codex's terms: no `$ARGUMENTS` substitution, `$name` instead of `/name`."""
    body = body.replace(
        "`$ARGUMENTS`",
        f"the arguments given with this skill — whatever the user wrote after `${name}`")
    if "$ARGUMENTS" in body:
        raise SystemExit(f"{SCRIPT}: commands/{name}.md uses $ARGUMENTS in a form this "
                         f"generator does not rewrite")
    # Longest first, so `/secaudit-code` is not rewritten as `/secaudit` plus a suffix.
    for command in sorted(commands, key=len, reverse=True):
        body = re.sub(rf"(?<![\w/.]){re.escape('/' + command)}(?![\w-])", f"${command}", body)
    return body


def command_skill(name: str, commands: list[str]) -> str:
    source = f"{CLAUDE_REL}/commands/{name}.md"
    fields, body = split_frontmatter(read(source), source)
    description = fields.get("description")
    if not description:
        raise SystemExit(f"{SCRIPT}: {source} has no description")
    hint = fields.get("argument-hint", "")
    if hint:
        description = f"{description} Arguments: {hint}"
    _, bash = split_tools(fields.get("allowed-tools", ""))
    allowlist = ", ".join(f"`{b}`" for b in bash)
    others = ", ".join(f"`${c}`" for c in commands)
    table = "\n".join(f"| {said} | {means} |" for said, means in (
        ("The text says", "Under Codex"),
        ("---", "---"),
        ("the **security-audit** skill",
         "this plugin's `security-audit` skill (`secaudit:security-audit`). Open its `SKILL.md` "
         "and follow it, `references/` included."),
        ("`/secaudit`, any `/command`", f"the skill of the same name: {others}."),
        ("Read / Grep / Glob", "shell read commands (`cat`, `sed -n`, `rg`, `ls`)"),
        ("WebSearch / WebFetch", "the web search tool"),
        ('Task, "a background subagent"', "spawn an agent and wait for its result"),
        ("the `secaudit-verifier` agent",
         "the custom agent of that name when this session has one; otherwise a default agent "
         f"given the `developer_instructions` of [agents/{VERIFIER}.toml]"
         f"(../../agents/{VERIFIER}.toml) as its instructions. Either way it is read-only: it "
         "reports, it does not edit."),
    ))

    return f"""---
name: {name}
description: {json.dumps(description, ensure_ascii=False)}
---

<!-- {generated_note(source)} -->

# {name}

The Codex form of SecAudit's `/{name}` command. It runs when the user names it (`${name}`), and
whatever they wrote after the name is its arguments.

## Reading this under Codex

The kit's skills and its verifier agent are written once, in Claude Code's vocabulary, and this
plugin carries them unchanged. Read them with this table:

{table}

Two things differ from Claude Code, and both matter:

1. **The command allowlist is a rule here, not a harness limit.** In Claude Code this command may
   run only the shell commands below without asking. Codex has no per-skill allowlist, so the
   same list binds as a rule: while this skill is running, ask the user before running anything
   outside it.

   {allowlist}

2. **The authorization hook runs only once it is trusted.** Codex skips a plugin's hook until the
   user has reviewed it in `/hooks`. Until then the passive-by-default posture rests on the
   skill's own authorization gate, which binds either way. A command that was not blocked is not
   a command that was authorized.

## Procedure

{codex_body(body, name, commands).rstrip()}
"""


def command_policy(name: str) -> str:
    return f"""# {generated_note(f'{CLAUDE_REL}/commands/{name}.md')}
# A command runs when the user names it (${name}), never implicitly — the `security-audit`
# skill carries the trigger phrases.
policy:
  allow_implicit_invocation: false
"""


# --------------------------------------------------------------------------- agents -> toml

def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def toml_multiline(value: str) -> str:
    """A TOML multi-line basic string. Backslashes and a run of three quotes are the only two
    things that can end or corrupt one, so those are the only two things escaped."""
    escaped = value.replace("\\", "\\\\").replace('"""', '""\\"')
    return f'"""\n{escaped.rstrip()}\n"""'


def agent_toml(name: str) -> str:
    source = f"{CLAUDE_REL}/agents/{name}.md"
    fields, body = split_frontmatter(read(source), source)
    if fields.get("name") != name:
        raise SystemExit(f"{SCRIPT}: {source} declares name `{fields.get('name')}`")
    granted, _ = split_tools(fields.get("tools", ""))
    denied, _ = split_tools(fields.get("disallowedTools", ""))
    writers = {"Write", "Edit", "NotebookEdit"}
    read_only = not (writers & set(granted))

    contract = [
        "# CODEX TOOL CONTRACT",
        "This role was written for Claude Code, where its frontmatter grants exactly these "
        f"tools: {', '.join(granted)}"
        + (f" — and denies {', '.join(denied)}" if denied else "")
        + ". Codex gives an agent the session's toolset instead, so the same limits are stated "
        "here and bind you as rules:",
    ]
    if read_only:
        contract.append(
            "- READ-ONLY. Never create, modify, move or delete a file — not with `apply_patch`, "
            "not with shell write syntax (`>`, `>>`, `tee`, `cp`, `mv`, `rm`, `sed -i`, a script "
            "that opens a file for writing). Return your result in your final message.")
    if "Bash" in granted:
        contract.append(
            "- Shell is allowed for read-only inspection and safe, minimal verification only.")
    contract.append(
        "- Where the text below names Read/Grep/Glob, use shell read commands; "
        "WebSearch/WebFetch means the web search tool.")

    lines = [f"# {generated_note(source)}",
             f"name = {toml_string(name)}",
             f"description = {toml_string(fields['description'])}"]
    # The Claude model name is not carried over: an agent inherits the session's model under
    # Codex. The reasoning effort is the part of that choice that translates.
    if fields.get("effort"):
        lines.append(f"model_reasoning_effort = {toml_string(fields['effort'])}")
    if read_only:
        lines.append('sandbox_mode = "read-only"')
    instructions = "\n".join(contract) + "\n\n" + body
    lines.append(f"developer_instructions = {toml_multiline(instructions)}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- manifests

def for_codex(text: str) -> str:
    for claude, codex in HARNESS_NAME:
        text = text.replace(claude, codex)
    return text


def dump(obj: dict) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def marketplace_entry() -> tuple[dict, dict]:
    marketplace = json.loads(read(".claude-plugin/marketplace.json"))
    entries = [p for p in marketplace["plugins"] if p["name"] == "secaudit"]
    if len(entries) != 1:
        raise SystemExit(f"{SCRIPT}: .claude-plugin/marketplace.json does not list `secaudit` "
                         f"exactly once")
    if entries[0]["source"] != f"./{CLAUDE_REL}":
        raise SystemExit(f"{SCRIPT}: .claude-plugin/marketplace.json points the plugin at "
                         f"`{entries[0]['source']}`; this generator reads ./{CLAUDE_REL}")
    return marketplace, entries[0]


def codex_plugin_manifest() -> str:
    claude = json.loads(read(f"{CLAUDE_REL}/.claude-plugin/plugin.json"))
    marketplace, entry = marketplace_entry()
    manifest = {key: claude[key] for key in
                ("name", "version", "description", "author", "homepage", "repository",
                 "license", "keywords") if key in claude}
    manifest["description"] = for_codex(manifest["description"])
    manifest["skills"] = "./skills/"
    manifest["hooks"] = claude["hooks"]
    manifest["interface"] = {
        "displayName": DISPLAY_NAME,
        "shortDescription": for_codex(marketplace["description"]).rstrip("."),
        "longDescription": entry["description"],
        "developerName": claude["author"]["name"],
        "category": CATEGORY,
        "capabilities": CAPABILITIES,
        "websiteURL": claude["homepage"],
        "defaultPrompt": DEFAULT_PROMPTS,
    }
    return dump(manifest)


def codex_marketplace() -> str:
    marketplace, entry = marketplace_entry()
    return dump({
        "name": marketplace["name"],
        "interface": {"displayName": DISPLAY_NAME},
        "plugins": [{
            "name": entry["name"],
            "source": {"source": "local", "path": f"./{CODEX_REL}"},
            "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
            "category": CATEGORY,
        }],
    })


# --------------------------------------------------------------------------- hooks

def codex_hooks() -> dict[str, str]:
    """The hook configuration with Codex's root variable, and the scripts it runs, unchanged.

    The path comes from the Claude manifest rather than being assumed, because the manifest is
    what decides which file is the hook configuration. Only `.json` and `.py` are carried: the
    hook's README documents the Claude Code side and links into the repository from there."""
    claude = json.loads(read(f"{CLAUDE_REL}/.claude-plugin/plugin.json"))
    config = claude["hooks"]
    if not (isinstance(config, str) and config.startswith("./hooks/")):
        raise SystemExit(f"{SCRIPT}: the Claude manifest's `hooks` is not a ./hooks/ path")
    files: dict[str, str] = {}
    for rel in tree("hooks"):
        if not rel.endswith((".json", ".py")):
            continue
        text = read(f"{CLAUDE_REL}/hooks/{rel}")
        if f"./hooks/{rel}" == config:
            if PLUGIN_ROOT_VARIABLE[0] not in text:
                raise SystemExit(f"{SCRIPT}: {CLAUDE_REL}/hooks/{rel} does not use "
                                 f"{PLUGIN_ROOT_VARIABLE[0]}; the Codex copy would be unanchored")
            text = text.replace(*PLUGIN_ROOT_VARIABLE)
        files[f"{CODEX_REL}/hooks/{rel}"] = text
    return files


# --------------------------------------------------------------------------- the file set

def outputs() -> dict[str, str]:
    commands = names("commands")
    shared = sorted({rel.split("/")[0] for rel in tree("skills")})
    clash = sorted(set(commands) & set(shared))
    if clash:
        raise SystemExit(f"{SCRIPT}: a command and a skill share a name, and under Codex both "
                         f"are skills: {clash}")
    if VERIFIER not in names("agents"):
        raise SystemExit(f"{SCRIPT}: the generated skills delegate to `{VERIFIER}`, and "
                         f"{CLAUDE_REL}/agents/{VERIFIER}.md does not exist")

    files: dict[str, str] = {}
    for rel in tree("skills"):
        files[f"{CODEX_REL}/skills/{rel}"] = read(f"{CLAUDE_REL}/skills/{rel}")
    for name in commands:
        files[f"{CODEX_REL}/skills/{name}/SKILL.md"] = command_skill(name, commands)
        files[f"{CODEX_REL}/skills/{name}/agents/openai.yaml"] = command_policy(name)
    for name in names("agents"):
        files[f"{CODEX_REL}/agents/{name}.toml"] = agent_toml(name)
    files.update(codex_hooks())
    files[f"{CODEX_REL}/.codex-plugin/plugin.json"] = codex_plugin_manifest()
    files[".agents/plugins/marketplace.json"] = codex_marketplace()
    return files


# Directories this script owns outright: a file in one of them that it did not produce is a
# leftover from a skill, command, agent or hook that no longer exists, and Codex would still
# load it. `README.md` and `install.py` beside them are written by hand and are not listed.
OWNED = tuple(f"{CODEX_REL}/{d}" for d in ("skills", "agents", "hooks", ".codex-plugin"))


def leftovers(expected: dict[str, str]) -> list[str]:
    found = []
    for owned in OWNED:
        for directory, dirnames, filenames in os.walk(os.path.join(REPO, *owned.split("/"))):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for filename in filenames:
                rel = os.path.relpath(os.path.join(directory, filename), REPO).replace("\\", "/")
                if rel not in expected and filename != ".DS_Store":
                    found.append(rel)
    return sorted(found)


def stale(expected: dict[str, str]) -> list[str]:
    out = []
    for rel, content in expected.items():
        try:
            current = read(rel)
        except OSError:
            current = None
        if current != content:
            out.append(rel)
    return sorted(out)


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    expected = outputs()
    changed, extra = stale(expected), leftovers(expected)

    if "--check" in argv:
        if changed or extra:
            print("The Codex plugin is stale — run: python3 scripts/gen_codex.py")
            print("\n".join(f"  changed: {rel}" for rel in changed))
            print("\n".join(f"  not generated (remove it): {rel}" for rel in extra))
            return 1
        print(f"The Codex plugin is current — {len(expected)} generated files.")
        return 0

    for rel in changed:
        path = os.path.join(REPO, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(expected[rel])
        print(f"wrote {rel}")
    for rel in extra:
        print(f"not generated, left in place — remove it by hand: {rel}")
    if not changed:
        print(f"Nothing to write — {len(expected)} generated files are current.")
    return 1 if extra else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
