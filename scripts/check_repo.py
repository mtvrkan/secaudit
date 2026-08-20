#!/usr/bin/env python3
"""Repository structure gate — manifests, plugin layout, links, and stray secrets.

These checks used to live as inline heredocs inside `.github/workflows/validate.yml`, where a
contributor could not run them without pushing. They are the same checks, moved into a file you
can run locally:

    python3 scripts/check_repo.py

Every check returns a list of failure strings; an empty list is a pass. Adding a check means
appending to CHECKS — the numbering is stable and referenced from CONTRIBUTING.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = os.path.join(REPO, "plugins", "secaudit")
SKILL = os.path.join(PLUGIN, "skills", "security-audit", "SKILL.md")
REFS = os.path.join(PLUGIN, "skills", "security-audit", "references")
MARKETPLACE = os.path.join(REPO, ".claude-plugin", "marketplace.json")
PLUGIN_JSON = os.path.join(PLUGIN, ".claude-plugin", "plugin.json")

# Documented manifest field sets. Claude Code silently ignores an unrecognized key, so a typo
# like `displayName` disables a feature with no error — we fail on it here instead.
PLUGIN_FIELDS = {"$schema", "name", "version", "description", "author", "homepage", "repository",
                 "license", "keywords", "dependencies", "hooks", "commands", "agents", "skills",
                 "mcpServers", "lspServers", "monitors", "channels", "userConfig", "settings"}
MARKETPLACE_ROOT_FIELDS = {"$schema", "name", "owner", "plugins", "version", "description",
                           "metadata", "forceRemoveDeletedPlugins",
                           "allowCrossMarketplaceDependenciesOn"}
MARKETPLACE_PLUGIN_FIELDS = PLUGIN_FIELDS | {"source", "category", "tags", "strict", "url",
                                             "sha", "ref", "path"}


def read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def repo_markdown() -> list[str]:
    out = []
    for path in glob.glob(os.path.join(REPO, "**", "*.md"), recursive=True):
        rel = os.path.relpath(path, REPO).replace("\\", "/")
        if rel.startswith(("node_modules/", ".git/", "site/")):
            continue
        out.append(rel)
    return sorted(out)


def frontmatter(path: str) -> str:
    txt = read(path)
    if not txt.lstrip().startswith("---"):
        return ""
    parts = txt.split("---", 2)
    return parts[1] if len(parts) >= 3 else ""


def bash_permissions(path: str) -> set[str]:
    fm = frontmatter(path)
    m = re.search(r"allowed-tools:\s*(.*?)(?:\n[a-zA-Z][\w-]*:|\Z)", fm, re.S)
    return {b.strip() for b in re.findall(r"Bash\(([^)]*)\)", m.group(1) if m else "")}


# --------------------------------------------------------------------------- checks

def check_11_manifests_parse() -> list[str]:
    fails = []
    for path in (MARKETPLACE, PLUGIN_JSON):
        try:
            load_json(path)
        except (OSError, json.JSONDecodeError) as e:
            fails.append(f"check 11: {os.path.relpath(path, REPO)} is not valid JSON: {e}")
    return fails


def check_12_manifest_required_fields() -> list[str]:
    fails = []
    mk = load_json(MARKETPLACE)
    if not mk.get("name"):
        fails.append("check 12: marketplace.json missing `name`")
    if not mk.get("owner", {}).get("name"):
        fails.append("check 12: marketplace.json missing `owner.name`")
    if not (isinstance(mk.get("plugins"), list) and mk["plugins"]):
        fails.append("check 12: marketplace.json `plugins[]` is empty")
    if not load_json(PLUGIN_JSON).get("name"):
        fails.append("check 12: plugin.json missing `name`")
    return fails


def check_13_no_unknown_manifest_fields() -> list[str]:
    fails = []

    def inspect(obj: dict, allowed: set[str], where: str) -> None:
        for key in obj:
            if key not in allowed:
                fails.append(f"check 13: {where} has unknown field `{key}`")

    inspect(load_json(PLUGIN_JSON), PLUGIN_FIELDS, "plugin.json")
    mk = load_json(MARKETPLACE)
    inspect(mk, MARKETPLACE_ROOT_FIELDS, "marketplace.json")
    for i, entry in enumerate(mk.get("plugins", [])):
        if isinstance(entry, dict):
            inspect(entry, MARKETPLACE_PLUGIN_FIELDS, f"marketplace.json plugins[{i}]")
    return fails


def check_14_plugin_structure() -> list[str]:
    required = [
        (SKILL, "file"),
        (os.path.join(PLUGIN, "commands"), "dir"),
        (os.path.join(PLUGIN, "agents"), "dir"),
        (REFS, "dir"),
        (os.path.join(PLUGIN, "hooks", "hooks.json"), "file"),
    ]
    fails = []
    for path, kind in required:
        ok = os.path.isfile(path) if kind == "file" else os.path.isdir(path)
        if not ok:
            fails.append(f"check 14: missing {kind} {os.path.relpath(path, REPO)}")
    return fails


def check_15_frontmatter_has_description() -> list[str]:
    """Commands and agents are routed by their description. Without one they are invisible."""
    fails = []
    for path in glob.glob(os.path.join(PLUGIN, "**", "*.md"), recursive=True):
        rel = os.path.relpath(path, REPO).replace("\\", "/")
        if rel.endswith("SKILL.md") or "/references/" in rel:
            continue
        head = read(path)[:600]
        if head.lstrip().startswith("---") and "description:" not in head:
            fails.append(f"check 15: {rel} has frontmatter but no `description:`")
    return fails


def check_16_command_allowlist_subset() -> list[str]:
    """A command may not grant Bash permissions the skill itself does not hold — that widens the
    blast radius past what the authorization gate and the skill's review cover."""
    skill_perms = bash_permissions(SKILL)
    if not skill_perms:
        return ["check 16: could not parse `allowed-tools` from SKILL.md"]
    fails = []
    for path in sorted(glob.glob(os.path.join(PLUGIN, "commands", "*.md"))):
        extra = bash_permissions(path) - skill_perms
        if extra:
            fails.append(f"check 16: {os.path.basename(path)} permits Bash the skill does not: "
                         f"{sorted(extra)}")
    return fails


def check_17_references_resolve() -> list[str]:
    """Any `references/NAME.md` mentioned anywhere in the plugin must be shipped. Auto-discovering
    — no hardcoded filename list that can drift."""
    present = {os.path.basename(p) for p in glob.glob(os.path.join(REFS, "*.md"))}
    missing = set()
    for path in glob.glob(os.path.join(PLUGIN, "**", "*.md"), recursive=True):
        for name in re.findall(r"references/([a-z0-9-]+\.md)", read(path)):
            if name not in present:
                missing.add(name)
    return [f"check 17: `references/{name}` is referenced but not shipped" for name in sorted(missing)]


def check_18_relative_links_resolve() -> list[str]:
    fails = []
    for rel in repo_markdown():
        base = os.path.dirname(os.path.join(REPO, rel))
        for _, target in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", read(os.path.join(REPO, rel))):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            path = target.split("#")[0]
            if path and not os.path.exists(os.path.normpath(os.path.join(base, path))):
                fails.append(f"check 18: {rel} -> {target}")
    return fails


def check_19_no_stray_secrets() -> list[str]:
    """Real-looking credentials must exist only inside the deliberately vulnerable fixture."""
    patterns = [re.compile(r"AKIA[0-9A-Z]{16}"),
                re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PGP) PRIVATE KEY-----")]
    allowed_exts = {".md", ".js", ".ts", ".json", ".yaml", ".yml", ".py", ".env", ".txt", ""}
    hits = set()
    for path in glob.glob(os.path.join(REPO, "**", "*"), recursive=True):
        rel = os.path.relpath(path, REPO).replace("\\", "/")
        if not os.path.isfile(path) or rel.startswith((".git/", "site/")):
            continue
        if "tests/fixtures/" in rel or os.path.splitext(rel)[1].lower() not in allowed_exts:
            continue
        try:
            txt = read(path)
        except (OSError, UnicodeDecodeError):
            continue
        if any(p.search(txt) for p in patterns):
            hits.add(rel)
    return [f"check 19: possible real secret outside fixtures: {h}" for h in sorted(hits)]


def check_20_hook_path_resolves() -> list[str]:
    """plugin.json's hooks path must point at a shipped file, or the authorization gate silently
    does not load and the whole passive-by-default posture drops to model discipline."""
    hooks = load_json(PLUGIN_JSON).get("hooks")
    if not hooks:
        return ["check 20: plugin.json declares no `hooks` path"]
    if not os.path.isfile(os.path.join(PLUGIN, hooks)):
        return [f"check 20: plugin.json hooks path does not resolve: {hooks}"]
    cfg = load_json(os.path.join(PLUGIN, hooks))
    if "PreToolUse" not in cfg.get("hooks", {}):
        return ["check 20: hooks.json declares no PreToolUse hook"]
    return []


CHECKS = [
    check_11_manifests_parse,
    check_12_manifest_required_fields,
    check_13_no_unknown_manifest_fields,
    check_14_plugin_structure,
    check_15_frontmatter_has_description,
    check_16_command_allowlist_subset,
    check_17_references_resolve,
    check_18_relative_links_resolve,
    check_19_no_stray_secrets,
    check_20_hook_path_resolves,
]


def main() -> int:
    # A legacy console codepage (e.g. Windows cp1254) must not crash a gate on an em dash.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    failures: list[str] = []
    for check in CHECKS:
        try:
            failures.extend(check())
        except Exception as e:  # a broken check must name itself, not vanish
            failures.append(f"{check.__name__} raised {type(e).__name__}: {e}")

    print(f"Repository structure — {len(CHECKS)} checks")
    if failures:
        print("FAIL:")
        print("\n".join("  - " + f for f in failures))
        return 1
    print("PASS — manifests, plugin layout, links and secret hygiene are intact.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
