#!/usr/bin/env python3
"""Render the landing page. Every number on it is computed from this repo, at build time.

    python3 scripts/gen_site.py            # write site/dist/
    python3 scripts/gen_site.py --check    # render, verify, discard (CI)

A marketing page is where a security tool is most tempted to round a number up, and the
temptation does not announce itself — someone edits prose six months after the measurement and
nobody notices the page now claims a recall the engine never had. So the template holds no
figures at all: it has `{{tokens}}`, and the values come from `eval/scorecard.json`, the
detector table, the compliance mapping and the gate list. `--check` fails if a token is
unsupplied, if a supplied token goes unused, or if a stat rendered onto the page disagrees with
its source.

Bilingual from one template rather than two files, because two files drift and the drift is
invisible until a Turkish reader is shown a number the English page corrected a year ago.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(REPO, "site")
DIST = os.path.join(SITE, "dist")

# One shell, one `<main>` per page. The shell carries the palette, the chrome, the nav, the
# footer and the script; a page carries only its own content and, if it needs any, its own rules
# through `{{page_css}}`. Copying the shell per page is the same mistake as writing the Turkish
# page by hand — the copy stops being a copy and nothing tells you when.
SHELL = os.path.join(SITE, "shell.html")


def page_body(name: str) -> str:
    return os.path.join(SITE, f"page-{name}.html")


def page_style(name: str) -> str:
    return os.path.join(SITE, f"css-{name}.css")

sys.path.insert(0, os.path.join(REPO, "kit"))
sys.path.insert(0, os.path.join(REPO, "scripts"))

ORIGIN = "https://secaudit.mtvrkan.com"
REPO_URL = "https://github.com/mtvrkan/secaudit"

# The author's signature, carried over from FollowLens' `developer-credit.tsx` so the two
# products sign themselves identically. Deliberately NOT in COPY and NOT translated: a signature
# reads the same in every language, which is also why it is a literal here rather than a
# translatable key — there is nothing for a translator to pick up by mistake.
DEVELOPER_NAME = "mtvrkan"
DEVELOPER_URL = "https://mtvrkan.com"

# `og:locale` wants a full language_TERRITORY tag, which the `lang` attribute deliberately
# does not carry: the pages are written for Turkish and English readers anywhere, not for two
# territories. This map exists only because the Open Graph vocabulary has no shorter form.
OG_LOCALES = {"en": "en_US", "tr": "tr_TR"}


def _site_images() -> tuple[dict, dict]:
    """The social cards and the home-screen icon, read from the script that draws them.

    Imported rather than restated, so the filename in the meta tag and the filename on disk are
    the same string by construction — and so the alt text describes the card the scraper will
    actually fetch. A page pointing at a card that does not exist renders as a broken preview,
    which is worse than no preview, and nothing but a human opening a share dialog would notice.
    """
    import gen_og_image
    return gen_og_image.COPY, gen_og_image.ICON


OG_CARDS, OG_ICON = _site_images()

_TOKEN = re.compile(r"\{\{(\w+)\}\}")


# --------------------------------------------------------------------------- facts

RV_README = os.path.join(REPO, "eval", "realvuln", "README.md")


def _rv_readme() -> str:
    with open(RV_README, encoding="utf-8") as f:
        return f.read()


def baselines(our_f3: str) -> list:
    """The benchmark's published baselines, read out of the page that already states them.

    These are the only figures on the site that are not this repository's own measurement, and
    there is nowhere machine-readable to get them from: RealVuln publishes them as prose. The
    choice is between typing them into this generator — where the whole point of the site is
    that nothing decaying is typed — and reading them from `eval/realvuln/README.md`, which
    check 27 already holds against `result.json`. So they are parsed, and the parse is gated:
    a table that stops having four rows, or whose SecAudit row stops agreeing with the scorer
    output, fails the build rather than rendering a stale comparison.
    """
    text = _rv_readme()
    try:
        after = text.split("Against the published baselines:", 1)[1]
    except IndexError:
        raise SystemExit("gen-site: eval/realvuln/README.md no longer states the baselines "
                         "table") from None

    rows = []
    for line in after.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            if rows:
                break
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != 5 or set(cells[0]) <= set("- :"):
            continue
        if cells[0].lower().startswith("category"):
            continue
        plain = [c.replace("**", "").strip() for c in cells]
        rows.append({"category": plain[0], "system": plain[1], "f3": plain[2],
                     "precision": plain[3], "recall": plain[4],
                     # The bold row is the one the benchmark did not publish — ours.
                     "ours": "SecAudit" in cells[1]})

    ours = [r for r in rows if r["ours"]]
    if len(rows) != 4 or len(ours) != 1:
        raise SystemExit(f"gen-site: expected 4 baseline rows with exactly 1 marked SecAudit, "
                         f"parsed {len(rows)} rows / {len(ours)} ours from README.md")
    if ours[0]["f3"] != our_f3:
        raise SystemExit(f"gen-site: the baselines table says SecAudit scores {ours[0]['f3']} "
                         f"and result.json says {our_f3}")
    return rows


def repro_commands() -> str:
    """The reproduction sequence, from the fenced block under README.md's `## Reproduce it`.

    Same reasoning as `baselines`: a command sequence copied onto a second page is a sequence
    that gets fixed in one place. A missing block fails the build."""
    text = _rv_readme()
    try:
        after = text.split("## Reproduce it", 1)[1]
        block = after.split("```bash", 1)[1].split("```", 1)[0]
    except IndexError:
        raise SystemExit("gen-site: eval/realvuln/README.md has no `## Reproduce it` bash "
                         "block") from None
    return block.strip("\n")


# --------------------------------------------------------------------------- install surfaces
#
# Six ways into one engine, and not one command on the install page is typed here. A stale
# figure on a marketing page is embarrassing; a stale command on an install page is broken —
# the reader runs it, it fails, and what they conclude is that the security scanner does not
# work. So every surface is read out of the file that defines it: the plugin ids from the
# manifest Claude Code itself loads, the package name and Python floor from `kit/pyproject.toml`,
# the Action's inputs from `action.yml`, the hook ids and their flags from
# `.pre-commit-hooks.yaml`, the client snippets and tool descriptions from `docs/mcp.md`, and
# the tool *names* from the server module. A file that stops having the shape these readers
# expect fails the build rather than rendering half a page — which is the same rule the figures
# have lived under since the first version of this script.
#
# The readers are regex rather than a YAML parse because the kit ships with zero runtime
# dependencies and its own build scripts hold to the same line. Each accepts exactly the shape
# the file it reads actually uses, and raises on anything else.

MARKETPLACE = os.path.join(REPO, ".claude-plugin", "marketplace.json")
PYPROJECT = os.path.join(REPO, "kit", "pyproject.toml")
COMMANDS_DIR = os.path.join(REPO, "plugins", "secaudit", "commands")
ACTION_YML = os.path.join(REPO, "action.yml")
DOCKERFILE = os.path.join(REPO, "Dockerfile")
HOOKS_YML = os.path.join(REPO, ".pre-commit-hooks.yaml")
MCP_DOC = os.path.join(REPO, "docs", "mcp.md")
SCANNERS_PY = os.path.join(REPO, "kit", "secaudit_core", "scanners.py")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def plugin_ids() -> dict:
    """Marketplace id, plugin id and version — from the manifest Claude Code itself reads.

    `/plugin install secaudit@secaudit-kit` is two identifiers that live in one JSON file and
    nowhere else. Typing them onto a page is how the page ends up naming a marketplace that was
    renamed a release ago, and the failure is silent on our side and total on the reader's."""
    data = json.loads(_read(MARKETPLACE))
    plugins = data.get("plugins") or []
    if len(plugins) != 1:
        raise SystemExit(f"gen-site: .claude-plugin/marketplace.json declares {len(plugins)} "
                         f"plugins; the install page is written for exactly one")
    return {"marketplace": data["name"], "plugin": plugins[0]["name"],
            "version": plugins[0]["version"], "owner": data["owner"]["name"]}


def plugin_commands() -> list:
    """The slash commands the plugin installs, out of their own frontmatter.

    Ordered shortest name first, which puts `/secaudit` — the one that runs the whole
    methodology — above the three that narrow it. Alphabetical would bury it under its own
    variants."""
    out = []
    for name in sorted(os.listdir(COMMANDS_DIR), key=lambda n: (len(n), n)):
        if not name.endswith(".md"):
            continue
        text = _read(os.path.join(COMMANDS_DIR, name))
        desc = re.search(r"^description:\s*(.+)$", text, re.M)
        hint = re.search(r"^argument-hint:\s*(.+)$", text, re.M)
        if not desc:
            raise SystemExit(f"gen-site: plugins/secaudit/commands/{name} has no "
                             f"`description:` in its frontmatter — Claude Code would list the "
                             f"command unexplained and so would this page")
        out.append(("/" + name[:-3],
                    hint.group(1).strip().strip('"') if hint else "",
                    desc.group(1).strip()))
    if not out:
        raise SystemExit("gen-site: plugins/secaudit/commands/ holds no commands")
    return out


def cli_meta() -> dict:
    """Package name, version, Python floor, console scripts and the dependency list.

    The dependency list is read rather than asserted empty: `assert_no_runtime_deps.py` is the
    gate for that claim, and a page that quietly renders "zero dependencies" from a hardcoded
    string would keep saying it after the first one was added."""
    text = _read(PYPROJECT)

    def field(key: str) -> str:
        m = re.search(rf'^{key}\s*=\s*"([^"]+)"', text, re.M)
        if not m:
            raise SystemExit(f"gen-site: kit/pyproject.toml has no `{key}`")
        return m.group(1)

    scripts = re.search(r"^\[project\.scripts\]\n(.*?)(?=^\[)", text, re.M | re.S)
    if not scripts:
        raise SystemExit("gen-site: kit/pyproject.toml declares no console scripts")
    deps = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.M | re.S)
    if deps is None:
        raise SystemExit("gen-site: kit/pyproject.toml has no `dependencies` list — the page "
                         "states what is in it and cannot state the absence of the field")
    return {
        "package": field("name"),
        "version": field("version"),
        "python": field("requires-python"),
        "scripts": re.findall(r'^([\w-]+)\s*=\s*"([^"]+)"', scripts.group(1), re.M),
        "deps": re.findall(r'"([^"]+)"', deps.group(1)),
    }


def _yaml_scalar(body: str, key: str, indent: int) -> str:
    """One scalar out of a YAML mapping body: plain, quoted, or a folded `>-` block."""
    pad = " " * indent
    m = re.search(rf"^{pad}{key}:[ \t]*(.*)$", body, re.M)
    if m is None:
        return ""
    head = m.group(1).strip()
    if head not in (">-", ">", "|", "|-"):
        return head.strip('"').strip("'")
    folded = []
    for line in body[m.end():].splitlines():
        if not line.strip():
            continue
        if not line.startswith(pad + "  "):
            break
        folded.append(line.strip())
    return " ".join(folded)


def action_inputs() -> list:
    """The Action's inputs, from the file GitHub itself reads. (name, default, description)

    An input renamed in `action.yml` and not here would leave the page documenting a key that
    silently does nothing in the reader's workflow — a security gate configured to fail on
    `high` that is in fact still on its default."""
    text = _read(ACTION_YML)
    block = re.search(r"^inputs:\n(.*?)(?=^\w)", text, re.M | re.S)
    if not block:
        raise SystemExit("gen-site: action.yml has no `inputs:` block")
    parts = re.split(r"^  ([\w-]+):[ \t]*$", block.group(1), flags=re.M)
    rows = []
    for name, body in zip(parts[1::2], parts[2::2]):
        desc = _yaml_scalar(body, "description", 4)
        if not desc:
            raise SystemExit(f"gen-site: action.yml input `{name}` has no description")
        rows.append((name, _yaml_scalar(body, "default", 4), desc))
    if not rows:
        raise SystemExit("gen-site: parsed no inputs out of action.yml")
    return rows


def docker_facts() -> dict:
    """Base image, the digest it is pinned to, the uid it drops to, and the entrypoint."""
    text = _read(DOCKERFILE)
    base = re.search(r"^FROM (\S+)(?:\s+AS \w+)?\s+#\s*(\S+)\s*$", text, re.M)
    user = re.search(r"^USER (\S+)\s*$", text, re.M)
    entry = re.search(r'^ENTRYPOINT \["([^"]+)"', text, re.M)
    if not (base and user and entry):
        raise SystemExit("gen-site: Dockerfile no longer states a digest-pinned FROM with its "
                         "tag in a trailing comment, a USER, and an ENTRYPOINT")
    return {"digest": base.group(1), "tag": base.group(2),
            "user": user.group(1), "entrypoint": entry.group(1)}


def hook_defs() -> list:
    """The pre-commit hooks this repository offers, with the flags each one actually runs."""
    rows = []
    for hid, body in re.findall(r"^- id: (\S+)\n(.*?)(?=^- id: |\Z)",
                                _read(HOOKS_YML), re.M | re.S):
        args = re.search(r"^  args: \[(.*)\]\s*$", body, re.M)
        rows.append((hid, _yaml_scalar(body, "name", 2),
                     " ".join(a.strip().strip('"') for a in args.group(1).split(","))
                     if args else ""))
    if not rows:
        raise SystemExit("gen-site: .pre-commit-hooks.yaml declares no hooks")
    return rows


def mcp_clients() -> list:
    """The per-client snippets, from the document that already maintains them.

    (client, where the file lives, syntax, the snippet itself)"""
    text = _read(MCP_DOC)
    try:
        section = text.split("## Per-client configuration", 1)[1].split("\n## ", 1)[0]
    except IndexError:
        raise SystemExit("gen-site: docs/mcp.md has no `## Per-client configuration` "
                         "section") from None
    rows = [(client.strip(), where.strip().rstrip(":"), syntax, code.strip("\n"))
            for client, where, syntax, code
            in re.findall(r"\*\*(.+?)\*\*\s*—\s*(.*?)\n+```(\w+)\n(.*?)```", section, re.S)]
    if len(rows) < 3:
        raise SystemExit(f"gen-site: parsed {len(rows)} client snippets out of docs/mcp.md; "
                         f"the section is documented as covering several")
    return rows


def mcp_tools() -> list:
    """Tool names from the server module, one-liners from the table in `docs/mcp.md`.

    Neither source alone is right. The module knows what exists and describes it in a schema
    written for a model, not a reader; the document has the sentence a person wants and no way
    to know it has gone out of date. Taking the name from one and the prose from the other
    makes the disagreement a build failure: a tool added to the server and not to the document
    is a capability nobody can discover, and a documented tool with nothing behind it is a
    promise the server will refuse."""
    from secaudit_mcp.server import TOOLS
    names = [t["name"] for t in TOOLS]
    rows = dict(re.findall(r"^\|\s*`(\w+)`\s*\|\s*(.+?)\s*\|\s*$", _read(MCP_DOC), re.M))
    missing = [n for n in names if n not in rows]
    extra = [n for n in rows if n not in names]
    if missing or extra:
        raise SystemExit(f"gen-site: docs/mcp.md and secaudit_mcp.server disagree about the "
                         f"tools — in the server but undocumented: {missing}; documented but "
                         f"not served: {extra}")
    return [(n, rows[n]) for n in names]


def optional_scanners() -> list:
    """The external scanners the engine uses when they are on PATH.

    Taken from the `_has(...)` guard inside each adapter rather than from the summary tuple
    beside them: the guard is what actually decides whether the tool runs, so it is the name
    the reader has to have installed."""
    text = _read(SCANNERS_PY)
    tools = []
    for m in re.finditer(r"^def run_(\w+)\(root.*?(?=^def |\Z)", text, re.M | re.S):
        found = re.search(r'_has\("([^"]+)"\)', m.group(0))
        if found and found.group(1) not in tools:
            tools.append(found.group(1))
    if not tools:
        raise SystemExit("gen-site: found no scanner adapters in secaudit_core/scanners.py")
    return tools


def mcp_essentials() -> list:
    """Command, arguments and transport — the three facts a client needs whatever its config
    format is, out of the table in `docs/mcp.md` that already states them."""
    text = _read(MCP_DOC)
    try:
        section = text.split("## What every client needs", 1)[1].split("\n## ", 1)[0]
    except IndexError:
        raise SystemExit("gen-site: docs/mcp.md has no `## What every client needs` "
                         "section") from None
    rows = re.findall(r"^\|\s*\*\*(.+?)\*\*\s*\|\s*(.+?)\s*\|\s*$", section, re.M)
    if len(rows) != 3:
        raise SystemExit(f"gen-site: expected 3 rows in docs/mcp.md's essentials table, "
                         f"parsed {len(rows)}")
    return rows


def _fenced(text: str, heading: str, marker: str = "", syntax: str = "bash") -> str:
    """The first fenced block under `heading` — after `marker` too, where one is given."""
    try:
        section = text.split(heading, 1)[1]
        if marker:
            section = section.split(marker, 1)[1]
        return section.split(f"```{syntax}\n", 1)[1].split("```", 1)[0]
    except IndexError:
        raise SystemExit(f"gen-site: no `{syntax}` block under {heading!r}"
                         + (f" after {marker!r}" if marker else "")) from None


def mcp_verify() -> str:
    """The one command that proves the server is reachable before anything is wired to it."""
    return _fenced(_read(MCP_DOC), "# SecAudit over MCP",
                   "Verify it before wiring anything up:").strip("\n")


def docker_commands() -> str:
    """Build and run, from `docs/ci.md` — the document that maintains them."""
    return _fenced(_read(os.path.join(REPO, "docs", "ci.md")), "## Docker").strip("\n")


def precommit_snippet(tag: str) -> str:
    """The `.pre-commit-config.yaml` a consumer writes, out of the header of the hooks file.

    It is a comment, which makes it the one snippet here that no tool validates — so the `rev:`
    in it is checked against the version the release will actually carry. An example pinning a
    tag the project never publishes is worse than no example: it fails on the reader's machine
    with an error about a missing revision, which reads as "this project is abandoned"."""
    text = _read(HOOKS_YML)
    try:
        after = text.split("via:", 1)[1]
    except IndexError:
        raise SystemExit("gen-site: .pre-commit-hooks.yaml no longer opens with a `via:` "
                         "example") from None
    lines = []
    for raw in after.splitlines():
        if raw.startswith("#   "):
            lines.append(raw[1:])
        elif lines:
            break
    if not lines:
        raise SystemExit("gen-site: parsed no example out of .pre-commit-hooks.yaml's header")
    pad = min(len(line) - len(line.lstrip()) for line in lines)
    block = "\n".join(line[pad:] for line in lines)
    stated = re.search(r"^\s*rev:\s*(\S+)\s*$", block, re.M)
    if not stated:
        raise SystemExit("gen-site: the pre-commit example states no `rev:`")
    if stated.group(1) != tag:
        raise SystemExit(f"gen-site: the pre-commit example pins `rev: {stated.group(1)}` and "
                         f"the release this repository would cut is {tag}")
    return block


def scanner_rows(tools: list) -> list:
    """What each optional scanner adds and how to install it, from `docs/getting-started.md`.

    The tools come from the adapters; the two sentences come from the document. A scanner the
    engine will run and the setup page never mentions is a dependency nobody knows to install,
    which is indistinguishable from the engine being worse than it is."""
    text = _read(os.path.join(REPO, "docs", "getting-started.md"))
    table = {name: (purpose.strip(), how.strip()) for name, purpose, how
             in re.findall(r"^(\S+)\s+#\s*(.+?)\s+→\s*(.+)$", text, re.M)}
    missing = [t for t in tools if t not in table]
    if missing:
        raise SystemExit(f"gen-site: docs/getting-started.md does not say how to install "
                         f"{missing} — the engine runs them when they are present")
    return [(t, table[t][0], table[t][1]) for t in tools]


def install_facts() -> dict:
    """The six surfaces, plus the one cross-file agreement the release depends on."""
    plugin = plugin_ids()
    cli = cli_meta()
    # The two manifests state the same release from opposite ends of the repository, and
    # `release.yml` refuses to build a tag that disagrees with `kit/pyproject.toml`. Nothing
    # compared the marketplace to either, so a plugin advertising one version while the wheel
    # carries another would have shipped quietly — and the install page names both.
    if plugin["version"] != cli["version"]:
        raise SystemExit(f"gen-site: marketplace.json says the plugin is "
                         f"{plugin['version']} and kit/pyproject.toml says the package is "
                         f"{cli['version']} — one release cannot have two version numbers")
    tag = "v" + cli["version"]
    tools = mcp_tools()
    scanners = optional_scanners()
    return {
        "in_plugin": plugin,
        "in_commands": plugin_commands(),
        "in_cli": cli,
        "in_mcp_clients": mcp_clients(),
        "in_mcp_tools": tools,
        "in_mcp_essentials": mcp_essentials(),
        "in_mcp_verify": mcp_verify(),
        "in_action": action_inputs(),
        "in_docker": docker_facts(),
        "in_docker_cmds": docker_commands(),
        "in_hooks": hook_defs(),
        "in_hook_snippet": precommit_snippet(tag),
        "in_scanners": scanner_rows(scanners),
        "version": cli["version"],
        "tag": tag,
        "package": cli["package"],
        "python_floor": cli["python"].lstrip(">="),
        # Rendered as stat blocks, so they are strings and they are gated: `verify` refuses a
        # page that states a count without the matching `data-count` beside it.
        "surfaces": str(len(SURFACE_ANCHORS)),
        "mcp_tools": str(len(tools)),
        "runtime_deps": str(len(cli["deps"])),
    }


def facts() -> dict:
    """Everything the page is allowed to state, from the source of truth for each."""
    from check_consistency import derive_facts
    from secaudit_core import compliance
    from run_checks import GATES

    with open(os.path.join(REPO, "eval", "scorecard.json"), encoding="utf-8") as f:
        score = json.load(f)
    # The external result, from the benchmark's own scorer output. The page used to say this
    # measurement "has not been run yet" — a sentence typed into this generator, which is why
    # no gate caught it going stale through six runs. Everything RealVuln-shaped on the page is
    # now read from here, and check 27 anchors the prose that surrounds it.
    with open(os.path.join(REPO, "eval", "realvuln", "result.json"), encoding="utf-8") as f:
        rv = json.load(f)

    # The second external result. A site that publishes one external number while a second one
    # exists is overstating by omission, which is the failure mode this whole generator is built
    # against — so the JavaScript figure is read here on the same terms as the Python one, and
    # the page states it with its caveat rather than beside it as a peer.
    with open(os.path.join(REPO, "eval", "secbenchjs", "result.json"), encoding="utf-8") as f:
        sb = json.load(f)
    sb_now = sb["overall"]
    # Worst class first: the page exists to say what the engine does *not* do on JavaScript, and
    # ordering by recall puts the two results that matter at the top instead of the flattering
    # ones. Same reasoning as the miss table on the benchmark page.
    sb_classes = sorted(
        ({"name": name, "tp": v["tp"], "labels": v["labels"],
          "pct": f"{100 * v['recall']:.1f}"} for name, v in sb["by_class"].items()),
        key=lambda c: float(c["pct"]))

    derived = derive_facts()
    overall = score["overall"]
    rv_now = rv["overall"]
    # Oldest first, this run last: the shape of the story is the movement, and the first bar
    # being the blind one is the caveat made visual.
    rv_history = [(r["overall"]["f3_score"], r["run_date"])
                  for r in reversed(rv["previous_runs"])] + [(rv_now["f3_score"], rv["run_date"])]

    # Every run the benchmark has scored, oldest first, each with the label the round was given
    # when it was committed. The landing page shows six bars; the benchmark page shows what each
    # bar cost, which is the only form in which "precision rose with recall" is checkable.
    # The oldest entry predates the convention of labelling a round, and what it carries
    # instead is a paragraph about reproduction rather than a name — so it gets the one label
    # that is true of it and of no other run, from copy, in the reader's language.
    runs = [dict(r["overall"], date=r["run_date"], label=r.get("label", ""))
            for r in reversed(rv["previous_runs"])]
    runs.append(dict(rv_now, date=rv["run_date"], label=rv["run_label"]))

    # Families, largest labelled pool first — the order that shows where the score is actually
    # decided. `other` alone holds more labels than the eleven smallest families together.
    fams = sorted(((k, v["tp"], v["total"]) for k, v in rv["by_family"].items()),
                  key=lambda kv: (-kv[2], kv[0]))
    # Repositories, best first. All of them: a leaderboard truncated to its top five is the
    # shape of a claim, and this page exists because the top five went two rounds stale.
    repos = sorted(((k, v) for k, v in rv["by_repo"].items()),
                   key=lambda kv: (-kv[1]["f3"], kv[0]))

    # The rule-based SAST row of the benchmark's own baselines. The landing page cites it — "a
    # published rule-based SAST scores X on the same corpus" is the only thing that makes 31.5
    # mean anything to a reader who has never seen this benchmark — and it cited it as a typed
    # 17.7 sitting three hundred lines from the table it was copied out of. The comparison is the
    # load-bearing part of that sentence, so it is read from the same parse the table is built
    # from and the name comes with it.
    bl = baselines(f"{rv_now['f3_score']:.1f}")
    peers = [b for b in bl if not b["ours"] and "SAST" in b["category"]]
    if len(peers) != 1:
        raise SystemExit(f"gen-site: expected exactly one rule-based SAST baseline to compare "
                         f"against, found {len(peers)} — the landing page states this comparison "
                         f"in a sentence and cannot pick between rows")
    sast = peers[0]

    return {
        "recall": f"{overall['recall']:.0%}",
        "precision": f"{overall['precision']:.0%}",
        "f3": f"{overall['f3']:.3f}",
        "trap_fps": str(overall["fp"]),
        "traps_total": str(score["false_positive_traps"]),
        "golden": str(score["labelled_vulnerabilities"]),
        "misses": str(overall["fn"]),
        "detectors": str(derived["detectors"]),
        "references": str(derived["references"]),
        "commands": str(derived["commands"]),
        "gates": str(len(GATES)),
        "asvs_cwes": str(len(compliance.CWE_TO_ASVS)),
        "asvs_chapters": str(len(compliance.ASVS_CHAPTERS)),
        # The one CRA figure the site still states: the landing page's compliance paragraph
        # names the date the reporting duty starts. The dedicated CRA page was removed; the
        # date stayed, because it is what a reader acts on and it comes from `compliance.py`.
        "cra_date": compliance.CRA_REPORTING_STARTS,


        # RealVuln — the external number. Formatted here so the template holds no arithmetic.
        "rv_f3": f"{rv_now['f3_score']:.1f}",
        "rv_precision": f"{rv_now['precision']:.3f}",
        "rv_recall": f"{rv_now['recall']:.3f}",
        "rv_repos": str(rv["repos_scored"]),
        "rv_repos_total": str(rv["repos_total"]),
        "rv_strict_f3": f"{rv['strict_micro']['f3_score']:.1f}",
        "rv_blind_f3": f"{rv_history[0][0]:.1f}",
        "rv_runs": str(len(rv_history)),
        "rv_history": rv_history,

        # The benchmark page states the confusion matrix rather than only the aggregates: four
        # counts are checkable against the scorer output, and a ratio on its own is not.
        "rv_tp": str(rv_now["tp"]),
        "rv_fp": str(rv_now["fp"]),
        "rv_fn": str(rv_now["fn"]),
        "rv_tn": str(rv_now["tn"]),
        "rv_f2": f"{rv_now['f2_score']:.1f}",
        "rv_strict_recall": f"{rv['strict_micro']['recall']:.4f}",
        "rv_strict_extra": str(rv["strict_micro"]["fn"] - rv_now["fn"]),
        "rv_labels": str(rv_now["tp"] + rv_now["fn"]),
        "rv_date": rv["run_date"],
        "rv_label": rv["run_label"],
        # The field is a running account of every re-measurement — 1,800 characters of it, which
        # belongs in the committed raw output and not in a five-row panel. The page states the
        # fact (this run was re-verified, on this date) and links to the account.
        "rv_reverified": re.match(r"\d{4}-\d{2}-\d{2}", rv["reverified"]).group(0)
        if re.match(r"\d{4}-\d{2}-\d{2}", rv["reverified"]) else rv["reverified"],
        "rv_tier": rv["tier"],
        "rv_scanner": rv["scanner"],
        "rv_bench_url": rv["benchmark"],
        "rv_bench_version": rv["benchmark_version"],
        "rv_gt_hash": rv["ground_truth_content_hash"],
        "rv_engine_digest": rv["engine_digest"],
        # One scale, for the landing page only. RealVuln's scorer emits F-scores on 0-100 and
        # precision and recall on 0-1; this repository's scorecard emits all three on 0-1. The
        # benchmark page passes each through exactly as published, because that page is a mirror
        # of the benchmark's own tables and a reader checking it against them needs the same
        # digits in the same form. The landing page does something else: it sets the two corpora
        # side by side in two panels, and there the mixed scales stop being a formatting detail.
        # F3 0.986 beside F3 31.5 is one metric rendered as two different quantities, and recall
        # 98% beside recall 0.301 asks the reader to convert before they can compare — on the one
        # comparison the whole page is built to invite. Same measurements, one presentation.
        "pct_recall": f"{overall['recall']:.1%}",
        "pct_precision": f"{overall['precision']:.1%}",
        "pct_f3": f"{overall['f3']:.1%}",
        "rv_pct_f3": f"{rv_now['f3_score'] / 100:.1%}",
        "rv_pct_precision": f"{rv_now['precision']:.1%}",
        "rv_pct_recall": f"{rv_now['recall']:.1%}",
        "rv_pct_strict_f3": f"{rv['strict_micro']['f3_score'] / 100:.1%}",
        "rv_pct_sast_f3": f"{float(sast['f3']) / 100:.1%}",
        "rv_sast_name": sast["system"],

        # SecBench.js. `sb_pct_recall` is the only figure quoted in prose; the rest exist so the
        # page can show the classes rather than assert a summary of them.
        "sb_recall": f"{sb_now['recall']}",
        "sb_pct_recall": f"{sb_now['recall']:.1%}",
        # The blind first run, read from the same file. Typed into the copy it would be the one
        # figure on this page nothing could hold — and it is the figure a sceptical reader cares
        # about most, so it is the last one that should be allowed to drift.
        "sb_blind_recall": f"{sb['blind_run']['overall']['recall']}",
        "sb_pct_blind_recall": f"{sb['blind_run']['overall']['recall']:.1%}",
        "sb_blind_tp": str(sb["blind_run"]["overall"]["tp"]),
        "sb_tp": str(sb_now["tp"]),
        "sb_labels": str(sb["labels_scored"]),
        "sb_packages": str(sb["packages_scanned"]),
        "sb_classes": sb_classes,
        "sb_date": sb["run_date"],
        "sb_benchmark": sb["benchmark"],
        "sb_worst_class": sb_classes[0]["name"],
        "sb_worst_tp": str(sb_classes[0]["tp"]),
        "sb_worst_labels": str(sb_classes[0]["labels"]),

        "rv_zero_repos": str(sum(1 for _, v in rv["by_repo"].items() if v["f3"] == 0.0)),
        "rv_missing_repos": rv["repos_missing"],
        "rv_missing_reason": rv["repos_missing_reason"],
        "rv_runs_rows": runs,
        "rv_families": fams,
        "rv_repo_rows": repos,
        "rv_baselines": bl,

        # Per-language recall on the fixture corpus, and the CWE list, both straight out of the
        # scorecard. The page shows fifteen rows because the corpus has fifteen languages — if
        # one is added the section grows on its own, which is the point of deriving it.
        "languages": str(len(score["by_language"])),
        "lang_recall": sorted(((name, v["recall"]) for name, v in score["by_language"].items()),
                              key=lambda kv: (-kv[1], kv[0])),
        "cwe_list": sorted(score["by_cwe"], key=lambda c: int(c.split("-")[1])),

        # The six install surfaces, read out of the files that define them. Merged into the
        # shared fact set rather than kept for one page, because `build` exempts everything in
        # `data` from the unused-token check — and because the landing page states the version
        # and the package name too. One consequence worth stating: a manifest that loses its
        # shape now fails the whole site build, not only the page that renders it. That is the
        # intended direction. The alternative is a landing page that renders while the install
        # page it links to cannot be built.
        **install_facts(),
    }


# ---------------------------------------------------------------------------- copy
#
# The words moved to `scripts/sitecopy/` when this file passed 2,700 lines with four more
# pages still to write. What stays here is everything that *derives* — the readers, the
# renderer and the verifier — because that is what has to be reviewed when a figure or a
# rule changes. Re-exported under their original names so every use below is unchanged.
from sitecopy.copy_index import COPY, E404, SHELL_KEYS          # noqa: E402
from sitecopy.copy_bench import (BENCH_CAVEATS, BENCH_COPY,  # noqa: E402
                                 REPRO_NOTES, RUN_LABELS_TR)
from sitecopy.copy_compare import CMP_ROWS, COMPARE_COPY   # noqa: E402
from sitecopy.copy_install import CHOOSE, INSTALL_COPY, SURFACE_ANCHORS  # noqa: E402

NAV = {
    "index": {
        "en": [("#what", "What it does"), ("#numbers", "Measured"),
               ("#disclosure", "Disclosure"), ("#langs", "Coverage"),
               ("#gate", "Authorization"), ("#evidence", "Evidence"), ("#miss", "Limits"),
               ("#install", "Install")],
        "tr": [("#what", "Ne yapıyor"), ("#numbers", "Ölçüm"),
               ("#disclosure", "Açık beyan"), ("#langs", "Kapsam"),
               ("#gate", "Yetkilendirme"), ("#evidence", "Kanıt"), ("#miss", "Sınırlar"),
               ("#install", "Kurulum")],
    },
    "benchmark": {
        "en": [("#disclosure", "Disclosure"), ("#runs", "Runs"), ("#baselines", "Baselines"),
               ("#families", "Families"), ("#repos", "Repositories"),
               ("#javascript", "JavaScript"), ("#reproduce", "Reproduce")],
        "tr": [("#disclosure", "Açık beyan"), ("#runs", "Koşular"), ("#baselines", "Referanslar"),
               ("#families", "Aileler"), ("#repos", "Depolar"),
               ("#javascript", "JavaScript"), ("#reproduce", "Tekrarlama")],
    },
    # Six of the install page's nine sections; Docker, pre-commit and the optional scanners are
    # one scroll from Action and all three are in the card grid at the top, which is that page's
    # own table of contents. A menu that lists everything is a menu nobody reads.
    # No sections, so no capsule: `shell_values` renders the whole nav element only when it
    # has links, and the 404 is the page that has none.
    "404": {"en": [], "tr": []},
    "install": {
        "en": [("#choose", "Choose"), ("#plugin", "Plugin"), ("#cli", "CLI"), ("#mcp", "MCP"),
               ("#action", "Action"), ("#docker", "Docker")],
        "tr": [("#choose", "Seçim"), ("#plugin", "Eklenti"), ("#cli", "CLI"), ("#mcp", "MCP"),
               ("#action", "Action"), ("#docker", "Docker")],
    },
    "compare": {
        "en": [("#table", "Capabilities"), ("#quotes", "In their words"), ("#not", "Limits")],
        "tr": [("#table", "Yetenekler"), ("#quotes", "Kendi ifadeleriyle"), ("#not", "Sınırlar")],
    },
}

# Where each page is published, per language. The root is the landing page; anything else gets a
# directory so its URL has no extension and its relative links do not depend on a trailing slash
# the server may or may not add.
# Short labels for the footer's list of pages. Deliberately not the page titles: a title is
# written for a search result and a footer link is written for a thumb.
FOOTER_LABELS = {
    "en": {"index": "Overview", "benchmark": "Measured", "install": "Install",
           "compare": "Compare"},
    "tr": {"index": "Genel bakış", "benchmark": "Ölçüm", "install": "Kurulum",
           "compare": "Karşılaştırma"},
}

PAGE_PATHS = {"index": "", "benchmark": "benchmark/", "install": "install/",
              "compare": "compare/"}


# Every page exists in both languages. The documents used to be the exception — one English
# body served under `/docs/` and `/tr/docs/` alike — and they are no longer on the site at all:
# `docs/*.md` is read on GitHub, where it is versioned with the code it describes.
ENGLISH_ONLY_PAGES: tuple[str, ...] = ()


def page_path(page: str, lang: str) -> str:
    """Root-relative, for anything the visitor clicks.

    """
    tail = PAGE_PATHS[page]
    if page in ENGLISH_ONLY_PAGES:
        lang = "en"
    return "/" + ("" if lang == "en" else f"{lang}/") + tail


def page_href(page: str, lang: str) -> str:
    """Absolute, for anything a machine reads: canonical, hreflang, sitemap, structured data.

    Navigation deliberately does NOT use this. An absolute internal link ties every click to the
    production origin, so the built site cannot be opened anywhere else — not from a local
    server, not from a preview deployment, not from a branch. Machines need the absolute form
    and people need the relative one; they are two different questions."""
    return ORIGIN + page_path(page, lang)

# Language display names for the coverage rows. The *list* comes from the scorecard; this only
# spells the keys nicely, and a key with no entry here falls back to its own name — so a new
# language in the corpus appears on the page immediately, just unprettified.
LANG_NAMES = {
    "csharp": "C#", "cpp": "C++", "javascript": "JavaScript", "typescript": "TypeScript",
    "python": "Python", "go": "Go", "java": "Java", "kotlin": "Kotlin", "swift": "Swift",
    "ruby": "Ruby", "php": "PHP", "rust": "Rust", "dart": "Dart", "docker": "Dockerfile",
    "terraform": "Terraform", "yaml": "YAML", "json": "JSON", "shell": "Shell",
    "plist": "Info.plist", "hcl": "HCL", "text": "Config / text",
}

# The evidence pack, as a small stack of documents. (format, title, line)
DOCS = {
    "en": [("--format cyclonedx", "CycloneDX 1.6 SBOM", "Components, licences, hashes."),
           ("--format openvex", "OpenVEX register", "A status and a reason per advisory."),
           ("--format cra", "EU CRA evidence pack", "Findings mapped to Annex I clauses."),
           ("--format sarif", "SARIF 2.1.0", "Uploads to GitHub code scanning.")],
    "tr": [("--format cyclonedx", "CycloneDX 1.6 SBOM", "Bileşenler, lisanslar, hash'ler."),
           ("--format openvex", "OpenVEX kayıt defteri", "Her advisory için durum ve gerekçe."),
           ("--format cra", "AB CRA kanıt paketi", "Bulgular Ek I maddelerine eşlendi."),
           ("--format sarif", "SARIF 2.1.0", "GitHub code scanning'e yüklenir.")],
}

# Where the engine can be reached from. (title, code, description)
# What running it actually looks like, in three steps. This is the block the site did not have:
# every section under it argues about some property of the tool — the score, the gate, the
# evidence, the limits — and each of those arguments assumes you already know what the thing
# does. Nothing here is a position. It is what you type, what runs, and what you get back.
STEPS = {
    "en": [
        ("Target", "secaudit ./repo",
         "A checkout, a single file, or a running URL once ownership has been asserted."),
        ("Analysis", "{detectors} detectors · taint",
         "Pattern detectors across {languages} languages, and a pass that follows untrusted "
         "input from its entry point to the call that consumes it."),
        ("Output", "sarif · sbom · openvex · cra",
         "Every finding with its file, its line and its path. SARIF for code scanning; the "
         "SBOM, the dependency verdicts and the CRA evidence pack are produced by the same "
         "run."),
    ],
    "tr": [
        ("Hedef", "secaudit ./repo",
         "Bir checkout, tek bir dosya ya da sahiplik beyan edildiğinde çalışan bir URL."),
        ("Analiz", "{detectors} detector · taint",
         "{languages} dilde desen detector'ları ve güvenilmez girdiyi giriş noktasından onu "
         "tüketen çağrıya kadar izleyen bir geçiş."),
        ("Çıktı", "sarif · sbom · openvex · cra",
         "Her bulgu; dosyası, satırı ve yolu ile birlikte. Code scanning için SARIF; SBOM, "
         "bağımlılık kararları ve CRA kanıt paketi aynı koşudan üretilir."),
    ],
}

SURFACES = {
    "en": [
        ("Claude Code plugin", "/secaudit .", "The full P1–P10 methodology, live target included."),
        ("Standalone CLI", "pip install secaudit-kit", "No key, no plan, no network. Zero deps."),
        ("MCP server", "python3 -m secaudit_mcp", "Codex, Cursor, OpenCode — same engine."),
        ("GitHub Action", "uses: mtvrkan/secaudit", "SARIF into code scanning on every push."),
        ("Docker", "docker run secaudit", "Pinned by digest, non-root, SBOM attached."),
        ("pre-commit", "repo: mtvrkan/secaudit", "Catch it before it reaches the branch."),
    ],
    "tr": [
        ("Claude Code eklentisi", "/secaudit .", "Canlı hedef dahil tam P1–P10 metodolojisi."),
        ("Bağımsız CLI", "pip install secaudit-kit", "Anahtar yok, plan yok, ağ yok. Sıfır bağımlılık."),
        ("MCP sunucusu", "python3 -m secaudit_mcp", "Codex, Cursor, OpenCode — aynı çekirdek."),
        ("GitHub Action", "uses: mtvrkan/secaudit", "Her push'ta code scanning'e SARIF."),
        ("Docker", "docker run secaudit", "Digest'e pinli, root değil, SBOM ekli."),
        ("pre-commit", "repo: mtvrkan/secaudit", "Dala ulaşmadan yakalayın."),
    ],
}

# The honest list. Each of these is a class the deterministic tier provably does not reach, and
# each one is already published in docs/what-we-miss.md — the page is quoting the repository,
# not softening it.
#
# `[[authz_tp]]` and `[[authz_total]]` are substituted from `result.json` in `index_values`. They
# used to be typed, and they rotted: the access-control figure read "1 of 76" here and on the
# what-we-miss page for the seven days after the scorer started saying 2, in the one section of
# the site whose whole purpose is to state a weakness accurately. A figure typed into copy is
# the only kind on this site that no gate holds, so this section no longer has one.
MISSES = {
    "en": [
        ("Business-logic flaws",
         "The rules being violated belong to the product and are recorded nowhere the analyzer "
         "can read. Only the model tier reaches this class, and it has no measured score."),
        ("Broken access control at the handler",
         "[[authz_tp]] of [[authz_total]] labelled cases detected on the external corpus. Most "
         "of those labels sit on a function definition: the flaw is a property of everything "
         "the handler returns."),
        ("Race conditions and TOCTOU",
         "Detection requires an interleaving model. A lexical pass reads a single execution, "
         "not two concurrently."),
        ("Code behind a dynamic dispatch",
         "Calls through a variable, a decorator or a dispatch table are not resolved. Inferring "
         "that edge is how an analysis begins attributing real sinks to the wrong function."),
    ],
    "tr": [
        ("İş mantığı hataları",
         "İhlal edilen kurallar ürüne aittir ve analizcinin okuyabileceği hiçbir yerde kayıtlı "
         "değildir. Bu sınıfa yalnızca model katmanı ulaşır ve o katmanın ölçülmüş bir skoru "
         "yoktur."),
        ("Handler düzeyinde bozuk erişim denetimi",
         "Dış veri kümesindeki [[authz_total]] etiketli vakadan [[authz_tp]] tanesi tespit "
         "edildi. Bu etiketlerin çoğu bir fonksiyon tanımının üzerindedir: kusur, handler'ın "
         "döndürdüğü her şeyin özelliğidir."),
        ("Yarış koşulları ve TOCTOU",
         "Tespit, iş parçacıklarının araya girme modelini gerektirir. Sözdizimsel bir geçiş tek "
         "bir yürütmeyi okur, eşzamanlı iki yürütmeyi değil."),
        ("Dinamik çağrı çözümlemesinin arkasındaki kod",
         "Bir değişken, decorator ya da dağıtım tablosu üzerinden yapılan çağrılar çözümlenmez. "
         "Bu kenarın tahmin edilmesi, analizin gerçek sink'leri yanlış fonksiyona atfetmeye "
         "başlaması demektir."),
    ],
}


def install_plugin_block() -> str:
    """The home page's install command, read from the manifest like the install page's is.

    It used to be a literal here while `page-install` derived the same two identifiers from
    `plugin_ids()` — so the page most people see first was the one that could go stale, and it
    would go stale silently. The docstring on `plugin_ids()` argues this case; the argument
    applied to this constant too and it took a check over the READMEs to notice.
    """
    plugin = plugin_ids()
    return (f'/plugin marketplace add {plugin["owner"]}/{REPO_URL.rsplit("/", 1)[-1]}\n'
            f'/plugin install {plugin["plugin"]}@{plugin["marketplace"]}')


INSTALL_CLI = ("python3 -m secaudit_core.cli ./repo --min high\n"
               "python3 -m secaudit_core.cli ./repo --format sarif   # GitHub code scanning\n"
               "python3 -m secaudit_core.cli ./repo --format cra     # EU CRA evidence pack")


# --------------------------------------------------------------------------- render

def escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# --------------------------------------------------------------------------- the mark
#
# A shield carrying an S whose lower half is a tick. Chosen by the author from supplied artwork
# rather than derived here, and worth stating plainly: this is the shape the security category
# already uses. An earlier note in this file argued against exactly that on the grounds that a
# mark which could belong to any security product is not a mark — that argument is not wrong,
# it was overruled, and it is recorded here rather than deleted so the trade-off stays visible.
# What the shield buys is instant category recognition; what it costs is distinctiveness.
#
# DERIVED FROM THE ARTWORK AT BUILD TIME, not redrawn by eye and not transcribed either. The
# source of truth is `site/mark-source.svg` — the designed file itself, two subpaths of lines and
# cubics under a translate — and the coordinates the page renders are computed from it below.
# Sixty-seven coordinate pairs pasted into this file would have been sixty-seven chances for the
# mark on the site to stop being the mark in the artwork, which is the same failure this whole
# script exists to prevent for numbers. Redraw the SVG, rebuild, and the site, the favicon and the
# social card all move together or the build stops.
#
# The one lossy step is flattening the cubics into polylines, and it is bounded rather than
# eyeballed: recursive subdivision until both control points sit within FLATTEN_TOL source units
# of the chord. Checked once by rasterising source and conversion to 512x512 and differencing the
# masks — 108 pixels of 56,432 disagreed (0.19% of the area) and every one had a neighbour that
# agreed, so the worst boundary error was a single pixel at 512, i.e. 0.06 of a viewBox unit.
# Antialias rounding, not shape error.
#
# TWO disjoint shapes, not an outline with a hole: the S cuts the shield's band above and below,
# so the upper mass and the lower mass are separate regions and the interior is simply outside
# both. Nothing needs a fill rule to punch the middle out — which is what lets the social card,
# whose canvas can only fill a polygon, draw the same mark the page does. Two properties that
# arrangement depends on are asserted rather than assumed: both rings wound the same way, so a
# nonzero renderer unions them instead of cancelling where they meet, and no ring crossing itself,
# which an even-odd renderer would turn into a hole.
#
# The lower half IS the tick: the shield's foot and the tick are one stroke, so there is one shape
# doing both jobs and no second colour to keep in step. Verified by rasterising at 16, 22, 28, 40
# and 72px and reading the pixels rather than the vector — it holds at 16, which is why there is
# no separate favicon variant.
MARK_SOURCE = os.path.join(SITE, "mark-source.svg")

# The mark is portrait, so the box is cut to it rather than padded out to a square. A square
# viewBox would have parked three empty units either side of the glyph, and since the CSS sizes
# the box, every one of those units would have come out of the mark: at 22px in the bar the shield
# would have rendered 16px wide against a 22px wordmark and read as the smaller thing. Consumers
# size by HEIGHT and let the width follow.
MARK_BOX = (24, 32)
MARK_MARGIN = 1.6

# In SOURCE units. One source unit is about 0.05 viewBox units, so this is 0.017 of a viewBox
# unit — a sixtieth of a pixel at the mark's nominal size, and less at every size it is used.
FLATTEN_TOL = 0.35


def _flatten_cubic(p0, p1, p2, p3, out, depth=0):
    """Subdivide until both control points lie within FLATTEN_TOL of the chord."""
    (x0, y0), (x3, y3) = p0, p3
    dx, dy = x3 - x0, y3 - y0
    span = (dx * dx + dy * dy) ** 0.5
    if span < 1e-9:
        off = max(abs(p1[0] - x0) + abs(p1[1] - y0), abs(p2[0] - x0) + abs(p2[1] - y0))
    else:
        off = max(abs(dy * p[0] - dx * p[1] + x3 * y0 - y3 * x0) / span for p in (p1, p2))
    if off <= FLATTEN_TOL or depth > 16:
        out.append(p3)
        return
    def mid(a, b):
        return ((a[0] + b[0]) / 2, (a[1] + b[1]) / 2)

    p01, p12, p23 = mid(p0, p1), mid(p1, p2), mid(p2, p3)
    p012, p123 = mid(p01, p12), mid(p12, p23)
    m = mid(p012, p123)
    _flatten_cubic(p0, p01, p012, m, out, depth + 1)
    _flatten_cubic(m, p123, p23, p3, out, depth + 1)


def _ring_area(ring) -> float:
    return sum(ring[i][0] * ring[(i + 1) % len(ring)][1]
               - ring[(i + 1) % len(ring)][0] * ring[i][1]
               for i in range(len(ring))) / 2.0


def _crosses_itself(ring) -> bool:
    """True if any two non-adjacent edges properly cross. The card fills even-odd."""
    n = len(ring)

    def side(o, a, b):
        return (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0])

    for i in range(n):
        a, b = ring[i], ring[(i + 1) % n]
        for j in range(i + 1, n):
            if j == i or (j + 1) % n == i or (i + 1) % n == j:
                continue
            c, d = ring[j], ring[(j + 1) % n]
            if ((side(c, d, a) > 0) != (side(c, d, b) > 0)) and \
               ((side(a, b, c) > 0) != (side(a, b, d) > 0)):
                return True
    return False


def mark_rings() -> list:
    """`site/mark-source.svg`, flattened and fitted to MARK_BOX.

    Deliberately narrow: absolute M/L/C and a single translate, which is what the artwork uses.
    A path command this does not understand raises rather than being skipped, because a silently
    dropped curve is a mark that is subtly wrong everywhere at once.
    """
    with open(MARK_SOURCE, encoding="utf-8") as f:
        svg = f.read()

    tx, ty = 0.0, 0.0
    moved = re.search(r"translate\(\s*(-?[\d.]+)\s*[, ]\s*(-?[\d.]+)\s*\)", svg)
    if moved:
        tx, ty = float(moved.group(1)), float(moved.group(2))

    rings = []
    for d in re.findall(r'<path\s[^>]*?d="([^"]+)"', svg, re.S):
        tokens = re.findall(r"[A-Za-z]|-?\d*\.?\d+", d)
        pts, cur, start, i = [], None, None, 0
        while i < len(tokens):
            op = tokens[i]
            i += 1
            if op in "Zz":
                continue
            if op not in ("M", "L", "C"):
                raise SystemExit(f"FAIL — mark-source.svg uses path command '{op}'; "
                                 f"gen_site.py understands only absolute M, L, C and Z.")
            n = 6 if op == "C" else 2
            a = [float(t) for t in tokens[i:i + n]]
            i += n
            if op == "C":
                _flatten_cubic(cur, (a[0] + tx, a[1] + ty), (a[2] + tx, a[3] + ty),
                               (a[4] + tx, a[5] + ty), pts)
                cur = (a[4] + tx, a[5] + ty)
                continue
            cur = (a[0] + tx, a[1] + ty)
            if op == "M":
                start = cur
            pts.append(cur)
        if pts and start and pts[-1] == start and len(pts) > 1:
            pts.pop()                                   # the Z already closes it
        rings.append(pts)

    if len(rings) != 2:
        raise SystemExit(f"FAIL — expected 2 subpaths in mark-source.svg, found {len(rings)}.")

    # One winding direction for both, so nonzero unions them rather than cancelling the overlap.
    rings = [r if _ring_area(r) > 0 else r[::-1] for r in rings]

    flat = [p for r in rings for p in r]
    x0, x1 = min(p[0] for p in flat), max(p[0] for p in flat)
    y0, y1 = min(p[1] for p in flat), max(p[1] for p in flat)
    box_w, box_h = MARK_BOX
    scale = (box_h - 2 * MARK_MARGIN) / (y1 - y0)
    ox = (box_w - (x1 - x0) * scale) / 2 - x0 * scale
    oy = (box_h - (y1 - y0) * scale) / 2 - y0 * scale
    if (x1 - x0) * scale > box_w - 2 * MARK_MARGIN:
        raise SystemExit("FAIL — the mark is wider than MARK_BOX leaves room for; widen the box.")

    out = []
    for r in rings:
        ring = [(round(x * scale + ox, 2), round(y * scale + oy, 2)) for x, y in r]
        # Rounding to 2dp can land neighbours on the same point; a zero-length edge is a
        # divide-by-zero waiting in the card's scanline fill.
        ring = [p for i, p in enumerate(ring) if p != ring[i - 1]]
        if _crosses_itself(ring):
            raise SystemExit("FAIL — a mark ring crosses itself; the social card fills even-odd "
                             "and would render a hole where the crossing is.")
        out.append(ring)
    return out


MARK_RINGS = mark_rings()

# Points rather than path data, because the social card is drawn by a canvas that can fill a
# polygon but cannot parse a path. One definition, two renderers — which is not pedantry here:
# the card and the page had already drifted into two different marks once, with the card's own
# docstring insisting they agreed.
MARK_PATH = "".join("M" + "L".join(f"{x} {y}" for x, y in ring) + "Z" for ring in MARK_RINGS)


def mark_svg(colour: str, extra: str = "") -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'viewBox="0 0 {MARK_BOX[0]} {MARK_BOX[1]}"{extra}>'
            f'<path d="{MARK_PATH}" fill="{colour}"/></svg>')


# Literal hex rather than a CSS variable: a data URI has no cascade to inherit from.
FAVICON_SVG = mark_svg("#ff7a45")


def favicon_href() -> str:
    from urllib.parse import quote
    return "data:image/svg+xml," + quote(FAVICON_SVG, safe="")


# One shape, one colour. The artwork fills with a top-to-bottom gradient (#FF9900 -> #FF7900 ->
# #FF5A00) and that is deliberately not reproduced. Three reasons, in order of weight: its top
# stop measures 2.3:1 against the light theme's paper, under the 3:1 that WCAG 1.4.11 asks of a
# meaningful graphic, so light mode would need a second pair of stops maintained in step with the
# first; the mark is drawn at 22px, where a gradient across 22 rows of pixels is a colour nobody
# can name; and the card's canvas cannot draw one, so the single definition would have to become
# two. A theme variable instead of a hex, so the mark darkens with everything else in light mode
# (#c2551f there, 3.8:1) rather than staying an orange that the paper washes out.
MARK_SVG = mark_svg("var(--accent)", ' aria-hidden="true"')


def bar(pct: float, i: int) -> str:
    """One recall bar. Same markup as the language rows on the landing page — same meaning,
    so the same component rather than a second one that drifts."""
    return (f'<span class="track"><span class="fill" style="--w:{pct:.0f}%;--i:{i}">'
            f"</span></span>")


def bench_values(lang: str, data: dict, copy: dict) -> dict:
    """Everything the benchmark page renders that is a table rather than a sentence."""
    # `now` marks the row this page is about — the current run, and the row in the baselines
    # table that is ours. A highlight, not a reordering: both tables stay in their own order.
    def tr(i: int, now: bool) -> str:
        cls = ' class="now"' if now else ""
        return f'<tr style="--i:{i}"{cls}>'

    def run_label(raw: str) -> str:
        """The round's own name, in the reader's language.

        `result.json` records it in English because that file is the record a benchmark
        maintainer reads, so the Turkish page used to render twenty-nine English sentences inside
        a translated table. A missing translation raises rather than falling back: a fallback is
        invisible from the page that needs it, in the language its author does not read.
        """
        if not raw:
            return copy["runs_first_label"]
        if lang == "en":
            return raw
        if raw not in RUN_LABELS_TR:
            raise SystemExit(f"gen-site: no Turkish for the run label {raw!r} — add it to "
                             f"`sitecopy/copy_bench.RUN_LABELS_TR`. The table is read in both "
                             f"languages and this row would have been English in both.")
        return RUN_LABELS_TR[raw]

    last = len(data["rv_runs_rows"]) - 1
    runs = "".join(
        tr(i, i == last) +
        f'<td class="mono">{escape(r["date"])}</td>'
        f'<td class="lbl">{escape(run_label(r["label"]))}</td>'
        f'<td class="mono num">{r["f3_score"]:.1f}</td>'
        f'<td class="mono num">{r["f2_score"]:.1f}</td>'
        f'<td class="mono num">{r["precision"]:.4f}</td>'
        f'<td class="mono num">{r["recall"]:.4f}</td>'
        f'<td class="mono num">{r["tp"]} / {r["fp"]} / {r["fn"]}</td></tr>'
        for i, r in enumerate(data["rv_runs_rows"]))

    base = "".join(
        tr(i, b["ours"]) +
        f'<td>{escape(b["category"])}</td><td class="lbl">{escape(b["system"])}</td>'
        f'<td class="mono num">{escape(b["f3"])}</td>'
        f'<td class="mono num">{escape(b["precision"])}</td>'
        f'<td class="mono num">{escape(b["recall"])}</td></tr>'
        for i, b in enumerate(data["rv_baselines"]))

    fams = "".join(
        f'<li class="famrow" style="--i:{i}"><span class="nm mono">{escape(name)}</span>'
        f'<span class="ct mono">{tp} / {total}</span>{bar(100.0 * tp / total, i)}'
        f'<span class="pc mono">{tp / total:.0%}</span></li>'
        for i, (name, tp, total) in enumerate(data["rv_families"]))

    # Same row shape as the RealVuln families, deliberately: it is the same question asked of a
    # different corpus, and a reader who has just learned to read one table should not have to
    # learn a second. Worst first — the two results this run exists to report are the two zeros.
    sb_rows = "".join(
        f'<li class="famrow" style="--i:{i}"><span class="nm mono">{escape(c["name"])}</span>'
        f'<span class="ct mono">{c["tp"]} / {c["labels"]}</span>'
        f'{bar(float(c["pct"]), i)}<span class="pc mono">{c["pct"]}%</span></li>'
        for i, c in enumerate(data["sb_classes"]))

    repos = "".join(
        f'<tr style="--i:{min(i, 12)}"><td class="mono lbl">{escape(name)}</td>'
        f'<td class="mono num">{v["f3"]:.1f}</td>'
        f'<td class="mono num">{v["precision"]:.3f}</td>'
        f'<td class="mono num">{v["recall"]:.3f}</td>'
        f'<td class="mono num">{v["tp"]}</td><td class="mono num">{v["fp"]}</td>'
        f'<td class="mono num">{v["fn"]}</td></tr>'
        for i, (name, v) in enumerate(data["rv_repo_rows"]))

    missing = "".join(f'<li><code>{escape(n)}</code></li>' for n in data["rv_missing_repos"])
    # Straight out of the scorer output and written as markdown, so it arrives with backticks in
    # it and with characters a raw token substitution would put into the document unescaped.
    reason = md_code(data["rv_missing_reason"])

    notes = "".join(f'<li><span class="x">{i + 1}</span><div><p class="d">{md_code(body)}</p>'
                    f"</div></li>"
                    for i, body in enumerate(REPRO_NOTES[lang]))

    caveats = "".join(
        f'<li><span class="x">{i + 1}</span><div><p class="t">{escape(title)}</p>'
        f'<p class="d">{escape(body)}</p></div></li>'
        for i, (title, body) in enumerate(BENCH_CAVEATS[lang]))

    # Digest strings are 71 characters and there are two of them; shown whole, because a digest
    # truncated for layout is a digest nobody can check, which is the only thing it is for.
    prov = "".join(
        f'<li><span class="cve">{escape(k)}</span><span class="pkg mono">{escape(v)}</span></li>'
        for k, v in (
            (copy["prov_gt"], data["rv_gt_hash"]),
            (copy["prov_engine"], data["rv_engine_digest"]),
            (copy["prov_bench"], f'{data["rv_bench_url"]} · {data["rv_bench_version"]}'),
            (copy["prov_tier"], data["rv_tier"]),
            (copy["prov_reverified"], data["rv_reverified"]),
        ))

    return {
        "bench_eyebrow_parts": segments(copy["bench_eyebrow"]),
        "bench_head_lines": head_lines(copy["bench_h1_1"], copy["bench_h1_2"]),
        # All three are on the page, inside the two renderers above rather than as bare strings.
        "bench_eyebrow": None, "bench_h1_1": None, "bench_h1_2": None,
        "runs_rows": runs,
        "baseline_rows": base,
        "fam_rows": fams,
        "sb_rows": sb_rows,
        "repo_rows": repos,
        "missing_repos": missing,
        "missing_reason": reason,
        "repro_note_items": notes,
        "cav_items": caveats,
        "prov_rows": prov,
        "repro_block": escape(repro_commands()),
        "bench_repo_link": data["rv_bench_url"],
        "raw_result_link": f"{REPO_URL}/blob/main/eval/realvuln/result.json",
        "home_href": page_path("index", lang),  # the finale's button, not the nav brand
        # The sibling page. With the menu no longer carrying page links, the two sub-pages reach
        # each other here or not at all.
        "install_page_href": page_path("install", lang),
        # Row headings for the provenance list, consumed above rather than rendered on their
        # own — same reason `runs_blind_label` is dropped on the landing page.
        "prov_gt": None, "prov_engine": None, "prov_bench": None,
        "prov_tier": None, "prov_reverified": None, "runs_first_label": None,
    }


# Backticks in the copy above are markdown out of habit and out of the README they were quoted
# from; rendering them as `<code>` keeps a path or a flag looking like one.
def segments(text: str, live: bool = True) -> str:
    """An eyebrow rendered as its own claims rather than as one sentence.

    Both eyebrows on this site are a list that a middot happens to be sitting between — *open
    source · MIT · defensive use only*, *RealVuln 1.0 · Tier 0 · run 2026-08-02* — so they are
    drawn as divided segments, with the first carrying the live pulse. The split happens here
    rather than as markup in the template so the copy stays one translatable string: a translator
    who writes two claims or four gets two or four segments, and nothing in the CSS has to know.
    """
    parts = [p.strip() for p in text.split("·") if p.strip()]
    return "".join(
        '<span class="seg' + (" live" if live and i == 0 else "") + '">'
        + ('<span class="pip"></span>' if live and i == 0 else "")
        + escape(part) + "</span>"
        for i, part in enumerate(parts))


def head_lines(first: str, second: str, second_lang: str = "") -> str:
    """A hero headline as two independently maskable lines.

    It used to be one string with a `<br>` in the middle, which cannot be revealed a line at a
    time — a line break is not a box, and only a box can be masked. The second line is set in the
    code face and the first is not, which is what makes the second read as the answer to the
    first rather than as more of the same sentence.
    """
    tag = ' class="shine"' + (f' lang="{second_lang}"' if second_lang else "")
    return "".join(
        '<span class="hl"><span' + (tag if i else "") + ">"
        + escape(line) + "</span></span>"
        for i, line in enumerate((first, second)))


def next_page(href: str, kicker: str, title: str, meta: str, reveal: bool) -> str:
    """The two links on the landing page that leave it, drawn as one component.

    They were pill buttons, indistinguishable from the ones that scroll — and a control whose
    label is the only clue that it costs you a page load is a control that gets clicked by
    accident and not clicked on purpose. This says where it goes, what is there, and carries an
    arrow that leans into the destination on hover.

    The third line is the point of the thing: it is three figures the destination is made of,
    every one of them already derived and already gated, so the promise cannot drift from the
    page it promises. `reveal` because one of the two sits in the right column of a `.split`,
    where the entrance carries a horizontal offset and a full-width child starts outside the
    column — the note in the template says the same thing at the site of it.
    """
    rv = " rv" if reveal else ""
    return (f'<a class="next glass tail{rv}" href="{href}">'
            f'<span class="nx-l"><span class="nx-k">{escape(kicker)}</span>'
            f'<span class="nx-t">{escape(title)}</span>'
            f'<span class="nx-m">{escape(meta)}</span></span>'
            f'<span class="nx-a" aria-hidden="true">'
            f'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" '
            f'stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h13m-5-6 6 6-6 6"/>'
            f"</svg></span></a>")


def md_code(text: str) -> str:
    """The two marks the copy is written with, turned into elements.

    Backticks were the only one handled, and `**` shipped to the page as four asterisks around
    the most important phrase on the CRA page — copy is written in the markdown habit of the
    documents it quotes, so the habit has to be either supported or removed, and supporting it is
    the smaller surprise. Everything else stays literal: this is not a markdown renderer and a
    page that half-renders markdown is worse than one that renders none.

    Emphasis is applied to the escaped text, and only in pairs — an odd `**` is left alone rather
    than opening a `<strong>` the page never closes.
    """
    out, parts = [], escape(text).split("`")
    for i, part in enumerate(parts):
        if i % 2:
            out.append(f"<code>{part}</code>")
            continue
        chunks = part.split("**")
        if len(chunks) % 2 == 0:            # unpaired: leave the text exactly as written
            out.append(part)
            continue
        out.append("".join(f"<strong>{c}</strong>" if j % 2 else c
                           for j, c in enumerate(chunks)))
    return "".join(out)


_TYPED_FIGURE_RE = re.compile(r"\d+\s+of\s+\d+")


def substitute(text: str, figures: dict[str, str]) -> str:
    """Fill `[[token]]` figures in copy, and refuse copy that types a measurement instead.

    The guard is a shape — `N of M` — and it catches the spelling that actually rotted. It does
    not catch the Turkish phrasing, which has no fixed shape, so the promise here is smaller
    than "no copy on this site states a typed measurement": it is that both languages are
    written from one template and the template's figures come from `result.json`.
    """
    if _TYPED_FIGURE_RE.search(text):
        raise SystemExit(f"gen-site: copy types a measured figure — {text[:80]!r}. Add it to "
                         f"`figures` and reference it as [[token]]; a number typed into copy "
                         f"is the one kind on this site that no gate holds")
    for token, value in figures.items():
        text = text.replace(token, value)
    if "[[" in text:
        raise SystemExit(f"gen-site: copy references a figure nothing supplies — {text[:80]!r}")
    return text


_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
_REGION = re.compile(r"(<style[^>]*>)(.*?)(</style>)|(<script[^>]*>)(.*?)(</script>)", re.S)


def strip_comments(html: str) -> str:
    """Remove the comments from what ships, and keep them in what is read.

    The templates in `site/` are heavily commented — every rule that looks arbitrary says why it
    is there — and every one of those bytes was being served. The live landing page was 112 KB
    with **43 KB of comments in it**, 38% of the document, readable by anyone who hits View
    Source. That is the wrong place for the reasoning: the explanation belongs in the repository,
    where it is versioned beside the code it describes and where a change to it is reviewable.

    So the source keeps its comments and the build drops them. Three passes, each deliberately
    conservative, because a stripper that is clever about JavaScript is a stripper that eventually
    eats a string:

    * `<style>` — block comments only. CSS has no line comments.
    * `<script>` — block comments, plus lines whose *first* non-space characters are `//`. A
      trailing `// note` is left alone on purpose: `https://` is the same two characters and the
      only way to tell them apart is to parse the language.
    * The document — HTML comments, after the two regions above have been replaced by
      placeholders, so a `<!--` written inside a script or a style is not treated as markup.
    """
    regions: list[str] = []

    def keep(match: re.Match) -> str:
        open_tag, body, close_tag = match.group(1, 2, 3)
        if open_tag is None:
            open_tag, body, close_tag = match.group(4, 5, 6)
            # Only actual JavaScript. `<script type="application/ld+json">` is data, and JSON has
            # no comments to remove — running a comment stripper over it can only ever damage a
            # string that happens to contain the same characters.
            if "json" in open_tag.lower():
                regions.append(open_tag + body + close_tag)
                return f"\x00{len(regions) - 1}\x00"
            body = _BLOCK_COMMENT.sub("", body)
            body = "\n".join(line for line in body.splitlines()
                             if not line.lstrip().startswith("//"))
        else:
            body = _BLOCK_COMMENT.sub("", body)
        regions.append(open_tag + body + close_tag)
        return f"\x00{len(regions) - 1}\x00"

    out = _REGION.sub(keep, html)
    out = _HTML_COMMENT.sub("", out)
    out = re.sub(r"\x00(\d+)\x00", lambda m: regions[int(m.group(1))], out)
    # Comment-only lines leave their indentation behind, which is a blank line with spaces on it.
    return re.sub(r"\n[ \t]*(?=\n)", "\n", out)


def newest_changelog_date() -> str:
    """The most recent `[YYYY-MM-DD]` in CHANGELOG.md — the sitemap's `lastmod`.

    Every Tier-1 change to this repository ends with an entry in that file, so its newest date is
    the repository's own answer to "when did anything here last change". Reading it beats both
    alternatives: a typed date rots, and a wall-clock date claims a modification on every build.
    """
    dates = re.findall(r"\[(\d{4}-\d{2}-\d{2})\]",
                       _read(os.path.join(REPO, "CHANGELOG.md")))
    if not dates:
        raise SystemExit("gen-site: CHANGELOG.md carries no `[YYYY-MM-DD]` entry, and the "
                         "sitemap's lastmod is read from the newest one")
    return max(dates)


def index_values(lang: str, data: dict, copy: dict) -> dict:
    steps = "".join(
        f'<li class="surface glass rv" style="--i:{i}"><span class="t">{escape(title)}</span>'
        f'<code>{escape(code.format(**data))}</code>'
        f'<span class="d">{escape(desc.format(**data))}</span></li>'
        for i, (title, code, desc) in enumerate(STEPS[lang]))

    langs = "".join(
        f'<li class="langrow" style="--i:{i}"><span class="nm">'
        f'{escape(LANG_NAMES.get(name, name))}</span>{bar(recall * 100, i)}'
        f'<span class="pc">{recall:.0%}</span></li>'
        for i, (name, recall) in enumerate(data["lang_recall"]))

    # Doubled, because the marquee translates by exactly -50% to loop seamlessly.
    cwes = "".join(f"<span>{escape(c)}</span>" for c in data["cwe_list"])
    marquee = cwes + cwes

    # Fanned out with alternating rotation around the centre of the stack.
    spread = [("-7deg", "-3.2rem", "-4.2rem"), ("-2.4deg", "-1rem", "-1.4rem"),
              ("2.4deg", "1rem", "1.4rem"), ("7deg", "3.2rem", "4.2rem")]
    docs = "".join(
        f'<article class="doc" style="--i:{i};--r:{r};--x:{x};--y:{y}">'
        # h3, not h4. The section above these is an h2 and nothing sits between, so h4 put a
        # rung in the outline that no heading occupies — the four document names were the only
        # place on the site where jumping by heading level skipped a step.
        f'<span class="fmt">{escape(fmt)}</span><h3>{escape(title)}</h3>'
        f"<p>{escape(line)}</p></article>"
        for i, ((fmt, title, line), (r, x, y)) in enumerate(zip(DOCS[lang], spread)))

    authz = next((v for v in data["rv_families"] if v[0] == "broken_access_control"), None)
    if authz is None:
        raise SystemExit("gen-site: result.json has no `broken_access_control` family, and the "
                         "misses section quotes its score — see the comment above MISSES")
    figures = {"[[authz_tp]]": str(authz[1]), "[[authz_total]]": str(authz[2])}

    misses = "".join(
        f'<li><span class="x">{i + 1}</span><div><p class="t">{escape(title)}</p>'
        f'<p class="d">{escape(substitute(body, figures))}</p></div></li>'
        for i, (title, body) in enumerate(MISSES[lang]))

    return {
        "eyebrow_parts": segments(copy["eyebrow"]),
        "head_lines": head_lines(copy["headline_1"], copy["headline_2"]),
        "what_cards": steps,
        "lang_rows": langs,
        "cwe_marquee": marquee,
        "comp_docs": docs,
        "miss_items": misses,
        "install_plugin": escape(install_plugin_block()),
        "install_cli": escape(INSTALL_CLI),
        # The two ways off this page. Relative hrefs, like every other internal link on the
        # site: an absolute one ties the built page to the production origin and it stops
        # working from a preview or a local server. The install section keeps the two commands
        # most people want and hands the other four surfaces over; the disclosure keeps its
        # prose and hands over the run history, which needs a table this page has no room for.
        "install_next": next_page(
            page_path("install", lang), copy["nx_install_kicker"], copy["where_more"],
            copy["nx_install_meta"], reveal=False),
        "bench_next": next_page(
            page_path("benchmark", lang) + "#runs", copy["nx_bench_kicker"], copy["runs_more"],
            copy["nx_bench_meta"], reveal=True),
        # The hero's second button. It used to open the benchmark's README on GitHub, which was
        # the best available answer before this site had a page for the measurement and stopped
        # being one the day it did.
        "bench_page_href": page_path("benchmark", lang),
        # Everything below is on the page inside something built above — the eyebrow's segments,
        # the headline's two masked lines, the two cross-page cards — which is why the template
        # no longer names any of them directly.
        "eyebrow": None,
        "headline_1": None,
        "headline_2": None,
        "where_more": None,
        "runs_more": None,
        "nx_install_kicker": None,
        "nx_install_meta": None,
        "nx_bench_kicker": None,
        "nx_bench_meta": None,
    }


def install_values(lang: str, data: dict, copy: dict) -> dict:
    """Every block on the install page that is a command, a table or a list of ids.

    Nothing in here is written; all of it is shaped. The values come out of the manifests and
    the documents by way of `install_facts`, and this function decides only how they are drawn.
    """
    plugin, cli, docker = data["in_plugin"], data["in_cli"], data["in_docker"]
    surfaces = SURFACES[lang]
    if len(surfaces) != len(SURFACE_ANCHORS):
        raise SystemExit(f"gen-site: the landing page lists {len(surfaces)} surfaces and the "
                         f"install page has {len(SURFACE_ANCHORS)} sections for them")

    # The hero grid, and the page's table of contents: the same six the landing page states,
    # each now pointing at the section that installs it.
    cards = "".join(
        f'<li><a class="surface glass rv" style="--i:{i}" href="#{anchor}">'
        f'<span class="n">{i + 1:02d}</span><span class="t">{escape(title)}</span>'
        f'<code>{escape(code)}</code><span class="d">{escape(desc)}</span></a></li>'
        for i, ((title, code, desc), anchor) in enumerate(zip(surfaces, SURFACE_ANCHORS)))

    choose = "".join(
        f'<tr style="--i:{i}"><td class="lbl">{escape(situation)}</td>'
        f'<td><a href="#{SURFACE_ANCHORS[idx]}">{escape(surfaces[idx][0])}</a></td>'
        f'<td class="lbl">{escape(cost)}</td></tr>'
        for i, (idx, situation, cost) in enumerate(CHOOSE[lang]))

    # The plugin's own commands. `.miss` pairs a marker with a title and a line of prose, which
    # is the shape a command has — name, arguments, what it does.
    # Name and arguments, and not the sentence under them. The prose is read out of the
    # command files and is written in English on purpose — it is what Claude Code itself shows
    # in the picker — so on this page it was four English paragraphs a reader scrolls past to
    # reach the next install path. The names and their flags are the part somebody types.
    commands = "".join(
        f'<li><span class="x ok">{i + 1}</span><div>'
        f'<p class="t"><code>{escape(name)}</code>'
        + (f'<span class="hint">{escape(hint)}</span>' if hint else "")
        + '</p></div></li>'
        for i, (name, hint, _desc) in enumerate(data["in_commands"]))

    hooks = "".join(
        f'<li><span class="x ok">{i + 1}</span><div>'
        f'<p class="t"><code>{escape(hid)}</code></p>'
        f'<p class="d">{escape(name)}<br><code>{escape(args)}</code></p></div></li>'
        for i, (hid, name, args) in enumerate(data["in_hooks"]))

    essentials = "".join(
        f'<li><span class="cve">{escape(label)}</span>'
        f'<span class="pkg">{md_code(value)}</span></li>'
        for label, value in data["in_mcp_essentials"])

    clients = "".join(
        f'<div class="snip"><p class="cap"><strong>{escape(name)}</strong> — {md_code(where)}'
        f'</p><pre class="sh"><code>{escape(code)}</code></pre></div>'
        for name, where, _syntax, code in data["in_mcp_clients"])

    cli_rows = "".join(
        f'<li><span class="cve">{escape(label)}</span>'
        f'<span class="pkg mono">{escape(value)}</span></li>'
        for label, value in (
            ("package", cli["package"]),
            ("version", cli["version"]),
            ("python", cli["python"]),
            ("commands", ", ".join(name for name, _ in cli["scripts"])),
            ("runtime deps", ", ".join(cli["deps"]) if cli["deps"] else "none"),
        ))

    docker_rows = "".join(
        f'<li><span class="cve">{escape(label)}</span>'
        f'<span class="pkg mono">{escape(value)}</span></li>'
        for label, value in (
            ("base", docker["tag"]),
            ("pinned to", docker["digest"].split("@", 1)[-1]),
            ("runs as", f'uid {docker["user"]}'),
            ("entrypoint", docker["entrypoint"]),
        ))

    scanners = "".join(
        f'<li class="surface glass rv" style="--i:{i}"><span class="t">{escape(tool)}</span>'
        f'<code>{escape(how)}</code><span class="d">{escape(purpose)}</span></li>'
        for i, (tool, purpose, how) in enumerate(data["in_scanners"]))

    plugin_block = (f'/plugin marketplace add {plugin["owner"]}/{REPO_URL.rsplit("/", 1)[-1]}\n'
                    f'/plugin install {plugin["plugin"]}@{plugin["marketplace"]}\n'
                    f'/{plugin["plugin"]} .')

    # Two paths, both permanently true: the released package, and the same package from any
    # commit. The comment on the first points at the section that explains which one exists.
    cli_block = (
        f'# the released package\n'
        f'pip install {cli["package"]}\n'
        f"\n"
        f"# or the same package from any commit, no release needed\n"
        f'pip install "git+{REPO_URL}#subdirectory=kit"\n'
        f"\n"
        f"secaudit .                             # audit this tree\n"
        f"secaudit . --min high --format sarif   # for GitHub code scanning\n"
        f"secaudit . --since main                # only what this branch introduced")

    slug = REPO_URL.split("github.com/", 1)[-1]
    action_block = (
        f"- uses: actions/checkout@v5\n"
        f"    with: {{ fetch-depth: 0 }}      # so --since can see the base branch\n"
        f"- uses: {slug}@{data['tag']}\n"
        f"    with:\n"
        f"      fail-on: high\n"
        f"      sarif: audit.sarif")

    return {
        "ins_eyebrow_parts": segments(copy["ins_eyebrow"]),
        "ins_head_lines": head_lines(copy["ins_h1_1"], copy["ins_h1_2"]),
        # On the page inside the two renderers above rather than as bare strings.
        "ins_eyebrow": None, "ins_h1_1": None, "ins_h1_2": None,
        "surface_cards": cards,
        "choose_rows": choose,
        "plugin_block": escape(plugin_block),
        "command_rows": commands,
        "cli_block": escape(cli_block),
        "cli_rows": cli_rows,
        "mcp_essentials": essentials,
        "mcp_verify_block": escape(data["in_mcp_verify"]),
        "mcp_client_blocks": clients,
        "action_block": escape(action_block),
        "docker_block": escape(data["in_docker_cmds"]),
        "docker_rows": docker_rows,
        "hook_block": escape(data["in_hook_snippet"]),
        "hook_rows": hooks,
        "scanner_items": scanners,
        "getting_started_link": f"{REPO_URL}/blob/main/docs/getting-started.md",
        # The sibling page — see the note in `bench_values`.
        "bench_page_href": page_path("benchmark", lang),
    }


# Which structured-data type each page is. The landing page is the product; the benchmark page
# is a measurement of it, and calling that a SoftwareApplication too would be describing the
# same thing twice to a machine that has no way of noticing.
JSONLD = {
    "index": lambda copy, url, lang: {
        "@type": "SoftwareApplication",
        "name": "SecAudit",
        "applicationCategory": "SecurityApplication",
        "operatingSystem": "Linux, macOS, Windows",
        "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
    },
    "benchmark": lambda copy, url, lang: {
        "@type": "Dataset",
        "name": copy["page_title"],
        "creator": {"@type": "Organization", "name": "SecAudit"},
        "license": "https://opensource.org/licenses/MIT",
        "isAccessibleForFree": True,
        "distribution": {"@type": "DataDownload", "encodingFormat": "application/json",
                         "contentUrl": f"{REPO_URL}/blob/main/eval/realvuln/result.json"},
    },
    # `TechArticle`, not `HowTo`. A HowTo without a `step` list is a type asserting a structure
    # the document does not have, and the honest reading of this page is documentation about
    # installing something — which is exactly what TechArticle is for.
    "404": lambda copy, url, lang: {"@type": "WebPage", "name": copy["page_title"]},
    # `WebPage`, not `TechArticle`: this one compares two products rather than teaching a task,
    # and claiming an article type for a comparison table is the same overstatement the rest of
    # the site refuses in prose.
    "compare": lambda copy, url, lang: {"@type": "WebPage", "name": copy["page_title"]},
    "install": lambda copy, url, lang: {
        "@type": "TechArticle",
        "headline": copy["page_title"],
        "proficiencyLevel": "Beginner",
        "about": {"@type": "SoftwareApplication", "name": "SecAudit",
                  "applicationCategory": "SecurityApplication"},
    },
}


def shell_values(page: str, lang: str, data: dict, copy: dict) -> dict:
    """Head, nav, footer and signature — identical on every page, by construction."""
    root = page in ROOT_PAGES
    canonical = f"{ORIGIN}/404.html" if root else page_href(page, lang)
    # Root-absolute on the 404, which renders at an address the generator did not choose: a
    # relative link there resolves against the path that did not exist.
    home = "/" if root else page_path("index", lang)

    # Every entry is an anchor into this page, so every entry gets `data-spy` and the capsule's
    # indicator has something to follow on all three pages rather than only on the landing one.
    # The whole element is the token rather than only its links: a page with no sections of its
    # own — the 404 — would otherwise render an empty capsule floating over it.
    links = "".join(f'<a href="{href}" data-spy="{href[1:]}">{escape(text)}</a>'
                    for href, text in NAV[page][lang])
    nav = (f'<nav class="navpillwrap" aria-label="{escape(copy["nav_label"])}">'
           f'<div class="navpill" id="navpill"><span class="pillglow"></span>{links}</div>'
           f"</nav>") if links else ""

    # Both languages, the open one marked. `aria-current` rather than a class, because "this is
    # the page you are on" is the thing being said and a screen reader should hear it too.
    seg = "" if root else "".join(
        '<a href="{}"{}>{}</a>'.format(
            page_path(page, code), ' aria-current="page"' if code == lang else "", code.upper())
        for code in COPY)

    # No alternates and no canonical for the 404: it is one file in two languages, served for
    # addresses that do not exist, and telling a crawler it is the canonical form of anything
    # would be inviting it into the index.
    # An English-only page advertises one alternate — itself — rather than a `tr` twin that is
    # not published. Claiming a translation that 404s is worse than claiming none.
    alt_langs = ("en",) if page in ENGLISH_ONLY_PAGES else tuple(COPY)
    hreflang = "" if root else "\n".join(
        [f'<link rel="alternate" hreflang="{code}" href="{page_href(page, code)}">'
         for code in alt_langs]
        + [f'<link rel="alternate" hreflang="x-default" href="{page_href(page, "en")}">'])

    jsonld = dict(JSONLD[page](copy, canonical, lang),
                  **{"@context": "https://schema.org", "url": canonical, "inLanguage": lang,
                     "codeRepository": REPO_URL, "description": copy["page_description"]})

    # Every published page, linked from the footer of every published page. The link check
    # verifies that a link resolves; nothing verified that a page could be *reached*, and the
    # comparison page shipped orphaned for exactly as long as it took to notice. `PAGE_TITLES`
    # keeps the labels short — a footer is not a table of contents.
    footer_links = "".join(
        '<a href="{}"{}>{}</a>'.format(
            page_path(name, lang),
            ' aria-current="page"' if name == page else "",
            escape(FOOTER_LABELS[lang][name]))
        for name in PAGE_PATHS)

    return {
        "footer_links": footer_links,
        "footer_nav_label": escape(copy["nav_label"]),
        "canonical": canonical,
        "head_extra": ('<meta name="robots" content="noindex">' if root else ""),
        # Absolute, because a relative `og:image` is ignored by every scraper. The template
        # declared `summary_large_image` and supplied no image at all, which asks for a big
        # preview card and gives it nothing to put in — a blank card, not an absent one.
        #
        # One card per language, and the filename and the alt text both come from the renderer
        # that draws them rather than being restated here: a Turkish page linking the English
        # card is the kind of thing that is invisible until somebody shares the link. The 404
        # renders as English and takes the English card, which is the right answer for a page
        # served at an address nobody chose.
        "og_image": f"{ORIGIN}/{OG_CARDS[lang]['file']}",
        # Root-absolute, not relative: the 404 is served at whatever address failed, so the one
        # page most likely to be bookmarked is the one a relative path would break on.
        "apple_icon": f"/{OG_ICON['file']}",
        # The external figure leads here for the same reason it leads on the page and on the
        # card: it is the one measured on a corpus this repository did not label.
        "og_alt": OG_CARDS[lang]["alt"].format(**data),
        "hreflang": hreflang,
        "mark_svg": MARK_SVG,
        "jsonld": json.dumps(jsonld, ensure_ascii=False,
                             separators=(",", ":")).replace("</", "<\\/"),
        "nav": nav,
        # Consumed by the nav element built above rather than rendered on its own.
        "nav_label": None,
        # Locale in the form a scraper expects, and every other locale the same page exists in.
        # Derived from the language list, so a third language is a nav entry and nothing else.
        "og_locale": OG_LOCALES[lang],
        "og_locale_alt": "".join(
            f'\n<meta property="og:locale:alternate" content="{OG_LOCALES[other]}">'
            for other in COPY if other != lang),
        "credit": (
            '<p class="credit" lang="en">Developed with '
            '<svg class="heart" viewBox="0 0 24 24" fill="currentColor" role="img" '
            'aria-label="love"><path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.7l-1-1.1a5.5 5.5 0 0 '
            '0-7.8 7.8l1.1 1L12 21l7.7-7.6 1.1-1a5.5 5.5 0 0 0 0-7.8z"/></svg> by '
            f'<a href="{DEVELOPER_URL}" rel="noreferrer">{DEVELOPER_NAME}</a></p>'),
        # The 404 offers both languages as buttons in its own body, so the segment in the bar
        # would be a second, quieter copy of the only choice the page is asking for.
        "lang_switch": "" if root else (
            f'<div class="langseg" role="group" aria-label="{copy["lang_label"]}">'
            f"{seg}</div>"),
        # Consumed by the segment's `aria-label` just above rather than rendered on its own.
        "lang_label": None,
        # The brand scrolls to the top where the top is this page, and goes home where it is not.
        "home_link": "#top" if page == "index" else home,
        "repo": REPO_URL,
        "favicon": favicon_href(),
    }


OFFICIAL_DOCS = "https://code.claude.com/docs/en/claude-security"


def compare_values(lang: str, data: dict, copy: dict) -> dict:
    """The capability table, the two quotations, and the four things this is not.

    The one page whose content is partly about somebody else's product, so the drawing is where
    the honesty lives: a `True` renders as a tick, a string renders as *the figure itself*, and
    `None` renders as an em dash. The score row is a string for that reason — "published score:
    ✅" is a claim a reader cannot check, and "35.9% / 22.3%" is one they can, because both
    numbers are on this site with their caveats and their raw scorer output.
    """
    def cell(v) -> str:
        if v is True:
            return '<td class="num yes" aria-label="yes">✓</td>'
        if v is None:
            return '<td class="num no" aria-label="no">—</td>'
        return f'<td class="num mono fig">{escape(str(v).format(**data))}</td>'

    rows = "".join(
        f'<tr style="--i:{i}"><td class="lbl">{escape(copy[key])}</td>'
        f"{cell(official)}{cell(ours)}</tr>"
        for i, (key, official, ours) in enumerate(CMP_ROWS))

    # Each quotation carries the note that says why it is on this page. A quote without that is
    # a pull-quote; with it, it is an argument the reader can disagree with.
    # The quotation itself is never translated, and the gloss under it is why this renderer has
    # three lines instead of two. A translated quotation is not a quotation: this page's own rule
    # is "quoted, not paraphrased", it prints the source and the date it was read beside the
    # words, and the Turkish tree used to render both sentences in Turkish under a panel headed
    # `code.claude.com/docs` — a claim about somebody else's product, in words they never wrote.
    # The original stays; `q_{n}_gloss` carries the reading, marked as ours.
    def quote(i: int, n: int) -> str:
        gloss = copy.get(f"q_{n}_gloss")
        return (f'<li style="--i:{i}"><span class="q">&ldquo;{escape(copy[f"q_{n}"])}&rdquo;</span>'
                + (f'<span class="gloss">{escape(gloss)}</span>' if gloss else "")
                + f'<span class="why">{escape(copy[f"q_{n}_note"])}</span></li>')

    quotes = "".join(quote(i, n) for i, n in enumerate((1, 2)))

    nots = "".join(
        f'<li class="famrow wide" style="--i:{i}">'
        f'<span class="nm">{escape(copy[f"not_{n}"])}</span>'
        f'<span class="why">{escape(copy[f"not_{n}_why"])}</span></li>'
        for i, n in enumerate((1, 2, 3, 4), start=0))

    return {
        # Every other eyebrow on this site goes through `segments`, which is what puts the text
        # inside a padded `.seg`. This one was interpolated straight into `.pill` — and `.pill`
        # carries no padding of its own, because on every page that was written correctly the
        # padding belongs to the segment. The capsule therefore drew its border hard against the
        # glyphs, which Turkish shows first: `ğ` reaches higher and `ç` lower than the ascii the
        # layout was eyeballed in.
        "cmp_eyebrow_parts": segments(copy["cmp_eyebrow"], live=False),
        "cmp_eyebrow": None,
        "cmp_head_lines": "".join(
            f'<span class="hl"><span>{escape(copy[f"cmp_head_{n}"])}</span></span>'
            for n in (1, 2)),
        "cmp_head_1": None, "cmp_head_2": None,
        "cmp_rows": rows,
        "quote_rows": quotes,
        "not_rows": nots,
        "cmp_official_link": OFFICIAL_DOCS,
        "install_href": page_path("install", lang),
        "home_href": page_path("index", lang),
        **{f"q_{n}": None for n in (1, 2)},
        **{f"q_{n}_note": None for n in (1, 2)},
        **{f"q_{n}_gloss": None for n in (1, 2)},
        **{f"not_{n}": None for n in (1, 2, 3, 4)},
        **{f"not_{n}_why": None for n in (1, 2, 3, 4)},
        **{key: None for key, _, _ in CMP_ROWS},
    }


def e404_values(lang: str, data: dict, copy: dict) -> dict:
    return {
        "e404_parts_en": segments(copy["e404_eyebrow_en"], live=False),
        "e404_parts_tr": segments(copy["e404_eyebrow_tr"], live=False),
        "e404_head_lines": head_lines(copy["e404_h1"], copy["e404_h2"], second_lang="tr"),
        # On the page inside the renderers above rather than as bare strings.
        "e404_eyebrow_en": None, "e404_eyebrow_tr": None, "e404_h1": None, "e404_h2": None,
        # Two buttons, one per language, and nothing else. A reader who has landed on an address
        # that does not exist is being asked one question — which language — and a third control
        # beside it is a second question nobody asked.
        "repo": None, "cta_repo": None,
    }


PAGE_COPY = {"index": COPY, "benchmark": BENCH_COPY, "install": INSTALL_COPY,
             "compare": COMPARE_COPY, "404": E404}
PAGE_VALUES = {"index": index_values, "benchmark": bench_values, "install": install_values,
               "compare": compare_values, "404": e404_values}
# Rendered like the others but written once, to the root, because the server picks it rather
# than a reader navigating to it.
ROOT_PAGES = ("404",)

# Copy that lands in the head rather than in the document body: escaped, never marked up.
HEAD_COPY = ("lang", "page_title", "page_description")


def build(page: str, lang: str, data: dict) -> str:
    # Copy strings may interpolate facts (a count inside a sentence), so they are formatted
    # first and in isolation. This used to run over the whole `values` dict at the end, which
    # was fine only while nothing else in it contained a brace — the JSON-LD block does, and
    # `.format()` would have read it as a field reference and raised.
    raw = {k: COPY[lang][k] for k in SHELL_KEYS}
    raw.update(PAGE_COPY[page][lang])
    copy = {k: (v.format(**data) if isinstance(v, str) and "{" in v else v)
            for k, v in raw.items()}

    # The head's two strings are the only copy on the site with a hard external length limit, and
    # the only copy whose overflow is invisible from the page: a search result cuts the title at
    # roughly 60 characters and the description at roughly 160, and everything past the cut is
    # written, shipped, rendered and never read. Six of the eight descriptions here were over —
    # one by a hundred characters — because they were written as prose in a file full of prose,
    # beside sentences that have no limit at all. Measured after formatting, because a
    # description that interpolates a figure is only as long as the figure makes it.
    for key, floor, ceiling in (("page_title", 15, 60), ("page_description", 50, 160)):
        n = len(copy[key])
        if not floor <= n <= ceiling:
            raise SystemExit(
                f"gen-site: {page}/{lang} {key} is {n} characters, outside {floor}-{ceiling} — "
                f"a search result would "
                f"{'truncate it mid-sentence' if n > ceiling else 'have nothing to show'}:\n"
                f"    {copy[key]}")

    # Copy is prose, written in the same markdown habit as the documents it quotes, and it was
    # being substituted into the document verbatim. Two consequences, both visible: a backtick
    # stayed a backtick, and `--since <ref>` lost its second half — the browser read `<ref>` as
    # an unknown element and swallowed it, so the sentence about the pull-request gate was
    # missing the argument it is about. Head values are escaped but not marked up: a `<code>`
    # element inside a `content` attribute is not a code element, it is broken markup. The
    # unmarked copy is what the structured-data block and the renderers below still see, so
    # nothing gets escaped twice.
    shown = {k: (v if not isinstance(v, str) else
                 escape(v) if k in HEAD_COPY else md_code(v))
             for k, v in copy.items()}

    with open(page_body(page), encoding="utf-8") as f:
        main = f.read()
    css = ""
    if os.path.exists(page_style(page)):
        with open(page_style(page), encoding="utf-8") as f:
            css = f.read()
    with open(SHELL, encoding="utf-8") as f:
        template = f.read().replace("{{main}}", main).replace("{{page_css}}", css)

    values = {**data, **shown, **shell_values(page, lang, data, copy),
              **PAGE_VALUES[page](lang, data, copy)}
    values = {k: v for k, v in values.items() if v is not None}

    missing = sorted(set(_TOKEN.findall(template)) - set(values))
    if missing:
        raise SystemExit(f"gen-site: {page} uses undefined token(s): {missing}")
    unused = sorted(set(values) - set(_TOKEN.findall(template)) - set(data))
    if unused:
        raise SystemExit(f"gen-site: {page}: value(s) supplied but never rendered: {unused}")

    html = _TOKEN.sub(lambda m: values[m.group(1)], template)

    # A Content-Security-Policy, and the hash in it is computed from the script it is describing
    # rather than pasted beside it. GitHub Pages cannot set response headers, so this is the meta
    # form: `frame-ancestors` and `report-uri` are header-only and deliberately absent rather
    # than written and silently ignored. `default-src 'none'` is the whole point — the page
    # fetches nothing, from anywhere, ever, and a security tool's own site is the last place that
    # should be taken on trust. `style-src` keeps `unsafe-inline` because the stagger delays are
    # `style="--i:N"` attributes, which no practical number of hashes covers; script is where the
    # hash earns its keep. Two passes because the hash of the script cannot be known until the
    # script has had its tokens substituted, and the marker is checked for in `verify`.
    script = re.search(r"<script>(.*?)</script>", html, re.S)
    if not script:
        raise SystemExit(f"gen-site: {page} has no inline script to hash for the CSP — either "
                         f"the shell changed shape or the policy is now describing nothing")
    digest = base64.b64encode(hashlib.sha256(script.group(1).encode("utf-8")).digest()).decode()
    return html.replace("__CSP_SCRIPT__", f"sha256-{digest}")


# What each page must be caught rendering. Every one of these is a figure that has, or could
# have, gone stale in prose while every gate stayed green — so "the template renders it" is
# asserted rather than assumed.
FIGURES = {
    "compare": ("rv_pct_f3", "sb_pct_recall", "mcp_tools"),
}

STATS = {
    # The percentage forms, because those are what this page renders. Gating the raw forms here
    # would have gone on passing while the panels showed something else: `0.301` is a substring
    # of nothing on the page, but `recall` and `f3` are dict keys whose raw values still exist,
    # and a gate that asserts a figure the page stopped printing asserts nothing.
    "index": ("pct_recall", "pct_precision", "pct_f3", "trap_fps", "detectors", "gates",
              "asvs_cwes",
              # The external figures are gated exactly like the fixture ones. They are the
              # numbers the page now leads with, and the page spent six benchmark runs
              # claiming this measurement had never happened, so "rendered" is not something
              # to take on trust here.
              "rv_pct_f3", "rv_pct_precision", "rv_pct_recall", "rv_repos"),
    # The benchmark page states the matrix the aggregates are computed from. A page that
    # renders F3 without the counts behind it is the shape this whole page argues against.
    "benchmark": ("rv_f3", "rv_f2", "rv_precision", "rv_recall", "rv_tp", "rv_fp", "rv_fn",
                  "rv_tn"),
    # Four counts that are each a promise the page then has to keep further down: six sections,
    # four slash commands listed by name, six MCP tools listed by name, and a dependency list
    # rendered from the manifest. The last one is the one worth gating — "zero dependencies" is
    # the claim a reader of a security tool checks, and a page that states it from anywhere but
    # the manifest would keep stating it after the first one was added.
    "install": ("surfaces", "commands", "mcp_tools", "runtime_deps"),
    # Nothing in STATS: the comparison page states its figures in table cells rather than in the
    # animated stat panels this block asserts against, and asserting the wrong shape is how a
    # gate ends up passing vacuously. Gated by FIGURES below instead.
    "compare": (),
    # Nothing to assert: the 404 states no figure, which is the point of it.
    "404": (),
}


def verify(name: str, page: str, data: dict) -> list[str]:
    """Assert the page states the facts it was given, and no leftover tokens survived.

    Cheap, and it catches the one failure that matters: a stat block that renders a number the
    scorecard does not support, because someone edited the template instead of the source."""
    problems = []
    leftover = _TOKEN.findall(page)
    if leftover:
        problems.append(f"unresolved token(s) in output: {sorted(set(leftover))}")
    # The CSP marker is a bare string rather than a token, so the substitution checks in `build`
    # cannot see it. Unreplaced it would ship a policy naming a script hash of `__CSP_SCRIPT__`,
    # which blocks the page's own script and leaves every reveal stuck at opacity 0.
    if "__CSP_" in page:
        problems.append("the CSP marker survived into the output — the policy would name a "
                        "hash that matches nothing and block the page's own script")

    # The shell's two composition tokens are substituted by a plain string replace, which has no
    # idea what a CSS comment is: a comment that spelled the main-element token out was replaced
    # too, and the entire landing page rendered inside the stylesheet. Every figure still
    # matched, every gate stayed green, and the page was a blank screen. Structure is therefore
    # asserted rather than assumed — one main element, and the stylesheet closed before the body
    # opens.
    if page.count("<main") != 1:
        problems.append(f"expected exactly one main element, found {page.count('<main')} — the "
                        f"shell's composition tokens went somewhere they were not meant to")
    if not 0 < page.index("</style>") < page.index("<body"):
        problems.append("the stylesheet does not close before the body opens — page content "
                        "was substituted into the style block")

    # Every nav entry names a section of this page. An entry pointing at an id the page does not
    # have is the quietest kind of broken link: it still looks like a link, it still highlights,
    # it simply does nothing when clicked, and the scroll-spy skips it without a word. The union
    # across languages, because the labels are translated and the anchors must not be.
    for anchor in sorted({a for entries in NAV[name].values() for a, _ in entries}):
        if f'id="{anchor[1:]}"' not in page:
            problems.append(f"the nav points at `{anchor}`, which is not a section of this "
                            f"page — the entry would highlight and scroll nowhere")

    for key in STATS[name]:
        # `>value</b>` rather than `<b>value</b>`: the stat elements carry a `data-count`
        # attribute that the counter animation reads, and the value has to be the element's
        # own text so the page still states it with scripting off. Matching the closing side
        # asserts exactly that — the rendered text, whatever attributes the tag grew.
        if f">{data[key]}</b>" not in page:
            problems.append(f"stat `{key}` ({data[key]}) is not on the page — the template "
                            f"stopped rendering it, or renders something else")
        if f'data-count="{data[key]}"' not in page:
            problems.append(f"stat `{key}` ({data[key]}) renders without a matching "
                            f"`data-count`, so the counter would animate to a different "
                            f"number than the page states")
    # Figures a page states in running text or in a table rather than in a stat panel. The
    # comparison page is the case this exists for: its SecAudit column puts a claim beside a
    # claim about somebody else's product, and the two cells that are numbers rather than ticks
    # are the ones a reader can check. A table that quietly stopped printing them would read as
    # two more ticks and assert more than this project can support.
    # Exactly one `h1`. The one heading rule every accessibility checklist agrees on, and the
    # rule this build broke the moment pages started being generated from files rather than
    # written: the hero states the document's name and the document states it again. Sixteen
    # pages, two languages, and nothing would have said so.
    h1s = len(re.findall(r"<h1[ >]", page))
    if h1s != 1:
        problems.append(f"the page has {h1s} `h1` elements — a document outline has exactly one, "
                        f"and a page with two is a page where the reader cannot tell which is "
                        f"the subject")

    for key in FIGURES.get(name, ()):
        # The *cell*, not the page. The first version of this asserted only that the number
        # appeared somewhere, and it passed with the cell mutated to a plain tick — because the
        # same figure is also quoted in the paragraph under the table. A gate that the prose can
        # satisfy is not gating the table, which is the whole thing it was written for.
        # The *cells*, collected first, then searched. Matching `>{figure}<` directly does not
        # work and the attempt is instructive: one cell states two figures at once
        # ("35.9% / 22.3%"), so neither is ever the whole of a cell's text.
        cells = re.findall(r'class="num mono fig">([^<]*)<', page)
        if not any(data[key] in c for c in cells):
            problems.append(f"figure `{key}` ({data[key]}) is not in a table cell of its own — "
                            f"the column stopped stating the number and now reads as a bare "
                            f"claim")

    # The claim that outlived its truth by six runs. Cheap to assert, and the assertion is the
    # only thing that would have caught it.
    for stale in ("has not been run", "henüz çalıştırılmadı", "Henüz çalıştırılmadı"):
        if stale in page:
            problems.append(f"the page still says {stale!r} about the external benchmark, which "
                            f"has been run {data['rv_runs']} times (F3 {data['rv_f3']})")
    return problems


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    data = facts()
    problems: list[str] = []
    pages = {}
    for name in PAGE_COPY:
        for lang in (("en",) if name in ROOT_PAGES else COPY):
            html = build(name, lang, data)
            pages[(name, lang)] = html
            problems += [f"[{name}/{lang}] {p}" for p in verify(name, html, data)]

    if problems:
        print("SITE CHECK FAILED:")
        print("\n".join("  - " + p for p in problems))
        return 1

    # Every internal link, resolved against the set of pages just rendered. A dead one is the
    # quietest possible defect on a static site — it looks like a link, it costs a page load, and
    # the only thing that reports it is a reader. It also makes the 404's own claim true: the
    # page says a link on this site cannot have brought you here, and this is what makes that a
    # statement rather than a hope.
    def out_path(name, lang: str) -> str:
        """Where a rendered page is written."""
        if name in ROOT_PAGES:
            return "404.html"
        else:
            tail = PAGE_PATHS[name]
        return ("" if lang == "en" else lang + "/") + tail + "index.html"

    built = {out_path(n, lg): h for (n, lg), h in pages.items()}
    ids = {path: set(re.findall(r'id="([^"]+)"', h)) for path, h in built.items()}
    links: dict[str, set[str]] = {}
    # The pages are not the only thing published. `href` also carries the home-screen icon, and
    # an asset the copy step does not know about fails here rather than as a missing icon on
    # somebody's phone — which is the same reasoning as the link check itself, one level down.
    assets = {c["file"] for c in OG_CARDS.values()} | {OG_ICON["file"]}
    for path, html in built.items():
        for href in sorted(set(re.findall(r'href="([^"]+)"', html))):
            if href.startswith(("http://", "https://", "mailto:", "data:")):
                continue
            target, _, frag = href.partition("#")
            if not target:
                if frag and frag not in ids[path]:
                    problems.append(f"[{path}] `#{frag}` is not an id on this page")
                continue
            # Root-absolute (every internal link the generator writes, and the 404's) or
            # relative to the directory this page sits in. `/` is the case worth spelling out:
            # it resolves to the empty path, and an empty path is the home page.
            if target.startswith("/"):
                resolved = target[1:]
            else:
                here = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
                resolved = here + target
            if resolved == "" or resolved.endswith("/"):
                resolved += "index.html"
            resolved = os.path.normpath(resolved).replace("\\", "/")
            if resolved in assets:
                continue
            if resolved not in built:
                problems.append(f"[{path}] `{href}` points at {resolved}, which is not a page "
                                f"this build produced")
            elif frag and frag not in ids[resolved]:
                problems.append(f"[{path}] `{href}` points at {resolved}, which has no "
                                f"`#{frag}`")
            elif resolved != path:
                links.setdefault(path, set()).add(resolved)

    # The mirror of the check above, and the one that was missing. That one asks whether a link
    # goes anywhere; this asks whether a page can be arrived at. The comparison page shipped
    # orphaned — rendered, published, in the sitemap, and reachable only by typing the URL —
    # because every check in this file was pointed the other way round.
    #
    # Walked from the home pages rather than counted, and both earlier attempts are why. Counting
    # "is this linked from anywhere" passed, because the footer links every page from every page
    # including itself. Excluding self-links passed too, because the language switcher makes any
    # two orphans link to each other — a pair of unreachable pages that vouch for one another is
    # exactly the shape a count cannot see and a walk can.
    reachable = {p for p in ("index.html", "tr/index.html") if p in built}
    frontier = list(reachable)
    while frontier:
        for nxt in links.get(frontier.pop(), ()):
            if nxt not in reachable:
                reachable.add(nxt)
                frontier.append(nxt)
    for path in sorted(set(built) - reachable):
        if path == "404.html":
            continue  # served for addresses that do not exist; nothing should link to it
        problems.append(f"[{path}] no path of links leads here from the home page — the build "
                        f"publishes it and a reader can only arrive by typing the address")

    if problems:
        print("SITE CHECK FAILED:")
        print("\n".join("  - " + p for p in problems))
        return 1

    if "--check" in argv:
        print(f"Site renders cleanly — {len(pages)} page(s), every internal link resolved, "
              f"recall {data['recall']}, F3 {data['f3']} own / {data['rv_f3']} external, "
              f"{data['detectors']} detectors, {data['gates']} gates, all derived from the repo.")
        return 0

    os.makedirs(DIST, exist_ok=True)
    # Remove pages a previous build wrote and this one did not.
    #
    # `site/dist/` is gitignored and CI builds it from a clean checkout, so a stale file here can
    # never reach the published site — this is about the local loop, where a build that removes
    # eighteen pages otherwise leaves all eighteen sitting on disk and the next `ls` says the
    # change did not happen. Scoped to `index.html` files and the directories that held them,
    # which is exactly the class that goes stale; assets are left alone, because deleting
    # something this function does not know it wrote is a worse failure than keeping it.
    wanted = {os.path.normcase(os.path.join(DIST, *out_path(n, lg).split("/")))
              for (n, lg) in pages}
    for root, _dirs, files in os.walk(DIST, topdown=False):
        for name in files:
            if name != "index.html":
                continue
            path = os.path.join(root, name)
            if os.path.normcase(path) not in wanted:
                os.remove(path)
        if root != DIST and not os.listdir(root):
            os.rmdir(root)
    for (name, lang), html in pages.items():
        # `/benchmark/index.html` rather than `/benchmark.html`: the URL then has no extension
        # and no trailing-slash ambiguity, which matters because the nav's anchors are built
        # from it on every other page.
        rel = out_path(name, lang)
        out = os.path.join(DIST, *rel.split("/"))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write(strip_comments(html))
    # A custom domain needs CNAME on the published branch, and it must agree with ORIGIN —
    # one produces the other, so they cannot disagree.
    with open(os.path.join(DIST, "CNAME"), "w", encoding="utf-8") as f:
        f.write(ORIGIN.split("//", 1)[1].rstrip("/") + "\n")
    # A sitemap is worth writing only because it is generated: four URLs are easy to keep in a
    # head, and the fifth is the one that gets forgotten. Same list the pages are written from,
    # so it cannot describe a page that was not published.
    # Each entry declares every language the same page exists in, including itself, which is
    # the form Google documents. Without it a crawler has to fetch and parse a page to discover
    # that the other one exists, and the two can be indexed as duplicates in the meantime.
    def alternates(name: str) -> str:
        return "".join(
            f'<xhtml:link rel="alternate" hreflang="{code}" href="{page_href(name, code)}"/>'
            for code in COPY) + (
            f'<xhtml:link rel="alternate" hreflang="x-default" '
            f'href="{page_href(name, "en")}"/>')

    # `lastmod`, which the sitemap did not carry and is the one element a crawler actually acts
    # on — without it every URL looks equally fresh forever, and the two pages that change when a
    # number moves look no different from the install page that has not changed in weeks.
    #
    # It is DERIVED, like everything else here, and from the repository's own record of when it
    # last changed: the newest date in CHANGELOG.md. A wall-clock `today` would be worse than
    # nothing — it would stamp every page as modified on every build, which is precisely the
    # inaccuracy that makes a crawler stop believing the field — and it would also make the
    # build non-reproducible, which check 3 would fail on tomorrow.
    stamp = newest_changelog_date()
    # `ROOT_PAGES` excluded, and not only because `page_href` has no path for them: a sitemap is
    # a list of pages worth indexing, and the 404 is the one page on the site that says so in a
    # `robots` meta tag of its own.
    urls = "\n".join(
        f"  <url><loc>{page_href(name, lang)}</loc>"
        f"<lastmod>{stamp}</lastmod>{alternates(name)}</url>"
        for name in PAGE_COPY if name not in ROOT_PAGES for lang in COPY)
    with open(os.path.join(DIST, "sitemap.xml"), "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" '
                'xmlns:xhtml="http://www.w3.org/1999/xhtml">\n'
                f"{urls}\n</urlset>\n")
    with open(os.path.join(DIST, "robots.txt"), "w", encoding="utf-8") as f:
        f.write(f"User-agent: *\nAllow: /\nSitemap: {ORIGIN}/sitemap.xml\n")
    # The cards have to ship with the pages, or the meta tag points at a 404 — which renders as
    # a broken preview rather than as no preview at all. Every card the renderer knows about,
    # rather than a filename repeated here: a third language would otherwise publish a page
    # whose card was never copied.
    for card in [c["file"] for c in OG_CARDS.values()] + [OG_ICON["file"]]:
        src_path = os.path.join(SITE, card)
        if not os.path.exists(src_path):
            print(f"gen-site: site/{card} is missing — run scripts/gen_og_image.py")
            return 1
        with open(src_path, "rb") as src, open(os.path.join(DIST, card), "wb") as dst:
            dst.write(src.read())
    print(f"Wrote site/dist/ — {len(pages)} page(s), every figure derived from the repo.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
