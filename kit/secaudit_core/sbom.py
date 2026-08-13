"""CycloneDX software bill of materials (Tier 0, zero dependencies, no LLM).

CRA Annex I Part II (1) obliges a manufacturer to identify and document the components of a
product with digital elements, "including by drawing up a software bill of materials in a
commonly used machine-readable format covering at the very least the top-level dependencies".
CycloneDX is one of the two formats market surveillance authorities recognise; this emits
CycloneDX 1.6 JSON.

What it does and does not claim:

* **Top-level dependencies, resolved to concrete versions where a lockfile says so.** With
  `package-lock.json` present the versions are exact; without one only the manifest's range is
  known, and the component is emitted with that range and a note rather than with a version
  invented from it. A version you guessed is worse than a version you flagged as unknown,
  because the whole point of an SBOM is being matched against advisories.
* **Not a full transitive graph.** Everything a lockfile lists could be emitted, but claiming
  a complete dependency tree from a manifest scan would overstate what was actually resolved.
  The regulation's floor is top-level; this meets the floor and says so in the document.
* **VEX is a separate artefact.** The SBOM says what is in the product; `deps.py` says which
  advisories affect it. Merging them would produce a document that is neither.

`serialNumber` and `timestamp` are supplied by the caller, never generated here: this module
stays deterministic so the same tree produces byte-identical output and a diff between two
SBOMs shows dependency changes rather than clock ticks.
"""
from __future__ import annotations

import json
import os
import re

SPEC_VERSION = "1.6"
CYCLONEDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"

_EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+")


def _purl(name: str, version: str) -> str:
    """A package URL. Scoped npm names keep their `@scope/` prefix, which purl encodes with a
    literal `@` in the namespace segment."""
    return f"pkg:npm/{name}@{version}" if version else f"pkg:npm/{name}"


def read_lockfile_versions(root: str) -> dict[str, str]:
    """name → resolved version, from `package-lock.json` when present.

    Handles both lockfile layouts: v1's `dependencies` map keyed by name, and v2/v3's
    `packages` map keyed by install path (`node_modules/foo`, `node_modules/@scope/bar`)."""
    path = os.path.join(root, "package-lock.json")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}

    versions: dict[str, str] = {}
    for install_path, entry in (data.get("packages") or {}).items():
        if not install_path or not isinstance(entry, dict):
            continue                                    # "" is the root project itself
        name = entry.get("name") or install_path.split("node_modules/")[-1]
        if entry.get("version"):
            versions[name] = entry["version"]
    for name, entry in (data.get("dependencies") or {}).items():
        if isinstance(entry, dict) and entry.get("version"):
            versions.setdefault(name, entry["version"])
    return versions


def _component(name: str, declared: str, resolved: str | None, scope: str) -> dict:
    version = resolved or ""
    component: dict[str, object] = {
        "type": "library",
        "bom-ref": _purl(name, version),
        "name": name,
        "version": version,
        "purl": _purl(name, version),
        "scope": scope,
    }
    if not resolved:
        # Say it plainly in the document. A consumer matching this against advisories has to
        # know the version is a constraint, not a fact.
        component["properties"] = [{
            "name": "secaudit:version-unresolved",
            "value": f"No lockfile entry; manifest declares the range `{declared}`. "
                     f"Resolve and re-run to get an exact version.",
        }]
    elif not _EXACT_VERSION.match(resolved):
        component["properties"] = [{"name": "secaudit:version-nonstandard",
                                    "value": f"Lockfile version `{resolved}` is not semver."}]
    return component


def build(root: str, target_name: str = "", serial_number: str = "",
          timestamp: str = "") -> dict:
    """A CycloneDX 1.6 document for the npm project at `root`.

    `serial_number` and `timestamp` are the caller's to supply — see the module docstring on
    why this stays clock-free."""
    from . import deps

    runtime, dev = deps.read_manifest(root)
    resolved = read_lockfile_versions(root)

    manifest: dict = {}
    try:
        with open(os.path.join(root, "package.json"), encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, json.JSONDecodeError):
        pass
    declared = {**(manifest.get("dependencies") or {}),
                **(manifest.get("optionalDependencies") or {}),
                **(manifest.get("peerDependencies") or {}),
                **(manifest.get("devDependencies") or {})}

    components = [
        _component(name, declared.get(name, ""), resolved.get(name),
                   "required" if name in runtime else "optional")
        for name in sorted(runtime | dev)
    ]

    unresolved = sum(1 for c in components if not c["version"])
    document: dict = {
        "$schema": CYCLONEDX_SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "SecAudit",
                                      "publisher": "SecAudit"}]},
            "component": {
                "type": "application",
                "bom-ref": target_name or manifest.get("name") or os.path.basename(
                    os.path.abspath(root)),
                "name": manifest.get("name") or target_name or os.path.basename(
                    os.path.abspath(root)),
                "version": manifest.get("version", ""),
            },
            "properties": [
                {"name": "secaudit:scope",
                 "value": "Top-level dependencies only — the floor set by CRA Annex I Part II "
                          "(1). Not a resolved transitive dependency graph."},
                {"name": "secaudit:versions-unresolved", "value": str(unresolved)},
            ],
        },
        "components": components,
    }
    if serial_number:
        document["serialNumber"] = serial_number
    if timestamp:
        document["metadata"]["timestamp"] = timestamp
    return document


def to_json(root: str, target_name: str = "", serial_number: str = "",
            timestamp: str = "") -> str:
    return json.dumps(build(root, target_name, serial_number, timestamp), indent=2)


def is_supported(root: str) -> bool:
    """Whether an SBOM can be produced for this tree at all.

    npm only, today. Returning False lets the caller say "no SBOM: this is not an npm project"
    instead of emitting an empty component list, which a consumer would read as "this product
    has no dependencies"."""
    return os.path.isfile(os.path.join(root, "package.json"))
