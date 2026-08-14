"""Dependency reachability and VEX classification (Tier 0, zero dependencies, no LLM).

A dependency scanner hands you a list of CVEs. That list is not a finding list: most of those
advisories describe code your project never loads, in a package pulled in transitively by a
build tool, or in a dev dependency that never ships. Reporting them all is how a security tool
teaches a team to close its reports — and under the EU Cyber Resilience Act, whose reporting
duty starts 2026-09-11, "which of these actually affects the product" stops being a matter of
taste and becomes a filing decision.

So each advisory is classified with a **VEX status** using the
[OpenVEX](https://github.com/openvex/spec) vocabulary, and the evidence for the call is stated
in the report:

  * ``affected`` — the package is imported by first-party source in this project.
  * ``under_investigation`` — present, but we cannot show it is imported (dynamic import,
    a language we do not index, a plugin loaded by name).
  * ``not_affected`` + ``vulnerable_code_not_present`` — declared in the manifest and imported
    nowhere in the tree.
  * ``not_affected`` + ``component_not_present`` — a dev-only dependency that no runtime file
    imports, so it is not part of the shipped product.

Honest bounds, same discipline as the taint tier:

  * Reachability here is **import-level, not symbol-level**. We can say "your code loads this
    package"; we cannot say "your code calls the specific vulnerable function". An ``affected``
    result therefore means "reachable enough to take seriously", not "proven exploitable".

    The reason is worth stating precisely, because an earlier version of this paragraph said
    "npm audit and OSV do not publish the affected symbol in a machine-usable form" and that is
    **too broad — OSV does, for some ecosystems.** Go advisories carry
    ``affected[].ecosystem_specific.imports[].symbols``, and RustSec carries affected function
    lists. Neither ecosystem is one this dependency scan reads: the import index covers
    JavaScript/TypeScript and Python, and for *those two* the statement holds — npm audit,
    GHSA and PyPI advisories do not carry an affected-symbol field, so there is nothing to
    match a call against.

    That makes symbol-level reachability blocked on a **data** gap for the ecosystems scanned
    here, not on analysis we have not written, and it is the reason no partial version ships.
    The alternative — deriving symbols by fetching each advisory's fix commit and diffing it —
    was considered and rejected: a fix commit also touches tests, docs and refactors, so which
    changed function is *the vulnerable one* would be a guess, and a guess that downgrades an
    advisory to ``not_affected`` is the single most dangerous output this module can produce.
    It becomes implementable the day this scan indexes an ecosystem whose advisories publish
    symbols — Go first — and not before.
  * The import index covers JavaScript/TypeScript and Python. In any other language every
    advisory stays ``under_investigation`` — never silently ``not_affected``.
  * Dynamic loading (``require(name)`` with a variable, ``importlib.import_module``) is
    invisible to the index. A package loaded that way reads as not imported, which is why the
    status is ``not_affected`` with a stated justification a human can overturn, and never a
    deletion from the report.

Nothing is ever dropped. A ``not_affected`` advisory stays in the register, downgraded and
labelled — that is what makes the register usable as evidence rather than a filtered view.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

# --------------------------------------------------------------------------- OpenVEX vocabulary

STATUS_AFFECTED = "affected"
STATUS_NOT_AFFECTED = "not_affected"
STATUS_UNDER_INVESTIGATION = "under_investigation"

JUSTIFICATION_CODE_NOT_PRESENT = "vulnerable_code_not_present"
JUSTIFICATION_COMPONENT_NOT_PRESENT = "component_not_present"

SKIP_DIRS = {".git", "node_modules", "__pycache__", "dist", ".next", "venv", ".venv", "build",
             "coverage", ".tox", ".mypy_cache"}

# Files that are part of the build/test harness rather than the shipped product. A dev-only
# dependency imported only from here is still not in the product.
_DEV_PATH = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|specs|e2e|examples?|scripts?|benchmarks?|docs?)/"
    r"|\.(?:test|spec)\.[jt]sx?$|(?:^|/)test_[^/]+\.py$|(?:^|/)conftest\.py$")

_JS_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")

# require('x') / import … from 'x' / import 'x' / import('x') / export … from 'x'
_JS_IMPORT = re.compile(
    r"""require\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""|(?:^|[\s;}])(?:import|export)\b[^;'"]*?from\s*['"]([^'"]+)['"]"""
    r"""|(?:^|[\s;}])import\s*['"]([^'"]+)['"]"""
    r"""|import\(\s*['"]([^'"]+)['"]\s*\)""",
    re.M)

# import x[.y] / from x[.y] import …  — top-level module only
_PY_IMPORT = re.compile(r"^\s*(?:from\s+([.\w]+)\s+import|import\s+([.\w]+))", re.M)


@dataclass(frozen=True)
class Verdict:
    """The VEX call for one package, plus the evidence that produced it."""
    status: str
    justification: str
    note: str

    @property
    def reachable(self) -> bool:
        return self.status != STATUS_NOT_AFFECTED


def js_package_of(specifier: str) -> str | None:
    """The npm package a JS import specifier resolves to, or None for a relative/builtin path.

    `@scope/pkg/sub` → `@scope/pkg`; `pkg/sub/path` → `pkg`; `./local` → None.
    """
    if not specifier or specifier.startswith((".", "/")) or ":" in specifier:
        return None
    parts = specifier.split("/")
    if specifier.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    return parts[0]


def build_import_index(root: str) -> dict[str, set[str]]:
    """Map package name → the set of first-party files that import it.

    Keeping the files rather than a bare boolean is what lets `classify` tell a dev-only
    dependency (imported solely from tests) from a runtime one, which is a different VEX
    justification and, for the CRA register, a different answer.
    """
    index: dict[str, set[str]] = {}
    if not os.path.isdir(root):
        return index

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1].lower()
            if ext not in _JS_EXTS and ext != ".py":
                continue
            try:
                if os.path.getsize(path) > 1_000_000:
                    continue
                with open(path, encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except OSError:
                continue
            rel = os.path.relpath(path, root).replace("\\", "/")

            if ext == ".py":
                for m in _PY_IMPORT.finditer(text):
                    module = (m.group(1) or m.group(2) or "").split(".")[0]
                    if module:
                        index.setdefault(module, set()).add(rel)
            else:
                for m in _JS_IMPORT.finditer(text):
                    spec = next((g for g in m.groups() if g), "")
                    pkg = js_package_of(spec)
                    if pkg:
                        index.setdefault(pkg, set()).add(rel)
    return index


def read_manifest(root: str) -> tuple[set[str], set[str]]:
    """(runtime dependency names, dev-only dependency names) from package.json."""
    path = os.path.join(root, "package.json")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return set(), set()
    runtime = set(data.get("dependencies") or {})
    runtime |= set(data.get("optionalDependencies") or {})
    runtime |= set(data.get("peerDependencies") or {})
    dev = set(data.get("devDependencies") or {}) - runtime
    return runtime, dev


def indexed_languages(root: str) -> bool:
    """Whether this tree contains any source the import index can actually read.

    Without this check a Go or Rust project would get `not_affected` for every advisory purely
    because we cannot parse it — a false all-clear, which is the worst failure mode a security
    tool has."""
    for _dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in (*_JS_EXTS, ".py"):
                return True
    return False


def classify(package: str, index: dict[str, set[str]], runtime_deps: set[str],
             dev_deps: set[str], indexable: bool = True) -> Verdict:
    """The VEX call for one vulnerable package."""
    if not indexable:
        return Verdict(STATUS_UNDER_INVESTIGATION, "",
                       "No JavaScript/TypeScript or Python source was indexed, so import "
                       "reachability could not be established. Triage manually.")

    importers = index.get(package, set())
    runtime_importers = sorted(f for f in importers if not _DEV_PATH.search(f))
    dev_importers = sorted(f for f in importers if _DEV_PATH.search(f))

    if runtime_importers:
        shown = ", ".join(runtime_importers[:3])
        more = f" (+{len(runtime_importers) - 3} more)" if len(runtime_importers) > 3 else ""
        return Verdict(STATUS_AFFECTED, "",
                       f"Imported by first-party runtime code: {shown}{more}.")

    if dev_importers and package in dev_deps:
        shown = ", ".join(dev_importers[:3])
        return Verdict(STATUS_NOT_AFFECTED, JUSTIFICATION_COMPONENT_NOT_PRESENT,
                       f"Dev-only dependency, imported solely from build/test code ({shown}); "
                       f"it is not part of the shipped product. Still fix it if CI runs "
                       f"untrusted input through it.")

    if dev_importers:
        shown = ", ".join(dev_importers[:3])
        return Verdict(STATUS_UNDER_INVESTIGATION, "",
                       f"Imported only from build/test code ({shown}) but declared as a runtime "
                       f"dependency — confirm whether it ships.")

    if package in dev_deps:
        return Verdict(STATUS_NOT_AFFECTED, JUSTIFICATION_COMPONENT_NOT_PRESENT,
                       "Dev-only dependency with no import found in this tree; not part of the "
                       "shipped product.")

    if package in runtime_deps:
        return Verdict(STATUS_NOT_AFFECTED, JUSTIFICATION_CODE_NOT_PRESENT,
                       "Declared as a direct dependency, but no import of it was found in "
                       "first-party source. A dynamic import would not be visible here — "
                       "overturn this if the package is loaded by name.")

    # Not declared in the manifest at all, so it arrived transitively. "We never import it"
    # says nothing here: one of the packages we DO import pulls it in and may well call the
    # vulnerable path. Concluding `not_affected` from a missing first-party import would be a
    # false all-clear on the single most common shape of supply-chain exposure.
    return Verdict(STATUS_UNDER_INVESTIGATION, "",
                   "Transitive dependency with no first-party import. Reachability depends on "
                   "which of your direct dependencies loads it — check the dependency path "
                   "(`npm ls <pkg>`) before dismissing it.")


def to_openvex(target: str, statements: list[dict]) -> str:
    """An OpenVEX document for the classified advisories.

    Emitted next to the report so the CRA evidence pack has a machine-readable answer to
    "which of these advisories affect the product", rather than a prose paragraph.
    `@id`/`timestamp` are left to the caller to stamp — this module is deterministic by
    construction and must not reach for a clock (see the resume/replay note in the tests).
    """
    doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "author": "SecAudit",
        "role": "tool",
        "version": 1,
        "statements": statements,
    }
    return json.dumps(doc, indent=2)


def vex_statement(package: str, vuln_id: str, verdict: Verdict) -> dict:
    """One OpenVEX statement. `products` uses a purl-shaped identifier where we can build one."""
    statement = {
        "vulnerability": {"name": vuln_id},
        "products": [{"@id": f"pkg:npm/{package}"}],
        "status": verdict.status,
        "status_notes": verdict.note,
    }
    if verdict.justification:
        statement["justification"] = verdict.justification
    return statement
