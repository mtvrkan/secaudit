"""Tier-0 engine — walk a source target, run the built-in detectors (and installed scanners
when present), and return a deduped ScanResult. No LLM involved; always runnable."""
from __future__ import annotations

import json
import os
import subprocess

from .detectors import DETECTORS, detectors_for, group_of
from .schema import Finding, ScanResult, Severity, Confidence, Verdict
from . import deps, exploitation, langs, redos, scanners, structural, taint

# Higher-fidelity sources win when two findings collide at the same file/line/class.
# `taint` outranks `builtin` because a proven source→sink path is strictly more evidence than
# a pattern match at the same spot, and sits below the real scanners, which carry their own
# dataflow engines. It never *replaces* a corroborated finding, though — see `_corroborate`.
_SOURCE_RANK = {"semgrep": 4, "osv": 4, "gitleaks": 4, "npm-audit": 3, "taint": 3,
                "structural": 3, "redos": 3, "llm": 2, "llm-logic": 2, "builtin": 1}

# How far apart a pattern match and a taint path may be and still describe the same bug.
# The regex usually fires where the dangerous string is built and the taint path where it is
# consumed, which in real code is a line or two later.
_CORROBORATION_WINDOW = 3

SKIP_DIRS = {".git", "node_modules", "__pycache__", "dist", ".next", "venv", ".venv", "build"}
MAX_BYTES = 1_000_000  # skip files larger than 1 MB (assets, minified bundles)

# The two entries in SKIP_DIRS that a package can legitimately publish. `.next`, `node_modules`
# and the rest are never the artifact — nothing in a manifest can make them worth reading.
_PUBLISHABLE_BUILD_DIRS = frozenset({"dist", "build"})

# Manifest keys whose values are paths into the published package. `exports` is walked because
# it nests arbitrarily (`{".": {"import": "./dist/x.mjs"}}`) and is the modern shape.
_MANIFEST_PATH_KEYS = ("main", "module", "browser", "types", "typings", "unpkg", "jsdelivr")


def _manifest_paths(node, key: str = "") -> list[str]:
    """Every string in a package.json that is a path into the package."""
    if isinstance(node, str):
        return [node] if key else []
    if isinstance(node, list):
        return [v for v in node if isinstance(v, str)] if key in ("files", "exports") else []
    if not isinstance(node, dict):
        return []
    out: list[str] = []
    for k, v in node.items():
        if not key:                                  # the manifest's top level
            if k in _MANIFEST_PATH_KEYS and isinstance(v, str):
                out.append(v)
            elif k in ("bin", "exports", "files"):
                out.extend(_manifest_paths(v, k))
        else:                                        # inside bin / exports / files
            out.extend(_manifest_paths(v, key))
    return out


def _is_own_release(path: str, cache: dict[str, set[str]] | None = None) -> bool:
    """Whether the scanned project's own manifest publishes this file.

    The mirror of `_published_build_dirs`, one level down: that function asks whether a
    *directory* is the artifact this package ships, and this asks it of a *file*. Both are
    answered by the manifest, because the manifest is the only place a project states what it
    publishes, and both exist because the default answer is right for an application and wrong
    for a library.

    Resolution walks **up** to the nearest `package.json` rather than reading one at the scan
    root, so a monorepo answers per package: `packages/ui/index.js` is `packages/ui`'s own
    release even though the repository root publishes something else entirely.

    A file sitting directly beside the manifest counts as well as one the manifest names. A
    package that ships `index.js` without a `main` is relying on Node's default, which resolves
    to exactly that file; requiring the key would make the rule depend on whether the author
    wrote down what npm would have assumed.
    """
    cache = {} if cache is None else cache
    directory = os.path.dirname(os.path.abspath(path))
    here = directory
    seen: list[str] = []
    while True:
        if here in cache:
            published = cache[here]
            break
        seen.append(here)
        manifest = os.path.join(here, "package.json")
        if os.path.isfile(manifest):
            published = set()
            try:
                with open(manifest, encoding="utf-8", errors="ignore") as fh:
                    for entry in _manifest_paths(json.load(fh)):
                        published.add(os.path.normcase(os.path.normpath(
                            os.path.join(here, entry.lstrip("./")))))
            except (OSError, ValueError):
                published = set()
            published.add(os.path.normcase(os.path.normpath(here)))   # the manifest's own folder
            break
        parent = os.path.dirname(here)
        if parent == here:
            published = set()
            break
        here = parent
    for directory_seen in seen:
        cache[directory_seen] = published
    if not published:
        return False
    target = os.path.normcase(os.path.normpath(os.path.abspath(path)))
    return target in published or os.path.normcase(os.path.normpath(directory)) in published


# How many release-bannered files in one directory make it a library drop. Two, not one:
# a single `@license` header is an ordinary thing for an application file to carry, and a
# threshold of one turned `src/` into a vendor directory in the first version of this.
_VENDOR_DROP_BANNERS = 2


def _is_vendor_drop(directory: str, cache: dict[str, bool]) -> bool:
    """Whether this directory is a copied-in library rather than application source.

    The third and last move of the same principle: `_published_build_dirs` asks the manifest
    about a directory, `_is_own_release` asks it about a file, and this asks the *directory about
    itself* — because the manifest is silent for the case that matters here. A Django or Flask
    application vendors its front end by copying a library into `static/js/`, where there is no
    `package.json` to consult and no `node_modules/` in the path.

    The evidence is the one thing a library drop has and application source does not: several
    files announcing themselves as somebody's release. `langs.has_release_preamble` decides that
    per file — a `/*!` banner or a UMD/`@license` preamble — and this counts them.

    Only the JS/TS files in the directory itself; never recursive. A directory is a unit somebody
    copied in, and walking down from `static/` would take one bannered pair and silence a tree.
    """
    if directory in cache:
        return cache[directory]
    banners = 0
    try:
        names = os.listdir(directory)
    except OSError:
        cache[directory] = False
        return False
    for name in names:
        if not name.lower().endswith(langs.JSTS_EXTS):
            continue
        path = os.path.join(directory, name)
        try:
            if os.path.getsize(path) > MAX_BYTES:
                continue
            with open(path, encoding="utf-8", errors="ignore") as fh:
                head = fh.read(64_000)
        except OSError:
            continue
        if langs.has_release_preamble(head):
            banners += 1
            if banners >= _VENDOR_DROP_BANNERS:
                break
    cache[directory] = banners >= _VENDOR_DROP_BANNERS
    return cache[directory]


def _published_build_dirs(dirpath: str, filenames: list[str]) -> set[str]:
    """Build directories this directory's own `package.json` publishes as the artifact.

    `dist/` and `build/` are skipped by default and that is right for an *application*: they are
    generated from the source sitting beside them, and a finding in one is addressed to a file
    nobody edits. It is wrong for a *published package*, where `dist/` is not a by-product but
    the JavaScript that runs on the installing machine — often the only JavaScript in the
    tarball. SecBench.js put a number on the cost: **35 of its labelled sinks** were invisible
    for this reason, which is a scoping decision reported as a detection failure.

    The manifest is what tells the two apart, so it is what decides. A package that says
    `"main": "dist/index.js"` has told npm that `dist/` is what it ships; nothing else here is
    ever un-skipped, whatever a manifest claims.
    """
    if "package.json" not in filenames:
        return set()
    try:
        with open(os.path.join(dirpath, "package.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError, UnicodeDecodeError):
        return set()
    if not isinstance(manifest, dict):
        return set()
    heads = {p.replace("\\", "/").lstrip("./").split("/")[0] for p in _manifest_paths(manifest)}
    return heads & _PUBLISHABLE_BUILD_DIRS


def roots_of(target: str | list[str]) -> list[str]:
    """Targets as a list. A single path stays a one-element list and takes the same code path.

    More than one exists because pre-commit passes the staged files as separate arguments, and
    the CLI accepted exactly one — so any commit touching two files invoked the hook with an
    argument argparse rejected, and every multi-file commit failed on a usage error rather than
    on a finding.
    """
    return [target] if isinstance(target, str) else list(target)


def base_of(roots: list[str]) -> str:
    """The directory relative paths are keyed on — every finding, SARIF location and golden id.

    One target keeps exactly the rule it always had: the directory itself, or the file's parent.
    Several fall back to their common ancestor, so a set of staged files still reports paths a
    reader can find, rather than paths relative to whichever one came first.
    """
    dirs = [r if os.path.isdir(r) else os.path.dirname(r) for r in roots]
    if len(dirs) == 1:
        return dirs[0]
    return os.path.commonpath([os.path.abspath(d) for d in dirs])


def _iter_files(root: str | list[str], published: list[str] | None = None):
    """Every file worth opening. `published` collects build directories entered because a
    `package.json` beside them says they are what the package ships — an out-parameter for the
    same reason `scan_code`'s are, so the report can name a scope decision it made."""
    seen: set[str] = set()
    base = base_of(roots_of(root))
    for one in roots_of(root):
        if os.path.isfile(one):
            key = os.path.normcase(os.path.abspath(one))
            if key not in seen:
                seen.add(key)
                yield one
            continue
        for dirpath, dirnames, filenames in os.walk(one):
            # Per directory, not once per root: a monorepo has one manifest per package and
            # each answers the question for its own subtree.
            keep = _published_build_dirs(dirpath, filenames)
            if keep and published is not None:
                published.extend(
                    os.path.relpath(os.path.join(dirpath, d), base).replace("\\", "/")
                    for d in sorted(keep) if d in dirnames)
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS or d in keep]
            for name in filenames:
                path = os.path.join(dirpath, name)
                # A file named twice, or named alongside a directory that contains it, would
                # otherwise be scanned twice and reported twice.
                key = os.path.normcase(os.path.abspath(path))
                if key in seen:
                    continue
                seen.add(key)
                yield path


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _line_text(text: str, pos: int) -> str:
    """The whole line `pos` falls on, uncut. `_evidence` truncates to 200 characters for the
    report; a line-scoped suppression has to read the line, not a summary of it."""
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text[start: end if end != -1 else len(text)]


def _evidence(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    line = text[start: end if end != -1 else len(text)].strip()
    return line[:200]


def scan_code(root: str | list[str], only: set[str] | None = None,
              read: list[str] | None = None,
              vendored: list[str] | None = None,
              published: list[str] | None = None) -> list[Finding]:
    """Run the pattern pack. `read` collects the paths actually opened, if a caller wants them,
    `vendored` the third-party assets deliberately not analysed, and `published` the build
    directories read because a manifest says they are the artifact.

    Out-parameters rather than a second return value or a second walk: every existing caller
    passes two arguments, and a separate counting pass would have to repeat the skip rules below
    — the size limit, the unreadable file, the extension with no detector — which is how a
    reported count and the real one drift apart.
    """
    findings: list[Finding] = []
    base = base_of(roots_of(root))
    # One manifest lookup per directory rather than per file: the walk up to the nearest
    # package.json is cheap, and repeating it for every file in a package is not.
    own_release_cache: dict[str, set[str]] = {}
    vendor_drop_cache: dict[str, bool] = {}
    for path in _iter_files(root, published):
        dets = detectors_for(path)
        if only is not None:
            dets = [d for d in dets if group_of(d.id) in only]
        if not dets:
            continue
        try:
            if os.path.getsize(path) > MAX_BYTES:
                continue
            with open(path, encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        # A vendored bundle is somebody else's release, and a finding in one is addressed to the
        # wrong maintainer. Checked after the read because three of the four signals are
        # properties of the content, not of the name — see `langs.is_vendored_asset`.
        #
        # Recorded, not merely skipped. This module already refuses to let "nothing was read"
        # render as "nothing was found"; a bound on coverage that the report does not state is
        # the same defect one size smaller, and it is the more dangerous size because the report
        # still looks complete. The caller turns this into a note naming the count.
        if langs.is_vendored_asset(path, text, _is_own_release(path, own_release_cache),
                                   _is_vendor_drop(os.path.dirname(os.path.abspath(path)),
                                                   vendor_drop_cache)):
            if vendored is not None:
                vendored.append(os.path.relpath(path, base).replace("\\", "/"))
            continue
        if read is not None:
            read.append(path)
        rel = os.path.relpath(path, base)
        rel_slash = rel.replace("\\", "/")
        if not structural.is_production_source(rel_slash):
            dets = [d for d in dets if d.about_committed_text]
            if not dets:
                continue
        # Two views of the file. Code-shape rules match the view with comments and string
        # contents blanked, so a rule catalog mentioning `eval(` in a literal is not read as a
        # call to eval; literal rules (secrets, SQL fragments, quoted header names) match the
        # raw text. Offsets are identical in both, so evidence always comes from the original.
        view = taint.code_view(text, path)
        for det in dets:
            scanned = text if (det.literal or view is None) else view
            sup = det.suppressor()
            if sup and sup.search(scanned):
                continue  # a control marker is present → cleared
            pre = det.precondition()
            if pre and not pre.search(scanned):
                continue  # this file is not the format the rule is about → not applicable
            line_sup = det.line_suppressor()

            for m in det.regex().finditer(scanned):
                # A control on the MATCHED LINE clears this match and nothing else — the
                # difference from `suppress_if` above, which clears the whole file. Read from the
                # raw text rather than the blanked view: an escaper's NAME survives blanking, but
                # a catalogue key inside a string literal does not, and both are evidence here.
                if line_sup and line_sup.search(_line_text(text, m.start())):
                    continue
                # Secret detectors must never print the value — redact the evidence line.
                evidence = ("[redacted] possible secret detected here (value not shown)"
                            if det.mask else _evidence(text, m.start()))
                findings.append(Finding(
                    detector_id=det.id, title=det.title, severity=det.severity,
                    confidence=det.confidence, cwe=det.cwe, owasp=det.owasp,
                    file=rel.replace("\\", "/"), line=_line_of(text, m.start()),
                    evidence=evidence, fix=det.fix,
                    source="builtin", verdict=Verdict.UNVERIFIED, maps_to=det.maps_to,
                ))
                if det.once_per_file:
                    break
    return findings


def _read_sources(root: str | list[str], exts: tuple[str, ...]) -> dict[str, str]:
    """Every analysable file under `root`, keyed by the forward-slash relative path every
    finding, SARIF location and golden-set id is keyed on."""
    files: dict[str, str] = {}
    base = base_of(roots_of(root))
    own_release_cache: dict[str, set[str]] = {}
    vendor_drop_cache: dict[str, bool] = {}
    for path in _iter_files(root):
        if not path.lower().endswith(exts):
            continue
        try:
            if os.path.getsize(path) > MAX_BYTES:
                continue
            with open(path, encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        if langs.is_vendored_asset(path, text, _is_own_release(path, own_release_cache),
                                   _is_vendor_drop(os.path.dirname(os.path.abspath(path)),
                                                   vendor_drop_cache)):
            continue
        rel = os.path.relpath(path, base)
        files[rel.replace("\\", "/")] = text
    return files


def scan_structural(root: str | list[str]) -> list[Finding]:
    """Run the structural analyses — the classes the pattern pack cannot decide.

    Separate from `scan_taint` because they ask a different kind of question. Taint asks where a
    value came from; these ask what the handler around it failed to do. A value can be perfectly
    clean and the handler still hand the row to the wrong person, accept unlimited password
    guesses, write an executable it never inspected, or let the caller pick which columns to
    set."""
    return structural.analyze_files(_read_sources(root, structural.EXTS))


def scan_redos(root: str | list[str]) -> list[Finding]:
    """Run the catastrophic-backtracking analysis over every analysable file."""
    return redos.analyze_files(_read_sources(root, redos.REDOS_EXTS))


def scan_taint(root: str | list[str]) -> list[Finding]:
    """Run the taint tier over every analyzable file and return one Finding per path.

    These are the findings the pattern pack structurally cannot produce: the source and the
    sink are usually on different lines, and the argument position matters (a value bound as
    a query parameter is the fix, not the bug). Confidence comes from the path's root — see
    `taint.TaintPath.confidence`."""
    # Read the whole analysable set first, then analyse it together. Per-file analysis cannot
    # see an import edge, and the import edge is where most real handler→helper flows live:
    # the route that reads the request and the module that does the dangerous thing are
    # almost never the same file.
    files = _read_sources(root, (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
                                 *langs.PHP_EXTS))

    findings: list[Finding] = []
    for tp in taint.analyze_files(files):
        # A data flow inside a test, a fixture or a seed script is the test's own flow. Every
        # sink this tier knows about describes something a *deployed* path does — the same
        # reasoning `structural/routes.py` applies to its rules and `detectors.py` now applies
        # to the pattern pack, and it is the tier where it matters most, because a taint finding
        # names two locations and a reader has to follow both. Filtered here rather than in
        # `_read_sources`: a production handler can legitimately reach a helper that lives in a
        # `scripts/` module, and dropping the file from the corpus would lose that path instead
        # of the report about the test.
        if not structural.is_production_source(tp.file):
            continue
        # A cross-module path is reported where the untrusted value enters, because that is
        # the route someone has to recognise — but the fix belongs in the callee, so the
        # callee's location is stated rather than left to be inferred from the path string.
        fix = (tp.sink.fix if tp.sink_file == tp.file
               else f"{tp.sink.fix} The dangerous call is in `{tp.sink_file}:{tp.sink_line}`; "
                    f"fix it there, and check the other callers of that function.")
        findings.append(Finding(
            detector_id=tp.sink.id, title=tp.sink.title,
            severity=_severity_for(tp.sink.severity, tp.confidence),
            confidence=tp.confidence, cwe=tp.sink.cwe, owasp=tp.sink.owasp,
            file=tp.file, line=tp.line, evidence=tp.evidence, fix=fix,
            source="taint", verdict=Verdict.UNVERIFIED, maps_to=tp.sink.maps_to,
            taint_path=tp.describe()))
    return findings


_SEVERITY_LADDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _severity_for(sink_severity: Severity, confidence: Confidence) -> Severity:
    """Severity is impact; confidence is certainty — but a report that ranks an unproven lead
    at Critical trains people to ignore Critical.

    A parameter-rooted path is a MEDIUM-confidence lead: whether the parameter carries
    untrusted data depends on callers we did not analyze. So it is reported one rung below the
    sink's inherent severity. Nothing is lost — where the pattern pack independently found the
    same sink, `_corroborate` keeps that finding at its full severity and merely attaches the
    path as evidence. This only caps findings the taint tier raised on its own.
    """
    if confidence == Confidence.HIGH:
        return sink_severity
    return _SEVERITY_LADDER[max(0, _SEVERITY_LADDER.index(sink_severity) - 1)]


def _corroborate(findings: list[Finding]) -> list[Finding]:
    """Fold taint evidence into the pattern findings it confirms, instead of double-reporting.

    A pattern hit and a taint path at the same spot are one bug seen twice. Reporting both
    inflates the count and makes the report look padded; dropping one throws away evidence.
    So the pattern finding absorbs the path — and, when the path is rooted in a framework
    request object, its confidence too, because reachability from untrusted input is exactly
    what "high confidence" is supposed to mean. Uncorroborated taint paths stay as their own
    findings; they are the ones the pattern pack could not see at all.

    Pairing is **nearest-first and one-to-one**, which is the part that has to be right. The
    window exists because a path is reported at the line the untrusted value entered while the
    pattern matched the line of the dangerous call, so the two are close but rarely equal. What
    the window does NOT establish is identity: two SQL injections a few lines apart in one file
    are the same file and the same CWE, and pairing in list order let the second one's pattern
    finding absorb the first one's path — deleting a real bug from the report while keeping the
    count plausible. Matching the closest pair first, and letting each finding be used once,
    means an exactly-coincident pair always wins and a genuinely separate bug is never consumed
    by its neighbour."""
    patterns = [f for f in findings if f.source != "taint"]
    paths = [f for f in findings if f.source == "taint"]

    candidates = sorted(
        (abs(path.line - pattern.line), pi, qi)
        for pi, pattern in enumerate(patterns)
        for qi, path in enumerate(paths)
        if path.file == pattern.file and path.cwe == pattern.cwe
        and abs(path.line - pattern.line) <= _CORROBORATION_WINDOW)

    paired_patterns: set[int] = set()
    absorbed: set[int] = set()
    for _, pi, qi in candidates:                  # ties break on index, so this is deterministic
        if pi in paired_patterns or qi in absorbed:
            continue
        pattern, path = patterns[pi], paths[qi]
        pattern.taint_path = path.taint_path
        if path.confidence == Confidence.HIGH:
            pattern.confidence = Confidence.HIGH
        paired_patterns.add(pi)
        absorbed.add(qi)

    return patterns + [p for i, p in enumerate(paths) if i not in absorbed]


def scan_dependencies(root: str, notes: list[str], tools: list[str]) -> list[Finding]:
    """Best-effort Claude-free dependency audit: run `npm audit --json` if a package.json and
    npm are present. Gracefully skipped otherwise. (Extension point for osv-scanner/pip-audit.)"""
    if not os.path.isdir(root) or not os.path.isfile(os.path.join(root, "package.json")):
        return []
    npm = any(os.access(os.path.join(p, exe), os.X_OK)
              for p in os.environ.get("PATH", "").split(os.pathsep)
              for exe in ("npm", "npm.cmd"))
    if not npm:
        notes.append("npm not found — dependency audit skipped (Tier-0 code scan still ran).")
        return []
    try:
        out = subprocess.run(["npm", "audit", "--json"], cwd=root, capture_output=True,
                             text=True, timeout=120, shell=(os.name == "nt"))
        data = json.loads(out.stdout)
    except Exception as e:  # offline / no lockfile / registry error
        notes.append(f"npm audit could not run ({e}) — dependency findings skipped.")
        return []
    tools.append("npm-audit")
    findings: list[Finding] = []
    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
               "moderate": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}

    for name, v in (data.get("vulnerabilities") or {}).items():
        sev = sev_map.get(str(v.get("severity", "moderate")).lower(), Severity.MEDIUM)
        findings.append(Finding(
            detector_id="DEP-NPM", title=f"Vulnerable dependency: {name}",
            severity=sev, confidence=Confidence.HIGH, cwe="CWE-1395", owasp="A06",
            file="package.json", line=1,
            evidence=f"{name}: {v.get('severity', '?')} severity (npm audit)",
            fix=f"Upgrade `{name}` to a fixed version (`npm audit fix` / bump the pin).",
            source="npm-audit", verdict=Verdict.CONFIRMED, package=name,
        ))
    return findings


def apply_vex(root: str, findings: list[Finding], notes: list[str]) -> list[Finding]:
    """Classify every dependency advisory by import reachability, in one place.

    Runs over any finding that names a package, whichever adapter produced it — npm audit,
    osv-scanner, or a future one. Doing this per adapter is how one of them silently ships
    without reachability, which is worse than not having it at all: the register would then
    look triaged while part of it was not."""
    packaged = [f for f in findings if f.package]
    if not packaged:
        return findings

    index = deps.build_import_index(root)
    runtime_deps, dev_deps = deps.read_manifest(root)
    indexable = deps.indexed_languages(root)
    if not indexable:
        notes.append("No JavaScript/TypeScript or Python source could be indexed — dependency "
                     "advisories are left `under_investigation` rather than assumed unreachable.")

    counts: dict[str, int] = {}
    for f in packaged:
        vex = deps.classify(f.package, index, runtime_deps, dev_deps, indexable)
        f.vex_status, f.vex_justification = vex.status, vex.justification
        f.triage_note = vex.note
        if not vex.reachable:
            # `not_affected` is a triage result, not a confirmation. A reader filtering on
            # CONFIRMED must not act on an advisory we ruled out.
            f.verdict = Verdict.PLAUSIBLE
            f.severity = _severity_for_vex(f.severity)
        counts[vex.status] = counts.get(vex.status, 0) + 1

    if counts:
        summary = ", ".join(f"{n} {status}" for status, n in sorted(counts.items()))
        notes.append(f"Dependency reachability (OpenVEX): {summary}. Import-level, not "
                     f"symbol-level — see the VEX status on each advisory for the evidence.")
    return findings


def _severity_for_vex(advisory_severity: Severity) -> Severity:
    """An advisory we have shown the product does not load is not a High.

    Two rungs down, because the gap between "your app is exploitable" and "a package you never
    import has a CVE" is wider than one step, and CI gates run on severity. The advisory stays
    in the register with its original severity in the evidence line — nothing is hidden, it is
    ranked honestly instead."""
    i = _SEVERITY_LADDER.index(advisory_severity)
    return _SEVERITY_LADDER[max(0, i - 2)]


def _dedupe(findings: list[Finding]) -> list[Finding]:
    # 1) exact same rule + location.
    seen, primary = set(), []
    for f in findings:
        if f.key() in seen:
            continue
        seen.add(f.key())
        primary.append(f)
    # 2) collapse *cross-tool* duplicates — the same class at the same spot reported by more
    #    than one source. Group by (file, line, cwe); within a group keep only the findings
    #    from the highest-fidelity source present (a real scanner over the built-in regex lead).
    #    Findings that share the top source are distinct detectors the tool emitted on purpose,
    #    so they are ALL kept — keying on the source-max instead of overwriting one-per-key
    #    avoids silently dropping two genuinely different findings that share a CWE at one line.
    groups: dict[tuple, list[Finding]] = {}
    for f in primary:
        groups.setdefault((f.file, f.line, f.cwe), []).append(f)
    out: list[Finding] = []
    for group in groups.values():
        top = max(_SOURCE_RANK.get(f.source, 0) for f in group)
        out.extend(f for f in group if _SOURCE_RANK.get(f.source, 0) == top)
    # 3) drop a coarse rule where a precise one covered the same LINE. This one cannot key on the
    #    CWE: the pair it exists for carries two different ones on purpose (a keyword guess is
    #    CWE-798, a Django signing key is CWE-321) and grouping them would be wrong for every
    #    other pair. The relation is declared by the detector itself, in `superseded_by`.
    supersedes = {d.id: set(d.superseded_by) for d in DETECTORS if d.superseded_by}
    if supersedes:
        by_line: dict[tuple, set[str]] = {}
        for f in out:
            by_line.setdefault((f.file, f.line), set()).add(f.detector_id)
        out = [f for f in out
               if not (supersedes.get(f.detector_id, set()) & by_line[(f.file, f.line)])]
    return out


def scan(target: str | list[str], run_deps: bool = True, use_scanners: bool = True,
         use_taint: bool = True, only: set[str] | None = None,
         check_exploitation: bool = False, use_structural: bool = True,
         use_redos: bool = True) -> ScanResult:
    # A target that is not there is not a clean tree. `os.walk` yields nothing for a path that
    # does not exist and raises nothing either, so a typo used to produce a full report with
    # every count at zero, the closing "no findings" line, and exit 0 — a green CI gate that had
    # audited nothing at all, for as long as the path stayed wrong. The CLI already refuses a URL
    # target for exactly this reason and says so in its message; the MCP server already refuses a
    # missing path. Refused here so the engine cannot be asked the question by any caller.
    roots = roots_of(target)
    for one in roots:
        if not os.path.exists(one):
            raise FileNotFoundError(one)

    # Everything downstream of the walk — the SBOM, the dependency scan, the VEX pass, the
    # report header — is about one tree. With several targets that tree is the directory they
    # share, which for a single target is the target itself and changes nothing.
    # `roots[0]`, not `target`: the CLI passes a list even for a single path, so reusing `target`
    # here put a one-element list into the report header, the SBOM and the dependency scan.
    root = base_of(roots) if len(roots) > 1 else roots[0]
    result = ScanResult(target=root, backend="none")
    result.tools_used.append("builtin-detectors")
    # The paths `scan_code` actually opened. Counted rather than inferred: the report's own
    # closing sentence is "across the files that were scanned", and until now it never said how
    # many that was — so a scan that read nothing (a tree whose code all sits under `build/` or
    # `node_modules/`, a `--only` group no file matches) was indistinguishable from a scan that
    # read everything and found nothing.
    read: list[str] = []
    vendored: list[str] = []
    published: list[str] = []
    result.findings.extend(scan_code(target, only, read, vendored, published))
    result.files_scanned = len(read)
    if use_taint:
        result.tools_used.append("taint")
        result.findings.extend(scan_taint(target))
    if use_structural:
        result.tools_used.append("structural")
        result.findings.extend(scan_structural(target))
    if use_redos:
        result.tools_used.append("redos")
        result.findings.extend(scan_redos(target))
    if use_scanners:
        result.findings.extend(
            scanners.run_installed_scanners(root, result.notes, result.tools_used))
    if run_deps:
        result.findings.extend(scan_dependencies(root, result.notes, result.tools_used))
    # After every dependency source has reported, so one pass classifies them all.
    apply_vex(root, result.findings, result.notes)
    # Corroborate BEFORE dedupe, not after. Dedupe collapses same-location findings by source
    # rank, and `taint` outranks `builtin` — running it first would delete the pattern finding
    # that corroboration exists to enrich, losing its detector id, its severity and the LLM
    # tier's triage key along with it.
    result.findings = _dedupe(_corroborate(result.findings))
    if check_exploitation:
        # After dedupe: the same advisory can arrive from npm audit and osv, and asking two
        # feeds about the same CVE twice is a slower way to get the same answer.
        cves = [f.detector_id for f in result.findings]
        catalog = exploitation.fetch(list(cves))
        exploitation.apply(result.findings, catalog, result.notes)
        result.tools_used.append("cisa-kev+first-epss")

    # The target existed and still nothing was read. Every remaining way to audit nothing lands
    # here: a tree whose code all sits under a skipped directory (`build/`, `node_modules/`,
    # `dist/`, `.venv/`), a `--only` group no file in this tree matches, a directory of formats
    # no detector claims. The counts below would all be zero and the report would read as a
    # clean bill of health, which is the one thing it must never do by accident.
    if not result.files_scanned:
        result.notes.insert(0, (
            "NO FILES WERE READ. Nothing under this target matched a detector, so every count "
            "below is zero because nothing was analysed — not because nothing was found. Usual "
            "causes: the path points above or beside the source, the code sits in a directory "
            f"this scan skips ({', '.join(sorted(SKIP_DIRS))}), or `--only` names a group no "
            "file here matches."))

    # Say what was not analysed, and why, and name enough of it to check. A scanner that
    # narrows its own scope without saying so reports a clean surface it never looked at, which
    # is the failure this whole module is arranged against — the `NO FILES WERE READ` guard
    # above is the same rule at the extreme. Reporting *these* files would be wrong (they are a
    # dependency's release, not this codebase), but so is letting the reader assume they were
    # covered: the fix for a vulnerable bundle is an upgrade, and nobody upgrades what they were
    # never told they are shipping.
    if vendored:
        shown = ", ".join(sorted(vendored)[:3])
        more = f", and {len(vendored) - 3} more" if len(vendored) > 3 else ""
        result.notes.append(
            f"{len(vendored)} vendored or minified JavaScript/TypeScript asset(s) were NOT "
            f"analysed — they are a third-party release rather than this codebase, and a finding "
            f"inside one is addressed to its maintainer, not to you ({shown}{more}). Upgrade the "
            f"dependency to fix anything in them; the dependency scan is what covers that.")

    # The mirror image of the vendored note: that one says what was skipped, this one says what
    # was read that normally is not. A scope that silently widens is as misleading as one that
    # silently narrows — a reader who sees findings in `dist/` and does not know why will assume
    # the tool cannot tell generated code from source.
    if published:
        shown = ", ".join(sorted(set(published))[:3])
        extra = len(set(published)) - 3
        result.notes.append(
            f"Build output was analysed because a `package.json` beside it names it as what the "
            f"package publishes ({shown}{f', and {extra} more' if extra > 0 else ''}). For an "
            f"installed package that directory is the code that runs; if this is an application "
            f"repository and the source beside it is what you edit, fix the source and the "
            f"finding here goes with it.")

    result.notes.append(
        "Tier-0 (deterministic, no LLM). Business-logic flaws — the rules being broken are the "
        "product's, and they are not written down anywhere the analyzer can read — remain "
        "outside this tier; run with an LLM backend for triage + logic-bug discovery.")
    if use_taint:
        result.notes.extend(taint.limitations())
    if use_structural:
        result.notes.extend(structural.limitations())
    if use_redos:
        result.notes.extend(redos.limitations())
    return result
