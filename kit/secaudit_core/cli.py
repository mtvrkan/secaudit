"""secaudit CLI — self-running, provider-agnostic security audit.

    python -m secaudit_core.cli <path> [--backend none|anthropic|openai|ollama]
                                        [--format md|html|json|sarif]
                                        [--min low|medium|high|critical]
                                        [--since GIT_REF] [--no-deps] [-o REPORT]

Tier 0 (deterministic detectors + npm audit) always runs. A backend, if given, enriches the
findings with LLM triage + logic-bug discovery. Exit code is non-zero if any finding at or
above --min-severity is reported (so it doubles as a CI gate)."""
from __future__ import annotations

import argparse
import os
import sys

from . import detectors, diff, engine, gitref, i18n, patch, report, sbom, spdx
from .backends import get_backend
from .schema import ScanResult

_MIN = {"low": 2, "medium": 3, "high": 4, "critical": 5}


def main(argv: list[str] | None = None) -> int:
    # Reports carry Unicode (→, ·). Don't let a legacy console codepage (e.g. Windows cp1254)
    # crash the tool on print — force UTF-8 where the stream supports it.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue                    # a replaced stream (a StringIO in tests)
        try:
            reconfigure(encoding="utf-8")
        except ValueError:
            pass                        # a detached or non-seekable stream

    ap = argparse.ArgumentParser(prog="secaudit", description=__doc__.splitlines()[0])
    ap.add_argument("target", help="file or directory to audit")
    ap.add_argument("--backend", default="none",
                    choices=["none", "anthropic", "claude", "openai", "ollama"],
                    help="LLM enrichment backend (default: none — pure Tier 0)")
    ap.add_argument("--format", default="md",
                    choices=["md", "html", "json", "sarif", "semgrep", "openvex",
                             "cyclonedx", "spdx", "cra"],
                    help="html emits a self-contained, printable report (print to PDF from a "
                         "browser — no rendering dependency to pin); "
                         "cyclonedx emits a CycloneDX 1.6 SBOM; cra emits the EU Cyber "
                         "Resilience Act evidence pack (SBOM + vulnerability register + "
                         "VEX + clause mapping); semgrep emits Semgrep-compatible JSON (what external "
                         "benchmarks and SAST tooling ingest); openvex emits only "
                         "the dependency reachability statements "
                         "(the machine-readable answer to which advisories affect "
                         "the product)")
    ap.add_argument("--min", dest="min_sev", default=None,
                    choices=list(_MIN), help="fail (non-zero exit) if a finding at/above this "
                                             "severity exists — or, with --since, if the change "
                                             "INTRODUCED one")
    ap.add_argument("--since", metavar="REF",
                    help="compare against the tree at this git ref (branch, tag or sha) and "
                         "report what the change introduced, resolved and left open. Both "
                         "trees are scanned in full, not just the changed files: taint "
                         "resolves across imports, so an edit in one file can create a finding "
                         "whose sink is in a file the change never touched. With --min, the "
                         "exit code is driven by INTRODUCED findings only — a gate that fails "
                         "on pre-existing debt fails every PR and gets switched off")
    ap.add_argument("--no-deps", action="store_true", help="skip the dependency (npm audit) scan")
    ap.add_argument("--no-scanners", action="store_true",
                    help="skip installed scanners (semgrep/gitleaks/osv); built-in pack only")
    ap.add_argument("--no-taint", action="store_true",
                    help="skip the taint tier (source→sink reachability); pattern matching only")
    ap.add_argument("--only", metavar="GROUPS",
                    help="run only these detector groups, comma-separated (e.g. `secret`, "
                         "`secret,docker`). Groups come from the detector ids themselves — "
                         "`--only ?` lists them. Narrows the scan for a pre-commit hook, where "
                         "a slow check is a check that gets bypassed")
    ap.add_argument("--exploitation", action="store_true",
                    help="look every CVE in the report up in CISA KEV and FIRST EPSS, and mark "
                         "the ones confirmed exploited in the wild — the class that starts the "
                         "EU CRA 24-hour clock. Off by default because it is the one part of "
                         "Tier 0 that reaches the network; only CVE ids are sent, never "
                         "anything about your code. An unreachable feed reports `unknown`, "
                         "never a clean bill")
    ap.add_argument("--suggest-patches", metavar="DIR",
                    help="write a verified patch per High/Critical finding into DIR. Needs "
                         "--backend. Nothing is ever applied: each patch is applied to a "
                         "THROWAWAY COPY, the copy is re-scanned, and it is only written out if "
                         "the finding is gone and no new finding appeared — then an independent "
                         "reviewer, given the diff but not the reasoning behind it, gets a veto. "
                         "A model proposes; the deterministic engine is what vouches")
    ap.add_argument("--patch-tests", metavar="CMD",
                    help="run this command against the patched copy and reject the patch if it "
                         "fails (e.g. `npm test`, `pytest -q`). Split like a shell argument "
                         "list but NOT run by a shell, so chain commands in a script rather "
                         "than with && . Strongly recommended: a patch that fixes a "
                         "vulnerability and breaks the product is not shippable, and which "
                         "matters more is not this tool's call")
    ap.add_argument("--lang", default=i18n.DEFAULT, metavar="LOCALE",
                    help=f"report language ({'|'.join(i18n.available())}). Only the report's "
                         f"own headings and labels are translated — finding titles and fix "
                         f"instructions stay in English, because they come from the detector "
                         f"definitions and a stale translated fix is worse than an English one")
    ap.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    ap.add_argument("--summary", metavar="PATH",
                    help="also write the human-readable Markdown report here. CI wants both "
                         "shapes of the same scan — a machine format to gate on and a readable "
                         "one to show a person — and running the scan twice to get them costs "
                         "double (with --since, four tree scans) and invites the two outputs "
                         "to disagree")
    args = ap.parse_args(argv)

    if _looks_like_a_url(args.target):
        print(
            f"`{args.target}` is a URL, and this command audits source code on disk.\n"
            f"\n"
            f"It did not scan anything. That is worth saying plainly, because the failure "
            f"this replaces was worse: the target was treated as a path, no file matched, "
            f"and the run finished with an empty report that reads exactly like a clean "
            f"bill of health.\n"
            f"\n"
            f"Live-target auditing is the Claude Code plugin, not this package — it needs an "
            f"authorization gate, which is a conversation with a human and not a flag:\n"
            f"    /secaudit {args.target}\n"
            f"To audit the code behind that site, point this at the checkout:\n"
            f"    secaudit ./path/to/repo",
            file=sys.stderr)
        return 2

    only = None
    if args.only:
        available = detectors.groups()
        listing = ", ".join(f"{g} ({n})" for g, n in available.items())
        if args.only.strip() in ("?", "list"):
            print(f"Detector groups: {listing}")
            return 0
        only = {g.strip().lower() for g in args.only.split(",") if g.strip()}
        unknown = sorted(only - set(available))
        if unknown:
            # Silently matching nothing would report a clean scan of a group that does not
            # exist — the worst possible answer from a security tool.
            print(f"--only: no such detector group(s): {', '.join(unknown)}. "
                  f"Available: {listing}", file=sys.stderr)
            return 2

    result = engine.scan(args.target, run_deps=not args.no_deps,
                         use_scanners=not args.no_scanners, use_taint=not args.no_taint,
                         only=only, check_exploitation=args.exploitation)
    result = get_backend(args.backend).enrich(result)

    if args.since:
        return _run_diff(args, result, only)

    if args.suggest_patches:
        _suggest_patches(args, result, only)

    out = {"json": report.to_json, "sarif": report.to_sarif, "html": report.to_html,
           "semgrep": report.to_semgrep_json, "openvex": report.to_openvex,
           "cyclonedx": lambda r: sbom.to_json(r.target),
           "spdx": lambda r: spdx.to_json(r.target),
           "cra": report.to_cra_pack,
           "md": lambda r: report.to_markdown(r, args.lang)}[args.format](result)
    _emit(out, args.output, f"{len(result.findings)} finding(s), backend={result.backend}")
    _write_summary(args.summary, report.to_markdown(result, args.lang), args.format)

    if args.min_sev:
        threshold = _MIN[args.min_sev]
        if any(f.severity.rank >= threshold for f in result.findings):
            return 1
    return 0


def _suggest_patches(args, result, only) -> None:
    """`--suggest-patches DIR`. Reports what it refused as well as what it wrote."""
    backend = get_backend(args.backend)
    if args.backend == "none":
        print("--suggest-patches needs a model to write the patch: add "
              "--backend anthropic|openai|ollama. (What *verifies* the patch is the "
              "deterministic engine, but something still has to propose one.)",
              file=sys.stderr)
        return

    def rescan(root: str):
        # The same tiers the finding came from. Verifying against a weaker scan than the one
        # that raised the finding would be verifying against nothing.
        return engine.scan(root, run_deps=False, use_scanners=not args.no_scanners,
                           use_taint=not args.no_taint, only=only)

    outcomes = patch.suggest(result, args.target, backend, rescan,
                             test_command=args.patch_tests or "")
    written, where = patch.write(outcomes, args.suggest_patches)
    refused = [o for o in outcomes if not o.ok]
    print(f"Patches: {written} verified, written to {where}/ (NOT applied). "
          f"{len(refused)} refused.", file=sys.stderr)
    for outcome in refused:
        print(f"  refused {outcome.finding.detector_id} "
              f"({outcome.finding.file}:{outcome.finding.line}): "
              f"{'; '.join(outcome.reasons)[:200]}", file=sys.stderr)


def _looks_like_a_url(target: str) -> bool:
    """Whether the target is a network address rather than a path on disk.

    Checked before anything runs. A URL handed to a source scanner matches no file, and the
    scanner then reports zero findings — which is indistinguishable from a clean audit unless
    someone notices the file count. Refusing loudly costs one run; the alternative costs
    somebody's belief that their site was checked.

    A bare hostname (`example.com`) is deliberately not caught: it is also a plausible
    directory name, and refusing to scan a real directory called `example.com` would be its
    own quiet failure.
    """
    lowered = target.lower()
    return lowered.startswith(("http://", "https://", "ftp://", "ws://", "wss://"))


def _write_summary(path: str | None, markdown: str, fmt: str) -> None:
    """`--summary PATH` — the readable rendering of the scan that just ran, not a second scan.

    Skipped when `--format md` already produced it, so `-o r.md --summary r.md` cannot end up
    writing the same file twice.
    """
    if not path or fmt == "md":
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write(markdown)


def _emit(text: str, output: str | None, summary: str) -> None:
    if not output:
        print(text)
        return
    with open(output, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"Wrote {output} — {summary}")


def _run_diff(args, current, only: set[str] | None) -> int:
    """`--since REF`: scan the baseline tree too, and report the difference."""
    if args.format not in ("md", "json"):
        print(f"--since renders as md or json; --format {args.format} describes a single scan, "
              f"not a comparison.", file=sys.stderr)
        return 2
    try:
        tree = gitref.baseline_tree(args.since, args.target)
    except gitref.GitError as e:
        print(f"--since {args.since}: {e}", file=sys.stderr)
        return 2

    with tree as baseline_path:
        absent = not os.path.exists(baseline_path)
        if absent:
            baseline = ScanResult(target=baseline_path, backend="none")
        else:
            # Dependency scanning is off for the baseline on purpose: `npm audit` reads
            # node_modules, which a git archive does not carry, so running it here would
            # produce an empty result and make every current advisory look newly introduced.
            # `diff.compare` excludes dependency findings from the comparison for the same
            # reason and reports them under their own heading.
            # Same detector selection on both sides. A baseline scanned with a different set
            # would report every finding the current set adds as introduced by the change.
            baseline = engine.scan(baseline_path, run_deps=False,
                                   use_scanners=not args.no_scanners,
                                   use_taint=not args.no_taint, only=only)
        # Both scans report paths relative to their own root, so a file keeps the same name in
        # the temp baseline and the work tree and the two indexes line up with no translation.
        result = diff.compare(baseline, current, args.since, tree.sha)
        result.baseline_absent = absent

    out = diff.to_json(result) if args.format == "json" else diff.to_markdown(result)
    counts = result.counts()
    _emit(out, args.output,
          f"{counts['introduced']} introduced, {counts['resolved']} resolved, "
          f"{counts['unchanged']} unchanged")
    _write_summary(args.summary, diff.to_markdown(result), args.format)

    if args.min_sev and diff.gate(result, _MIN[args.min_sev]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
