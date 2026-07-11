"""secaudit CLI — self-running, provider-agnostic security audit.

    python -m secaudit_core.cli <path> [--backend none|anthropic|openai|ollama]
                                        [--format md|json|sarif] [--min low|medium|high|critical]
                                        [--no-deps] [-o REPORT]

Tier 0 (deterministic detectors + npm audit) always runs. A backend, if given, enriches the
findings with LLM triage + logic-bug discovery. Exit code is non-zero if any finding at or
above --min-severity is reported (so it doubles as a CI gate)."""
from __future__ import annotations

import argparse
import sys

from . import engine, report
from .backends import get_backend

_MIN = {"low": 2, "medium": 3, "high": 4, "critical": 5}


def main(argv: list[str] | None = None) -> int:
    # Reports carry Unicode (→, ·). Don't let a legacy console codepage (e.g. Windows cp1254)
    # crash the tool on print — force UTF-8 where the stream supports it.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(prog="secaudit", description=__doc__.splitlines()[0])
    ap.add_argument("target", help="file or directory to audit")
    ap.add_argument("--backend", default="none",
                    choices=["none", "anthropic", "claude", "openai", "ollama"],
                    help="LLM enrichment backend (default: none — pure Tier 0)")
    ap.add_argument("--format", default="md", choices=["md", "json", "sarif"])
    ap.add_argument("--min", dest="min_sev", default=None,
                    choices=list(_MIN), help="fail (non-zero exit) if a finding at/above this severity exists")
    ap.add_argument("--no-deps", action="store_true", help="skip the dependency (npm audit) scan")
    ap.add_argument("--no-scanners", action="store_true",
                    help="skip installed scanners (semgrep/gitleaks/osv); built-in pack only")
    ap.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    args = ap.parse_args(argv)

    result = engine.scan(args.target, run_deps=not args.no_deps, use_scanners=not args.no_scanners)
    result = get_backend(args.backend).enrich(result)

    out = {"json": report.to_json, "sarif": report.to_sarif,
           "md": report.to_markdown}[args.format](result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"Wrote {args.output} — {len(result.findings)} finding(s), backend={result.backend}")
    else:
        print(out)

    if args.min_sev:
        threshold = _MIN[args.min_sev]
        if any(f.severity.rank >= threshold for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
