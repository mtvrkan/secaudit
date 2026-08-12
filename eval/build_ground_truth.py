#!/usr/bin/env python3
"""Generate the fixture ground truth from the fixtures themselves.

    python3 eval/build_ground_truth.py           # write it
    python3 eval/build_ground_truth.py --check    # fail if the committed file is stale (CI)

The labels are **derived, not typed**. Every planted flaw in `vulnerable-app` carries a
`V<n> —` marker comment and every safe counterpart in `secure-app` carries `S<n> —`; the CWE
for each id comes from the golden-set table in `tests/expected-findings.md`. So editing a
fixture and forgetting to update the ground truth is a build failure, not a silently wrong
score — which matters more here than anywhere else in the repo, because a wrong label makes
every number computed from it wrong in a direction nobody notices.

Output follows the [RealVuln](https://github.com/kolega-ai/Real-Vuln-Benchmark) ground-truth
schema on purpose: the same harness then scores our fixtures and any external corpus, so the
number we publish about ourselves is computed the same way as the number a third party
publishes about us. The `S<n>` entries become `is_vulnerable: false` **false-positive traps**
— safe implementations of the very same feature, which is the hardest thing for a scanner to
stay quiet on and the whole reason the secure fixture exists.
"""
from __future__ import annotations

import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(REPO, "tests", "fixtures")
GOLDEN = os.path.join(REPO, "tests", "expected-findings.md")
OUT = os.path.join(REPO, "eval", "ground-truth", "secaudit-fixtures", "ground-truth.json")

SCHEMA_VERSION = "1.0.0"

# `| V1 | SQL injection | A05 / CWE-89 | `server.js` … |`
_ROW = re.compile(r"^\|\s*(V\d+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|", re.M)
# A marker comment: `// V1 — …`, `# V17 — …`, `// S8 ↔ V8`
_MARKER = re.compile(r"(?:^|\s)([VS])(\d+)\s*[—–-]")

_LANG = {".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
         ".ts": "typescript", ".tsx": "typescript", ".py": "python", "Dockerfile": "docker",
         # A per-language score only means something for languages that have fixtures. Every
         # entry below was added with a paired vulnerable/safe file, so a language appearing
         # here is a language actually being measured rather than one merely claimed.
         ".go": "go", ".java": "java", ".php": "php", ".rb": "ruby", ".cs": "csharp",
         ".rs": "rust", ".kt": "kotlin", ".dart": "dart", ".tf": "terraform",
         ".yaml": "yaml", ".yml": "yaml", ".plist": "plist", ".json": "json"}


def language_of(name: str) -> str:
    if name == "Dockerfile":
        return "docker"
    return _LANG.get(os.path.splitext(name)[1].lower(), "other")


def golden_rows() -> dict[str, dict]:
    """id → {class, owasp, cwes} from the golden-set table."""
    with open(GOLDEN, encoding="utf-8") as f:
        text = f.read()
    rows: dict[str, dict] = {}
    for vid, vclass, mapping, location in _ROW.findall(text):
        # `A08 / CWE-502/94/95` means any of 502, 94 or 95 is a correct classification.
        # Expanded by splitting the token rather than with a repeated capture group, because
        # Python keeps only the LAST repetition of a group — which would silently drop the
        # middle CWE of a three-way list and score a correct answer as a miss.
        cwes = [f"CWE-{n}" for token in re.findall(r"CWE-[\d/]+", mapping)
                for n in token[4:].split("/") if n]
        owasp = (re.search(r"\b(A\d{2}|LLM\d{2})\b", mapping) or [None])[0] if re.search(
            r"\b(A\d{2}|LLM\d{2})\b", mapping) else ""
        rows[vid] = {
            "class": vclass.strip(),
            "owasp": owasp or "",
            "cwes": list(dict.fromkeys(cwes)) or ["CWE-Other"],
            "location_hint": location.strip(),
        }
    return rows


def markers_in(path: str) -> list[tuple[str, int, int]]:
    """[(id, start_line, end_line)] for every marker in a fixture file.

    The marker sits on the comment; the sink is a line or two below it, so a region runs from
    the marker to just before the next one. Region matching (rather than exact-line matching)
    is what keeps the score from measuring line-number bookkeeping instead of detection."""
    with open(path, encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()
    hits: list[tuple[str, int]] = []
    for i, line in enumerate(lines, start=1):
        m = _MARKER.search(line)
        if m:
            hits.append((f"{m.group(1)}{m.group(2)}", i))
    regions = []
    for idx, (mid, start) in enumerate(hits):
        end = hits[idx + 1][1] - 1 if idx + 1 < len(hits) else len(lines)
        regions.append((mid, start, end))
    return regions


def build() -> dict:
    rows = golden_rows()
    findings = []

    for corpus, vulnerable in (("vulnerable-app", True), ("secure-app", False)):
        root = os.path.join(FIXTURES, corpus)
        for name in sorted(os.listdir(root)):
            path = os.path.join(root, name)
            if not os.path.isfile(path):
                continue
            for mid, start, end in markers_in(path):
                prefix, num = mid[0], mid[1:]
                if (prefix == "V") != vulnerable:
                    continue          # a V marker in the secure fixture is a cross-reference
                golden = rows.get(f"V{num}")
                if not golden:
                    continue          # a marker with no golden-set row is not a label
                findings.append({
                    "id": f"{corpus}:{mid}",
                    "is_vulnerable": vulnerable,
                    "vulnerability_class": golden["class"],
                    "primary_cwe": golden["cwes"][0],
                    "acceptable_cwes": golden["cwes"],
                    "owasp": golden["owasp"],
                    "file": f"{name}",
                    "corpus": corpus,
                    "language": language_of(name),
                    "location": {"start_line": start, "end_line": end},
                    "evidence": {
                        "source": "secaudit-fixture",
                        "description": (golden["location_hint"] if vulnerable else
                                        f"Safe implementation of {golden['class']} — a correct "
                                        f"scanner stays quiet here (false-positive trap)."),
                    },
                })

    return {
        "schema_version": SCHEMA_VERSION,
        "repo_id": "secaudit-fixtures",
        "repo_url": "https://github.com/mtvrkan/secaudit",
        "type": "paired-synthetic",
        "authorship": "human_authored",
        "note": ("Derived from the fixture marker comments and the golden-set table by "
                 "eval/build_ground_truth.py — never edit this file by hand. Every "
                 "`is_vulnerable: false` entry is a SAFE implementation of the same feature "
                 "as its vulnerable twin, which is a far harder trap than unrelated clean code."),
        "findings": findings,
    }


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    data = build()
    rendered = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    vulnerable = sum(1 for f in data["findings"] if f["is_vulnerable"])
    traps = len(data["findings"]) - vulnerable

    if "--check" in argv:
        try:
            with open(OUT, encoding="utf-8") as f:
                current = f.read()
        except OSError:
            print(f"FAIL — {os.path.relpath(OUT, REPO)} is missing. "
                  f"Run: python3 eval/build_ground_truth.py")
            return 1
        if current != rendered:
            print(f"FAIL — {os.path.relpath(OUT, REPO)} is stale (a fixture or the golden set "
                  f"changed). Run: python3 eval/build_ground_truth.py")
            return 1
        print(f"Ground truth is current — {vulnerable} labelled vulnerabilities, "
              f"{traps} false-positive traps.")
        return 0

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(f"Wrote {os.path.relpath(OUT, REPO)} — {vulnerable} labelled vulnerabilities, "
          f"{traps} false-positive traps.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
