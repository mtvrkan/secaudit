#!/usr/bin/env python3
"""Generate `site/og.png` — the Open Graph / Twitter card, from repository facts.

    python3 scripts/gen_og_image.py           # write it
    python3 scripts/gen_og_image.py --check   # fail if the committed image is stale (CI)

The roadmap had this down as needing headless Chrome, and that is the reason it sat unfinished:
an image only regenerable by installing a browser is one that stops matching the numbers
printed on it the first time those numbers move — and the numbers on a social card are the
first claim anyone sees about this project. `zlib` is enough to write a PNG (see
`pngwriter.py`) and a card of filled shapes and stroked text does not need a layout engine.

Every figure comes from `eval/scorecard.json` and the gate list. Nothing on this image is typed
here, which is the same rule the landing page and the coverage tables already follow — a
marketing asset is exactly where an out-of-date number does the most damage.
"""
from __future__ import annotations

import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))
sys.path.insert(0, os.path.join(REPO, "kit"))

import strokefont as font                                              # noqa: E402
from pngwriter import Canvas                                           # noqa: E402

OUT = os.path.join(REPO, "site", "og.png")
SCORECARD = os.path.join(REPO, "eval", "scorecard.json")

WIDTH, HEIGHT = 1200, 630

# The landing page's dark palette, so the card and the site it links to are the same product.
INK = (19, 19, 17)
PANEL = (26, 26, 23)
PAPER = (242, 240, 234)
MUTED = (160, 156, 146)
BRAND = (179, 74, 31)
GREEN = (95, 170, 120)


def facts() -> dict:
    with open(SCORECARD, encoding="utf-8") as f:
        card = json.load(f)
    overall = card["overall"]
    import run_checks
    return {
        "recall": f"{overall['recall']:.1%}",
        "f3": f"{overall['f3']:.3f}",
        "traps": f"{overall['fp']}/{card['false_positive_traps']}",
        "languages": str(len(card["by_language"])),
        "gates": str(len(run_checks.GATES)),
        "flaws": str(overall["tp"] + overall["fn"]),
    }


def shield(canvas: Canvas, cx: float, cy: float, size: float) -> None:
    """The favicon's mark, scaled. Same silhouette so the tab icon and the card agree."""
    s = size / 32.0
    outline = [(16, 2), (4, 7), (4, 16), (7, 23), (12, 28), (16, 30),
               (20, 28), (25, 23), (28, 16), (28, 7)]
    canvas.polygon([(cx + (x - 16) * s, cy + (y - 16) * s) for x, y in outline], BRAND)
    tick = [(10.5, 16), (14.5, 20), (21.5, 12)]
    for i in range(len(tick) - 1):
        x1, y1 = tick[i]
        x2, y2 = tick[i + 1]
        canvas.line(cx + (x1 - 16) * s, cy + (y1 - 16) * s,
                    cx + (x2 - 16) * s, cy + (y2 - 16) * s, PAPER, 3.2 * s)


def metric(canvas: Canvas, x: float, y: float, value: str, label: str, accent) -> None:
    """Value on the baseline `y`, label below it. Both are drawn from the same origin so the
    columns line up regardless of how wide the value happens to be."""
    font.draw(canvas, value, x, y, 44, accent, weight=3.4, tracking=2.6)
    font.draw(canvas, label, x, y + 28, 14, MUTED, weight=1.7, tracking=3.0)


def render() -> bytes:
    data = facts()
    canvas = Canvas(WIDTH, HEIGHT, INK)

    canvas.rect(0, 0, WIDTH, 8, BRAND)                     # top rule
    canvas.rect(64, 300, WIDTH - 128, 2, (44, 44, 40))     # divider under the wordmark
    canvas.rect(64, 448, WIDTH - 128, 138, PANEL)          # metrics panel

    shield(canvas, 118, 148, 116)

    font.draw(canvas, "SECAUDIT", 196, 168, 76, PAPER, weight=5.2, tracking=4.0)
    font.draw(canvas, "AUTHORIZED SECURITY AUDIT KIT", 200, 214, 20, MUTED,
              weight=2.0, tracking=5.0)

    font.draw(canvas, "TAINT ANALYSIS ACROSS MODULE BOUNDARIES", 64, 368, 26, PAPER,
              weight=2.6, tracking=3.0)
    font.draw(canvas, "SBOM · VEX · EU CRA EVIDENCE · MEASURED, NOT CLAIMED", 64, 414, 22,
              MUTED, weight=2.0, tracking=3.0)

    metric(canvas, 100, 528, data["recall"], "RECALL", GREEN)
    metric(canvas, 336, 528, data["f3"], "F3 SCORE", GREEN)
    metric(canvas, 572, 528, data["traps"], "FALSE POSITIVES", GREEN)
    metric(canvas, 856, 528, data["languages"], "LANGUAGES", PAPER)
    metric(canvas, 1024, 528, data["gates"], "CI GATES", PAPER)

    return canvas.to_png()


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    rendered = render()

    if "--check" in argv:
        try:
            with open(OUT, "rb") as f:
                current = f.read()
        except OSError:
            print(f"FAIL — site/og.png is missing. Run: python3 scripts/gen_og_image.py")
            return 1
        if current != rendered:
            print("FAIL — site/og.png no longer matches the measured numbers. "
                  "Run: python3 scripts/gen_og_image.py")
            return 1
        print(f"OG image is current ({len(current):,} bytes).")
        return 0

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(rendered)
    data = facts()
    print(f"Wrote site/og.png — {WIDTH}×{HEIGHT}, {len(rendered):,} bytes, "
          f"recall {data['recall']}, F3 {data['f3']}, {data['languages']} languages, "
          f"{data['gates']} gates.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
