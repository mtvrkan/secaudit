#!/usr/bin/env python3
"""Generate the Open Graph / Twitter cards — one per language — from repository facts.

    python3 scripts/gen_og_image.py           # rasterise them (needs Chrome)
    python3 scripts/gen_og_image.py --check    # fail if a committed card is stale (no Chrome)

**The card is HTML now, and the reason the previous one was not is worth keeping.** It used to
be drawn by hand into a PNG with `zlib` and a 52-glyph stroke font, because the roadmap had this
down as needing headless Chrome and a build step that needs a browser installed is a build step
that fails for a contributor who has done nothing wrong. That reasoning was sound about the
*gate* and wrong about the *asset*. What it bought was a card nobody could design: no lowercase,
no serif, no italic, no gradient — everything set in one outlined mono face, which is why the
card ended up as a wall of tracked-out capitals and a four-column strip of figures.

So the two concerns are separated instead of traded:

* **Rasterising** shells out to Chrome and is run by hand, like the landing page's own screenshot
  assets. The output PNGs are committed as source. A contributor without Chrome can still run
  every gate; they simply cannot regenerate the cards, and nothing asks them to.
* **Freshness** is still gated, and this is the part the stroke-font version was really
  protecting. The card prints a measured figure, so a card that outlives its number is the
  failure mode — `site/og.facts.json` records the facts each committed card was rendered from,
  and `--check` compares that record against `gen_site.facts()` **without opening Chrome**. Edit
  a number and the build fails until the cards are redrawn. That is the whole of what check 4
  ever asserted, and it now asserts it in a form that does not dictate how the pixels are made.

The type is Windows-first — `Sitka Display`, falling back to Palatino and Georgia — because these
are rasterised on the maintainer's machine and committed, not built in CI. A Linux render would
produce a different-looking card, which is exactly why the PNG is the artefact and the HTML is
not published.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))
sys.path.insert(0, os.path.join(REPO, "kit"))

from pngwriter import Canvas                                           # noqa: E402

WIDTH, HEIGHT = 1200, 630

# The landing page's dark palette, so the card and the site it links to are the same product.
INK = (19, 19, 17)
BRAND = (255, 122, 69)

TEMPLATE = os.path.join(REPO, "site", "og.html")
STAMP = os.path.join(REPO, "site", "og.facts.json")

# Everything language-dependent, in one place. `<em>` is the accent half of the headline: the
# claim that separates this from every other scanner is not that it audits, it is that the audit
# has a number anyone can re-run, so that is the half set in italic.
COPY = {
    "en": {
        "file": "og.png",
        "h1size": "78px",
        "headline": "Offline security audit with<br><em>a published score</em>.",
        "proof": "F3 {rv_f3}",
        "proof_note": "RealVuln, {rv_repos} real repositories",
        "alt": "SecAudit — offline security audit with a published score: "
               "F3 {rv_f3} on RealVuln, {rv_repos} real repositories scored by others",
    },
    "tr": {
        "file": "og.tr.png",
        "h1size": "70px",
        "headline": "Çevrimdışı güvenlik denetimi,<br><em>yayımlanmış bir skorla</em>.",
        "proof": "F3 {rv_f3}",
        "proof_note": "RealVuln, {rv_repos} gerçek depo",
        "alt": "SecAudit — skoru yayımlanmış çevrimdışı güvenlik denetimi: "
               "RealVuln üzerinde F3 {rv_f3}, {rv_repos} gerçek depo",
    },
}

DOMAIN = "secaudit.mtvrkan.com"

# The home-screen icon. An SVG favicon covers every browser that reads one, and covers nothing
# else: iOS bookmarks a screenshot of the page when there is no `apple-touch-icon`, and a
# screenshot of a dark landing page is a grey rectangle. Square, opaque and unrounded — the
# platform rounds it, and an icon that rounds itself gets rounded twice. Still drawn in Python:
# it is the mark on a background and has no type on it, so nothing about it wanted a browser.
ICON = {"file": "apple-touch-icon.png", "size": 180}

# The facts the cards are made of. Named rather than "everything `facts()` returns", so that a
# new figure appearing on the landing page does not invalidate every committed card for a number
# the card never printed.
FACT_KEYS = ("rv_f3", "rv_repos")

CHROME_CANDIDATES = (
    r"C:/Program Files/Google/Chrome/Application/chrome.exe",
    r"C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google/Chrome/Application/chrome.exe"),
    r"C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
)


def facts() -> dict:
    """Every figure on the card, from the call the pages are built from."""
    import gen_site
    return gen_site.facts()


def card_facts(data: dict) -> dict:
    return {key: data[key] for key in FACT_KEYS}


def find_chrome() -> str:
    for path in CHROME_CANDIDATES:
        if path and os.path.exists(path):
            return path
    found = shutil.which("chrome") or shutil.which("chromium") or shutil.which("google-chrome")
    if found:
        return found
    raise SystemExit(
        "gen-og: Chrome not found. This script rasterises the cards with headless Chrome; "
        "install it, or leave the committed PNGs alone — `--check` and every gate in "
        "scripts/run_checks.py run without it.")


def render_html(lang: str, data: dict) -> str:
    """The card's markup, with the same mark the site draws and the same figures it prints."""
    import gen_site

    copy = COPY[lang]
    with open(TEMPLATE, encoding="utf-8") as f:
        html = f.read()
    values = {
        "lang": lang,
        "mark": gen_site.mark_svg("#131311", ' aria-hidden="true"'),
        "h1size": copy["h1size"],
        "headline": copy["headline"],
        "domain": DOMAIN,
        "proof": copy["proof"].format(**data),
        "proof_note": copy["proof_note"].format(**data),
    }
    for key, value in values.items():
        html = html.replace("{{" + key + "}}", value)
    if "{{" in html:
        raise SystemExit(f"gen-og: site/og.html references a token nothing supplies "
                         f"({html[html.index('{{'):][:40]!r})")
    return html


def shoot(chrome: str, html: str, out: str) -> None:
    """One card, rasterised. `--force-device-scale-factor=1` so the card is 1200×630 exactly."""
    with tempfile.TemporaryDirectory() as work:
        page = os.path.join(work, "card.html")
        with open(page, "w", encoding="utf-8") as f:
            f.write(html)
        subprocess.run(
            [chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
             "--force-device-scale-factor=1", "--default-background-color=00000000",
             f"--window-size={WIDTH},{HEIGHT}", f"--screenshot={out}",
             "--virtual-time-budget=2000", f"--user-data-dir={os.path.join(work, 'profile')}",
             page],
            check=True, capture_output=True)
    if not os.path.exists(out):
        raise SystemExit(f"gen-og: Chrome wrote no file to {out}")


def render_icon() -> bytes:
    """The mark on the card's own background, at home-screen size.

    Nothing but the mark: 180 pixels is roughly a centimetre of glass and a wordmark set at that
    size would be four grey smears. The margin is a tenth of the box, which keeps the shield
    clear of the corner radius the platform applies.
    """
    import gen_site

    size = ICON["size"]
    canvas = Canvas(size, size, INK)
    bw, bh = gen_site.MARK_BOX
    scale = size * 0.62 / bh
    for ring in gen_site.MARK_RINGS:
        canvas.polygon([(size / 2 + (x - bw / 2) * scale, size / 2 + (y - bh / 2) * scale)
                        for x, y in ring], BRAND)
    return canvas.to_png()


def stale(data: dict) -> list[str]:
    """What `--check` reports: the committed cards' facts against today's."""
    want = card_facts(data)
    problems = []
    for name in [c["file"] for c in COPY.values()] + [ICON["file"]]:
        if not os.path.exists(os.path.join(REPO, "site", name)):
            problems.append(f"site/{name} is missing")
    if not os.path.exists(STAMP):
        problems.append(f"site/{os.path.basename(STAMP)} is missing — nothing records which "
                        f"figures the committed cards were drawn from")
        return problems
    with open(STAMP, encoding="utf-8") as f:
        recorded = json.load(f)
    for key, value in want.items():
        if str(recorded.get("facts", {}).get(key)) != str(value):
            problems.append(f"the cards say {key}={recorded.get('facts', {}).get(key)!r} and the "
                            f"repository now measures {value!r}")
    return problems


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    data = facts()

    if "--check" in argv:
        problems = stale(data)
        if problems:
            print("FAIL — the social cards no longer describe this repository:")
            for problem in problems:
                print(f"  - {problem}")
            print("Run: python3 scripts/gen_og_image.py   (needs Chrome; the PNGs are committed)")
            return 1
        print(f"Social cards are current ({len(COPY)} cards + the home-screen icon, "
              f"F3 {data['rv_f3']} on {data['rv_repos']} repositories).")
        return 0

    chrome = find_chrome()
    for lang, copy in COPY.items():
        shoot(chrome, render_html(lang, data), os.path.join(REPO, "site", copy["file"]))
    with open(os.path.join(REPO, "site", ICON["file"]), "wb") as f:
        f.write(render_icon())
    with open(STAMP, "w", encoding="utf-8") as f:
        json.dump({
            "note": "The figures the committed social cards were rendered from. `--check` holds "
                    "this against gen_site.facts() so a card cannot outlive its number, without "
                    "needing the browser that drew it.",
            "facts": card_facts(data),
        }, f, indent=2)
        f.write("\n")
    print(f"Wrote {', '.join('site/' + c['file'] for c in COPY.values())}, "
          f"site/{ICON['file']} — cards {WIDTH}×{HEIGHT} via {os.path.basename(chrome)}, "
          f"F3 {data['rv_f3']} on {data['rv_repos']} repositories.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
