#!/usr/bin/env python3
"""A single-stroke vector font, defined as polylines on a 6×10 grid.

Enough glyphs for a social card: uppercase, digits and a little punctuation. Lowercase is
absent, and that is a design constraint the card is drawn around rather than an omission to
fix later — a card typeset in caps is a normal choice, and every glyph here is hand-placed, so
doubling the set doubles the surface for a wonky letter nobody notices until it is published.

Coordinates run x: 0→6 left to right, y: 0→10 bottom to top (baseline at 0, cap height at 10).
The renderer flips y, so glyph definitions read the way you would draw them.
"""
from __future__ import annotations

# Each glyph is a list of polylines. `advance` is the horizontal step after drawing it.
GLYPHS: dict[str, list[list[tuple[float, float]]]] = {
    "A": [[(0, 0), (3, 10), (6, 0)], [(1.2, 3.8), (4.8, 3.8)]],
    "B": [[(0, 0), (0, 10), (4.2, 10), (5.6, 8.7), (5.6, 6.6), (4.2, 5.3), (0, 5.3)],
          [(4.2, 5.3), (5.9, 3.9), (5.9, 1.4), (4.4, 0), (0, 0)]],
    "C": [[(6, 8.2), (4.2, 10), (1.8, 10), (0, 8.2), (0, 1.8), (1.8, 0), (4.2, 0), (6, 1.8)]],
    "D": [[(0, 0), (0, 10), (3.4, 10), (6, 7.4), (6, 2.6), (3.4, 0), (0, 0)]],
    "E": [[(6, 10), (0, 10), (0, 0), (6, 0)], [(0, 5.2), (4.4, 5.2)]],
    "F": [[(6, 10), (0, 10), (0, 0)], [(0, 5.2), (4.4, 5.2)]],
    "G": [[(6, 8.2), (4.2, 10), (1.8, 10), (0, 8.2), (0, 1.8), (1.8, 0), (4.2, 0), (6, 1.8),
           (6, 4.4), (3.4, 4.4)]],
    "H": [[(0, 10), (0, 0)], [(6, 10), (6, 0)], [(0, 5.2), (6, 5.2)]],
    "I": [[(3, 10), (3, 0)], [(1, 10), (5, 10)], [(1, 0), (5, 0)]],
    "J": [[(6, 10), (6, 2), (4.2, 0), (1.8, 0), (0, 2)]],
    "K": [[(0, 10), (0, 0)], [(6, 10), (0, 4.6)], [(2.2, 6.4), (6, 0)]],
    "L": [[(0, 10), (0, 0), (6, 0)]],
    "M": [[(0, 0), (0, 10), (3, 5.4), (6, 10), (6, 0)]],
    "N": [[(0, 0), (0, 10), (6, 0), (6, 10)]],
    "O": [[(1.8, 10), (4.2, 10), (6, 8.2), (6, 1.8), (4.2, 0), (1.8, 0), (0, 1.8), (0, 8.2),
           (1.8, 10)]],
    "P": [[(0, 0), (0, 10), (4.4, 10), (6, 8.6), (6, 6.6), (4.4, 5.2), (0, 5.2)]],
    "Q": [[(1.8, 10), (4.2, 10), (6, 8.2), (6, 1.8), (4.2, 0), (1.8, 0), (0, 1.8), (0, 8.2),
           (1.8, 10)], [(3.6, 2.6), (6.2, 0)]],
    "R": [[(0, 0), (0, 10), (4.4, 10), (6, 8.6), (6, 6.6), (4.4, 5.2), (0, 5.2)],
          [(3.2, 5.2), (6, 0)]],
    "S": [[(6, 8.6), (4.2, 10), (1.6, 10), (0, 8.6), (0, 6.6), (1.6, 5.2), (4.4, 5.2),
           (6, 3.8), (6, 1.4), (4.4, 0), (1.8, 0), (0, 1.4)]],
    "T": [[(0, 10), (6, 10)], [(3, 10), (3, 0)]],
    "U": [[(0, 10), (0, 2), (1.8, 0), (4.2, 0), (6, 2), (6, 10)]],
    "V": [[(0, 10), (3, 0), (6, 10)]],
    "W": [[(0, 10), (1.4, 0), (3, 6.2), (4.6, 0), (6, 10)]],
    "X": [[(0, 10), (6, 0)], [(6, 10), (0, 0)]],
    "Y": [[(0, 10), (3, 5.2), (6, 10)], [(3, 5.2), (3, 0)]],
    "Z": [[(0, 10), (6, 10), (0, 0), (6, 0)]],
    "0": [[(1.8, 10), (4.2, 10), (6, 8.2), (6, 1.8), (4.2, 0), (1.8, 0), (0, 1.8), (0, 8.2),
           (1.8, 10)], [(0.8, 1.8), (5.2, 8.2)]],
    "1": [[(1.4, 8), (3, 10), (3, 0)], [(1, 0), (5, 0)]],
    "2": [[(0, 8.4), (1.8, 10), (4.4, 10), (6, 8.4), (6, 6.6), (0, 0), (6, 0)]],
    "3": [[(0, 10), (6, 10), (2.6, 5.6), (4.6, 5.6), (6, 4.2), (6, 1.4), (4.4, 0), (1.6, 0),
           (0, 1.4)]],
    "4": [[(4.6, 0), (4.6, 10), (0, 3.2), (6, 3.2)]],
    "5": [[(6, 10), (0, 10), (0, 5.6), (4.4, 5.6), (6, 4.2), (6, 1.4), (4.4, 0), (1.6, 0),
           (0, 1.4)]],
    "6": [[(6, 8.6), (4.2, 10), (1.8, 10), (0, 8.2), (0, 1.8), (1.8, 0), (4.2, 0), (6, 1.8),
           (6, 3.8), (4.2, 5.4), (1.8, 5.4), (0, 3.8)]],
    "7": [[(0, 10), (6, 10), (2.2, 0)]],
    "8": [[(1.8, 5.4), (0, 6.8), (0, 8.6), (1.8, 10), (4.2, 10), (6, 8.6), (6, 6.8),
           (4.2, 5.4), (1.8, 5.4), (0, 3.8), (0, 1.4), (1.8, 0), (4.2, 0), (6, 1.4),
           (6, 3.8), (4.2, 5.4)]],
    "9": [[(0, 1.4), (1.8, 0), (4.2, 0), (6, 1.8), (6, 8.2), (4.2, 10), (1.8, 10), (0, 8.6),
           (0, 6.2), (1.8, 4.6), (4.2, 4.6), (6, 6.2)]],
    ".": [[(2.6, 0), (3.4, 0)]],
    ",": [[(3.2, 0.6), (2.4, -1.2)]],
    "%": [[(0, 1.6), (6, 8.4)], [(0.4, 8.4), (2, 8.4), (2, 10), (0.4, 10), (0.4, 8.4)],
          [(4, 0), (5.6, 0), (5.6, 1.6), (4, 1.6), (4, 0)]],
    "/": [[(0, 0), (6, 10)]],
    "-": [[(1, 5.2), (5, 5.2)]],
    "·": [[(3, 5), (3.2, 5)]],
    "+": [[(3, 8), (3, 2.4)], [(0.4, 5.2), (5.6, 5.2)]],
    "(": [[(4.4, 10), (1.6, 6.6), (1.6, 3.4), (4.4, 0)]],
    ")": [[(1.6, 10), (4.4, 6.6), (4.4, 3.4), (1.6, 0)]],
    " ": [],
}

GLYPH_WIDTH = 6.0
DEFAULT_TRACKING = 2.2


def text_width(text: str, size: float, tracking: float = DEFAULT_TRACKING) -> float:
    """Width of `text` drawn at cap height `size`, so a caller can centre it."""
    unit = size / 10.0
    if not text:
        return 0.0
    return len(text) * (GLYPH_WIDTH + tracking) * unit - tracking * unit


def draw(canvas, text: str, x: float, y: float, size: float, colour, weight: float = 1.0,
         tracking: float = DEFAULT_TRACKING) -> float:
    """Draw `text` with its baseline at `y` and left edge at `x`. Returns the ending x.

    An unknown character is skipped rather than substituted. A missing glyph leaving a gap is
    visible to whoever looks at the image; a box or a wrong letter shipped as a brand asset is
    the same bug wearing a disguise.
    """
    unit = size / 10.0
    step = (GLYPH_WIDTH + tracking) * unit
    for char in text:
        strokes = GLYPHS.get(char.upper())
        if strokes:
            for polyline in strokes:
                for i in range(len(polyline) - 1):
                    x1, y1 = polyline[i]
                    x2, y2 = polyline[i + 1]
                    canvas.line(x + x1 * unit, y - y1 * unit,
                                x + x2 * unit, y - y2 * unit, colour, weight)
        x += step
    return x
