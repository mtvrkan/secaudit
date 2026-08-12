#!/usr/bin/env python3
"""A minimal PNG encoder and 2D rasterizer, standard library only.

The roadmap assumed the Open Graph image would need headless Chrome, and that assumption is
what kept it as "the one remaining manual step" — a build artefact nobody can regenerate
without installing a browser is a build artefact that goes stale the first time a number on it
changes. `zlib` and `struct` are enough to write a PNG, and a card made of filled polygons and
stroked text does not need a browser to draw it.

Deliberately small: 8-bit RGB, no alpha channel, no interlacing, no colour profiles. Enough for
a social card and nothing more. Anti-aliasing is 3× supersampling with a box downsample, which
is crude, entirely predictable, and produces identical bytes for identical input — the property
that matters, because this file is committed and CI compares it.
"""
from __future__ import annotations

import struct
import zlib

SUPERSAMPLE = 3


class Canvas:
    """An RGB raster with polygon fill and polyline stroke, drawn at `SUPERSAMPLE`× and
    downsampled on export."""

    def __init__(self, width: int, height: int, background: tuple[int, int, int]):
        self.width = width
        self.height = height
        self.scale = SUPERSAMPLE
        self._w = width * self.scale
        self._h = height * self.scale
        self._px = bytearray()
        for _ in range(self._h):
            self._px += bytes(background) * self._w

    # ---------------------------------------------------------------- primitives
    def _set(self, x: int, y: int, colour: tuple[int, int, int]) -> None:
        if 0 <= x < self._w and 0 <= y < self._h:
            i = (y * self._w + x) * 3
            self._px[i:i + 3] = bytes(colour)

    def rect(self, x, y, w, h, colour) -> None:
        s = self.scale
        for yy in range(int(y * s), int((y + h) * s)):
            if not 0 <= yy < self._h:
                continue
            start = max(0, int(x * s))
            end = min(self._w, int((x + w) * s))
            if end > start:
                i = (yy * self._w + start) * 3
                self._px[i:i + (end - start) * 3] = bytes(colour) * (end - start)

    def polygon(self, points, colour) -> None:
        """Even-odd scanline fill. Enough for the convex and simple shapes a card needs."""
        s = self.scale
        pts = [(x * s, y * s) for x, y in points]
        if len(pts) < 3:
            return
        ys = [p[1] for p in pts]
        for yy in range(max(0, int(min(ys))), min(self._h, int(max(ys)) + 1)):
            centre = yy + 0.5
            crossings = []
            for i in range(len(pts)):
                x1, y1 = pts[i]
                x2, y2 = pts[(i + 1) % len(pts)]
                if (y1 <= centre < y2) or (y2 <= centre < y1):
                    crossings.append(x1 + (centre - y1) * (x2 - x1) / (y2 - y1))
            crossings.sort()
            for i in range(0, len(crossings) - 1, 2):
                start = max(0, int(crossings[i]))
                end = min(self._w, int(crossings[i + 1]) + 1)
                if end > start:
                    j = (yy * self._w + start) * 3
                    self._px[j:j + (end - start) * 3] = bytes(colour) * (end - start)

    def line(self, x1, y1, x2, y2, colour, width=1.0) -> None:
        """A stroked segment, drawn as a quad plus round caps so joins do not gap."""
        s = self.scale
        dx, dy = (x2 - x1) * s, (y2 - y1) * s
        length = (dx * dx + dy * dy) ** 0.5
        half = max(0.5, width * s / 2)
        if length < 1e-9:
            self._disc(x1 * s, y1 * s, half, colour)
            return
        nx, ny = -dy / length * half, dx / length * half
        ax, ay = x1 * s, y1 * s
        bx, by = x2 * s, y2 * s
        self._quad([(ax + nx, ay + ny), (bx + nx, by + ny),
                    (bx - nx, by - ny), (ax - nx, ay - ny)], colour)
        self._disc(ax, ay, half, colour)
        self._disc(bx, by, half, colour)

    def _quad(self, pts, colour) -> None:
        ys = [p[1] for p in pts]
        for yy in range(max(0, int(min(ys))), min(self._h, int(max(ys)) + 1)):
            centre = yy + 0.5
            crossings = []
            for i in range(4):
                x1, y1 = pts[i]
                x2, y2 = pts[(i + 1) % 4]
                if (y1 <= centre < y2) or (y2 <= centre < y1):
                    crossings.append(x1 + (centre - y1) * (x2 - x1) / (y2 - y1))
            crossings.sort()
            for i in range(0, len(crossings) - 1, 2):
                start = max(0, int(crossings[i]))
                end = min(self._w, int(crossings[i + 1]) + 1)
                for xx in range(start, end):
                    self._set(xx, yy, colour)

    def _disc(self, cx, cy, r, colour) -> None:
        for yy in range(int(cy - r), int(cy + r) + 1):
            span = r * r - (yy + 0.5 - cy) ** 2
            if span <= 0:
                continue
            half = span ** 0.5
            for xx in range(int(cx - half), int(cx + half) + 1):
                self._set(xx, yy, colour)

    # ---------------------------------------------------------------- export
    def _downsample(self) -> bytes:
        s = self.scale
        area = s * s
        out = bytearray(self.width * self.height * 3)
        for y in range(self.height):
            rows = [(y * s + k) * self._w for k in range(s)]
            for x in range(self.width):
                r = g = b = 0
                base = x * s
                for row in rows:
                    i = (row + base) * 3
                    for k in range(s):
                        r += self._px[i]; g += self._px[i + 1]; b += self._px[i + 2]
                        i += 3
                o = (y * self.width + x) * 3
                out[o] = r // area
                out[o + 1] = g // area
                out[o + 2] = b // area
        return bytes(out)

    def to_png(self) -> bytes:
        raw = self._downsample()
        stride = self.width * 3
        # Filter type 0 (None) on every scanline. A real encoder would choose per line; this
        # one does not, because a fixed choice is what makes the output byte-identical run to
        # run, which is what lets CI compare the committed file.
        scanlines = b"".join(b"\x00" + raw[y * stride:(y + 1) * stride]
                             for y in range(self.height))

        def chunk(kind: bytes, data: bytes) -> bytes:
            return (struct.pack(">I", len(data)) + kind + data
                    + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))

        header = struct.pack(">IIBBBBB", self.width, self.height, 8, 2, 0, 0, 0)
        return (b"\x89PNG\r\n\x1a\n"
                + chunk(b"IHDR", header)
                + chunk(b"IDAT", zlib.compress(scanlines, 9))
                + chunk(b"IEND", b""))
