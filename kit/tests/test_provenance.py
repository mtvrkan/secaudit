#!/usr/bin/env python3
"""Whose code is this? — the six signals that decide a JS/TS file is somebody else's release.

The predicate itself lives in `langs.is_vendored_asset` and the two questions it cannot answer
alone live in `engine`: whether the scanned project's own manifest publishes the file, and
whether the directory it sits in is a copied-in library drop. All three are silencing decisions,
which is the direction that needs tests most — a silencing bug removes findings and nothing in a
report says so.
"""
from __future__ import annotations

import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KIT)

from secaudit_core.engine import _is_vendor_drop                      # noqa: E402
from secaudit_core.langs import has_release_preamble, is_vendored_asset  # noqa: E402

APP = "el.innerHTML = '<li>' + name + '</li>';\n"
BANNER = "/*! jQuery Cookie Plugin v1.3 | MIT */\n" + APP
UMD = ("(function (root, factory) { factory(root); }(this, function (root) {\n" + APP + "}));\n")


def test_application_source_is_not_vendored() -> None:
    assert not is_vendored_asset("static/js/app.js", APP)


def test_a_banner_and_a_umd_preamble_each_stand_alone() -> None:
    assert is_vendored_asset("static/js/cookie.js", BANNER)
    assert is_vendored_asset("static/js/loader.js", UMD)


def test_a_package_s_own_release_keeps_its_banner() -> None:
    """The signal that decides an application is exactly the signal a library ships with.

    `own_release` is what tells the two apart, and it is why 59 of SecBench.js's labelled sink
    files were never opened for two published rounds.
    """
    assert not is_vendored_asset("index.js", BANNER, own_release=True)
    assert not is_vendored_asset("index.js", UMD, own_release=True)
    # …and the signals that are about the artifact rather than its provenance still apply.
    assert is_vendored_asset("dist/index.min.js", APP, own_release=True)


def test_a_directory_of_libraries_makes_its_plain_siblings_vendored(tmp_path) -> None:
    """A library does not arrive as one file.

    `static/js/foundation/` held two bannered files and twelve plain ones, and the twelve were
    read as application source — 20 of one rule's 22 false positives on the external benchmark.
    """
    drop = tmp_path / "foundation"
    drop.mkdir()
    (drop / "foundation.cookie.js").write_text(BANNER, encoding="utf-8")
    (drop / "foundation.placeholder.js").write_text(UMD, encoding="utf-8")
    (drop / "foundation.orbit.js").write_text(APP, encoding="utf-8")

    cache: dict[str, bool] = {}
    assert _is_vendor_drop(str(drop), cache)
    assert is_vendored_asset("static/js/foundation/foundation.orbit.js", APP, vendor_drop=True)


def test_one_bannered_file_does_not_make_a_directory_a_drop(tmp_path) -> None:
    """Two, not one. A single `@license` header is ordinary in application source, and a
    threshold of one turns `src/` into a vendor directory."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vendored-helper.js").write_text(BANNER, encoding="utf-8")
    (src / "app.js").write_text(APP, encoding="utf-8")
    (src / "view.js").write_text(APP, encoding="utf-8")

    assert not _is_vendor_drop(str(src), {})


def test_a_drop_does_not_reach_into_its_subdirectories(tmp_path) -> None:
    """A directory is the unit somebody copied in. Walking down from `static/` would take one
    bannered pair and silence a tree."""
    root = tmp_path / "static"
    root.mkdir()
    (root / "a.js").write_text(BANNER, encoding="utf-8")
    (root / "b.js").write_text(UMD, encoding="utf-8")
    child = root / "app"
    child.mkdir()
    (child / "main.js").write_text(APP, encoding="utf-8")

    cache: dict[str, bool] = {}
    assert _is_vendor_drop(str(root), cache)
    assert not _is_vendor_drop(str(child), cache)


def test_own_release_wins_over_the_directory_signal() -> None:
    """A package whose own files carry banners must not silence itself — the same defect as
    `own_release`, one scope up."""
    assert not is_vendored_asset("index.js", APP, own_release=True, vendor_drop=True)


def test_has_release_preamble_ignores_the_signals_that_are_about_one_file() -> None:
    """A minified filename says nothing about the file beside it, so the directory question is
    asked with the banner signals only."""
    assert has_release_preamble(BANNER)
    assert has_release_preamble(UMD)
    assert not has_release_preamble(APP)
