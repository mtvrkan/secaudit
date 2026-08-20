"""Locale bundles: complete, consistent, and honest about what they do not translate.

A translation rots in a way nobody notices, because the person who can see it is rarely the
person editing the renderer. Every check here is a way that happens: a key added to the report
and not to a bundle, a placeholder renamed on one side, a heading translated to an empty
string. The last is the worst — a missing heading does not look like a bug, it looks like a
report with one fewer section.
"""
from __future__ import annotations

import json
import os
import re
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(KIT)
sys.path.insert(0, KIT)

from secaudit_core import i18n, report                                   # noqa: E402
from secaudit_core.schema import (Confidence, Finding, ScanResult,       # noqa: E402
                                  Severity)

fails: list[str] = []
_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def check(condition: bool, message: str) -> None:
    if not condition:
        fails.append(message)


def bundles() -> dict[str, dict]:
    out = {}
    for name in sorted(os.listdir(i18n.BUNDLE_DIR)):
        if name.endswith(".json"):
            with open(os.path.join(i18n.BUNDLE_DIR, name), encoding="utf-8") as f:
                out[name[:-5]] = json.load(f)
    return out


def test_every_bundle_has_every_key() -> None:
    loaded = bundles()
    english = set(loaded[i18n.DEFAULT])
    for locale, bundle in loaded.items():
        missing = sorted(english - set(bundle))
        extra = sorted(set(bundle) - english)
        check(not missing, f"{locale}.json is missing {missing} — those render in English, "
                           f"which is the fallback working, but it is still an untranslated "
                           f"report shipping as a translated one")
        check(not extra, f"{locale}.json has keys English does not: {extra}. A key nothing "
                         f"reads is a translation someone wrote for nothing")


def test_placeholders_match() -> None:
    """`{n}` renamed on one side renders the English template instead of the translation, and
    the report still looks fine — which is why this needs a test rather than a review."""
    loaded = bundles()
    english = loaded[i18n.DEFAULT]
    for locale, bundle in loaded.items():
        if locale == i18n.DEFAULT:
            continue
        for key, text in bundle.items():
            if key not in english:
                continue
            want = set(_PLACEHOLDER.findall(english[key]))
            got = set(_PLACEHOLDER.findall(text))
            check(want == got,
                  f"{locale}.json `{key}` uses placeholders {sorted(got)}; English uses "
                  f"{sorted(want)}. A mismatch silently falls back to the English string")


def test_no_empty_strings() -> None:
    for locale, bundle in bundles().items():
        blank = sorted(k for k, v in bundle.items() if not str(v).strip())
        check(not blank, f"{locale}.json has empty values for {blank}. An empty heading does "
                         f"not look like a bug; it looks like a missing section")


def test_a_missing_key_is_loud() -> None:
    strings = i18n.Strings("en")
    rendered = strings("no.such.key")
    check("no.such.key" in rendered and rendered.strip() != "",
          f"a missing key must render visibly, got {rendered!r}")


def test_unknown_locale_falls_back_rather_than_failing() -> None:
    strings = i18n.Strings("xx")
    check(strings("report.summary") == i18n.Strings("en")("report.summary"),
          "an unknown locale must fall back to English, not produce an empty report")


def test_partial_translation_falls_back_per_key() -> None:
    """Per key, not per bundle — so a translation can ship at 90% instead of not at all."""
    strings = i18n.Strings("tr")
    original = dict(strings._bundle)
    try:
        strings._bundle.pop("report.summary", None)
        check(strings("report.summary") == i18n.Strings("en")("report.summary"),
              "a key missing from a bundle must fall back to English, not to a blank")
        check(strings("report.findings") != i18n.Strings("en")("report.findings"),
              "...while the keys that ARE translated stay translated")
    finally:
        strings._bundle.clear()
        strings._bundle.update(original)


def test_every_key_the_renderer_asks_for_exists() -> None:
    """The direction that actually breaks reports: the renderer gains a key, the bundle does
    not. Rendered against a real result rather than by grepping, so a key reached only on one
    branch still counts."""
    finding = Finding(
        detector_id="SEC-JS-CMDI", title="OS command injection", severity=Severity.CRITICAL,
        confidence=Confidence.HIGH, cwe="CWE-78", owasp="A03", file="server.js", line=19,
        evidence="exec('ping ' + req.query.host)", fix="Use execFile.",
        taint_path="L18: req.query.host → L19: sink", vex_status="affected",
        vex_justification="imported", triage_note="confirmed", exploitation="exploited",
        exploitation_note="On CISA KEV.")
    result = ScanResult(target="x", findings=[finding], tools_used=["builtin"],
                        notes=["a note"], backend="none")
    for locale in bundles():
        rendered = report.to_markdown(result, locale)
        unresolved = re.findall(r"⟪([^⟫]+)⟫", rendered)
        check(not unresolved,
              f"{locale}: the renderer asked for keys no bundle has: {sorted(set(unresolved))}")
        check("Use execFile." in rendered,
              f"{locale}: the fix text must stay in English — it comes from the detector and "
              f"changes with the engine")


def test_translated_report_says_what_is_not_translated() -> None:
    """Someone reading a Turkish report with English fix instructions should be told that is
    deliberate, not left to wonder whether the translation broke."""
    result = ScanResult(target="x", findings=[], tools_used=["builtin"], backend="none")
    turkish = report.to_markdown(result, "tr")
    english = report.to_markdown(result, "en")
    check(i18n.Strings("tr")("lang.note") in turkish,
          "a non-English report must explain why finding text stays in English")
    check(i18n.Strings("tr")("lang.note") not in english,
          "...and the English report must not carry that note, which would be noise")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    test_every_bundle_has_every_key()
    test_placeholders_match()
    test_no_empty_strings()
    test_a_missing_key_is_loud()
    test_unknown_locale_falls_back_rather_than_failing()
    test_partial_translation_falls_back_per_key()
    test_every_key_the_renderer_asks_for_exists()
    test_translated_report_says_what_is_not_translated()

    if fails:
        print("I18N TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    loaded = bundles()
    print(f"I18N TESTS PASSED — {len(loaded)} locale(s) ({', '.join(sorted(loaded))}), "
          f"{len(loaded[i18n.DEFAULT])} keys each, placeholders consistent, per-key fallback "
          f"works, no key the renderer asks for is missing, and fix text stays in English.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
