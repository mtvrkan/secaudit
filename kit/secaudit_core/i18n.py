"""Report strings as data, so adding a language is a file rather than a fork of the renderer.

WHAT IS TRANSLATED, AND WHAT DELIBERATELY IS NOT

Translated: the report's own furniture — headings, table labels, the sentences the tool says
about itself and its limits. These are written once per language and do not go stale when a
detector changes.

**Not** translated: finding titles, evidence, and above all **fix instructions**. Those come
from `detectors.py` and the taint sink catalog, and they change with the engine. Translating
them would put 79 detectors × N languages behind every rule edit, and the failure mode is
specific and bad: a *stale translated fix* tells someone to apply a remediation the rule no
longer recommends, in a language where they cannot see it disagrees with the English. An
English fix next to Turkish chrome is obviously English. A wrong Turkish fix is not obviously
wrong. Security terms (CWE, CVE, OWASP, the detector ids) stay in English for the same reason
they do in every other language's security writing: they are identifiers.

Bundles are plain JSON under `secaudit_core/locales/`. No dependency, no compilation step, no `.po` toolchain —
a translator edits one file and the gate tells them if they missed a key.
"""
from __future__ import annotations

import json
import os

# Inside the package, not at the repo root. A bundle directory beside the source works
# perfectly in a checkout and ships in no wheel, so `--lang tr` on an installed copy would
# quietly render English — the failure looking exactly like a translation nobody wrote.
BUNDLE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locales")

DEFAULT = "en"

_cache: dict[str, dict] = {}


def available() -> list[str]:
    try:
        return sorted(n[:-5] for n in os.listdir(BUNDLE_DIR) if n.endswith(".json"))
    except OSError:
        return [DEFAULT]


def load(locale: str) -> dict:
    locale = (locale or DEFAULT).lower()
    if locale not in _cache:
        path = os.path.join(BUNDLE_DIR, f"{locale}.json")
        try:
            with open(path, encoding="utf-8") as f:
                _cache[locale] = json.load(f)
        except (OSError, json.JSONDecodeError):
            _cache[locale] = {} if locale == DEFAULT else load(DEFAULT)
    return _cache[locale]


class Strings:
    """Lookup for one locale, falling back to English key by key.

    Falling back per key rather than per bundle is what lets a partial translation ship: a
    Turkish bundle missing three keys renders those three in English instead of failing or —
    worse — rendering an empty heading, which is how a missing string becomes an invisible one.
    """

    def __init__(self, locale: str = DEFAULT):
        self.locale = (locale or DEFAULT).lower()
        self._bundle = load(self.locale)
        self._fallback = load(DEFAULT) if self.locale != DEFAULT else self._bundle

    def __call__(self, key: str, **kwargs) -> str:
        text = self._bundle.get(key) or self._fallback.get(key)
        if text is None:
            # A missing key renders as the key itself. Loud on purpose: an empty string would
            # silently delete a heading from a report someone is about to hand to an auditor.
            return f"⟪{key}⟫"
        try:
            return text.format(**kwargs) if kwargs else text
        except (KeyError, IndexError):
            # A bundle whose placeholders do not match the call site is a translation bug, and
            # showing the untranslated template beats raising in the middle of a report.
            return self._fallback.get(key, text)

    def severity(self, value: str) -> str:
        return self(f"severity.{value.lower()}")
