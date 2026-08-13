#!/usr/bin/env python3
"""Run every suite in this directory the way CI runs it, from inside pytest.

The suites are scripts whose verdict is `main()`'s exit code. pytest collects their
`test_*`-named functions, but most of what each suite checks is called only from `main()` —
`test_taint.py` alone reaches sixteen check functions that way. Without this file, `pytest
kit/tests` exercises a fraction of the suite and reports green on the rest.

Named `test_zz_` so it collects last: the per-test attribution from `conftest._fail_watch`
should be what a contributor reads first, and this file's failure — one line per suite — is
the backstop underneath it.

Each module runs in the same interpreter, so `fails` is cleared first. Otherwise a message
already reported (with attribution) by a collected test would be reported again here as an
anonymous duplicate.
"""
from __future__ import annotations

import importlib
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(HERE)
if KIT not in sys.path:
    sys.path.insert(0, KIT)

# Every suite except this one. Derived from the directory, not typed: a new suite is covered
# the moment it is added, which is the only way this file cannot silently fall behind.
SUITES = sorted(
    name[:-3] for name in os.listdir(HERE)
    if name.startswith("test_") and name.endswith(".py") and name != os.path.basename(__file__)
)


def test_every_suite_is_listed():
    """The list above is derived, so this asserts the directory itself is not empty-ish.

    A glob that matches nothing yields an empty parametrization, and an empty parametrization
    is a file full of tests that pass by not existing."""
    assert len(SUITES) >= 15, f"expected the full suite set, found {SUITES}"


@pytest.mark.parametrize("suite", SUITES)
def test_suite_main(suite):
    module = importlib.import_module(suite)
    fails = getattr(module, "fails", None)
    if isinstance(fails, list):
        fails.clear()
    code = module.main()
    assert code == 0, f"{suite}.main() exited {code} — run `python3 kit/tests/{suite}.py`"
