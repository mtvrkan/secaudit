#!/usr/bin/env python3
"""Make `pytest kit/tests` mean what CI means.

Every suite in this directory is a **script**: assertions are recorded by appending to a
module-level `fails` list (or one local to `main()`), and the verdict is `main()`'s exit code.
CI runs each file that way — `python3 kit/tests/test_taint.py` — so the gates are real.

`pytest` was not. It collects the `test_*`-named functions, but those functions do not raise:
they append to `fails` and return, and a returned list is not a verdict pytest can read. The
whole suite therefore reported green with the flagship SQL-injection sink deleted from the
engine — verified by deliberately breaking it. A green run that cannot go red is worse than no
run, because someone trusts it.

Two mechanisms, deliberately both:

* `_fail_watch` — a per-test autouse fixture that fails a test when it grew its module's
  `fails`. This is the one that gives **attribution**: the failure lands on the test that
  caused it, with the message that test wrote. It reports as a teardown ERROR rather than a
  FAILED, because that is where a fixture can observe the list — red either way, and the
  message is the suite's own.
* `test_suite_main` in `test_zz_suite_mains.py` — runs each module's `main()` and asserts it
  exits 0. This is the one that gives **coverage**: most of what these suites check is called
  only from `main()` and was never collected by pytest at all.

Neither replaces the other, and neither replaces CI running the scripts directly.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _fail_watch(request):
    """Fail the test that appended to its module's `fails` list.

    Snapshot-and-compare rather than "is `fails` empty at the end": the list is module-level
    and accumulates across tests, so an emptiness check would blame every test after the first
    failure. Comparing lengths attributes each message to the test that produced it.
    """
    fails = getattr(request.module, "fails", None)
    if not isinstance(fails, list):
        yield
        return
    before = len(fails)
    yield
    new = fails[before:]
    if new:
        pytest.fail("\n".join(f"  - {message}" for message in new), pytrace=False)
