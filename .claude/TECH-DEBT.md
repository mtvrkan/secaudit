# Tech debt ledger

One row per flag. Never a duplicate (same file + same flag = leave the existing row). Delete a
row when the condition is genuinely gone, not when it becomes inconvenient.

| Date | Location | Flag | Noticed while |
|---|---|---|---|
| 2026-08-18 | kit/secaudit_core/langs.py:is_vendored_asset | FWD: an unminified third-party library whose banner is prose rather than a pragma is still read as application source. The fifth signal added on 2026-08-18 — a UMD/AMD wrapper, or an `@license`/`@preserve` pragma — catches `lodash.js` and the bundles that declare themselves, and it changed nothing on the 62-repository corpus, so it is an unmeasured improvement rather than a measured one. `static/js/foundation/foundation.js` opens with a plain `/*` block saying "Free to use under the MIT license" and is still missed. The obvious widening — a leading comment containing a licence word — is what stops this being closed: a per-file corporate licence header has exactly that shape, and dropping application source is the worse of the two errors. Any wider version needs the accounting the last one had (143 false positives removed for one true positive) | closing the four other rows of this ledger |

<!-- Closed 2026-08-18: two detectors reporting the same line. `Detector.superseded_by` now
     declares that one rule is another's coarse approximation, and `engine._dedupe` drops the
     coarse one where the precise one fired on the same line. It could not key on the CWE — the
     pair carries CWE-798 and CWE-321 on purpose — which is exactly why the schema needed a
     field rather than the dedupe needing a wider group. -->

<!-- Closed 2026-08-18: a POST form inside a multi-line `<!-- … -->` block reported as a live
     hole. `taint.code_view` grew an `html` lexical group (no quote characters — in a document an
     attribute value is content, not a literal), so comments are blanked with a lexer and offsets
     are preserved. The three fixed-width lookbehinds are gone. Cost, stated because the gate
     made it visible: a rule scanned against the view cannot be exported to the Semgrep pack, so
     only `SEC-TPL-FORM-NO-CSRF` moved — the one with 39 measured unmatched findings. The other
     four template rules keep the raw view and their exported rules. -->

<!-- Closed 2026-08-18: thirteen quadratic JS/TS matchers in this engine's own source. All
     thirteen rewritten to be linear, the `REDOS-PY` ceiling of 13 in `test_dogfood.py` deleted
     rather than lowered. Every rewrite was checked match-for-match against 7 MB of real
     JavaScript before it landed and the published figures were re-measured, since the engine
     digest moved either way. The recurring shape was two `\s*` separated by a possibly-empty
     group; folding the trailing repeat inside the optional group keeps the language identical
     and removes the split. -->

<!-- Closed 2026-08-18: the taint tier's superlinear cost. Two per-file caches — the line split
     and `blank_strings` — took `lodash@4.17.21` from 11.6s to 2.3s on the machine that measured
     both (the 44.7s in the original row was a different machine and is not comparable). A scope
     is built once per function per summary round, so a 17k-line file was being split into lines
     5,633 times for 1,483 functions: 5.7 of 12.7 seconds, none of it analysis. Recorded because
     the profiler and the clock disagreed on the second cache — `blank_strings` showed 1.5s of
     profiled time and bought 0.2s of wall clock, the difference being per-call profiler
     overhead on 111,398 calls. -->

<!-- Closed 2026-08-15: `h2.rv` reveal never fired for a heading a fragment link landed on,
     because `clip-path` empties the box IntersectionObserver measures. Fixed by masking instead
     of clipping — a paint operation leaves the geometry alone. Verified on the case that was
     reported (`/tr/#disclosure`) and on a nav click into `/install/#action`. -->

<!-- Closed 2026-08-16: gen_site.py was 3,029 lines with four more pages still to write.
     The three copy dictionaries moved to `scripts/sitecopy/` (one module per page); the
     generator keeps everything that derives — the readers, the renderer, the verifier — and is
     now 1,896 lines. Verified the only way a generator refactor can be: `site/dist` is
     byte-identical across all 13 files, before and after. Named `sitecopy` rather than `site`
     because `site` is a standard-library module and the package shadowed it. -->
