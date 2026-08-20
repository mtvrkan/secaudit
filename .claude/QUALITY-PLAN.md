# Quality plan — detection 74 → 90, technical debt 70 → 90

Two of the five scores in the 2026-08-18 assessment were low for different reasons, and only one
of them is about missing work. **Technical debt is a list**: five rows in `.claude/TECH-DEBT.md`,
each already diagnosed, each deferred on purpose. **Detection quality is a distribution**: 1,058
of 1,762 RealVuln labels are still missed, and half of them sit in classes where nothing fires.

This page states what "90" has to mean as a number before any of it is built, because a score a
person assigns can be argued into existence and a measured one cannot.

## Exit criteria — the plan is done when these are true, not when the rounds are finished

**Detection quality → 90**

| Metric | Now | Target | Where it is read from |
|---|---|---|---|
| RealVuln F3 (recall ×9) | 41.6 | **≥ 55** | `eval/realvuln/result.json`, benchmark's own scorer |
| RealVuln recall | 0.400 | **≥ 0.55** | same |
| RealVuln precision | 0.672 | **≥ 0.65** (hold) | same |
| SecBench.js recall | 0.541 | **≥ 0.62** | `eval/secbenchjs/result.json` |
| Sealed slice recall | reported | **reported separately, never merged into the headline** | `eval/heldout.json`, check 41 |
| Noise floor / 1k lines | 0.27 | **≤ 0.40** | `eval/noisefloor/result.json` |

Precision is a *hold*, not a target, and it is the honest constraint on this whole plan: recall
bought by widening a rule until it matches everything is not detection, and F3 rewards it anyway
because it weights recall nine to one. Every round below reports both.

**Technical debt → 90**

| Item | Now | Target |
|---|---|---|
| Open rows in `.claude/TECH-DEBT.md` | 5 | **≤ 1** |
| Own-engine quadratic ReDoS matchers (`test_dogfood.py` cap) | 13 | **0** |
| Taint tier on a 17k-line file (`lodash.js`) | 44.7 s | **< 5 s** |
| Cross-detector duplicate findings | unmodelled | **suppressed, with a schema field that says so** |
| Gates | 44 green | **44+ green, engine digest re-stamped, every published figure re-measured** |

## The rule that governs every round

**An engine change moves `engine_digest`, and check 32 then fails the build until every published
figure has been re-measured.** That is not an obstacle to work around; it is why the numbers in
this repository are worth anything. So the measurement loop comes back *first*, and no round is
called finished on an argument about what a change should do.

Corpus-informed selection is disclosed, not hidden: reading RealVuln's false negatives to decide
what to build is what rounds three onward did, and `measurement_is_no_longer_blind` in
`result.json` already says so. The SecBench.js sealed slice (125 packages, check 41) is the only
blind instrument left and stays sealed.

## Rounds

**R0 — restore the measurement loop.** Clone the benchmark, clone the 62 reachable repositories,
re-run the current engine and reproduce 704 / 344 / 1058 exactly. If the baseline does not
reproduce digit for digit, nothing after this point can be attributed to a change.

**R1 — the authorization classes.** `broken_access_control` 1/76 and `missing_auth` 4/74: 145
labels, and a structural analysis that is supposed to reach them and does not. Read every miss
and ask the R-round question — *does a rule exist at all for this shape* — before touching a
threshold.

**R2 — `other`, 541 misses.** Half of everything still missed. It is a grab-bag by construction,
so the work is to cluster it by CWE and file type and find the classes with no detector at all,
which is the shape that produced the two largest gains this project has had.

**R3 — `sensitive_data_exposure` 103 and `security_misconfiguration` 66.** Config and hygiene
classes where detectors exist for some frameworks and languages and not others.

**R4 — the classes where a rule exists and still misses.** `xss` 48, `sql_injection` 35, `ssrf`
21, `path_traversal` 17. Check the *source* list and the *file type* first, per the two levers
that worked before.

**R5 — the debt list, five rows.** Taint perf, the 13 quadratic matchers, cross-detector
suppression, HTML comment handling, the vendored-asset filter.

**R6 — re-measure, re-stamp, rewrite.** All three corpora, engine digest, README figures, the
launch drafts that nothing gates, and `docs/what-we-miss.md`, which has to keep saying what is
still missed.


---

## Outcome, 2026-08-18 — measured, not claimed

**Detection quality.** Every target met, and precision rose rather than being spent.

| Metric | Before | Target | After |
|---|---|---|---|
| RealVuln F3 | 41.6 | ≥ 55 | **59.5** |
| RealVuln recall | 0.400 | ≥ 0.55 | **0.587** |
| RealVuln precision | 0.672 | hold ≥ 0.65 | **0.675** |
| Noise floor / 1k lines | 0.27 | ≤ 0.40 | **0.31** |
| SecBench.js recall | 0.541 | ≥ 0.62 | **0.524 — not met, and the corpus moved** |
| Sealed slice | reported | reported separately | **0.5785 sealed vs 0.5088 unsealed** |

**The SecBench.js target was missed and the reason is not the engine.** Nineteen more packages
have been removed from npm since the previous run: 575 of 600 fetched against 594, and a label in
a package that cannot be fetched counts as a miss. The comparable figure — misses caused by *no
rule fired at the sink* — went **217 → 213** on the smaller corpus. This round's work was Python
rules on a Python corpus, so a JavaScript recall gain was never the plan; what mattered here was
that the thirteen ReDoS rewrites, which touch the JavaScript front ends, did not cost anything.
They did not.

The one number nobody planned and everybody should read: **the sealed held-out slice scores
higher than the rest** (0.5785 against 0.5088). It is not a blind figure — those packages were
present for both corpus-informed rounds, sealing only stops *future* tuning — but it is the
closest thing to evidence that these rules generalise rather than fit.

**Technical debt.** Four of five rows closed, the fifth narrowed and left open on purpose.

| Item | Before | Target | After |
|---|---|---|---|
| Open rows in `.claude/TECH-DEBT.md` | 5 | ≤ 1 | **1** |
| Own-engine quadratic ReDoS matchers | 13 | 0 | **0** |
| Taint tier on `lodash.js` | 11.6 s | < 5 s | **2.3 s** |
| Cross-detector duplicates | unmodelled | suppressed with a schema field | **`Detector.superseded_by`** |
| Gates | 44 green | 44 green, digest re-stamped | **44 green, all three corpora re-measured** |

## What was tried and rejected, so it is not tried again

* **Widening `AUTHZ-PY-IDOR` to accept a principal without separate authorization evidence.**
  7 → 10 labels for 19 → 29 findings: +3 true positives, +7 false ones. Reverted.
  `broken_access_control` (1 of 76) and `missing_auth` (4 of 74) are still the largest pool of
  misses and still need the business-logic pass, exactly as `docs/what-we-miss.md` has said since
  the class was first measured.
* **Reporting CSV injection per export function rather than per file.** +4 true positives for
  +44 false ones, F3 identical to three decimal places, precision 0.669 → 0.644. One finding per
  file is also the better report: the fix is one shared helper.
* **A column clause for cleartext storage over the full sensitive vocabulary.** 130 findings for
  20 labels, with `password` alone accounting for 18 and none of them labelled — a `password`
  column is hashed by the framework that owns it and the name cannot tell you otherwise.
  Narrowed to the vocabulary where the name IS the value: 60 findings for 19 labels.
* **Moving all five template rules to the blanked HTML view.** It would have withheld four more
  rules from the exported Semgrep pack to fix something measured on exactly one of them.

## The method, in one paragraph

Every gain this round came from the same question, and it is not "why does this rule miss": it is
**"is there a rule at all for this shape"**. Answering it needs the misses grouped by CWE and by
file type rather than read one at a time — 961 of 1,058 missed labels turned out to have no
finding anywhere near them, and half of those sat in classes the pack had never modelled. The
three fixes to *existing* rules came from the same discipline applied one level down: a rule that
knows `verify=False` and none of the standard library's three other spellings, a rule that reads
a framework's own request object as a schema, a dotted-name walker that gives up at a call in the
middle of a receiver chain. None of those is a threshold to tune. Each is a question nobody had
asked of code that already worked.
