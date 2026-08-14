# Changelog

All notable changes to SecAudit are documented here. This project follows
[Semantic Versioning](https://semver.org) and [Keep a Changelog](https://keepachangelog.com).

## [Unreleased]

### Added
- **Continuous mode — `--watch`, the EU CRA's 24-hour clock in practice.** A scan answers what is
  wrong with the code now; it cannot answer the question the regulation attaches a deadline to,
  because that question is about the world: *a dependency you already ship became actively
  exploited overnight and nothing in your repository changed.* `--watch` records the advisories a
  scan found with the reachability verdict the VEX pass gave each, then re-asks CISA KEV and FIRST
  EPSS about exactly those CVE ids and reports the transitions.
  Four rules bound it and one of them is the point: **a feed that could not be reached is never
  "no change."** When neither feed answers, no comparison is produced, the stored state is left
  untouched so the next good run still compares against real data, and the exit code is non-zero —
  a quiet night and a failed check must not be tellable apart by exit code alone. Status is a
  high-water mark (a feed that stops listing a CVE has not un-exploited it), reachability ranks
  rather than filters, and the comparison is pure so the alerting logic is tested offline against
  constructed catalogs. All four refusals proven by mutation.
  [`docs/continuous-mode.md`](docs/continuous-mode.md). [2026-08-14]
- **PCI DSS 4.0.1 mapping — four requirements, and a refusal list with reasons.** Findings now
  carry `pci_dss_requirement`, and `--format cra` gains a `pci_dss` block. Only requirements whose
  text was read and cross-checked appear: 6.2.4 (which enumerates its own attack classes, so a CWE
  mapping onto it is a reading rather than an invention), 6.3.1, 6.3.2 and 8.6.2.
  **What it refuses to say is the load-bearing half.** Every CWE the engine emits either maps or
  sits in `PCI_NOT_ASSERTABLE` with the reason, gated by check 24. Almost all refusals reduce to
  two facts no source scan establishes: whether the data is account data, and whether the
  component is in the cardholder data environment. Requirements 3.x, 4.x and 9.x are therefore
  absent entirely. **SOC 2 and ISO 27001 stay unmapped** — their control texts are behind
  copyright and paywalls, so a mapping could only name numbers nobody can check. PCI is mapped and
  they are not for exactly one reason: PCI SSC publishes its standard for free.
  [`docs/compliance.md`](docs/compliance.md). [2026-08-14]
- **SBOM and build-provenance attestation on every release.** `release.yml` emits CycloneDX and
  SPDX SBOMs generated *by the tool being released*, then attests the wheel and sdist with SLSA
  build provenance and an SBOM attestation — verifiable with `gh attestation verify`, no key of
  ours involved. Signing happens in its own job so the build never holds a token that can vouch
  for its own output; an attestation binds to the artefact digest, so signing a downloaded copy
  signs the same bytes. Both action SHAs resolved through the GitHub API, and zizmor 1.26.1 is
  clean on the result. [`docs/supply-chain.md`](docs/supply-chain.md). [2026-08-14]
- **Browser-driven live checks (P10).** The phase that a `curl`-shaped methodology structurally
  cannot run: DOM XSS by reading sources and sinks in the bundle, `postMessage` handlers with no
  origin check, auth-flow walking (session fixation, cookie flags as the browser received them,
  logout invalidation, reset-token handling), post-login surface discovery, and the two-role
  replay that decides broken access control by measurement. **The browser comes from the harness,
  not from this kit** — `secaudit_core` keeps its zero runtime dependencies, and shipping a
  browser engine to get DOM coverage would trade the package's best property for one phase. The
  reference states the rule that phase needs most: a browser pointed at the target is executing
  the target's code, so it never reuses the operator's profile, never navigates off-scope, and
  never triggers a dialog — which is also why the confirmation canary is a DOM write and not
  `alert(1)`. [2026-08-14]
- **Two standalone skills** — `exploitation-watch` and `compliance-pack`. Both answer questions
  the audit skill does not: one is about time, the other turns findings that already exist into
  documents someone else reads. Neither competes with `security-audit` for routing, which is why
  these two and not a fifteen-way split of the methodology (see *Changed*). [2026-08-14]

### Fixed
- **Code-scanning alerts were re-created on every unrelated edit.** The SARIF
  `partialFingerprints` value was `detector:file:line`, so any insertion earlier in a file changed
  the fingerprint of every alert below it — GitHub closed those alerts and opened new ones, taking
  the dismissal, the assignee and the review comments with them. That is the exact failure the
  field exists to prevent. Fingerprints are now content-derived and stable under line shifts, with
  an occurrence ordinal so two identical findings in one file stay distinct: content alone
  collided on **3 of 100** findings on this repository's own source, and a collision means GitHub
  merges two alerts into one and the second disappears. Both properties are tested, and both
  tests were proven by mutation — the uniqueness half was silently vacuous until the fixture
  gained a genuinely duplicated line. [2026-08-14]
- **A scan hung outright on any repository that vendors a JavaScript bundle.** The structural
  analyses follow evidence into module-local helpers to avoid reporting an app that factored its
  auth gate out properly, and all five traversals carried the visited set *down each branch*
  rather than across the traversal. That enumerates every distinct path through the call graph
  instead of visiting each helper once — exponential, not linear, and it was reached by ordinary
  code: on `materialize.js` the analysis finished the first 6,750 lines in 0.12s and had not
  finished the first 7,000 ten minutes later. A full 62-repository benchmark run went from
  stalling on the seventh repository to **1.4 minutes**. Reachability cannot change on a second
  arrival at the same helper, so the answers are identical — verified by diffing findings across
  all 376 JavaScript and TypeScript files in the external corpus (368 comparable, **0
  differing**; the 8 that were not comparable are the bundles the old form never finishes).
  [2026-08-14]
- **The JavaScript missing-authentication rule reported browsers.** `_MOUNT` looks for a
  receiver, an HTTP verb and a string-literal path, and a front end's HTTP client is written
  exactly that way — `await api.post('/tickets', body)` is indistinguishable by shape from
  `app.post('/tickets', handler)`. Every hit landed in a React `frontend/src/` tree, reporting
  the *caller* of an endpoint for not authenticating it: **147 false positives, 0 true
  positives** on RealVuln. Narrowed by the distinction that is actually about the bug — a route
  registration discards the call's value, a client call uses it (awaits, returns, assigns,
  collects, or chains it). Deliberately not a list of client library names, which one rename
  would silence. **147 of 147 removed; precision 0.4711 → 0.5419, F3 31.2 → 31.5.** [2026-08-14]
- **`structural/authz.py` emitted a `source` the dedup ranking had never heard of.** Its two
  findings said `source="authz"` while every other structural analysis says `"structural"`, and
  `_dedupe` scores an unknown source 0 — below `builtin` — so the two analyses that exist to
  report broken access control and missing authentication were the only ones a plain regex match
  could evict at the same file, line and CWE. No gate could see it: the fixtures produce no authz
  finding through the engine, and `test_authz.py` calls `analyze_file` directly, so dedup never
  ran on one. Measured on RealVuln before keeping it: no figure moves. [2026-08-14]
- The launch checklist quoted **F3 26.0**, two rounds stale, while every gate was green — check 27
  anchored the README, the roadmap and the benchmark page, and not that page. [2026-08-14]

### Added
- **Check 32 — the published benchmark figures now have to name the engine that produced them.**
  Check 27 compares the prose to `result.json`; nothing compared `result.json` to the code, and
  that gap shipped (see the correction below). `result.json` now carries an `engine_digest` over
  every `secaudit_core` module that can change what the measured run emits, with the exclusions
  each carrying their reason and a second failure for any new module classified as neither. It
  cannot re-run a 62-repository benchmark in CI and does not try to; it makes staleness loud.
  Proven by mutation in three directions: a rule change, a detector change, and an unclassified
  new module. [2026-08-14]
- **Check 31 — a finding source that `engine._SOURCE_RANK` does not rank now fails the build**,
  because `_dedupe` reads it with `.get(source, 0)` and an unranked source loses every collision
  in silence rather than erroring. [2026-08-14]

### Changed
- **Two more dead tests, and the gate that finds them.** Check 33 requires every `test_*` function
  to be reachable from its suite's `main()` or to contain an `assert`, because these suites are
  scripts whose verdict is an exit code and their `check()` helpers append to a list rather than
  raising. It was written after a new `test_pci_mapping` was added and not wired into `main()`:
  the suite printed PASSED and every assertion in it — including the ones about what the tool must
  refuse to tell an auditor — had never executed. Turning the gate on found two more, in
  `test_semgrep_pack.py` and `test_taint.py`: pytest bridges that called the underlying check but
  did not assert, so pytest collected them, reported them green, and could not go red whatever
  they found. Both now assert. [2026-08-14]
- **Check 06 covers every skill, not the one it was written for.** Sibling skills would otherwise
  have shipped ungated — the same shape as a reference nothing routes to: present, plausible and
  never reached. It also now requires `name:` and `description:` on each, since a skill without
  them is never routed to at all. [2026-08-14]
- ⛔ **G9's fifteen-way skill split was deliberately not done**, and this is a decision rather
  than an omission. Its stated justification is a competitor's skill *count*; that is a discovery
  hypothesis nobody here has measured, and this repository does not ship unmeasured claims. It
  also carries a concrete regression: fifteen narrowly-described skills compete with the
  orchestrator for routing, and a model picking `web-tests` instead of running P1→P10 would
  silently narrow an audit — a security tool reporting a clean surface it never looked at, which
  is the failure mode named on nearly every page here. What shipped instead is the part whose
  value is not in dispute: two skills for jobs the audit methodology does not contain. [2026-08-14]
- **The symbol-level reachability roadmap item was wrong and is corrected rather than deleted.**
  It said "neither npm audit nor OSV publishes the affected symbol in a machine-usable form." OSV
  does, for Go; RustSec does too. What is true is narrower and decides the item: **npm and PyPI —
  the two ecosystems this scan indexes — have no such field**, so there is nothing to match a call
  against. Deriving symbols from each advisory's fix commit was considered and rejected: a fix
  commit also touches tests, docs and refactors, so picking the vulnerable function out of the
  diff is a guess, and a guess that downgrades an advisory to `not_affected` is the most dangerous
  output the VEX pass can produce. The real prerequisite is indexing Go, which is now the item to
  schedule. [2026-08-14]
- `result.json` records a `reverified` note: the benchmark was re-cloned from scratch on
  2026-08-14, all 62 repositories re-scanned and re-scored, and the ground-truth digest and every
  published figure reproduced exactly. [2026-08-14]

### Added
- **The business-logic pass — the gap the roadmap has called #1 since it was written.** Four
  classes no pattern can decide are now asked of a model over a deterministic extract rather than
  over the repository: missing ownership (CWE-639), missing authorization (CWE-862), workflow
  skips (CWE-841) and trusted client values (CWE-602). `structural/handlermap.py` extracts what
  each mounted handler knows about its caller, which identifiers the request chose, which state
  fields it writes and whether it checked the state it came from, and which money-shaped values
  it took from the body; the model adjudicates that shortlist instead of hunting. The map emits
  no finding and is not in `_RULES`, so **Tier 0 is byte-identical and the published RealVuln
  figure is untouched** — deliberately, because a number that moved would need a re-measurement
  this change is not entitled to.
  Four refusals defend it and each one is counted in the report rather than dropped: a class
  outside the table (no fallback CWE), a file the model was not shown, a line outside every
  handler span, and a weakness Tier 0 already reported in that handler. The reserved model call
  comes out of the existing four-call ceiling, not on top of it, and the breadth that costs on a
  large repository is stated in the scan's own coverage note.
  **The tier remains unmeasured**, and `docs/what-we-miss.md` still lists these classes as gaps
  for exactly that reason. [2026-08-13]
- `--backend replay` is now a CLI choice, which is how the Tier-1 path can be exercised
  end-to-end with no API key. [2026-08-13]

### Fixed
- **A discovered flaw was counted once per model call.** Nothing deduplicated the `extra`
  channel, so a repository-wide logic bug visible from more than one context chunk was merged up
  to four times and inflated the report's own finding count. [2026-08-13]
- **Every model-reported flaw was filed as CWE-284**, whatever it actually described — a
  compliance section naming a weakness nobody found is worse than one that omits it. The logic
  channel maps each class to its own weakness and drops anything outside the table. [2026-08-13]
- Consistency check 24 could not see the business-logic weaknesses at all: it keys on what the
  engine emits, and its notion of "emits" was the detector pack plus the taint sinks. A class
  added without an ASVS chapter now fails the build, which is what the check exists to do.
  [2026-08-13]
- `kit/README.md` advertised a default model two versions stale (`claude-opus-4-8` against the
  engine's `claude-opus-5`). Nothing gated it. [2026-08-13]

### Added
- **The four structural analyses now answer for JavaScript and TypeScript too.** Missing
  authentication, IDOR, unbounded credential testing, unrestricted upload and mass assignment
  were Python-only, which meant the project's single largest detection gain — the rate-limit rule
  at 85 true positives — did nothing on any Node, Express, NestJS or Next.js codebase, where most
  of the target audience is. `secaudit_core/structural/js.py` recognises a route by a mount
  carrying a **string literal path** (`app.post('/x', …)`), a NestJS method decorator, or a
  Next.js App Router / Pages API export, and reads the whole mount call as the handler — because
  middleware is exactly where this ecosystem puts its auth and its limiters.
  **It does not share a call path with the Python rules.** Those produce the published RealVuln
  figure, and threading a second, parserless front end through them would put every JavaScript
  mistake inside the measured path.
  **Correction, 2026-08-14 — this entry claimed "the benchmark was re-run afterwards and returned
  530 TP / 448 FP / 1232 FN, F3 31.5, identical to the committed result." That is not what the
  engine did.** `eval/realvuln/result.json` was last written by `8fc17e1`, one commit *before*
  this change, and was never rewritten; re-measured on 2026-08-14 this analysis returns **595**
  false positives, precision 0.4711 and F3 31.2. The claim is corrected here rather than edited
  away, because the sentence is the interesting part: nothing in the repository had to change for
  a published number to stop being true, and no gate was looking. That is what check 32 is for.
  The rule has since been narrowed and the figures are honest again — see [Unreleased].
  The JavaScript side has
  no external number and says so in its own `limitations()`: RealVuln v1 is Python-only, so what
  is asserted is a regression floor — the shapes in `kit/tests/test_structural_js.py` are found,
  and the shipped secure fixture stays silent. [2026-08-13]
- The language-coverage matrix now reads which analyses a language actually gets out of the
  engine instead of a sentence written into the generator. That sentence was correct only while
  exactly one language had structural analysis, and it is the same shape of bug as the matrix
  claiming "single file" for months after the taint engine went cross-module. [2026-08-13]

### Fixed
- **A mass-assignment exemption that was both dead and wrong.** The JavaScript rule excused any
  handler containing `const { … } = req.body`, on the reasoning that destructuring to named
  fields is the idiomatic allowlist. It decided nothing in the case it was written for — a
  handler that destructures and then writes the named fields never matches the wholesale-write
  pattern at all — and in the one case it did decide, it silenced a real finding: pulling two
  fields out and then passing the whole body to `create()` is mass assignment, not a fix. Same
  shape as a limiter anywhere in a file counting as protection everywhere in it. Found by
  mutation: removing the exemption changed no test, which is what a branch that decides nothing
  looks like. [2026-08-13]
- **String literals were being read out of the blanked view, twice.** Routes are found on
  `code_view`, where string contents are blanked so a mount written inside a comment or a
  template literal is not a mount — but the route path and the Next.js `req.method === 'DELETE'`
  branch both live *inside* literals, so both arrived empty. Every path-dependent rule silently
  switched off: login stopped looking public, auth endpoints stopped naming an auth action, and
  every Pages API handler read as a GET. The view decides whether a construct is code; anything
  read out of a literal now comes from the source. [2026-08-13]
- **Three flags were accepted and then ignored.** All three failed the same way — no output, no
  message, exit 0 — which is the one failure mode this tool refuses everywhere else (it is why a
  URL target is turned away instead of scanned as a path, and why an unknown `--only` group is an
  error instead of an empty scan). `--summary PATH` was skipped for *every* `--format md` run, on
  the reasoning that markdown had already produced the file; without `-o` the report goes to
  stdout, so `--format md --summary r.md` wrote nothing at all, and a CI job publishing `r.md`
  afterwards published an earlier run's file or none. It is now skipped only when `-o` has
  already written that exact path, which is all the original guard was reaching for.
  `--suggest-patches` was unreachable under `--since`, because `main` returned into diff mode
  before the patch step — so the combination that most obviously belongs together (gate a pull
  request on what it introduced, then offer a fix for it) did nothing; it now patches the
  **introduced** findings, the same set the exit code is derived from. And `--lang` never reached
  the HTML renderer, which took no locale argument at all, so `--lang tr --format html` produced
  an English document; `to_html` is now localized against the same bundle `to_markdown` uses,
  including the `<html lang>` attribute. Where a bound genuinely exists rather than a bug —
  the diff report's vocabulary is not in the locale bundles — `--lang` now says so instead of
  quietly rendering English. Each fix is proven by reverting it and watching its test fail.
  [2026-08-13]
- **The HTML report's disclaimer was asserted as an English sentence.** The test pinned the
  literal string "not a statement that the code is safe", so it would have passed a Turkish
  report that carried no disclaimer at all — the assertion was about wording, not about the
  guarantee. It now checks, for every shipped locale, that the bundle's own `clean.meaning`
  reaches the rendered page and that `<html lang>` matches. [2026-08-13]

### Changed
- **The RealVuln page now states the stricter reading of its own run.** The benchmark's scorer
  emits two aggregates and `result.json` has carried both since the first round: the `micro` one
  the published 31.5 comes from, and a `strict_micro` one counting 141 more labels as missed —
  F3 **29.3**, recall 0.2785, on the identical 530 true positives and 448 false ones. `micro`
  remains the quoted figure because it is the aggregate RealVuln's own baselines are quoted in,
  but a stricter number sitting in the committed raw output and named nowhere in the prose is the
  omission that page exists to prevent. The honest range is now published as 29.3 – 31.5.
  [2026-08-13]
- **The LLM tier never saw the code it was asked to audit.** The enrichment prompt carried only
  Tier-0's own output — detector id, file, line, severity and a single line of `evidence` — and no
  source. Two claims rested on that payload and neither could hold: triage ("decide if this is
  real and reachable in THIS code") was judging a citation rather than the code, and **logic-bug
  discovery was structurally impossible** — the `extra` channel asks for the flaws the pattern
  scan missed, which live in handlers Tier 0 never flagged and were therefore never in the
  payload. `secaudit_core/llmcontext.py` now builds a real source context: merged excerpts around
  every finding first, then whole unflagged files ranked toward request handlers, so a truncated
  context loses discovery breadth and never loses the code behind a finding. Bounded at
  240k characters per call and **four calls per scan**, and what was not sent is reported —
  a triage over a partial view is not printed as a clean bill. A model-reported finding citing a
  file outside the context is refused and counted rather than merged. Every assertion is on the
  payload that reaches the transport, not on the builder's return value; proven by five
  mutations, two of which initially survived. [2026-08-13]
- **This file claimed a release that never happened.** `## [1.0.0] — 2026-07-11 · Initial public
  release` sat at the bottom of the changelog while no `v1.0.0` tag existed, nothing had been
  uploaded to PyPI and the repository was private — so a reader would have concluded the project
  had shipped and that everything above that heading was a later increment. It was the last claim
  in the repo still typed by hand rather than derived from the thing it describes, and it was
  wrong in the flattering direction. The section is now dated prose inside `[Unreleased]`, where
  all of it belongs until a tag exists. **Check 30** refuses any `## [x.y.z]` heading with no
  matching `vx.y.z` tag, proven by re-introducing the heading and watching the build fail.
  `validate.yml` gained `fetch-depth: 0` for the same reason: the default shallow checkout fetches
  no tags, so the gate would have answered "no tags exist" for a repository that has them and
  failed the first correct release. [2026-08-13]
- **Three rows of the gap analysis pointed at a phase the roadmap did not contain.** G7, G11 and
  G12 are routed to P4; the document went P3 → P5, with P4's items (MCP server, PyPI packaging,
  Action, Docker, live-target depth, continuous mode) absorbed under P3's heading along with its
  exit criteria. P4 — Distribution now exists where its content already was. [2026-08-13]
- **The rate-limit rule was silent on the code it exists to report, in three ways.** A limiter
  mentioned anywhere in a file silenced every route in it, so one `@limiter.limit` on `/login`
  protected an unlimited `/admin-login` beside it; `attempt` was a limiter marker on its own, so
  a handler recording a failed password read as protected — writing the break-in down is what an
  unprotected endpoint does instead of bounding it; and an unrelated route logging the word was
  enough to switch the file off. Module-level now means module-level, and an attempt count is
  evidence of a limit only where something is compared against it. **F3 30.9 → 31.5 on RealVuln,
  +10 true positives for +6 false positives, precision 0.5405 → 0.5419.** Found by asking why the
  rule's suppression branches had no test coverage, not by reading a label. [2026-08-13]
- **KEV/EPSS feeds could crash a scan instead of degrading it.** The handler caught `OSError`,
  and `http.client`'s exceptions are not `OSError`s — `IncompleteRead` from a connection dropped
  mid-body escaped, which is the most likely real failure of a multi-megabyte feed. That broke
  the module's own rule that an unreachable feed is a stated unknown. Every transport failure now
  lands as an error string. Found by covering the network seam with a stubbed transport.
  [2026-08-13]

### Changed
- **Tier 1 now sends your source code, and the docs say so before you run it.** This is a real
  change in what leaves the machine: previously a remote backend saw findings metadata, now it
  sees source. `--backend ollama` (local, nothing leaves the host) is therefore a different
  decision rather than a cheaper one, and the README and FAQ answer the question per run mode
  instead of only for the Claude Code plugin. Files matching credential patterns (`.env*`,
  `*.pem`, `*.key`, `*.p12`, `id_rsa`, `secrets/`, `*.tfstate`, …) are withheld from **every**
  backend including the local one, and the count of withheld files is reported. [2026-08-13]
- **Check 27 now gates the prose, the run-history table, the per-family recall table and the
  per-repository leaderboard**, not just headings and headline rows. Four sentences kept the
  previous round's F3 through a green build, the per-family table read `other 219 / 831` after
  the scorer said 229, and the leaderboard was two rounds stale — every one of them invisible
  because nothing tied it to `result.json`. All 12 new sub-checks were proven non-vacuous by
  mutation. [2026-08-13]
- The EPSS privacy claim — "nothing about the scanned project leaves the machine" — is asserted
  against the requests actually made rather than by searching `fetch_epss` for a substring. The
  old check passed on any refactor that kept the words and dropped the behaviour. [2026-08-13]

### Added
- Tests for `to_semgrep_json`, the renderer RealVuln's scorer reads and the only one with no
  test: a silent change there moves the published F3 and looks like a detection regression.
  [2026-08-13]
- **F3 30.9 on RealVuln**, up from 26.0, with **precision rising alongside recall for the third
  consecutive round** (0.511 → 0.540; recall 0.246 → 0.295). Five runs now share one clone:
  12.5 → 13.3 → 24.6 → 26.0 → 30.9. [2026-08-13]
- **Missing rate limiting on credential-testing endpoints — 0 → 85 true positives at 0.842
  precision**, the largest single-rule gain in the project. 99 labels named a missing rate limit
  and the engine found none, because "endpoint without a limiter" describes almost every
  endpoint. The labels are narrower: an endpoint that *tests a credential* accepts unlimited
  attempts (CWE-307). The rule fires only where the route names an authentication action and the
  handler reaches a credential check, and it looks for a limiter in decorators, dependencies,
  module-local helpers and anything registered on the app — a limiter installed as middleware
  protects handlers that never mention it. [2026-08-13]
- **Unrestricted file upload (CWE-434) — 0 → 8 at 0.800 precision.** An upload is read, a write
  happens, and no check stands between them. [2026-08-13]
- **Mass assignment (CWE-915) — 0 → 1.** Effectively unmoved, and published as such: the corpus's
  labels mostly pass the body through a helper *named* like a validator that does not restrict
  fields, and this rule judges whether an allowlist is present, never whether it is adequate.
  [2026-08-13]
- `secaudit_core/structural/` — the four handler-level analyses now share one model of what a
  route is. `_route_of` decides which frameworks are recognised at all, and four private copies
  would have given four answers to "is this a route" inside one report. [2026-08-13]

### Changed
- **The structural analyses are scoped to production sources.** Every rule in the package
  describes something a *deployed handler* fails to do, so test modules, fixtures, migrations and
  scripts are out of scope by construction. The detector pack still scans them — a committed
  secret in a test is a real secret. [2026-08-13]
- `docs/what-we-miss.md` now covers brute force, unrestricted upload and mass assignment, and its
  generator refuses to write the page if any rule's probe stops producing its CWE — a silent drop
  would move a class back to "no deterministic coverage" on a page that looked freshly generated.
  [2026-08-13]

### Fixed
- **Extension *extraction* is no longer read as extension *validation*.** Counting `splitext` as
  a check silenced the one handler that splits the extension off precisely so it can keep it on
  the file it writes. [2026-08-13]
- **An upload attribute now counts only on a value reached from the request.** Matching
  `.filename` anywhere reported a password-list generator and a test module as vulnerable
  handlers; anchoring it removed twelve of fourteen false positives and gained a true one.
  [2026-08-13]
- `secaudit_core.structural` was added to `[tool.setuptools] packages` — the packaging gate
  caught it, which is the second time that gate has stopped a subpackage from being absent from
  the wheel while every source-checkout test passed. [2026-08-13]

### Added
- **F3 26.0 on RealVuln, and the first two structural analyses.** Precision rose with recall
  again (0.504 → 0.511, recall 0.233 → 0.246), the second round running — the signal that these
  are rules rather than curve-fitting. Four runs now share one clone: 12.5 → 13.3 → 24.6 → 26.0,
  with the previous engine re-scored on this checkout first and reproducing 24.6 / 0.5037 /
  0.2327 digit for digit, and the ground-truth digest recomputed and unmoved. [2026-08-13]
- **ReDoS analysis (`secaudit_core/redos.py`) — `denial_of_service` 0 → 16 of 44**, from 17 true
  positives and **zero** false ones. Catastrophic backtracking is decided from the regex's parse
  tree (star height above one; repeated groups with overlapping alternatives). The limitations
  page had filed this class as out of reach; it was wrong, and now says what is actually
  missing. [2026-08-13]
- **Authorization analysis (`secaudit_core/authz.py`) — `missing_auth` 0 → 4 of 74,
  `broken_access_control` 0 → 1 of 76.** Off zero, and close to all that can be said for the
  IDOR half; the honest accounting of what each version cost is in `eval/realvuln/README.md`.
  The 42 deliberate false-positive traps in the corpus are all cleared, including the FastAPI
  shape where the gate is injected as a parameter default and never called. [2026-08-13]
- **A Tier-1 measurement harness for the external corpus** (`eval/realvuln/run.py --backend`).
  The LLM tier is the kit's headline claim and has no measured number; the harness makes the
  measurement one command, refuses to write under the reproducible `secaudit` slug, and ships
  **unrun** — with the README saying so rather than leaving the gap unnamed. [2026-08-13]
- **Integration-seam coverage** (`kit/tests/test_integration_seams.py`): scanner adapters
  spawned as real subprocesses against fake executables on PATH, and the LLM request shape,
  key refusal and error-containment policies asserted through an injected transport. Coverage
  floor 88% → 89%; `backends.py` 66% → 90%, `scanners.py` 69% → 84%. [2026-08-13]

### Fixed
- **A `.cmd`/`.bat`-shimmed scanner was detected and then unrunnable on Windows.** `shutil.which`
  honours PATHEXT so `_has` reported the tool present, but `CreateProcess` does not apply PATHEXT
  when searching PATH — so semgrep, gitleaks or osv-scanner installed via npm, scoop or pipx was
  silently downgraded to the built-in pack with a note blaming the tool. Found by covering the
  seam rather than by a bug report. [2026-08-13]
- **A stale gate count in `validate.yml`** said 32 where the runner listed 35, and a second in
  `CONTRIBUTING.md` said 15. Check 29 now derives the count and fails the build on any typed one,
  in any workflow or document. [2026-08-13]
- The default Anthropic model is `claude-opus-5`, and `max_tokens` was raised to 16000 because it
  bounds thinking and response text together on a model that thinks by default — 4096 could
  truncate the triage JSON mid-object. [2026-08-13]

### Added
- **F3 24.6 on RealVuln — above rule-based SAST's published 17.7 for the first time, on both
  metrics** (precision 0.504 vs 0.205, recall 0.233 vs 0.175). Three runs on one clone of the
  corpus: 12.5 → 13.3 → 24.6, with the original engine re-run on the same checkout and
  reproducing 12.5 digit for digit, so every delta is the engine.

  **The number is no longer blind, and that is disclosed wherever it appears.** 12.5 and 13.3
  were measured on a corpus this engine had never seen. 24.6 was measured after its 1,543 false
  negatives were grouped by class and the code behind them read. What that showed was not a
  modelling weakness but an inventory gap — a set of rules any SAST ships and this one did not
  have — so nothing added is fitted to a fixture; but the *selection* was corpus-informed, which
  is the same caveat `eval/scorecard.md` has always carried about the fixture set. The honest
  successor is a benchmark this repository has not read.

  What moved: `open_redirect` **0 → 37 of 40** (there was no Python redirect sink at all),
  `other` **35 → 131 of 831** and `sensitive_data_exposure` **0 → 31 of 141** (six configuration
  and crypto-hygiene detectors, plus credentials and raw bodies reaching a logger),
  `security_misconfiguration` **17 → 39 of 108**, `sql_injection` **2 → 11 of 71**. The
  highest-leverage change added no sinks at all: `request.url`, `request.META`, `request.COOKIES`
  and a dozen more were not *sources*, so every sink downstream of them was unreachable however
  well it was modelled. **Precision rose with recall** (0.407 → 0.504), which is the reason to
  read these as rules rather than as curve-fitting.

  What did not move, and will not through more patterns: `broken_access_control` (0/76),
  `missing_auth` (0/74) and `denial_of_service` (0/44) have no local signature.
  `path_traversal` stayed at 3/39 across nine added filesystem sinks over two rounds — the
  prediction that more sinks would help it was made twice and was wrong twice. [2026-08-13]
- **Six configuration and crypto-hygiene detectors**, each with a safe-shape control in the
  suite because a config linter that fires on a correct settings module is one everybody
  switches off on day two: a non-cryptographic PRNG generating tokens (CWE-330, bound to
  security-shaped variable names so `random.choice` picking a colour is untouched), cookies set
  without `HttpOnly`/`Secure` (CWE-1004), CSRF exemptions (CWE-352), `DEBUG` defaulting on when
  the environment variable is unset (CWE-16), `ALLOWED_HOSTS = ['*']` (CWE-16), and a signing
  key whose fallback literal is committed to the source (CWE-321). Plus four taint sinks —
  open redirect, `Template()` SSTI, NoSQL injection through pymongo, and CWE-532 for
  credentials, cookies, headers or raw bodies reaching a logger. The logging rule is narrowed to
  material that must not be persisted: every service logs request data on purpose, and a rule
  that fired on all of it would be muted within a day. 79 → 85 detectors. [2026-08-13]

### Changed
- **`taint.py` is a package.** 2,100 lines in one module was the last standing design flag
  against an otherwise well-gated engine. Split along the seams the file already had as comment
  banners — `model`, `catalog`, `lexical`, `pyanalysis`, `jsanalysis`, and the cross-module
  resolver in `__init__` — with the import arrow running one way so a cycle is a build error
  rather than an initialisation-order bug. Every name the rest of the repository imported from
  `taint` is still importable from `taint`; the longest module is now 524 lines.
  **The split exposed a packaging bug that would have shipped:** `[tool.setuptools] packages`
  is an explicit list, so the new subpackage was simply absent from the wheel — an installed
  copy would have failed at import while every test in a source checkout passed, because a
  checkout has the directory either way. `scripts/check_packaging.py` now walks the tree and
  fails on any importable package the manifest does not list. [2026-08-13]
- **Check 28: `CODE_SHAPE_DETECTORS` is the only thing that may set `literal=False`.** Four
  detectors set it in their own constructors, so the pack scanned the blanked view for 42
  detectors while the set that documents which ones listed 38 — and check 25 compares the prose
  against the set. A prose number, a set and a field, with the field silently outvoting the
  other two. [2026-08-13]

### Added
- **The RealVuln diagnosis was acted on, and re-measured: F3 12.5 → 13.3.** The previous run
  said SQL injection scored 2 of 71 on real Django and FastAPI code because the ORM escape
  hatches were not sinks. They are now — `.raw()`, `.extra()` including the keyword arguments it
  is almost always called with, and `execute`/`executemany`/`exec_driver_sql` on a receiver named
  like a connection or session — and a route handler's parameters are treated as request data
  rather than a MEDIUM lead, for the two shapes that can be recognised without guessing: a
  routing decorator, and a Django view whose first parameter is named `request`. **SQL injection
  2 → 7 of 71.** The larger gain came from a sink that was simply absent: `res.send(str)` sets
  `Content-Type: text/html`, so reflected XSS through Express was invisible — **XSS 1 → 11 of
  98**, with Django's `HttpResponse` and `mark_safe` alongside it.
  **Path traversal was predicted to move and did not: 3 → 3 of 39**, through nine added
  filesystem sinks on both languages, plus one false positive. The prediction was wrong, and the
  remaining misses there are about which values are believed attacker-controlled rather than
  which call is dangerous.
  The previous engine was re-scanned and re-scored on the same clone of the corpus, and
  reproduced the committed 2026-08-12 figures digit for digit (F3 12.5, TP 204 / FP 297 /
  FN 1558) — which is what makes the delta attributable to the engine rather than to corpus
  drift. **Cost, stated because it is real:** precision 0.407 → 0.393, forty-two more false
  positives for fifteen more true positives, and the row is still last of the four in the
  comparison table, below Semgrep's 17.7. `eval/realvuln/run.py` gained `--scanner` so two
  builds can be scored against one clone, and its printed instructions no longer name a
  `--all-repos` flag that does not exist. [2026-08-13]
- **A third Windows reproduction note.** Recomputing the benchmark's ground-truth content hash
  on Windows produces a different digest for an identical corpus — `compute_gt_hash.py` hashes
  raw bytes and joins paths with `os.sep`, so a CRLF checkout and backslash separators each
  change it. Normalising to LF with forward slashes reproduces the published digest exactly.
  Recorded in `result.json` because the first reading looks like the ground truth moved, which
  would have invalidated the whole comparison. [2026-08-13]

### Fixed
- **`pytest kit/tests` could not go red.** Every suite here is a script: assertions append to a
  `fails` list and the verdict is `main()`'s exit code. The `test_*`-named functions pytest
  collects do not raise, so a returned list of failures was a value pytest ignored — and most of
  what each suite checks is only reachable from `main()`, which pytest never called. Verified by
  deleting the flagship JavaScript SQL-injection sink from the engine: `pytest` reported 75
  passed, while `scripts/run_checks.py` went red on four gates. CI was always running the
  scripts directly, so the gates were real and only the pytest view was fictional — but that is
  the view a contributor runs. Added `kit/tests/conftest.py` (a per-test fixture that fails the
  test which grew its module's `fails`, giving attribution) and `kit/tests/test_zz_suite_mains.py`
  (runs every suite's `main()` under pytest, giving coverage). Re-verified by breaking the same
  sink again: 3 failed, 3 errors. Three test functions that returned a value instead of
  asserting were split into a checking function and a `test_`-named wrapper. [2026-08-13]
- **`dirpath` was reported unused and then really was.** The new lint gate caught an
  undefined-name error introduced while fixing its own warning, which is the shortest possible
  argument for having one. Also closed two file handles left to the garbage collector in
  `engine.py` and one in `tests/grade-report.py`. [2026-08-13]

### Added
- **Lint, type and coverage gates.** `ruff` (correctness rules, not house style), `mypy` over the
  shipped package, and a coverage floor measured at **88%** and set there rather than at a round
  number below it — the same rule `eval/thresholds.json` states for the detection floors.
  Configuration lives in a new repository-root `pyproject.toml` that holds tool settings and
  deliberately no `[project]` table. The three tools are the only gates that need something this
  repository does not ship, so they SKIP when absent and CI passes `--require`, which turns the
  skip back into a failure. mypy's 20 findings were fixed rather than silenced: `gitref._git`
  returned `bytes | str` from one flag and every caller had to guess; the MCP tool dispatcher
  indexed its handler table with an unvalidated JSON value; the Python taint helpers were
  annotated `ast.AST`, the base class, which has none of the attributes they use. [2026-08-13]
- **`--tier1` on the eval harness, so the LLM tier has a number.** Tier 1 was excluded from the
  scorecard on the correct grounds that a model is not reproducible — but "not in the gate" had
  become "not measured at all", and *"the LLM tier reaches what Tier 0 cannot"* was sitting
  beside two measured claims as an unmeasured one. `--tier1 replay` runs a captured response
  through the real enrichment path, so it measures the pipeline rather than any model, and it
  refuses to combine with `--check` or `--gate` because the committed scorecard is the Tier-0
  floor. **What it reports is not flattering and is now printed:** Tier 1 adds exactly one
  finding, in the right place — inside the `V3` IDOR block that is Tier 0's only labelled miss —
  and it does not score as a recovery, because it reports `CWE-284` where the label accepts
  `CWE-639`. Under the repository's own label rules that is not grounds for widening the label:
  `CWE-284` is a parent, and only a more specific child is admissible. [2026-08-13]
- **Dependabot for GitHub Actions and Docker, and a CodeQL workflow.** Every action here is
  pinned to a commit SHA, which is immutable — that is the point, and also the problem: a pinned
  action never updates, including past the advisory that made the update necessary. CodeQL is
  the only reading of this source that is not ours; the dogfood gate runs *this* engine on
  itself and therefore cannot find a class of bug the engine does not model. It is gated on an
  `ENABLE_CODEQL` repository variable because CodeQL needs Advanced Security on a private
  repository, and a permanently-red workflow is one everybody learns to ignore. The
  `github/codeql-action` SHA was resolved through the GitHub API, not written from memory.
  [2026-08-13]

### Changed
- **CI runs the gate list instead of restating it.** The Linux job was twenty hand-written steps
  duplicating `scripts/run_checks.py`, which the Windows job already called. It now calls the
  runner too, so there is one list. Check 26 was inverted to match: instead of comparing two
  copies of the same list — a problem that no longer exists — it now walks the repository and
  fails if any check script is in *neither*, which is the hole the old form could not see. A
  test file nobody runs looks exactly like a test file that passes. The packaging check that
  lived as an inline heredoc in the workflow moved to `scripts/check_packaging.py` so it can be
  run locally, and gained a check that the locale bundles still ship. [2026-08-13]

### Security
- **The Pages workflow held `pages: write` and `id-token: write` at workflow level**, so the
  build job — which checks out the tree and runs a generator over it — ran holding a token that
  can publish the site. Both scopes moved to the `deploy` job that actually needs them. Found by
  running the pinned `zizmor==1.26.1` locally for the first time: it reported two HIGH findings,
  which means this step would have failed the next CI run. Both CI-only steps have now been
  executed at their pinned versions on this machine — `semgrep==1.140.0 --validate` accepts the
  exported pack (41 rules, 0 configuration errors) and zizmor is clean at exit 0 — so neither is
  an unverified claim any more. [2026-08-12]
- **A committed `scope.yaml` no longer authorizes active testing.** The PreToolUse guard read
  the file from the working directory and trusted `i_am_authorized: true` in it, so cloning any
  repository that shipped one and opening a session there would have opened the authorization
  gate before the user had seen the file — the assertion travelled with the repo instead of
  coming from the operator. The guard now asks `git ls-files` whether the file is tracked and
  refuses it if so, with a block message that says why and how to fix it. When git cannot answer
  the file is refused rather than assumed trustworthy; `SECAUDIT_ACTIVE=1` remains the channel a
  repository cannot supply. The docs had asked for the file to stay uncommitted all along — this
  makes it a property of the gate rather than advice. Exercised against real directories and a
  real git index in the guard's self-test. [2026-08-12]

### Added
- **RealVuln has been run, and the result is published unedited: F3 12.5.** 62 of the 66
  benchmark repositories (four are gone from GitHub — all four deliberately vulnerable teaching
  apps, the densest and most pattern-obvious in the corpus, so their absence works against this
  number rather than for it), Tier 0 only, scored by the benchmark's own scorer. That is
  **below** rule-based SAST's published 17.7: precision 0.407 against Semgrep's 0.205, recall
  0.116 against its 0.175, and F3 weights recall nine times as heavily as precision. The engine
  reaches 80–90% on classes with a syntactic sink and 0% on the classes `what-we-miss.md`
  already said it cannot decide. One result was not predicted and is the most useful thing the
  run produced: **SQL injection 2 of 71** — the flagship class, missed on real Django and
  FastAPI code that reaches SQL through ORM escapes our sources do not treat as request-rooted.
  Full per-family and per-repo breakdown in `eval/realvuln/README.md`; the scorer's raw output
  is committed as `eval/realvuln/result.json`. [2026-08-12]
- **Consistency check 27 puts the external number under the same gate as every other number.**
  It is the figure with the strongest pull toward drift — third-party, unflattering, and
  destined for a launch post — and nothing in the repo would have had to change for a
  rounded-up retelling to go unnoticed. Each stated F3, precision and recall is anchored to a
  phrase that names *our* result (so the pages can still quote Semgrep's 17.7) and checked
  against `result.json`; deleting the row a number lives in fails the check too, so the gate
  cannot be made vacuous by an edit. [2026-08-12]
- **The documented reproduction command did not exist.** `score.py --all-repos` is not a flag
  the benchmark has; it scores one repository at a time. The runner's docs now carry the
  invocation that was actually used, plus the `PYTHONUTF8=1` a Windows console needs before
  `score.py` can write its own report. [2026-08-12]

### Fixed
- **`const { name } = req.query` reached no sink.** Destructuring was listed as an unmodeled
  bound and had been one since the JS scanner was written — which meant the single most common
  way an Express handler reads request data produced no taint path at all, while the same code
  written as `const name = req.query.name` was reported as Critical. A documented gap is still a
  gap when it sits on the majority shape. Flat patterns are now followed in declarations and in
  parameter lists, including renames, defaults, rest elements, array patterns and TypeScript
  annotations, and the bound property is named in the reported source (`req.query.name`, not
  `req.query`) so a reader can refute it. Nested patterns remain declined rather than guessed
  at, and the docstring, `limitations()` and the generated what-we-miss page say so. A paired
  V62/S62 fixture puts both the flaw and its safe twin in the measured corpus. [2026-08-12]
- **Corroboration deleted findings it was supposed to merge.** A taint path and a pattern hit at
  the same spot are one bug seen twice, so the pattern finding absorbs the path — but pairing
  matched on file + CWE + a 3-line window, in list order, and proximity is not identity. Two SQL
  injections a few lines apart in one file meant the second one's pattern finding absorbed the
  first one's path, and that finding then vanished from the report: a false negative manufactured
  by the deduplication layer, on code the engine had already analysed correctly. Pairing is now
  nearest-first and one-to-one, so an exactly-coincident pair always wins and a separate bug is
  never consumed by its neighbour. [2026-08-12]
- **A destructured parameter shifted every parameter after it.** `_js_param_names` dropped a
  pattern it could not name, so `f(a, {b}, c)` reported two parameters and a call's second
  argument resolved against the third parameter — an interprocedural finding attributed to an
  argument that never carried the taint. The position is now held by an empty name, which
  matches no summary entry: unknown rather than misattributed. [2026-08-12]
- **Four stated numbers had drifted from what the repo derives.** README and ROADMAP said 40 of
  79 detectors were exported to the Semgrep pack with 39 withheld; the generator exports 41 and
  withholds 38. ROADMAP said 39 detectors scan the blanked code view; there are 38. Check 08 had
  not caught any of it because it only reads the *total* in those sentences, which was right the
  whole time. New check 25 recomputes both subsets and attributes each "N of M detectors" claim
  by the marker next to it, so a new kind of subset claim is not silently compared against the
  wrong denominator. [2026-08-12]
- **`taint.py`'s own docstring understated the engine by several modules.** Its "honest bounds"
  section still said one cross-module hop and that a chain through a third module was not
  followed, while `limitations()` — the list that actually ships in reports — said any depth.
  The code has run to a fixed point over the import graph since cross-module resolution landed,
  and `test_cross_module` has pinned a three-module chain the whole time; only the prose was
  stale. Understating a bound is the same failure as overstating one: it is a claim nobody
  measured. [2026-08-12]
- **One of the 32 gates ran in no workflow.** `scripts/check_python_floor.py` — the only thing
  enforcing `requires-python = ">=3.9"`, since the suite itself runs on a newer interpreter —
  lived in the local runner alone, and `run_checks.py`'s docstring asked for the two lists to be
  kept in sync by hand. New check 26 fails the build when a gate in the local runner runs in no
  workflow, which is the same treatment a typed number gets. [2026-08-12]
- **`gen_semgrep_pack.exportable()` returned a reason when a detector was *not* exportable** — a
  predicate whose name asserted the opposite of its truthiness. Renamed to `withheld_reason()`.
  The test suite's summary line already counted the wrong-looking set while printing the right
  number, which is how long an inverted name survives. [2026-08-12]

### Added
- **CI runs the whole gate set on Windows.** The kit makes Windows-specific claims that
  ubuntu-latest cannot execute even once: the hook's `python3 || python || py` fallback chain
  exists because python.org installs have no `python3`, the engine normalises `\` into the `/`
  paths every finding and SARIF location is keyed on, `npm audit` is invoked with `shell=True`
  only on `nt`, and diff mode shells out to git. The new job runs `scripts/run_checks.py` rather
  than a second copy of the step list, so the two cannot drift. [2026-08-12]
- **The Python version CI runs on is pinned** instead of being whatever `python3` the runner
  image happens to ship — a runner bump would otherwise change what a green build means without
  a line of the workflow changing. [2026-08-12]
- **Open Graph card (`site/og.png`), generated — no headless Chrome.** The roadmap had this
  down as needing a browser, which is why it stayed unfinished: an asset only regenerable by
  installing Chrome stops matching the numbers printed on it the first time those numbers move,
  and the numbers on a social card are the first claim anyone sees. `zlib` is enough to write a
  PNG, so the repo now carries a small PNG encoder and a stroke font
  (`scripts/pngwriter.py`, `scripts/strokefont.py`) and draws the card from filled polygons and
  stroked text. Every figure comes from `eval/scorecard.json` and the gate list. Rendering is
  deterministic — fixed filter byte, fixed supersample — so CI compares the committed file byte
  for byte. It proved itself immediately: adding the gate that checks the card changed the gate
  count printed on the card, and the gate caught it. [2026-08-12]
- **Every third-party Action and the Docker base are now pinned to resolved digests**, looked up
  through the GitHub and registry APIs rather than written from memory. `pypa/gh-action-pypi-publish`
  needed two hops: `v1.14.2` is an *annotated tag*, so the ref API returns a tag object, and
  pinning that would not resolve to anything `uses:` can check out — the commit it dereferences
  to is what is pinned. [2026-08-12]
- **i18n as data — `--lang tr`, bundles in `i18n/*.json`.** Adding a language is one file, not
  a fork of the renderer. What is translated is the report's own furniture: headings, table
  labels, the sentences the tool says about itself. What is **not** translated, deliberately,
  is finding titles, evidence and fix instructions — those come from the detector definitions
  and change with the engine. Translating them would put 79 detectors × N languages behind
  every rule edit, and the failure mode is specific: a *stale translated fix* tells someone to
  apply a remediation the rule no longer recommends, in a language where they cannot see it
  disagrees with the English. An English fix beside Turkish chrome is visibly English; a wrong
  Turkish fix is not visibly wrong. A translated report says this about itself. [2026-08-12]
- **Fallback is per key, not per bundle**, so a translation can ship at 90% instead of not at
  all — and a key no bundle defines renders as `⟪key⟫` rather than as an empty string, because
  a missing heading does not look like a bug, it looks like a report with one fewer section.
  [2026-08-12]
- **Gate 31** checks every bundle has every key, that placeholders match across locales (a
  renamed `{n}` silently falls back to English and the report still looks fine), that no value
  is blank, and — the direction that actually breaks reports — that every key the renderer asks
  for exists, checked by rendering a real result rather than by grepping. [2026-08-12]
- **Fixture corpus 23 → 61 planted flaws, 3 → 15 languages.** Go, Java, PHP, Ruby,
  C#, Rust, Terraform, Kubernetes, GitHub Actions, Kotlin/Android, Dart, iOS plist and JSON
  config now have paired vulnerable/safe fixtures, and each safe twin is a safe implementation
  of the *same feature* rather than unrelated clean code — the trap is the point. Before this,
  detectors for ten languages had zero fixtures, which means the per-language table was not a
  measurement of them; it simply did not mention them. Recall **98.4%** (60/61),
  precision 100%, F3 **0.985**, 0 false positives on 61 traps. [2026-08-12]
- **Verified patch suggestion — `--suggest-patches DIR`** (needs `--backend`). This was held
  back until it could be built without the failure that makes it dangerous: a security patch
  nothing verified gets applied by someone who believes it was checked, against a finding they
  now consider closed. The resolution is to split the halves by determinism — **a model
  proposes, the deterministic engine vouches.** Each patch is applied to a throwaway copy, the
  copy is re-scanned, and the two scans are compared with the same machinery `--since` uses:
  the finding must be gone and nothing new may appear anywhere. An independent reviewer runs
  after that and gets a **veto only** — it can reject a patch the deterministic pass accepted,
  it can never rescue one the pass rejected, and it is never shown the author's reasoning,
  because a reviewer given the argument for a patch reviews the argument. Nothing is ever
  applied; verified patches are files you read. [2026-08-12]
- **Four refusals, each because its opposite causes harm**: a diff touching any file outside
  the finding's is refused before it is run *and before any model sees it* (the control against
  an injection carried in scanned source must not itself be model output); a patch that removes
  routes or functions is refused, because deleting the feature makes the finding disappear and
  is what a loop driven by "does the scanner still complain" converges on; a patch that trades
  one vulnerability for another is refused; and a patch whose tests fail is refused, because
  which matters more is not this tool's call. An unparseable or errored review counts as
  rejection, never approval. [2026-08-12]
- **Gate 30** is almost entirely refusals — the value of this feature is the patches it
  declines to hand over. No model is called: a scripted backend returns canned diffs, which
  mirrors how the feature actually splits. [2026-08-12]
- **KEV + EPSS exploitation status (`--exploitation`)** — every CVE in the report is looked up
  in CISA's Known Exploited Vulnerabilities catalog and FIRST's EPSS model, so a register of
  dozens of advisories has an order to work in that is not CVSS. This is the signal the EU CRA
  attaches a deadline to: from 2026-09-11 the 24-hour early warning triggers on an *actively
  exploited* vulnerability, not on any CVE, and it is carried in the CRA evidence pack's
  register. Four rules hold it up: it is off by default (the one part of Tier 0 that reaches the
  network, and only CVE ids are ever sent — nothing about your code); an unreachable feed
  reports `unknown` and says so, never a clean bill; KEV can raise a severity to Critical but
  never lower one, because a curated list is evidence of exploitation and not evidence of
  safety; and there is deliberately no `not_exploited` value in the vocabulary, because a
  status that reads as a clean bill will be used as one. EPSS never moves a severity at all —
  it is a model's probability, reported as one. [2026-08-12]
- **SPDX 2.3 SBOM (`--format spdx`)** alongside CycloneDX. Not a choice between them: CycloneDX
  is built for vulnerability correlation, SPDX is an ISO standard and is what procurement,
  legal review and EO 14028 / NTIA minimum elements ask for. The component list is taken from
  `sbom.build()` rather than re-derived, so the two documents cannot disagree about what is in
  the product — a gate asserts they list the identical purls. Licence fields are `NOASSERTION`
  everywhere and the document says that is a stated unknown rather than a to-do: a manifest and
  a lockfile do not record dependency licences, and a guessed SPDX identifier in a document
  whose purpose is licence compliance is the most damaging thing that module could emit.
  [2026-08-12]
- **Eval: per-CWE breakdown, and a gate for the regression an aggregate hides.** Results are now
  keyed by CWE as well as by this project's own class names, so they can be compared with
  another tool's or a benchmark's numbers. More importantly, overall recall can *rise* while a
  whole class stops being detected — add three fixtures of one kind, lose the only fixture of
  another. The gate now fails when any class, CWE or language that was previously detected
  drops to zero. Its floors are read from the committed scorecard rather than typed: at this
  corpus size most classes have a single fixture, so invented per-class thresholds would be
  worse than none. [2026-08-12]
- **Gate 29** covers the above, offline — the feeds are injected through the same object the
  network path builds. [2026-08-12]
- **Semgrep rule pack — `rules/secaudit/*.yaml`**, generated from `detectors.py`
  ([pack README](rules/secaudit/README.md)). Teams already running Semgrep get these rules
  without adding a second scanner, and this project gets a second, independently maintained way
  to run its own detections. **40 of 79 detectors are exported; 39 are deliberately withheld**,
  each with its reason published: code-shape rules match a view with comments and string
  literals blanked, which `pattern-regex` cannot do, and `suppress_if` rules clear on a marker
  anywhere in the file, which `pattern-not-regex` cannot express. Exporting them anyway would
  ship rules knowingly noisier than the ones whose precision this project publishes — numbers
  that would then describe something nobody is running. [2026-08-12]
- **Gate 28 checks the pack is equivalent, not that it looks right.** Every exported pattern is
  applied to the shipped fixtures and must produce the identical `(file, line, span)` hits as
  its detector; flags must survive translation (a dropped `(?i)` silently narrows a rule, an
  added one silently widens a case-sensitive secret pattern into false positives); and a
  withheld detector appearing in the pack fails. Semgrep itself is not a dependency of the
  suite — CI validates the YAML envelope against the real tool, so semantics are checked
  everywhere and the schema where the tool exists. [2026-08-12]
- **Distribution: GitHub Action, Docker image, pre-commit hooks, release pipeline**
  ([docs/ci.md](docs/ci.md)). The Action runs the code in the checkout rather than
  `pip install`-ing itself, so the version audited is the commit reviewed and there is no window
  where a compromised release of a security scanner runs with your repository already checked
  out. On a pull request it gates on introduced findings and picks the base branch up
  automatically — and when `fetch-depth` hides the base commit it warns and audits the whole
  tree, failing *stricter* than asked rather than quietly weaker. PR commenting is opt-in: a
  security workflow should not acquire write access to your PRs as a side effect of being
  installed. [2026-08-12]
- **`--only GROUPS`** — run a subset of detectors (`--only secret`, `--only secret,docker`;
  `--only ?` lists them). Groups are derived from the detector ids, so a new detector joins its
  group by being named consistently and there is no second list to forget. An unknown group is
  exit `2`, never an empty pass: silently reporting a clean scan of a group that does not exist
  is the worst answer a security tool can give. [2026-08-12]
- **`--summary PATH`** — write the readable Markdown alongside a machine format from one scan.
  CI wants both shapes, and getting them by running the scan twice costs double (four tree
  scans with `--since`) and lets the number the gate used disagree with the number a reviewer
  reads. [2026-08-12]
- **Gate 27: the advertised Python floor is checked, not just declared**
  (`scripts/check_python_floor.py`). `requires-python = ">=3.9"` is a promise pip enforces by
  *allowing* the install on 3.9, where the code then fails at the first call to whatever was too
  new. It reads the floor from `pyproject.toml` and scans for constructs above it. [2026-08-12]
- **Diff mode — `secaudit . --since <ref>`** ([docs](docs/diff-mode.md)): what a change
  introduced, resolved and left open. With `--min`, the exit code is driven by *introduced*
  findings only, which is the difference between a gate a PR can clear and a gate that gets
  disabled — an absolute gate fails every PR in any repo with history, and the fix teams reach
  for is `continue-on-error`, which stops it catching the new Critical too. Pre-existing
  findings are still printed under their own heading; a diff that hides open findings to keep
  the build green is doing the same damage more quietly. Exit `2` is reserved for "the
  comparison could not be made" (not a repo, unknown ref, single-scan `--format`), because
  *this change is unsafe* and *I could not tell you whether it is safe* must not be the same
  signal. [2026-08-12]
- **Both trees are scanned whole in diff mode, not just the changed files.** The optimisation
  is wrong here and fails silently: taint resolves across import edges, so editing a helper can
  create a finding whose source is a route in a file the commit never touched — a changed-files
  scan never reads that route, reports nothing, and calls the PR clean. Verified on a commit
  that edits only `util.js` and produces a Critical at `server.js:2`. [2026-08-12]
- **Findings are matched by content, not by line number.** Adding an import moves every finding
  below it; a line-keyed diff reports all of them as resolved *and* re-introduced on a commit
  that changed nothing about them, and a tool that cries wolf on a no-op commit is one people
  learn to skip. Identity is rule + file + matched-line text, with an occurrence index so two
  identical dangerous lines stay two findings — collapsing them would let fixing one read as
  fixing both. The regression test fails against a line-keyed implementation. [2026-08-12]
- **`kit/secaudit_core/gitref.py`** materialises a ref with `git archive` piped through the
  standard library's `tarfile`, so the working tree, index and stash are untouched, nothing is
  left behind if the run dies, and no external `tar` binary is required. Members are checked
  for path escape and links before extraction — git cannot record those, but "the producer is
  trustworthy" is the assumption behind every tar-extraction CVE. [2026-08-12]
- **Gate 26: diff mode**, run against throwaway git repositories rather than a mocked git.
  Every failure mode this feature actually has — ref resolution, tree extraction, two scan
  roots agreeing on path names — lives in the plumbing a mock would replace. [2026-08-12]
- **MCP server (`kit/secaudit_mcp/`, `python3 -m secaudit_mcp`)** — the same engine, reachable
  from Codex, Cursor, OpenCode, Copilot CLI or anything that speaks the Model Context Protocol.
  Six tools: `scan_source`, `scan_dependencies`, `generate_sbom`, `compliance_pack`,
  `explain_finding`, `coverage`. Standard library only; the zero-runtime-dependency invariant
  is unchanged. Two omissions on purpose: no tool probes a system (consent to probe a running
  system is a human decision, and a tool that scans whatever URL it is handed scans whatever a
  prompt injection puts in front of it — the test suite asserts no tool schema accepts a
  `url`, `host` or `endpoint`), and no `suggest_patch` until the review agent that has to vouch
  for a patch exists. The dependency tools do reach the network to look advisories up by
  package name, which is stated rather than rounded to "offline". [2026-08-12]
- **`coverage` is an MCP tool, not a doc page.** A model that receives findings but cannot ask
  for the bounds summarises an empty result as "no security issues found" — a claim the engine
  never made. The generated limitations are callable, and `initialize` tells the client to call
  them before summarising. [2026-08-12]
- **Cross-module taint** — `taint.analyze_files()` analyses the whole scanned set together
  and resolves a call to a function imported from another file against that file's summary,
  iterating over the import graph to a fixed point so a chain laundering through several
  modules resolves. Resolution is always by an explicit import statement, never by matching
  names globally — that is what keeps a longer chain from becoming a longer guess; bare
  specifiers never resolve, because a package is not our code. Measured by golden finding
  **V23**, whose two files are each innocent when read alone. Recall 95.7% (22/23), F3 0.961,
  0 false positives on 23 traps. Whole-repo scan of this repository: 0.8s. [2026-08-12]
- A cross-module finding is reported where the untrusted value **enters** (the route someone
  has to recognise) while naming the callee's file and line as where the fix belongs. Both
  ends are needed: only the sink loses which route reaches it, only the caller loses what to
  change. [2026-08-12]
- **Interprocedural taint for JavaScript/TypeScript** — the summary machinery that was
  Python-only now runs over every brace-delimited named JS function, so a route handler that
  reads the request and hands it to a helper resolves to one HIGH-confidence path naming both
  ends, instead of two half-findings. Measured by new golden finding **V22**, the JS twin of
  V21. Recall 95.5% (21/22), F3 0.959, still 0 false positives on 22 safe-implementation
  traps. [2026-08-12]
- **`docs/language-coverage.md`, generated** (`scripts/gen_language_matrix.py`) — analysis
  depth per language read out of the taint dispatch table, the detector pack's extension
  tuples and the lexical models `code_view` knows. "Supported languages" decays in one
  direction only: a language gets listed when work starts and never unlisted when it stops.
  Generating it made the gap it was built to expose visible immediately — Rust had zero
  detectors. [2026-08-12]
- **Rust detectors** (`SEC-RS-UNSAFE`, `SEC-RS-TRANSMUTE`, `SEC-RS-CMDI`) and a Rust lexical
  model. Three narrow rules, not a broad pack: in a language where most of the usual sinks
  cannot exist, the classes worth a rule are the ones where the code opts out of the
  compiler's guarantees. The lexical model lists only `"` as a quote — `'` is a lifetime
  marker far more often than a char literal. [2026-08-12]
- **`docs/what-we-miss.md`, generated** (`scripts/gen_what_we_miss.py`) — the false negatives:
  measured misses from the committed scorecard, classes with no deterministic coverage,
  the taint tier's own bounds, language gaps and compliance gaps. Generated because a
  hand-written limitations page is accurate for one release and then silently becomes an
  understatement, which is the worst direction for this particular document to drift.
  [2026-08-12]
- **HTML report (`--format html`)** — self-contained and printable, which is also the PDF path
  via the browser's own print-to-PDF rather than a rendering dependency to ship and pin. No
  external stylesheet, script, font or image, so it renders identically on a machine with no
  network. Escaping is tested against hostile input: a scanner that renders its own evidence
  line unescaped plants the bug it was hired to find. [2026-08-12]
- Site: an inline SVG favicon (data URI, so the page stays a single file) and a comparison row
  for MCP reach. [2026-08-12]
- **Landing page (`site/`, `scripts/gen_site.py`)** — bilingual EN/TR, self-contained (no
  external fonts, scripts or images), theme-aware, ~11 KB per page. The template holds **no
  figures at all**: it has `{{tokens}}`, and every value comes from `eval/scorecard.json`, the
  detector table, the compliance mapping and the gate list at build time. `--check` fails if a
  token is unsupplied, if a supplied value goes unrendered, or if a stat on the page disagrees
  with its source — so editing the page instead of the code breaks the build. Verified by
  typing a number into the template and watching it fail. Both languages render from one
  template, because two files drift and the drift is invisible until a Turkish reader is shown
  a number the English page corrected a year ago. [2026-08-12]
- `.github/workflows/site.yml` — publishes to GitHub Pages on every push to main, so a figure
  on the page cannot lag the code that produced it. [2026-08-12]
- README: **"How this differs from Claude Code's built-in security tools"** — a capability
  table naming what Anthropic's two official plugins cover and what they deliberately do not,
  with their own documentation quoted rather than paraphrased, and an explicit recommendation
  to install them alongside. A visitor deciding between tools should not have to reverse-engineer
  the answer from a feature list. [2026-08-12]
- **Compliance mapping (`secaudit_core/compliance.py`)** — findings now carry an **OWASP ASVS
  5.0** chapter (V1-V17) and the **EU Cyber Resilience Act** clauses they bear on. ASVS is
  mapped at chapter granularity, deliberately: ASVS 5.0 moved external cross-references out to
  OWASP's CRE project, so there is no authoritative CWE→requirement crosswalk to copy, and a
  chapter mapping that fits on one screen and can be argued with beats a requirement mapping
  that looks precise and is guessed. CRA is mapped at clause level, because those numbers are
  fixed by the regulation. Consistency check 24 fails the build if a detector or taint sink
  introduces a CWE with no chapter — 34 of 34 emitted CWEs are covered. [2026-08-12]
- **PCI DSS, SOC 2 and ISO 27001 are explicitly NOT mapped**, and `compliance.summary()` keeps
  saying so. Each needs a citable source per control; shipping a plausible guess for a standard
  an auditor will check is worse than shipping nothing. [2026-08-12]
- **CycloneDX 1.6 SBOM (`secaudit_core/sbom.py`, `--format cyclonedx`)** — top-level
  dependencies with versions resolved from the lockfile where one exists. A package with no
  lockfile entry is emitted with an **empty version and an explicit
  `secaudit:version-unresolved` property**, never a version inferred from the declared range:
  an SBOM exists to be matched against advisories, so a guessed version is worse than a flagged
  one. Deterministic — no clock inside, so two SBOMs of the same tree diff on dependencies
  rather than on timestamps. [2026-08-12]
- **CRA evidence pack (`--format cra`)** — SBOM + full vulnerability register (VEX status,
  reachability path, ASVS chapter, clause mapping, remediation) + the clauses the scan itself
  is evidence toward, in one machine-readable file. Exploitation status is emitted as an
  explicit `null`, never `false`: the difference between "checked, not exploited" and "not
  checked" is what decides whether an Article 14 24-hour clock has started. The pack carries a
  disclaimer stating it is input to a compliance process and not a certificate, and a test
  asserts that disclaimer is still there. [2026-08-12]
- `kit/tests/test_compliance.py` — weighted toward the claims rather than the plumbing, because
  a wrong chapter is a footnote while an invented SBOM version is something someone files with
  a regulator. [2026-08-12]
- **Interprocedural taint analysis for Python** — each function is reduced to a summary (which
  parameters reach a sink, which escape through the return value, whether it fetches untrusted
  input itself), call sites are resolved against those summaries, and the whole thing iterates
  to a fixed point. This connects the shape almost all real code takes — a handler reads the
  request, a helper does the dangerous thing — into one HIGH-confidence path naming both ends,
  where before it produced a source that went nowhere and an unattributed parameter lead.
  A local function that does not pass parameter taint to its return value now **launders** it,
  which is a precision win a subtree scan cannot make. [2026-08-12]
- Golden finding **V21** — SQL injection across a function boundary, with its safe counterpart
  S21 where the same value still crosses the boundary but arrives as a bound parameter. The
  interprocedural work is measured by the corpus rather than only asserted by unit tests, and
  S21 is specifically the trap for an analysis that reports any tainted value reaching
  `execute()`. Measured: **95.2% recall (20/21), 100% precision, F1 0.976, F3 0.957, 0 trap
  false positives.** [2026-08-12]
- **Measured detection quality (`eval/`)** — a scoring harness, derived labels, and committed
  results, replacing prose claims with a number anyone can reproduce:
  `python3 eval/harness.py`. Tier 0, no LLM, no external scanners: **95% recall
  (19/20), 100% precision, F1 0.974, F3 0.955, 0 false positives on the 20
  safe-implementation traps.** The single miss is IDOR, which has no reliable static
  signature and is documented as belonging to the LLM tier. [2026-08-12]
- `eval/build_ground_truth.py` — generates the labels from the fixture marker comments and the
  golden-set table, in the [RealVuln](https://github.com/kolega-ai/Real-Vuln-Benchmark)
  ground-truth schema, so the number we publish about ourselves is computed the same way as a
  third party's. Editing a fixture without regenerating is a build failure. [2026-08-12]
- `eval/thresholds.json` + `eval/scorecard.md` / `.json` — regression floors set to measured
  values with the reasoning written beside each, and a committed scorecard CI fails on when it
  stops matching what the engine measures. [2026-08-12]
- `eval/realvuln/` — runner and reproduction steps for the external benchmark, plus an honest
  reading guide (Python-only corpus, Tier 0 only, teaching apps are denser than real code).
  Not yet run; the result will be published there verbatim. [2026-08-12]
- `report.to_semgrep_json()` and `--format semgrep` — Semgrep CLI JSON, the de-facto SAST
  interchange format. RealVuln scores any scanner emitting this shape without a custom
  parser, which is how SecAudit gets an externally computed number. [2026-08-12]
- Consistency check 23 — the README's measured figures must equal `eval/scorecard.json`. A
  stale recall number in a security tool's README is precisely what this gate exists to
  prevent. [2026-08-12]

- **Taint tier (`secaudit_core/taint.py`)** — source→sink reachability analysis, still with
  zero runtime dependencies and no LLM. Python uses a real `ast` walk; JavaScript/TypeScript
  uses a brace-aware statement scanner (no JS parser exists in the standard library, and
  vendoring one would break the zero-dependency invariant). It answers the question a
  single-line regex cannot: *does untrusted input actually reach this sink?* On the shipped
  corpus it produces 13 paths covering 11 golden classes, and 0 high-confidence paths on the
  secure negative control. [2026-08-12]
- Findings now carry a **reachability path** (`Finding.taint_path`) rendered in the Markdown
  report and in the SARIF message, so a reviewer can follow — and refute — each hop rather
  than accept a verdict. [2026-08-12]
- **Dependency reachability + OpenVEX (`secaudit_core/deps.py`)** — every dependency advisory
  is now classified by whether first-party source actually imports the package, and carries an
  [OpenVEX](https://github.com/openvex/spec) status with the evidence for the call. A declared
  but never-imported package becomes `not_affected/vulnerable_code_not_present` and drops two
  severity rungs; a dev-only dependency imported solely from tests becomes
  `not_affected/component_not_present`; an undeclared transitive package and an unindexable
  tree stay `under_investigation`, because concluding otherwise from a missing first-party
  import would be a false all-clear on the most common shape of supply-chain exposure.
  Nothing is ever removed from the register — a filtered register is not evidence.
  Classification runs in one engine pass over every source (npm audit, osv-scanner) rather
  than per adapter. [2026-08-12]
- `--format openvex` on the CLI, emitting the OpenVEX document — the machine-readable answer
  to "which of these advisories affect the product", which is the question the EU Cyber
  Resilience Act's reporting duty (from 2026-09-11) actually asks. [2026-08-12]
- `kit/tests/test_deps.py` — every import syntax, every `classify` branch, and explicit
  assertions that the two false-all-clear cases stay `under_investigation`. [2026-08-12]
- `--no-taint` on the CLI, for a pattern-only run. [2026-08-12]
- `kit/tests/test_taint.py` — unit coverage for the lexical view, plus one vulnerable/safe
  snippet pair per rule so every assertion measures precision and recall together, plus the
  corpus floor. Wired into CI and `run_checks.py`. [2026-08-12]
- `ROADMAP.md` — the plan of record for v2.0: competitive analysis of the field as of
  2026-08 (including Anthropic's two official security plugins), the three-pillar
  positioning, a numbered gap list, and six phases with CI-gated exit criteria. [2026-08-12]
- `scripts/run_checks.py` — one command that runs every gate CI runs, with `--fast` and
  `--list`. A red build is now reproducible locally. [2026-08-12]
- `scripts/check_consistency.py` (checks 01–10) — recomputes every number the docs state
  about the kit from the detector table, the golden set and the shipped plugin tree, and
  fails the build when a document disagrees. Also validates internal integrity: unique
  detector ids, compiling patterns, resolvable `maps_to`, Critical-implies-high-confidence,
  and that every CWE-798 detector masks its evidence. `--facts` emits the derived values as
  JSON for downstream generators. [2026-08-12]
- `scripts/check_repo.py` (checks 11–20) — the manifest, layout, link and secret-hygiene
  checks, moved out of the workflow so they can be run locally. [2026-08-12]
- `LICENSING.md` — records the decision to stay single-license MIT rather than adopt the
  ecosystem's MIT-code/CC-BY-content split, and why that split does not work when the
  Markdown *is* the program. [2026-08-12]

### Changed
- **The language matrix stopped claiming taint is single-file**, which it had claimed for the
  whole life of the cross-module work. The generator existed to keep that page honest, but the
  scope was a literal string typed *into the generator*, and its `--check` gate compares the
  page against the generator — so a hand-written claim one directory further from the reader
  passes every gate. Scope is now read from `TAINT_DEPTH`, alongside the front end, and the
  same fix is applied to the MCP `coverage` tool, which had the sentence typed inline too.
  [2026-08-12]
- The published limitations no longer say a chain through a third module is not followed. The
  real bound is the scanned set: an import edge is followed to any depth, and a chain leaving
  into an excluded directory, a third-party package, or a language without taint depth stops
  there. Understating a limit is not the safe direction — a bounds list that is wrong in the
  generous direction is a bounds list nobody checks. [2026-08-12]
- **`kit/tests/test_engine.py` resolves golden ids by region, not only by `maps_to`.**
  `maps_to` is a property of the *detector*, so one detector class covers one golden id — but
  V2 and V22 are the same class (`exec` with a shell string) reached two different ways, one
  directly and one across a function boundary. Keyed on `maps_to`, finding both looked
  identical to finding one, and the interprocedural tier the fixture exists to measure would
  have scored as a no-op. The repo now has one definition of "detected" rather than two that
  can disagree. [2026-08-12]
- **Consistency check 05 no longer requires a second measurement denominator.** It used to
  demand the phrase `**N/N** target sink classes` in the README, which counted distinct
  `maps_to` values — bookkeeping about the detector pack — sitting one paragraph from the
  scorecard's recall over labelled vulnerabilities. Two numerators, two denominators, both
  called a measurement. Check 05 now guards that a measurement claim exists and that there is
  only one; check 23 still verifies every stated number against the generated scorecard.
  [2026-08-12]
- **Consistency check 08 exempts dated snapshot blocks** (`<!-- snapshot:begin -->`). The
  ROADMAP's baseline table records what was true on 2026-08-12; forcing it to track the
  current detector count would quietly rewrite the repo's own history, and the baseline a
  roadmap measures progress against is precisely the number that must not move. Verified the
  exemption is scoped, not a bypass: a wrong count outside a block still fails. [2026-08-12]
- `.github/workflows/validate.yml` — the eight inline Python heredocs are now two script
  calls; the workflow dropped from 261 to 96 lines with no loss of coverage. [2026-08-12]
- `CONTRIBUTING.md` — documents the local check commands and what the consistency gate will
  do to you when you add a detector. [2026-08-12]
- `.gitignore` — ignore `.pytest_cache/`, `*.egg-info/`, `.venv/` and `site/`. [2026-08-12]

### Fixed
- **A URL handed to the CLI was scanned as a file path.** No file matched, so the run finished
  with an empty report — indistinguishable from a clean audit unless someone noticed the file
  count, which is the worst answer a security tool can give. It is now exit `2` with an
  explanation and a pointer to the plugin, which is where live-target auditing lives because it
  needs an authorization gate. A bare hostname is deliberately still treated as a path: refusing
  to scan a real directory called `example.com` would be its own quiet failure, and the test
  covers both directions. [2026-08-12]
- **The landing page declared a large social card and supplied no image.**
  `twitter:card: summary_large_image` with no `og:image` asks a scraper for a full-width preview
  and gives it nothing to put there — which renders as a blank card, not as no card. Both
  `og:image` and `twitter:image` are now emitted as absolute URLs (a relative one is ignored by
  every scraper), and the card is copied into `site/dist/` so the tag does not point at a 404.
  [2026-08-12]
- **The locale bundles would not have shipped.** They sat at the repo root, outside the
  package, so they worked perfectly in a checkout and appeared in no wheel — `--lang tr` on
  every installed copy would have silently rendered English, a failure indistinguishable from a
  translation nobody wrote. Moved into `secaudit_core/locales/` with `package-data`, and
  verified by building the wheel and running `--lang tr` from a clean venv rather than by
  reading the manifest. [2026-08-12]
- **`SEC-RS-CMDI` could never fire.** It was listed as a code-shape rule, so it was matched
  against the view with string-literal *contents* blanked — but the thing it matches on is
  literal content: `Command::new("sh")` becomes `Command::new("  ")`, and `.arg("-c")` becomes
  `.arg("  ")`. It had been dead since it shipped, and nothing noticed because Rust had no
  fixture. Found by planting one. A detector with no fixture is an unmeasured claim, which is
  the argument for this whole expansion. [2026-08-12]
- **Our own tool flagged our own patch verifier, and it was right.** `_run_tests` ran the
  user's test command with `shell=True`; the dogfood gate failed on `SEC-PY-CMDI` in
  `patch.py`. Special-casing ourselves was the wrong repair — the shell would have been
  interpreting that string with its working directory inside a sandbox containing
  model-authored code, so globs and expansions resolve against content the run just generated.
  Now split into an argv and executed without a shell; chain commands in a script.
  [2026-08-12]
- **The no-shell fix then introduced a worse bug, caught by its own test.** Splitting with
  `posix=False` on Windows keeps the quotes inside the token, so `python -c "sys.exit(1)"`
  reached the interpreter as a quoted *string literal*, evaluated cleanly and exited 0 — a
  failing test command silently reporting success, in the exact direction that certifies a bad
  patch. Split with `posix=True` on every platform; subprocess re-quotes correctly for Windows
  itself. [2026-08-12]
- **`SEC-CI-MUTABLE-ACTION` missed half of the branch refs it exists to catch** — it matched
  `@main`, `@master`, `@develop` and `@HEAD`, but not `@release/v1` or any other ref containing
  a slash. Found by pointing the scanner at this repository's own new release workflow, which
  had reached for exactly that form. A plain version tag (`@v4`) is still deliberately not
  matched: it is mutable too, but flagging it fires on nearly every workflow in existence, and a
  rule that fires everywhere gets suppressed everywhere. [2026-08-12]
- **The package could not be built at all.** `kit/pyproject.toml` declared
  `authors = [{ name = "mtvrkan", email = "" }]`, and an empty string is not a valid email in
  the metadata spec, so `python -m build` failed before producing anything. Found by building
  the wheel instead of trusting the manifest — nothing in the suite had ever built it.
  [2026-08-12]
- **Findings depended on the order files were walked in.** The module-graph fixed point made a
  fixed number of passes over the file list, so it settled wherever the passes ran out — and a
  pass that visits a callee before its caller propagates immediately, while the opposite order
  defers to the next pass. The same six files in two orders produced two different answers, and
  the failing one dropped the chain's *entry point*, keeping an interior module whose parameter
  merely might be tainted and losing the route where untrusted input actually enters. Replaced
  with a worklist over the reverse import graph that runs to convergence: order now changes how
  many steps it takes, never what it settles on. Chain depth is no longer capped either (was
  effectively 4 hops in the unlucky order), and it is faster, because a worklist re-derives only
  what a change can reach. [2026-08-12]
- **Nothing asserted that determinism**, which is why it went unnoticed — the existing
  cross-module tests each used one file order. There is now a test that runs four orders of the
  same six-module chain and requires one answer, *and* requires that answer to be the correct
  one, so it cannot pass by every order agreeing to miss the bug. [2026-08-12]
- **The taint test runner crashed instead of printing failures** containing any non-Latin-1
  character, on a cp1254 console: the reporter had no stream reconfigure, so a `UnicodeEncodeError`
  traceback replaced the failure list and sent the reader after the wrong bug. [2026-08-12]
- **A multi-module chain blamed the middle module.** `FunctionSummary` carried the sink's line
  but not its file, so in `A -> B -> C` the finding pointed at B. The file now travels with
  the line, and the rendered path distinguishes the three cases — sink here, sink in the
  function just called, sink further down the chain — because `inside b.py:relay()` names a
  function that does not live in that file. [2026-08-12]
- **Cross-module imports were invisible in JavaScript** because the import scan ran over
  `code_view`, which blanks string-literal *contents* — and a JS module specifier is a string
  literal, so `require('./util')` became `require('      ')`. Python was unaffected (an import
  names a module, not a string), which is exactly how a bug like this survives: it works in
  one language and the other looks like a missing feature. [2026-08-12]
- The recorded LLM response in `kit/tests/fixtures/llm-response.json` pins line numbers, so
  editing a fixture above one of them broke the two-tier test with "SQLi was not confirmed" —
  sending the reader into the merge logic after a bug that was really a moved line. The
  assertion now reports which lines the detector actually fires at and names the file to
  update. [2026-08-12]
- **The JS `return` handler ignored sanitizers** while assignment propagation honoured them,
  so a helper that constrained its argument and returned the result
  (`return ALLOWED.has(v) ? v : 'a'`) was summarised as passing taint straight through, and
  every caller inherited a false positive from the one place that fixed it. Found by the
  laundering assertion in the new JS interprocedural test. [2026-08-12]
- `SEC-RS-UNSAFE` was first written against CWE-1108 (excessive reliance on global variables),
  which is not the weakness being flagged. It is CWE-758 — reliance on behaviour the language
  does not define. Caught by consistency check 24, which refuses any CWE the engine emits
  without an ASVS chapter. [2026-08-12]
- **Eval scoring compared basenames**, so a detection in `vulnerable-app/auth.js` scored as a
  false positive against the `secure-app/auth.js` trap of the same name — reporting 7 trap
  false positives where there were none, and understating precision by 29 points. Path
  matching is now component-aligned. Caught on the harness's first run. [2026-08-12]
- Golden-set labels for V9 and V15 were incomplete, scoring correct detections as misses: V9's
  Dockerfile plants three distinct issues (root user, unpinned base, baked secret) but listed
  only one CWE, and V15's eval sink is correctly classified as CWE-95, a child of the listed
  CWE-94. `expected-findings.md` now documents the two admissible reasons to widen a label,
  because widening one and improving a scanner produce the same green build. [2026-08-12]
- `build_ground_truth.py` parsed `CWE-502/94/95` with a repeated capture group, which in
  Python keeps only the last repetition — silently dropping the middle CWE. [2026-08-12]
- The secure fixture's `Dockerfile` used a marker form (`S9 ↔ V9`) no other secure file uses,
  so it carried no false-positive trap. The negative control is now symmetric: one trap for
  every planted flaw. [2026-08-12]
- `test_engine.py` and `grade-report.py` hardcoded the golden-set size (`range(1, 21)`,
  `!= 20`). Both now derive it, because a literal count keeps a test passing while it silently
  stops covering a newly planted flaw — and the natural "fix" is to bump the number, which
  cements the gap. [2026-08-12]
- The eval gate compared a raw float against a floor stated to three decimals, so a value that
  renders as exactly the floor (0.9569… vs 0.957) failed it. Both sides are now compared at
  the precision they are published at — an off-by-epsilon trap teaches contributors to lower
  the floor rather than fix the code. [2026-08-12]

- **Code-shape detectors no longer match inside string literals or comments.** 36 of the 76
  detectors describe code shape rather than literal text; those are now scanned against a
  view with comments and string contents blanked (offsets preserved, so evidence and line
  numbers are unchanged). Found by the dogfood gate: the kit's own new sink catalog contains
  the string `"eval": Sink(…)`, which the old `\beval\s*\(` rule read as a call to `eval`.
  Detectors that legitimately match inside a literal — secrets, SQL fragments, quoted header
  names, `createHash('md5')`, `alg === 'none'` — are unaffected. [2026-08-12]
- Taint findings rooted in a function parameter are reported one severity rung below the
  sink's inherent severity, because whether a parameter carries untrusted data is caller
  knowledge the analysis does not have. A report that ranks unproven leads at Critical trains
  people to ignore Critical. Corroborated pattern findings keep their full severity. [2026-08-12]

---

Methodology hardening from a real (non-fixture) dogfood engagement — a full source+live
audit of a production-scale Node/Express/Next.js app, run end-to-end through the skill.

### Added
- `web-tests.md` §4.2 — **CAPTCHA/anti-automation strength check**: verify a challenge
  response doesn't leak its own answer (SVG/HTML `<text>` nodes, response headers, hidden
  fields, predictable RNG) before trusting it as an effective control. Directly sourced
  from a live finding: a CAPTCHA's answer was recoverable from its own SVG response with a
  one-line regex, no OCR needed.
- `web-tests.md` §4.8 — sample security headers (CSP especially) from **more than one
  route class** (public page / authenticated page / API-JSON) before generalizing; page
  and API layers commonly run different middleware with different policies.
- `web-tests.md` §4.15 (new) — reflected-parameter checks must confirm the actual encoding
  context (e.g. SSR/hydration payload JSON-escaping) rather than concluding from a raw
  substring match alone.
- `runbook.md` — **"Session & credential hygiene during authenticated testing"**: persist
  auth tokens to a scratch file across tool calls (shell state doesn't persist between
  invocations), budget active-auth requests against the target's own rate limit before
  firing more, treat real/production credentials the user hands you as off-limits for
  destructive-adjacent live actions (mark such findings `PLAUSIBLE` via code review
  instead of live-confirming them), and revoke test sessions + delete cached token files
  at the end of the engagement.
- `runbook.md` — **"Parallelizing a Both engagement"**: for source+live audits, dispatch
  the static source-code track to a background subagent while live recon/testing runs in
  the foreground, then cross-reference. Cut real engagement wall-clock time roughly in
  half with no coverage loss.
- `SKILL.md` §2 — "URL + source" route now points at the parallelization pattern above
  instead of implying sequential execution.

Second pass — lessons re-mined from an earlier real engagement (`batukar.com`, a Critical
finding: unauthenticated config/settings endpoints leaking SMTP credentials wholesale):
- `api-tests.md` §API3 — expanded the one-line "excessive data exposure" mention into a
  concrete checklist: enumerate every config/settings-serving endpoint (public *and*
  admin — a shared-serializer bug usually hits both), diff the full response against what
  the UI actually consumes, grep field names for `smtp`/`key`/`secret`/`token`/`password`/
  `credential`. This exact pattern was the root cause of a real Critical (SMTP password
  exposed to every unauthenticated page load via an "intentionally public" settings
  endpoint).
- `api-tests.md` — documented the **no-op replay** technique: to safely test whether a
  state-changing endpoint is authz-protected without ever risking a real mutation, `GET`
  current values then `PUT`/`POST` them back unchanged (net diff: zero). Generalizes beyond
  API3 to any write-endpoint authz check.
- `web-tests.md` §4.14 — added a concrete live-test recipe for WebSocket/Socket.IO room
  authorization: connect unauthenticated, join the highest-privilege room observed in the
  client bundle, listen via a catch-all handler for a bounded window while triggering an
  unrelated harmless action, and rate the finding by whether a privileged event actually
  arrives (vs. flagging missing handshake auth as defense-in-depth regardless).
- `web-tests.md` §4.5/§4.8 — CORS rejection should return a clean 4xx, not throw a 500
  (uncontrolled error-path signal); duplicate/conflicting security headers from two layers
  (reverse proxy + app middleware) is its own finding independent of either value's safety.

### The first plugin build — 2026-07-11

The Claude Code plugin + marketplace for authorized, defensive security auditing of a live
URL or a source-code repo. This was written as `## [1.0.0] — 2026-07-11 · Initial public
release`, and it was never released: no `v1.0.0` tag exists, nothing was uploaded to PyPI,
and the repository has been private throughout. A version heading is a claim that an
artefact with that number exists and can be fetched; nothing here can be. Everything in this
file is therefore unreleased, and the first tag pushed will be `v1.0.0` covering all of it —
which is what `kit/pyproject.toml` and `docs/launch-checklist.md` already say. Check 30 now
refuses any version heading that has no matching git tag, so this cannot recur silently.

#### Core
- `/secaudit`, `/secaudit-code`, `/secaudit-passive`, `/secaudit-deps` commands.
- `security-audit` skill with a phased methodology (P1–P9) and progressive-disclosure references.
- `secaudit-verifier` adversarial finding-verification agent — **read-only** (`Read`, `Grep`,
  `Glob`, `WebFetch`, `WebSearch`, `Bash`; `Write`/`Edit` denied) with an explicitly skeptical,
  refute-first prompt. Fine-grained Bash scoping is enforced by the parent command's
  `allowed-tools` and the session's permission rules, not the agent frontmatter.
- Hybrid scanning engine: auto-uses `semgrep`/`opengrep`, `trivy`, `osv-scanner`,
  `gitleaks`, `trufflehog`, `grype`/`syft`, `noseyparker`, `zizmor`, `checkov`/`kics`,
  `testssl.sh` when installed; LLM-analysis fallback otherwise. Zero tools required to start.
- Safe-by-default posture with an authorization gate for active testing; active-recon tools
  (`nuclei`, `nmap`, ZAP, ProjectDiscovery suite) stay gated behind explicit approval.
- **Deterministic passive/active enforcement** via a PreToolUse hook
  (`hooks/active-scan-guard.py`): blocks offensive scanners, state-changing/payload-bearing
  HTTP requests, and read-only `GET`s carrying a crafted probe payload (SQLi/traversal/SSRF/
  XSS/SSTI/CRLF canaries) at the harness level unless `scope.yaml` asserts
  `i_am_authorized: true` or `SECAUDIT_ACTIVE=1` is set — not left to model discipline. The
  probe-payload check is high-precision (defense-in-depth, not a WAF). Ships with a
  `--selftest` (18 active blocked, 12 passive allowed) gated in CI.
- English + Turkish report output.

#### Coverage
- OWASP Web Top 10 (2025), API Top 10 (2023), LLM Top 10 (2025), Mobile Top 10 (2024),
  CWE Top 25; dependency/CVE (OSV/GHSA/NVD/CISA KEV); secrets; infra/IaC/containers.
- **Auth & identity** (`auth-identity.md`): JWT (`alg:none`, RS256→HS256 confusion,
  `kid`/`jku` injection), OAuth 2.0 / OIDC (`redirect_uri`, `state`, PKCE), SAML (XSW,
  comment-truncation), sessions, MFA, passkeys/WebAuthn.
- **Modern web** (`web-tests.md`): HTTP request smuggling / desync (CL.TE/TE.CL/CL.0/0.CL),
  web cache poisoning & deception, client-side prototype pollution, DOM clobbering,
  client-side path traversal (CSPT), Cross-Site WebSocket Hijacking, and XXE (CWE-611).
- **Agentic-AI & MCP** (`llm-ai-security.md`): OWASP Top 10 for Agentic Applications (2026, emerging)
  and MCP Top 10 (2025) — tool poisoning, rug-pull tool definitions, memory poisoning,
  indirect prompt injection (RAG / tool output / multimodal / Unicode-tag smuggling),
  per-action authz, tool sandboxing.
- **Supply chain**: self-replicating install-script worms (Shai-Hulud family), mutable-tag
  CI compromise (`tj-actions` CVE-2025-30066), slopsquatting, `xz`-style build backdoors,
  provenance verification (npm provenance / SLSA / Sigstore, `npm audit signatures`).
- **CI/CD hardening** (`infra-cloud.md`): `zizmor` auditor, SHA-pinning, `pull_request_target`
  and script-injection checks, OIDC / trusted publishing, subdomain-takeover / dangling DNS.
- **API depth** (`api-tests.md`): GraphQL (introspection, depth/alias/batching), rate-limit
  bypass, gRPC, HTTP/2 Rapid Reset (CVE-2023-44487) — assessed by version/config, never flooding.
- **Mobile** (`mobile.md`): IPC/exported-component & deep-link/universal-link takeover,
  runtime hardening (Frida/objection), dynamic toolchain (MobSF, apktool/jadx, adb, proxy).
- Business-logic / race-condition and cloud IAM privilege-escalation coverage.

#### Reporting
- Severity-ranked findings with impact, evidence, root cause, specific fix, and retest step.
- `CONFIRMED` / `PLAUSIBLE` / `REFUTED` verdicts plus a "Considered & Dismissed" section, a
  dependency/CVE register, positive controls, and a 24–72h / 7–14d / 30–60d remediation roadmap.

#### Quality & safety
- Self-test harness: a **multi-language** intentionally-vulnerable fixture (`tests/fixtures/`)
  with **20 planted code flaws** (16 JavaScript + 4 Python), a golden set
  (`tests/expected-findings.md`), a fallback-mode dogfooding run (`examples/self-test-report.md`),
  and a deterministic `tests/selftest.py` that mechanically asserts all 20 sinks + 3 secrets
  are present and that `npm audit` reports the cited CVEs.
- **Precision (negative control):** a paired **secure** fixture (`tests/fixtures/secure-app`)
  implementing the *same* 20 features safely (S1–S20 ↔ V1–V20), with an expected-clean spec
  (`tests/expected-clean.md`). Measures false-positive rate — the complement of the vulnerable
  fixture's recall. `selftest.py` gates it deterministically: no vulnerable sink marker may
  reappear **and** every safe control must stay present, so the corpus can't drift into being
  vulnerable or be emptied out.
- Report grader (`tests/grade-report.py`): scores any produced report against the golden set
  (CWE + unique-token matching, coverage + dependency/secret-section gates), and runs in CI
  against the reference report (`--min 20`) so it can never silently drop a finding.
- CI validation workflow (`permissions: contents: read`, SHA-pinned actions): JSON-manifest
  validity, unknown-manifest-field rejection (mirrors `--strict`), frontmatter, command
  Bash-allowlist-subset, reference-integrity, relative-link, and stray-secret checks, the
  fixture self-test, the golden-set coverage gate, the **PreToolUse hook config + guard
  self-test**, and a **pinned, blocking** `zizmor` self-lint.
- Scope template, sanitized example report, and full documentation set.

#### Standalone kit (provider-agnostic, self-running)
- `kit/` — a dependency-free Python CLI that runs **outside** a Claude Code session (CI / cron /
  shell) and is **not tied to Claude**. Two tiers: **Tier 0** (deterministic detectors + installed
  scanners + `npm audit`, no LLM, always runs) and **Tier 1** (optional LLM enrichment — triage +
  logic-bug discovery — with a pluggable backend: `anthropic` / `openai` / `ollama` (local) /
  `none`, all over urllib, no vendor SDK). Claude stays the best default but is optional.
- **Detector pack:** 66 built-in deterministic detectors across JS/TS, Python, Go, Java, PHP,
  Ruby, C#, Kotlin, Swift, Dart, Dockerfile, Terraform, and Kubernetes — injection,
  deserialization, SSRF, XXE, weak crypto, secrets (AWS/GitHub/Slack/OpenAI/Google/Stripe/JWT/
  private-key), CORS/cookie config, cloud IAM/storage misconfig, and mobile (WebView JS-interface,
  ATS, world-perms, Flutter cert-bypass) — each with an optional `suppress_if` control marker.
  Secret findings are **redacted** (the kit never prints secret values; asserted in tests).
- **Installed-scanner integration:** semgrep (SARIF), gitleaks (JSON), and osv-scanner (JSON)
  are used when present and normalized into the common schema; higher-fidelity sources win on
  collision. Gracefully falls back to the built-in pack when a scanner is absent.
- **Reproducible, LLM-free measurement** (`kit/tests/test_engine.py`, CI-gated): **19/19** target
  sink classes found on the vulnerable corpus with **0 HIGH-confidence false positives** on the
  secure negative control. The one class the deterministic tier can't reach (V3 / IDOR / missing
  authz) is reserved, by design, for the LLM tier.
- **Real-code precision** (`kit/tests/test_dogfood.py`): the engine scans the kit's own ~1.5k-line
  production source (real code, nothing planted) and must report **0 High/Critical** — a
  false-positive check on genuine code, not a tuned fixture.
- **Two-tier pipeline, verified whole:** `kit/tests/test_enrich_e2e.py` runs Tier-0 → LLM triage →
  report in CI via a *replayed* model response (no key), asserting the LLM tier adds the IDOR/V3
  finding and triages Tier-0 leads. `kit/tests/test_live_llm.py` runs the same against a **real**
  provider when a key/Ollama is present and skips cleanly in CI. A `replay` backend makes captured
  responses reusable.
- **Output & CI:** Markdown / JSON / **SARIF 2.1.0** (GitHub code scanning); `--min` severity gate
  (non-zero exit); a bundled composite **GitHub Action** (`kit/action.yml`) + example workflow.
  Packaged via `pyproject.toml` (`secaudit` console entry point, zero runtime deps). UTF-8 output
  forced so a legacy console codepage can't crash a report.
