# Changelog

All notable changes to SecAudit are documented here. This project follows
[Semantic Versioning](https://semver.org) and [Keep a Changelog](https://keepachangelog.com).

## [Unreleased]

### Added
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

## [1.0.0] — 2026-07-11

Initial public release — a Claude Code plugin + marketplace for authorized, defensive
security auditing of a live URL or a source-code repo.

### Core
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

### Coverage
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

### Reporting
- Severity-ranked findings with impact, evidence, root cause, specific fix, and retest step.
- `CONFIRMED` / `PLAUSIBLE` / `REFUTED` verdicts plus a "Considered & Dismissed" section, a
  dependency/CVE register, positive controls, and a 24–72h / 7–14d / 30–60d remediation roadmap.

### Quality & safety
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

### Standalone kit (provider-agnostic, self-running)
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
