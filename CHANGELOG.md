# Changelog

All notable changes to SecAudit are documented here. This project follows
[Semantic Versioning](https://semver.org) and [Keep a Changelog](https://keepachangelog.com).

## [Unreleased]

### Fixed
- **Every page shipped a Content-Security-Policy naming a hash of bytes that were not in the file, so the browser blocked the site's own script and the whole site went still.** The build hashed the inline script and *then* edited it: `strip_comments` ran at write time, and its line filter drops the script's trailing newline whether or not there was a comment to remove. One byte, and `script-src 'sha256-…'` stopped matching. Nothing errored on the page — there is no visible failure mode for a blocked inline script — so what a reader saw was a site with no reveals, no counting figures, no typed hero line, no nav-pill highlight, no back-to-top button, and a header that never went opaque as it passed over the content. Comments now come out **before** the hash is taken, so what is hashed is what is written, and `verify` re-derives the hash from the shipped page and fails the build when the two part company — asserted by rebuilding the old byte order and watching the new gate reject it. All 45 gates green. [2026-08-22]
- **The sticky header was not sticky on iOS, and the line that broke it was there to stop sideways scrolling.** `body{overflow-x:hidden}` makes `body` a scroll container of its own while `html` stays `visible`, and a `position:sticky` child then pins to that container rather than to the viewport. Chrome keeps the header pinned regardless, which is why it went unnoticed; WebKit does not, so on a phone the topbar scrolled away with the content — and below 62rem the pinned nav capsule is hidden, leaving the page with no chrome at all. The clip moved to the root, `html{overflow-x:hidden;overflow-x:clip}`, where the viewport takes it and no new scroll container is created. Both declarations deliberately: `clip` is the right one and is Safari 16+, and a browser that does not know it falls back to `hidden` on the root, which propagates to the viewport and leaves sticky alone. `body` now declares no overflow at all. [2026-08-22]

## [1.0.0] — 2026-08-21

First published release. Everything below was built before it and is listed under it rather than
split across invented earlier versions: there was no earlier version, and a release history that
implies otherwise is the same typed-and-wrong claim the rest of this repository exists to refuse.
Check 30 holds this heading against the `v1.0.0` tag, so the claim cannot outlive the artefact.

### Added
- **One command that re-measures every published figure, and it is a gate.** `scripts/measure_all.py` freezes the engine digest before the first scan and re-checks it after the last, takes an `O_EXCL` lock so two runs cannot write the same per-entry caches, runs RealVuln → noise floor → SecBench.js → CVEfixes, and prints the delta against the committed figures. Both things it prevents happened by hand on 2026-08-20: a one-word comment moved the digest mid-measurement (`engine_digest` hashes bytes) and left four result files describing three engines, and two CVEfixes scans raced the same cache. Corpora absent from the machine are **skipped out loud**. `--selftest` — the lock is exclusive, all four result files render, the digest is complete — is check 45. [2026-08-20]
- **SSRF reaches the ordinary outbound-HTTP surface: 3 sink names became 21.** The rest of the `requests` verbs, a bare `urlopen`, `httpx`, `urllib3`, and `request`/`putrequest` on a receiver named like a connection. `session` is deliberately **not** a receiver and `.get()`/`.post()` are deliberately not method sinks: `session.get(key)` is a Flask dictionary lookup, and the taint requirement does not save it. **Measured: +0 true positives on RealVuln, +1 false one, and zero findings across 2,674,253 lines of noise floor.** The widening was built on a correct reading — 16 of 21 missed SSRF labels had no finding of ours in the file — and a wrong conclusion about why: fourteen are in one file where every call is higher-order (`_urlopen(urlopen, user_input)` passes the sink *function* as an argument), which no vocabulary reaches. Kept as an unmeasured improvement, labelled as one. [2026-08-20]
- **`SEC-PY-DEBUG-CONFIG` — and the reason it had to be its own rule is worth more than the finding.** Code-shape rules are matched against `code_view`, where the *contents of every string literal are blanked*, so `app.config['DEBUG']` arrives as `app.config['     ']` and a pattern naming the key inside the brackets is **dead text**: it matches in a unit test and never in a scan. The same trap took the client-decision rule two rounds ago. The new rule reads the raw text (`literal=True`, as the secret rules do) with a comment-line suppressor, since raw text still has comments in it. `SEC-PY-DEBUG` gained the two spellings that survive blanking — `app.debug = True` and `app.config.update(DEBUG=True)`. **RealVuln F3 61.1 → 61.2**, 1070 / 561 / 692. [2026-08-20]


### Removed
- **The install page lost its four reference blocks and kept every install path.** Gone: the release-state section (which surface waits for a tag, and the PyPI trusted-publishing note), the seven-row `action.yml` input table, the six-tool MCP manifest, and the sentence of prose under each of the four slash commands. What stays is what somebody types — the two plugin lines, the `pip` lines, the per-client MCP config for five clients, the workflow snippet, the Docker and pre-commit blocks. The page went from 363 rendered lines to 256. **One sentence was rescued rather than cut**: `pip install secaudit-kit` can still succeed with somebody else's package until the name is claimed, and that warning now sits under the CLI block where a reader is about to run the command. The readers behind the deleted tables still run — `in_action` and `in_mcp_tools` are read at build time and still fail it when `action.yml` or `docs/mcp.md` disagrees with the code. [2026-08-20]
- **Three pages, and the machinery under them: `/cra/`, `/docs/` (plus one page per file in `docs/`) and `/demo/`.** The site is nine pages instead of thirty-one, and what went with them is the ~300-line markdown renderer that existed only to serve the documents, the build-time demo transcript, and four stylesheets. The reasoning is the one the roadmap already used to cut a separate "what it is" page: `docs/*.md` is read on GitHub where it is versioned beside the code it describes, the landing page's hero already shows one finding in full, and a page arguing a regulation is a second subject a reader of a scanner did not come for. The CRA *evidence pack* is untouched — `--format cra` produces it — and the one date a reader acts on is still on the landing page, still read from `compliance.py`. All 44 gates green after the removal, which is its own small finding: no check depended on those pages. [2026-08-20]

### Changed
- **The templates and stylesheets in `site/` carry no comments at all now — 53,870 bytes, 40% of that source, moved to `.claude/SITE-NOTES.md`.** Removed rather than kept-and-stripped-at-build, because the global rule is about the file as well as the byte: anything served as-is is public, and a `site/` full of prose about itself reads as scaffolding rather than as a product. **Moved, not deleted** — 169 comments are in the notes file with their line number and the declaration each one preceded, because a rule whose reason is gone gets "simplified" by the next person and the bug it was written for comes back. The notes live under `.claude/` beside `TECH-DEBT.md` rather than in `docs/`, since `gen_site.py` fails the build on an unlinked `docs/*.md`. Verified the only way this can be: the built pages are **content-identical** — 897 of 898 lines byte-for-byte, and the one that moved is the CSP meta tag, whose `script-src` hash *had* to change because the inline script's bytes did. [2026-08-20]
- **The site was shipping 43 KB of its own commentary to every reader — 38% of the landing page — and the build drops it now.** The templates in `site/` explain every rule that looks arbitrary, which is right; serving those bytes is not. `strip_comments()` removes them from what is written to `dist` while the source keeps them, so the reasoning stays in the repository where it is versioned beside the code and a change to it is reviewable. The landing page went **112,437 → 66,186 bytes**. Three deliberately conservative passes: block comments in `<style>`, block comments plus *full-line* `//` in `<script>` — a trailing `// note` is left alone because `https://` is the same two characters and telling them apart needs a parser — and HTML comments last, after both regions are placeholdered so a `<!--` inside a script is not read as markup. `<script type="application/ld+json">` is skipped entirely: JSON has no comments to remove and a stripper run over it can only damage a string. Verified rather than assumed — every page's JavaScript passes `node --check` and every JSON-LD block parses, and the built page was rendered in headless Chrome to confirm the reveal system still runs. [2026-08-20]
- **Both READMEs now say what the tool does before they say how well it does it, and the decorative icons are gone.** The page opened with a tagline, a command block and then three benchmark bullets — a reader could get four screens in without learning that it reads a repository, follows untrusted input to dangerous calls, checks dependencies for reachability, finds secrets and reads infrastructure files. A new **What it actually does** section says that plainly: what it takes, what it reports for a repo, what it does with a URL, what comes back, and how it runs. Six bullets that the new section made redundant were deleted rather than left to say the same thing twice. Every decorative emoji was removed from headings, bullets and callouts; the only symbols left are the ones carrying meaning — the arrows in a taint path, the box-drawing in the pipeline diagram, and the ticks in the comparison table. The social card now opens both files, which is also the first check that it renders. [2026-08-20]
- **The social card is HTML rasterised by Chrome now, and the gate it used to justify was rebuilt rather than dropped.** It was drawn in pure Python — `zlib` plus a 52-glyph stroke font — on the argument that a build step needing a browser fails for a contributor who has done nothing wrong. **That was right about the gate and wrong about the asset.** What it bought was a card nobody could design: no lowercase, no serif, no italic, no gradient, everything set in one outlined mono face. So the two concerns are separated instead of traded. Rasterising shells out to Chrome and is run **by hand**, with the PNGs committed as source. Freshness — the part the stroke font was really protecting, because the card prints a measured figure — is still a gate: `site/og.facts.json` records the figures each committed card was drawn from and `--check` holds that against `gen_site.facts()` **without opening a browser**. Move a number and the build fails until the cards are redrawn; a contributor with no Chrome still runs all 45 gates. The card itself now follows the house style of the other kit: warm radial glow, rounded mark tile, monospace wordmark, a serif headline whose accent half is italic, and a footer row carrying the domain against the measured figure. `scripts/strokefont.py` went with it — 148 lines that existed only to letter that card. [2026-08-20]
- **The social card was redesigned around what the product *is* rather than around its largest number.** It carried nine figures: a 130px `61.2`, a four-column strip of detectors / languages / gates / dependencies, a strap under the wordmark, and the mark again at five times its header size bleeding off the right edge. Every one was true and derived, and together they said nothing — a reader who has never heard of this project saw a number as the biggest thing on the card and no way to tell it was a security scanner at all. A social card is read at thumbnail size by somebody who is not looking for you. Now: the mark, one two-line statement of what it is, one line of evidence for it, the domain. The number stays **external** (F3 on RealVuln, scored by their scorer) because a card leading with the internal fixture figure is the exact mistake this file's history records. The Turkish card drops "çevrimdışı" rather than "güvenlik": `ÇEVRİMDIŞI GÜVENLİK DENETİMİ` needs type at 43 where the English line sets at 58, and of the two adjectives the one naming what the product *is* wins. [2026-08-20]
- **The pinned section-nav capsule is gone below 62rem.** On a phone it had stopped being navigation and become a floating bar over the content: it needed sideways scrolling to read, 4.6rem of body padding so it would not sit on the footer, and it pushed the back-to-top button up with it. Three accommodations for a control that duplicates scrolling. The page's sections are reachable by scrolling and the site's pages are in the footer. Removed with it: the body padding, the button's displacement, and a `--chrome` reservation that was cropping 4.6rem off every mobile hero to make room for an element that is no longer drawn. [2026-08-20]
- **`README.tr.md` is now a full document rather than a third of one — 181 lines to 455, at parity with the English page.** It was missing the entire install, usage, standalone-CLI, comparison-table, features, MCP, ethics and contributing halves, and — more seriously — it was missing the **noise floor** entirely, which is one of the four headline numbers and the only one that answers "how much of my time will this waste". The English page lost 47 lines in the same pass: three round-by-round narratives about *how* a benchmark figure moved belong in `eval/` and this file, not in the document somebody reads to decide whether to install anything. Every measured figure, every caveat and every disclosure stayed. [2026-08-20]

### Fixed
- **Our CycloneDX document was not a CycloneDX document to the first consumer that read one, and the release pipeline is where we found out.** `--format cyclonedx` emitted no `serialNumber` unless a caller supplied one, and the CLI never supplied one; `actions/attest` requires `bomFormat`, `specVersion` **and** `serialNumber` before it will accept a file as CycloneDX, so `v1.0.0` failed at the attestation step — after the wheel had built and passed its clean-venv smoke test. The field is optional in the schema and mandatory in practice, which is the more useful definition. It is now **derived from the document's own JSON** (`uuid5`, a real RFC 4122 URN) rather than randomised, so `sbom.py` keeps the promise its docstring makes: the same tree still produces a byte-identical BOM, and a diff between two of them still shows dependency changes rather than a fresh UUID. Asserted in `test_compliance.py` against all three fields the consumer checks — the previous test asserted the two we happened to emit. `sbom.py` is outside the engine digest (`reached only by --format cyclonedx`), so no measured figure moved. [2026-08-20]
- **The figure rows sat at four different heights, and the fix that was supposed to prevent that was under-reserving by an em.** `.stat` bottom-aligned each cell, so a label wrapping to two lines pushed its **number** up — the first thing a reader looks at was the thing out of line. `min-height:2.4em` on the label was meant to equalise one- and two-line labels and could not: the label inherits `line-height:1.6`, so two lines need `3.2em`. Numbers are top-aligned now, the label carries its own `line-height:1.35` against a matching `2.7em` reserve, and a row containing the emphasised `.stat.big` figure reserves that figure's height for every number box in the row — without which the taller number pushed its own label 7px out of line, a defect that was there before the reported one and that nobody had noticed. Measured, not eyeballed: number and label spreads are **0px** on all three rows, and an audit over all nine pages in both languages — comparing the first text element of every same-class sibling sharing a visual row — reports nothing above 2px. The rationale is in `.claude/SITE-NOTES.md`, since the stylesheet no longer carries comments. [2026-08-20]
- **The 404 printed the same message twice, once per language, and now prints one.** Two stacked headlines, then the same paragraph in English and Turkish — which reads as a page that could not decide rather than as one that speaks your language. GitHub Pages serves a single `404.html` for the whole site and cannot choose by path, so both halves stay in the markup and the stylesheet shows one; the address that failed is the cue, and a path under `/tr/` gets the Turkish half. The eyebrow became one pill per language rather than one carrying both — `.seg` sizes its ends with `:first-child`/`:last-child` and a *hidden* segment still matches those, so hiding one inside a shared pill leaves the visible end unpadded. The Turkish line is the headline's second line, set in the code face and the accent colour as a contrast to the first; shown alone it now takes the first line's treatment, so both languages get the same page. English shows with no script, since it is the site's `x-default`. [2026-08-20]
- **The back-to-top button no longer sits on the footer it duplicates.** It hides again in the last 120px of travel, where the footer already carries the site's links — on a phone it was a filled circle on top of the byline. [2026-08-20]
- **The footer stopped falling to the left edge when it stopped fitting on one line.** `space-between` has nothing to distribute once the three blocks wrap, so each landed left at a different width. Centred below 48rem, where they read as the one signature block they are. [2026-08-20]
- **`sitemap.xml` carried no `lastmod`,** so every URL looked equally fresh forever and the pages that change when a number moves looked no different from the install page. It is derived, like everything else here — the newest date in `CHANGELOG.md`, which is this repository's own record of when it last changed. A wall-clock `today` would be worse than nothing: it would claim a modification on every build, which is the inaccuracy that makes a crawler stop believing the field, and it would break the reproducible-build gate the next day. The file is also written one URL per line now instead of on one line. [2026-08-20]
- **Two more figures were stale, in the Turkish README, and they were stale because of the shape of the page.** It stated the SecBench.js classes as inline prose — `prototype-pollution` **62/185** and `redos` **26/87** where the scorer says **72** and **28** — and check 35 gates that table by matching *table rows*, so prose was invisible to it. The Turkish page now carries the same table in the same shape, and check 35 reads **both** READMEs. Third instance of one defect in one day: a translated page is the one nobody re-reads when a number moves. [2026-08-20]
- **The front page understated the tool by twenty labels, in the sentence claiming nothing had moved — check 45 now holds every family score written into prose.** `README.md` read "What still does not move: `broken_access_control` (1/76), `missing_auth` (4/74) and `path_traversal` (3/39)." The scorer said **2, 7 and 23**. Path traversal is the instructive one: it had gone 3 → 23 of 39 after the round that read its labels, so the sentence was not merely stale — it was denying an improvement this project had already made and measured, on the page every reader starts at. Check 27 has held `eval/realvuln/README.md`'s table cell by cell since the day a table cell went stale; nothing held the **prose**, which is where a number gets quoted to somebody who will never open the table. Check 45 reads every `` `family` (N/M) `` in `README.md`, `README.tr.md` and `docs/*.md` against `by_family`. CHANGELOG and the plan documents are excluded by design: a dated entry recording that a family stood at 1/76 that day stays true. [2026-08-20]
- **The page that documents our weaknesses had a stale number on it, and the gate that guards this repository's numbers could not see it — on the site too, in both languages.** `docs/what-we-miss.md` said the access-control rule finds **1 of 76** labelled cases; the scorer had been saying 2 since 2026-08-18, when a Django routing fix moved it. The reason nothing caught it is the shape of the check: the drift gate compares the page against `gen_what_we_miss.py`'s output, and the number was typed **inside the generator**, so a stale figure was stale in both and the two agreed. `gen_site.py` carried the same literal a third and fourth time, in the EN and TR copy of the landing page's misses section. Both generators now substitute `[[token]]` figures — the access-control one read from `eval/realvuln/result.json` at build time — and both **refuse prose that types a count** rather than referencing one, so the next one cannot be introduced quietly. The six remaining per-rule counts have no committed source to derive from, so they now print the date they were measured instead of borrowing the authority of a derived figure. A measured number typed into copy was the only kind in this repository that nothing held. [2026-08-20]
- **The Turkish landing page said "korpus" in the one place the sweep missed** — the misses section, rewritten to "veri kümesi" with the rest of it. [2026-08-20]
- **The comparison page was quoting Anthropic in words Anthropic never wrote.** Its own rule is *quoted, not paraphrased* — it prints the source and the date it was read beside the sentences — and the Turkish tree rendered both quotations **in Turkish**, under a panel headed `code.claude.com/docs`. A translated quotation is not a quotation, and this is the one page on the site that makes factual claims about somebody else's product. The originals now stand in their own language in both trees, with the Turkish reading below each one as a separately styled gloss, marked as ours. [2026-08-20]
- **The quotation panel's two halves sat on two different left edges.** `#quotes .reg li` carried `padding:1.5rem 0`, so each quotation started hard against the panel border while `code.claude.com/docs` sat 1.1rem in — the header read as inset and the content read as having escaped it. The rows take the chrome's own 1.1rem now, so the first character of a quotation lines up with the first traffic light above it, and the rule between the two quotations stays full-bleed because a border draws on the box rather than inside the padding. [2026-08-20]
- **The closing card is taller and its heading is wider, and the two changes belong together.** Lowering the heading with a top margin was the wrong instrument: it pushed the block down inside a card whose padding had not moved, so the gap above the heading grew to twice the gap under the buttons. Padding does the same job symmetrically — the content stays centred and the whole card has more room. The width is the other half: `.finale h2` is capped at 18ch in the shell, which is right for `Install the official plugins. Then install this one.` and wrong for a Turkish sentence of the same meaning, which broke into three lines mid-clause. At 26ch both languages fall on their own two sentences. [2026-08-20]
- **(superseded the same day) The closing card's heading was two lines lower via a margin.** `.finale` centres large type in a tall padded card and the first line landed close enough to the top edge to read as the card's cap. `2lh` — two lines of the heading's own text — keeps the gap right when the heading wraps to a different number of lines in the other language, with a rem fallback for a browser without the unit. [2026-08-20]
- **The comparison page's eyebrow had no padding at all.** Every other eyebrow on the site goes through `segments()`, which is what puts the text inside a padded `.seg` — this one was interpolated straight into `.pill`, and `.pill` carries no padding of its own precisely because on every page written correctly the padding belongs to the segment. The capsule drew its border hard against the glyphs, which Turkish shows first: `ğ` reaches higher and `ç` lower than the ascii the layout was eyeballed in. It renders like the others now, the first and last segments get extra padding so the rounded ends do not eat into them, and a `:not(:has(.seg))` floor stops the next capsule doing it silently. [2026-08-20]
- **The Turkish comparison copy was rewritten end to end.** It read as a translation rather than as writing: `checkout'unuzdaki` for a working copy, `çok-ajanlı`, `kahramandaki bağlantıyı` for "the link in the hero" — a literal rendering of *hero* that means "in the protagonist". Every string on the page is redone in a professional register, `cevap` giving way to `yanıt`, anglicisms to Turkish, and the em dashes and separators matching the English tree. [2026-08-20]

### Fixed
- **Two heroes were giving part of the first screen away, and the rule now asks instead of assuming.** `.hero .heroinner` reserves the section's own bottom padding — `100svh - chrome - pad-b` — because on every other page the thing after the hero is the *next section*, and that reservation is what lands it exactly at the fold. Two heroes carry more inside themselves: the benchmark page keeps its result matrix there and the install page keeps the four counts and the six surface cards. The reserved strip handed itself to that sibling and it peeked in under the note. `.hero:has(.heroinner + *)` asks the question the arithmetic was assuming an answer to, so neither page needs an override of its own — the install page's, added earlier the same day, was deleted. [2026-08-20]
- **(superseded the same day) The install page's stat row was peeking above the fold.** `.hero .heroinner` reserves the section's own bottom padding — `100svh - chrome - pad-b` — because on every other page the thing after the hero is the *next section*, and that reservation is what lands it exactly at the fold. The install hero carries the four counts and the six surface cards *inside* the same section, so the reserved strip handed itself to the counts and they showed under the note. The copy column takes the whole first screen here; everything else starts below it. [2026-08-20]

### Changed
- **`korpus` is `veri kümesi` in Turkish — 46 occurrences, and the headline it fixes is the benchmark page's own.** A Latin loan nobody outside the field reads has been replaced by the ordinary phrase for a dataset. `korpusu` was the one form that could not be replaced mechanically — it is both the accusative (`bu korpusu okumadı`) and the possessive (`başkasının korpusu`), which take different endings — so those eight were done by hand. `kıyaslama` stays reserved for *benchmark*, which is why the noun could not be that. The Turkish headline needed three characters more than the shared `17ch` and had broken into four lines; `html[lang="tr"] .hero h1` gets 26ch and it is two again — scoped by language, because the English headline sits correctly where it is. [2026-08-20]
- **`motor` is `çekirdek` everywhere the site and the README speak Turkish.** Thirty-seven occurrences across four copy modules, `README.tr.md`, the Turkish locale bundle and one string still living in the generator — every inflection carried over rather than pattern-replaced, so `motoru` became `çekirdeği` and `motordan` became `çekirdekten` rather than something a reader trips on. `katman` stays reserved for *tier*, which is why the noun could not be that. [2026-08-20]
- **The run-history table is now in the reader's language.** Twenty-nine round labels live in `eval/realvuln/result.json` in English, because that file is the record a benchmark maintainer reads — so the Turkish page rendered twenty-nine English sentences inside a translated table. `RUN_LABELS_TR` translates them and **a missing translation fails the build** rather than falling back: a fallback is invisible from the page that needs it, in the language its author does not read. [2026-08-20]
- **Scrollbars and stat rows, both of which were the platform's defaults showing through.** A horizontal overflow on a dark page was drawing the operating system's own opaque white trough across the bottom of a table; the scrolling regions are themed now, with a stable gutter so a table does not shift when its bar appears. And the four figures in a stat card sat on four baselines — the lead figure is 2.8rem and its neighbours 2rem — so their captions started at four heights; the tall row is reserved and bottom-aligned, the caption has a two-line floor (`tuzaklarda yanlış pozitif` wraps in Turkish and not in English, which is why the misalignment differed per language), and a card's stats are pinned to its bottom so a neighbour's longer paragraph cannot skew them. [2026-08-20]

### Added
- **A login the project never wrote — RealVuln F3 60.5 to 61.1, recall 0.5999 to 0.6067, precision 0.6577 to 0.6562.** Django ships the credential-testing endpoints most projects use, and a project that uses them writes no handler at all: `path("accounts/login/", auth_views.LoginView.as_view())` is the whole login. Every structural rule here reads a *function*, so on this shape there was nothing to read and the rate-limit rule was silent on **eighteen labelled cases of exactly the flaw it exists to find**. `RATELIMIT-PY-AUTHVIEW` reads the URL conf, and asks the **project** rather than the module whether attempts are bounded — `django-axes` is an entry in `INSTALLED_APPS` and a middleware line in `settings.py`, and the file that wires the login never mentions it. **22 findings, 12 true positives, 10 false ones, labelled traps unmoved at 248**; the ten are Django projects with no limiter of any kind whose sibling repository carries a hand-written label on the identical line — unlabelled rather than wrong, and counted against us anyway. `LogoutView`, `PasswordChangeView` and `PasswordResetConfirmView` are excluded on purpose: the first tests nothing, the second is behind a session an attacker would have to hold already, and the third tests an HMAC Django generated rather than a secret a person chose. The other three corpora were re-measured because the engine digest moved, and they say the rule is as narrow as it claims: **zero findings across 2,674,253 lines** of noise floor (which holds no Django project, so that silence is real and its instrument is narrow — both belong in the same sentence), SecBench.js unchanged to the digit, and CVEfixes one finding heavier at 28,167 with every recall figure unchanged to the digit. [2026-08-20]

### Fixed
- **A project's own auth middleware was invisible to the missing-auth rule, and only a real application could show it.** `mw.authAdminApi` is Ghost's name for its own guard, used **220 times**, and no marker list can contain a name a project invents — so every route carrying it was reported as unauthenticated. `_AUTH_NAMING` reads the naming *convention* instead: `auth` followed by a capital, which is also its precision, because `author` and `authority` continue in lower case. A fixture pins both directions. [2026-08-20]
- **Ember's Mirage mock server counted as production code.** `mirage/config/posts.js` mounts `server.post('/posts', …)` with no authentication because it *is* the fake backend a test talks to — 26 findings, every one about a fixture. [2026-08-20]

### Added
- **`TryGhost/Ghost` and `directus/directus` joined the noise floor, for the reason phpMyAdmin joined a round earlier.** The JavaScript structural rules ask what a request **handler** does, and the corpus held an HTTP framework, an HTTP client, a date library and a promise library — none of which mounts a route. Those rules had been measured against a corpus that could not contain their subject and reported zero for it. The two applications reported 730 findings between them, the first read of which produced both fixes above: **1,252 findings → 1,119, High+Critical 376 → 243**, with the thirteen previously-measured trees unchanged to the digit at 389 and 0.28 per 1,000 lines. The published floor is now **0.42 per 1,000 lines over 2,674,253 lines**, and the two Express applications are its upper half — 0.47 and 0.75 against 0.28 across the libraries, which is the number to quote for an application. [2026-08-20]

### Added
- **One commit can be a hundred labels, and `result.json` now says which cells that happened in.** A CVE fixed by a repository-wide refactor deletes lines in hundreds of files and every one becomes a labelled entry, so a per-language cell can read as a broad detection failure while being three commits wearing many filenames. The new `concentration` block is computed from the labels rather than from the scan, and it cuts both ways on purpose: **TypeScript's 8.8% is partly this** — its three biggest cells are 372, 372 and 237 labels from *one commit each* — and **`JavaScript CWE-707` at 90.7%, the best figure on the page, is one CVE too** (264 labels, one commit). Neither number is wrong; both are narrower than they look, and this makes that checkable instead of something a reader has to notice. [2026-08-19]

### Fixed
- **The seal check matched on a substring, and a four-digit sealed identifier is a prefix of a five-digit unsealed one from the same year.** Check 41 reported a broken seal on a file that named the *other* CVE entirely — found the first time this repository published a table of CVE identifiers. It is bounded on the right now. The same round also taught `eval/cvefixes/score.py` to redact a sealed identifier rather than print it: the concentration figure is a fact about the corpus and publishable, the identifier is not. [2026-08-19]

### Added
- **Three structural questions JavaScript could not be asked — and not one number moved on any of the four corpora, which is the finding rather than a disappointing result.** `structural/` decides eleven questions about a handler and six had a Python front end and no JavaScript one. Three land now: **`EXPOSE-JS-INTERNALS`** (CWE-209 — a stack trace, a driver's error text, `process.env` or a deployment path in a response body the handler builds itself; `next(err)` delegates the decision and is not reported), **`TRUST-JS-CLIENT-DECISION`** (CWE-807 — a branch on `req.headers['x-user-role']`, with transport headers and cryptographically verified values exempt) and **`ENUM-JS-CREDENTIAL`** (CWE-204 — a login answering a missing account differently from a wrong password). These three report a PRESENCE where the four before them report an ABSENCE, so they are held to the opposite discipline: the evidence has to be on the line, not merely missing from it. **What backs them is nine fixtures asserted in both directions and nothing else.** RealVuln is Python; SecBench.js has five classes and none is one of these; CVEfixes' JavaScript labels for these CWEs are deleted `import` lines and `package.json` version fields; and the noise floor holds no Express application. They fire — 11 and 4 findings on CVEfixes, none landing on a labelled hunk, `TRUST` not once — and they are silent across 1,372,511 lines of maintained code. `js.py`'s `limitations()` now says exactly that. [2026-08-19]

### Fixed
- **The client-decision rule could not read the header it is about.** `code_view` blanks string-literal *contents*, so on the blanked view `req.headers['x-user-role']` and `req.headers['content-type']` are the same expression — and the transport-header exemption, which is the whole precision of the rule, could never fire. It reads the raw text now. Found by the fixture that asserts content negotiation is ordinary code, which is what that fixture is for. [2026-08-19]
- **The dogfood ceiling for `ENUM-PY-RESPONSE` is 1**, and it is the oldest joke in this repository told once more: the rule that reports a login answering "no such account" and "wrong password" differently now fires on `structural/js.py`, the file that *describes* those two messages in order to find them. Raised rather than narrowed, for the reason the path-traversal ceiling above it gives. [2026-08-19]

### Added
- **A PHP taint tier — CVEfixes PHP 11.7% → 15.7%, headline 13.2% → 15.7%, CVE reading 20.7% → 24.5%, strict 6.2% → 7.4%.** The six superglobal rules see a request value sitting *inside* a dangerous call; `taint/phpanalysis.py` sees the shape PHP is actually written in, which is one assignment long — `$id = $_GET['id'];` and then `$id` in a query, an include, a shell call, a filesystem call, a header or an `echo`. It exists because the largest single PHP rule available was **measured and rejected** two rounds ago: SQL built by interpolation reaches +1,100 labelled files and matches **1,225 lines inside `laravel/framework` alone**. The same sink behind one hop of taint is **silent** in Laravel, Symfony's HTTP layer and PHPMailer, and costs 32 findings in phpMyAdmin — noise floor 0.26 → 0.28 per 1,000 lines. Kept apart from `taint/__init__.py`'s summary engine on purpose: that tier is interprocedural and cross-module, this one is neither, and the language-coverage matrix now prints both `False`s rather than letting PHP borrow a depth claim it does not implement. Every path is MEDIUM confidence — the source is certain, the reach is not, because this pass has no function boundaries. [2026-08-19]

### Changed
- **The unsealed slice moved further than the sealed one this round — 12.71% → 15.32% against 15.01% → 17.06% — and that is the expected shape here rather than a warning.** `eval/HELDOUT.md` defines the signature of corpus fitting as the unsealed slice moving *while the sealed one does not*; both moved, by 2.6 and 2.1 points, and the sealed slice remains the higher of the two in absolute terms (17.06% against 15.32%). The round was diagnosed by reading unsealed misses, which is what unsealed labels are for. [2026-08-19]
- **`test_zz_suite_mains.py` demanded a `main()` from a pytest-only suite**, which is the same incoherence `check 33` carried: both now allow a file whose every test asserts, since pytest is already a verdict route for each of them. [2026-08-19]

### Fixed
- **A vendored library does not arrive as one file — RealVuln precision 0.6471 → 0.6577, 27 false positives gone for 1 true positive.** `is_vendored_asset` decided per file, and on `static/js/foundation/` it was wrong fourteen times over: two files there carry a `/*!` banner (jQuery Cookie and a placeholder shim, neither of them Foundation itself) and the other twelve carry nothing, so a copied-in library drop was read as somebody's own front end. `engine._is_vendor_drop` asks the **directory** instead — the third and last move of a principle this engine already applied twice, after `_published_build_dirs` asked the manifest about a directory and `_is_own_release` asked it about a file. Bounded twice, because a silencing signal that spreads is the dangerous kind: **two** bannered files in one directory rather than one, never recursive, and never applied to a file the scanned project's own manifest publishes. **`SEC-JS-HTML-CONCAT` went from 22 findings on RealVuln to 1**, and the one that remains is application code. Measured before it shipped: 17 files newly silenced across 62 RealVuln repositories, 5 in phpMyAdmin, and **zero** across `axios` and `date-fns` — 1,878 files of modern application source. F3 unchanged at 60.5, labelled traps unmoved at 248, CVEfixes unchanged to the digit (one file per entry, so no directory to ask), SecBench.js dropped 13 unmatched findings and no labelled sink. [2026-08-19]
- **Two gates were wrong about their own subject.** `check 33` demanded a `main()` from a suite whose every test carries an `assert` — after proving, three lines earlier, that pytest can already fail the build on each of them. And its per-family delta rendered a round that gives one finding back as `**+-1**`. Both fixed; the first is why `kit/tests/test_provenance.py` could not be added until now. [2026-08-19]

### Added
- **A suppression that reads the matched LINE instead of the whole file — noise floor 0.35 → 0.26 per 1,000 lines for 6 labelled files.** `suppress_if` clears a finding when a control marker appears anywhere in the file, and that bluntness is why `SEC-JS-HTML-CONCAT` shipped with no suppressor at all: an escaper on the same line as the concatenation genuinely answers the rule, and suppressing on it cost **3 labelled files at line scope against 27 at file scope**, because a module that escapes four values and forgets the fifth is the shape the bug comes in. `Detector.suppress_line_if` is that missing scope. Two things now clear this rule on the line itself — an escaper call, and a **translation catalogue**: `'<div>' + Messages.strMissingColumn + '</div>'` joins a string the application ships with itself, and that shape alone was **65 of phpMyAdmin's 220 matched lines** against 15 for the escaper. **121 findings dropped, High+Critical unmoved at 99, CVEfixes headline 13.2% → 13.2% (1,669 → 1,662 files) and CVE reading 20.9% → 20.7%; RealVuln unchanged to the digit for the fourth run running.** [2026-08-19]

### Changed
- **The Semgrep pack withholds the rule rather than exporting a louder version of it.** `pattern-not-regex` filters the matched range, and this rule's match is a few characters wide, so an exported copy would keep every finding the engine drops — 80 of 220 on one checkout. 61 of 114 detectors exported, 53 withheld with published reasons. [2026-08-19]

### Added
- **Six PHP rules, and PHP goes 3.4% → 11.7% on CVEfixes — headline 8.1% → 13.2%, CVE reading 15.9% → 20.9%, strict 3.3% → 6.2%.** PHP is 64% of those labels and had three rules against it. What makes the gap closable without a taint tier is a property of the language rather than a trick: **PHP spells the source inside the sink.** `$_GET`, `$_POST`, `$_REQUEST` and `$_COOKIE` are superglobals — no import, no binding, no parameter to resolve — so a rule that sees one inside `echo` (`SEC-PHP-XSS-ECHO`, +240 files), a query call (`SEC-PHP-SQLI-SUPERGLOBAL`, +79), an `include` (`SEC-PHP-LFI`, +7), a filesystem call (`SEC-PHP-PATHTRAV`, +37) or `header()` (`SEC-PHP-HEADER-INJECT`, +29) has seen the whole path. A sixth, `SEC-PHP-XSS-SHORTECHO`, takes the other half of PHP's XSS surface — `<?= $row['title'] ?>` in a language that escapes nothing on the way out — and is deliberately the narrow form with **no call inside the tag**, because one line cannot tell `<?= $this->escape($x) ?>` from `<?= $obj->rawHtml() ?>`: 240 labelled files instead of 560, and the 320 given up are the ones where something might have escaped. **All six together match zero lines across 664,722 lines of maintained PHP and zero in phpMyAdmin's 325,732.** [2026-08-19]
- **`phpmyadmin/phpmyadmin` joined the noise floor, because a rule about `echo` is a rule about a template.** The four PHP projects added a round earlier are a framework, an HTTP layer, an HTTP client and a mailer, and none of them contains a page. 248,000 lines of a maintained, security-conscious PHP application is the shape those rules actually run against. [2026-08-19]

### Changed
- **Two candidate rules were measured and rejected, and the bigger one would have been the largest single win in this file.** SQL built by interpolation (`"SELECT … WHERE id=$id"`) reaches **+1,100 labelled files on its own — PHP recall 3.7% → 21.3%** — and matches **1,225 lines inside `laravel/framework` alone**, because a query builder's own source is full of SQL with variables in it. A rule that fires 1,225 times on the framework everybody uses is a rule nobody keeps switched on; it is in `ROADMAP.md` waiting on a PHP taint tier. A shell sink with a superglobal argument added 0 files — `SEC-PHP-EXEC` already reports those lines. [2026-08-19]
- **The noise floor is 0.35 per 1,000 lines, and the rise from 0.16 is one rule on one project — a rule this repository had published as costing two findings.** 310 of phpMyAdmin's findings are `SEC-JS-HTML-CONCAT`, 260 in `js/src/`, most on lines like `details += '<div>' + Functions.escapeHtml(...) + '</div>'` where the value **is** escaped one call away on the same line. The round that shipped that rule measured it here and reported two findings across 382,057 lines; the number was true and useless, because the corpus held an HTTP framework, an HTTP client, a date library and a promise library and **not one page that builds DOM**. The instrument was blind to the shape the rule is about. Published as the rise it is, with the fix — a line-scoped suppression, which this pack does not have — scheduled as its own round rather than written up as an explanation. [2026-08-19]

### Fixed
- **PHP got an instrument before it got rules, and the instrument immediately reported that two of the three PHP rules already shipping were wrong.** PHP is 64% of the labels in `eval/cvefixes/` and scores worst of the four languages there, so it is the largest gap this engine has — and no corpus in this repository contained PHP that was **not** vulnerable: RealVuln is Python, SecBench.js is JavaScript, and the noise floor had none. Four maintained PHP projects joined it (`laravel/framework`, `symfony/http-foundation`, `guzzle/guzzle`, `PHPMailer/PHPMailer`), and the first scan said: **146 findings in Laravel alone.** `SEC-PHP-EXEC` was reading `$redis->eval(`, `Process::exec(` and `$this->system(` as PHP's language constructs — a method that shares a name with a construct is not that construct — and `SEC-PHP-UNSER` was reporting `function unserialize(` *declarations* and calls already carrying PHP's own `['allowed_classes' => false]` control, which is the whole defence against object injection. Both narrowed: **125 matched lines in Laravel → 21** for the first, against a measured cost of 8 labelled CVEfixes files out of 167; the second went 136 → 114 and dropped to MEDIUM confidence, because it sees a sink and no source. Requiring a request-shaped argument was measured and **rejected** — it takes 74 labelled files to 15, since real PHP object injection arrives through a cookie or a session read three functions earlier. **CVEfixes PHP 3.5% → 3.4%, headline 8.2% → 8.1%, CVE reading 16.1% → 15.9%; RealVuln and SecBench.js unchanged to the digit.** [2026-08-19]
- **`.phtml` was advertised and unreachable, and the noise floor's denominator did not count PHP at all.** `langs.py` had no PHP family, so the three PHP detectors each spelled `(".php",)` inline and a `.phtml` file — the same language, opened in HTML mode — was never scanned by any of them. The same omission reached the measurement: `noisefloor/run.py` counted lines for `.py` and the JS/TS family only, so when four PHP repositories joined, the numerator gained 157 findings and the denominator gained 273 lines. Both now derive from `langs.PHP_EXTS`. [2026-08-19]

### Changed
- **The noise floor is 0.16 per 1,000 lines and that is NOT an improvement on 0.33.** The corpus grew from eight trees to twelve and PHP is verbose, so the denominator went 382,057 → 1,046,779 lines while the numerator went 127 → 168. **On the same eight trees as every earlier round the figure is unchanged to the digit — 127 findings, 0.33 per 1,000 lines, 28 actionable.** Both numbers are published, in that order, because a corpus change that happens to flatter the headline is the easiest kind of number to quote without its caveat. The PHP half contributes 41 findings across 664,722 lines, 36 of them Laravel's cache and queue paths calling `unserialize` on state the framework serialised itself. [2026-08-19]

### Added
- **HTML built by concatenation, which is where the JavaScript XSS labels actually live — CVEfixes JavaScript 11.5% → 18.1%, TypeScript 6.0% → 9.0%, headline 6.7% → 8.2%, strict 1.9% → 3.3%.** `SEC-JS-DOMXSS` requires the sink on the same line — `innerHTML =`, `document.write(`, `.html(` — which is where its precision comes from and also its ceiling. Read out of the unsealed CVEfixes misses rather than guessed: most of this class assembles the markup in one place and writes it in another, often in another function (`out += '<tr><td>' + opt + '</td>'`, `list.push('<a href="/u/' + id + '">' + name + '</a>')`). `SEC-JS-HTML-CONCAT` drops the sink and keeps the other half — a string literal that is HTML, joined to something that is not a literal. Three precision decisions, each measured: two joined literals are a library assembling a static template and are excluded; the literal must contain a tag rather than an angle bracket, so `'a < b: ' + n` is prose and not markup; and there is **no `suppress_if`**, because this pack's suppression is per FILE and at that scope a module that escapes four values and forgets the fifth goes silent — it costs 3 labels per line and 27 per file, and the file scope is the shape the bug comes in. **The sealed slice moved further than the unsealed one — 8.14% → 9.87% against 6.36% → 7.78%** — which is the opposite of what a rule fitted to the labels it was read from produces, and the first time this repository has been able to show that shape rather than promise it. [2026-08-19]

### Changed
- **The bill for it, in full: RealVuln F3 60.6 → 60.5, precision 0.6559 → 0.6471, and 2 findings per 382,057 lines on the noise floor.** RealVuln is a Python corpus whose JavaScript carries no labels, so the rule can only be counted against it there: +22 findings, 0 true positives, **true positives unmoved at 1058 and the labelled trap count unmoved at 248** — the instrument that separates a false positive from an unlabelled real finding did not move. Twenty of the 22 are one unminified third-party library (`static/js/foundation/foundation.*.js`) whose main file is correctly skipped as somebody else's release while its siblings carry no banner of their own; that is a scoping defect, it is now in `ROADMAP.md` as its own round, and it was not fixed inside a detection round. The two noise-floor findings are both in `express/lib/response.js`, on a value escaped one line above — the measured price of shipping without a file-scoped suppressor, published rather than tuned away. SecBench.js is unchanged at 0.5445 recall: none of its five classes is XSS. [2026-08-19]

### Fixed
- **The scanner was skipping the source of the very packages it was pointed at — SecBench.js recall 0.5236 → 0.5445, prototype pollution 0.3351 → 0.3892, ReDoS 0.2989 → 0.3218.** `langs.is_vendored_asset` treats a `/*!` banner and an `@license`/UMD preamble as *"this is somebody else's distributed release"*. That is right for an application with a library copied into it and exactly wrong when the thing under audit **is** a library: a package's own `index.js` opens that way precisely because it is a release — its own. Measured before it was fixed: **59 of 516 resolvable labelled sink files were never opened**, concentrated in the two classes with the worst recall (19% of prototype-pollution, 27% of ReDoS). A rule cannot miss what the scanner never reads, and part of what those classes published as a detection failure was a scoping decision. The fix is the principle this engine already applied to *directories* — `_published_build_dirs` asks the manifest whether `dist/` is the artifact — moved down to files: `engine._is_own_release` walks up to the nearest `package.json`, so a monorepo answers per package, and a file that manifest names (or that sits beside it) is the project's own source whatever its banner says. Minified names and `node_modules/` still win either way: a minified file is unreadable whoever wrote it. **The unsealed slice moved and the sealed one did not** (0.5088 → 0.5354 against 0.5785 → 0.5785), which `eval/HELDOUT.md` defines as the signature of corpus fitting; the round took no input from any label, and the number is published beside that argument rather than under it. RealVuln is unchanged to the digit — this is JavaScript — and the noise floor stayed at 0.33. [2026-08-19]
- **The same 22% hole exists inside CVEfixes and it is that corpus's construction, not the engine's.** It materialises one file per entry, so a package's `index.js` has no `package.json` beside it and nothing can answer the question the fix above asks: 475 of 2,159 JavaScript files and 44 of 1,531 TypeScript files are never opened. Documented as a bound on that figure rather than patched by writing a manifest next to them, which would be inventing evidence the dataset does not contain. [2026-08-19]
- **The dogfood ceiling for `TAINT-PY-PATH` is 13, not 12, and the extra one is the fix above.** `_is_own_release` joins `package.json` to a directory walked up from a path it was handed — the identical shape to `_published_build_dirs` two functions below it, already inside the count. Raised with the reason written next to it rather than narrowed: `open(os.path.join(tainted_dir, "index.html"))` in a web application is still the attacker choosing the directory. [2026-08-19]

### Added
- **The Secure cookie flag, which the HttpOnly rule had been swallowing whole — F3 59.7 → 60.6, recall 0.5897 → 0.6005, labelled traps unmoved at 248.** `SEC-PY-COOKIE-FLAGS` suppresses itself on `httponly=True`, so a cookie that set HttpOnly and never Secure was read as a fixed cookie and reported by nothing. They are different flags against different attacks: one stops a script reading the cookie, the other stops the network doing it. Two rules now, `SEC-PY-COOKIE-NO-SECURE` for the call and `SEC-PY-COOKIE-SETTINGS-NO-SECURE` for the Django settings module, the second bounded to *selective* hardening — a file that sets HttpOnly or SameSite has thought about cookie security, so a missing Secure beside them is an omission, while a module that configures none of them is not reported at all. **+19 true positives for +42 findings the scorer counts against us; precision 0.6695 → 0.6559, and the noise floor 0.31 → 0.33 per 1,000 lines.** Stated rather than buried: this round bought recall at a real precision cost, and the instrument that decides whether it started firing on *correct* code — the labelled trap count — did not move. [2026-08-18]

### Changed
- **`Detector.once_per_file`, because a rule whose subject is the file was reporting per line.** A settings module missing `SESSION_COOKIE_SECURE` is one omission with one fix, and the pattern that finds it matches every cookie line the module *did* harden — so the same problem was reported three times. The benchmark's scorer counts a second finding on an already-matched label as a false positive, exactly as a reader would, and the measurement made that visible: 45 findings for 19 labels, 589 false positives against 560 once the flag was set and 555 once both cookie rules used it. Not a benchmark accommodation — a report that says the same thing three times is worse to read as well as to score. [2026-08-18]

### Fixed
- **A Django view was never public; the engine only thought so — F3 59.5 → 59.7, `missing_auth` 4 of 74 → 7, `broken_access_control` 1 of 76 → 2, traps unmoved at 248.** `_route_of` records no path for a Django function view or a class-based view, because the framework keeps it in `urls.py`. `Route.public_by_design` read that empty string as the site root and answered yes — so **every Django view in every codebase was filed as deliberately unauthenticated** and exempted from the missing-authentication rule. The exemption was invisible in the worst way available: it looked like a rule that simply found nothing. An unknown path is not a claim about who may call it, so the route now carries whether its path is known, and with none the handler's *name* is the only signal left — which keeps `login` exempt, as a test now pins. Cost: +17 findings the scorer counts against us, precision 0.676 → 0.6695. [2026-08-18]

### Changed
- **The other half of the same idea was measured and rejected: `request.user` where it stands.** Django's principal is an attribute of the request, not a local, and the framework's own idiom is `filter(owner=request.user)` — while `_mentions` only knew `ast.Name`, so 26 labelled handlers were read as having no principal at all. Teaching the matcher dotted names is a genuine gap closed, and it converted **none** of those 26 into a finding while costing **+26 false positives and the first trap this repository has ever lost (248 → 247)**. The trap count is what separates a false positive from an unlabelled real finding; a round that moves it has stopped being a recall round. Reverted, and recorded here so the next attempt starts after it rather than at it. [2026-08-18]

### Added
- **A third external corpus, and the first one adopted under the seal from its first minute (`eval/cvefixes/`).** `eval/HELDOUT.md` has said since 2026-08-16 that every corpus here had been read, and that from that point *no improvement can be defended as generalising*. [CVEfixes](https://doi.org/10.5281/zenodo.13118970) (Bhandari, Naseer & Moonen, PROMISE 2021; CC-BY-4.0) is the answer to that sentence rather than a fourth number for the README. Its `code_before` column carries the whole vulnerable file and its `diff_parsed` column the line numbers the fix deleted, so the corpus is materialised from the dataset itself and the labels are somebody else's. **A fifth of the CVEs is sealed by `build_corpus.py` as part of building the corpus** — not as a later step someone could take after a first look — which makes it the one slice in this repository that is blind on its first run rather than a baseline. Two recalls are reported: location-only, and location *plus* a CWE the label accepts. The strict one is the headline, and the reason is a fixture written to test the scorer, where **a command-injection label was scored by a SQL-injection finding nine lines away** — vulnerable files hold more than one bug, so location alone hands out credit for finding a different one. [2026-08-18]
- **And the number it produced, which is the worst one this repository has ever published: 13.3% of CVEs, 6.7% of vulnerable files.** 3,576 CVEs, 12,619 files, 37,019 labelled hunks, Tier 0. Per language it runs Python 19.4% · JavaScript 11.5% · TypeScript 6.0% · PHP 3.5%, and PHP is 64% of the labels — the headline is dragged down hardest by the language this engine covers least, which is the finding rather than a reason to drop PHP from the corpus. The gap to F3 59.5 on RealVuln is not a contradiction: RealVuln is 62 *applications*, and this engine's two strongest tiers both start at an application's entry point — taint at a request source, the structural analyses at a route decorator. CVEfixes is mostly libraries, and a library has no request. **What is worth being pleased about is the seal: sealed 8.06% against unsealed 6.32%.** The held-out fifth scored slightly higher than the rest, so "nothing was fitted to this corpus" is now measured rather than asserted — the first time that sentence in `eval/HELDOUT.md` has had evidence under it. Three caveats all push the figure down and are left in: 1,051 files the engine never read (vendored/minified/oversized) count as misses, a deleted line is not always the bug, and no filter keeps only the CWE classes the pack models — choosing which CVEs count is exactly what an external corpus exists to stop us doing. [2026-08-18]
- **The blind number is on the front page, in both languages, and gated in the same change that put it there (check 44, and check 32 now lists a fourth result file).** Publishing a figure and gating it are one edit here, not two, because this repository already knows what the gap between them costs: check 27 exists because prose kept a stale RealVuln figure through four commits with every gate green, and the launch checklist kept 26.0 through two rounds for the same reason. A bad number needs the gate more than a good one — it is the kind a later edit rounds, softens or quietly drops. The sealed/unsealed pair is anchored too, since those two figures are the whole evidence that the held-out mechanism works. Verified the only way a gate can be: the CVE-level figure was edited to 31.3 and the build failed with the line naming both values, then restored. [2026-08-18]

### Changed
- **A fourth reading of the authorization classes, from the one angle the first three did not try — measured, rejected, and written down so the fifth round starts here.** The three previous attempts all asked *is there a check?*, and `_receives(call, principals)` kept answering yes. This round asked a different question: **does the check see the object it is authorizing?** The signal is real and visible in the corpus — in one file `update_status` calls `can_view_application(actor, app, …)` while the vulnerable `add_note` calls `can_write_internal_notes(actor)`, and the difference between them is whether the loaded object is an argument. Two shapes were built and scored against all 62 repositories. **(A)** report an object bound from a caller-supplied id that nothing in the handler ever relates to the principal: **16 labels, for 175 findings the scorer counts against us** (8 on labelled traps, 167 in no labelled region) — projected precision 0.676 → 0.61 to move F3 59.5 → 59.8. **(B)** narrow it to the observed shape, a permission call that receives the principal and never the object: **3 labels for 54 unlabelled findings.** B is worse because the narrowing selects for the wrong thing: `require_admin` on an admin endpoint is the same shape as `can_write_internal_notes` on a borrower's note, and which of the two is correct depends on whether the role is global — the domain question, again, wearing a new syntax. `broken_access_control` stays at 1 of 76 and `missing_auth` at 4 of 74. [2026-08-18]

### Fixed
- **The linter and type-checker caches were never ignored by this repository — only by the machine it was written on.** `.mypy_cache/` and `.ruff_cache/` are absent from `.gitignore`; `git status` is clean here because a global ignore covers them, which means the property held for the environment rather than for the tree. A contributor without that global config commits several hundred binary cache files on their first PR and nothing in the repository objects. Same class of defect this project keeps finding elsewhere — a guarantee that is really an accident of where it was checked. [2026-08-18]

### Added
- **Nine rule families the external corpus had no rule of any kind for — F3 41.6 → 59.5, recall 0.400 → 0.587, precision 0.672 → 0.675.** The question that produced them is the one this project's two largest previous gains both came from: not "why does this rule miss" but "is there a rule at all for this shape". Reading the 1,058 missed labels by CWE answered it — 961 of them had no finding anywhere near, and half of those sat in classes the pack had never modelled. New: CSV formula injection (`CSVINJ-PY-EXPORT`, 25 of 29 labels), account enumeration from differential messages (`ENUM-PY-RESPONSE`, 40 of 40), access decided by a caller-supplied cookie or header (`TRUST-PY-CLIENT-DECISION`, 30 of 30), cleartext storage of sensitive values (`PLAINTEXT-PY-STORAGE`, 19 of 62), caller-sized allocation (`RESOURCE-PY-UNBOUNDED`, 15 of 43), exception and environment detail in a response (`EXPOSE-PY-EXCEPTION`/`EXPOSE-PY-INTERNALS`, 36 of 83), CORS origin reflection in Python (`SEC-PY-CORS-REFLECT`), and a browser security header assigned its off value (`SEC-HEADER-DISABLED`). **Precision went up while recall rose by 19 points**, which is the signal this repository has always used to tell a rule from a fitted pattern. [2026-08-18]

### Changed
- **Three existing rules were missing the spelling the corpus actually uses, and each was one edit.** `SEC-PY-TLS` knew `verify=False` and none of the three standard-library spellings (`ssl._create_unverified_context`, `CERT_NONE`, `check_hostname = False`) — 29 labels. `MASSASSIGN-PY` read a FastAPI handler's `request: Request` annotation as a declared field set and fell silent on every FastAPI route in the corpus, and it required a `**` spread where the corpus writes `workset.update(payload)` — 10 of 40 labels became 32. `taint/pyanalysis._py_dotted` gave up on a call in the middle of a receiver chain, so `MongoClient(url).ops.records.find_one(query)` reached no sink at all: the NoSQL sinks existed and could not fire, and `sql_injection` recall moved 36 → 67 on the same fix. [2026-08-18]
- **The authorization classes were tried again and the widening was measured and rejected — recorded so nobody spends a fourth round on it.** `broken_access_control` (1 of 76) and `missing_auth` (4 of 74) are the largest single pool of misses left. `AUTHZ-PY-IDOR` requires both an authenticated principal AND separate authorization evidence before it will call a caller-supplied lookup an IDOR; dropping the second requirement — a principal in scope IS evidence that authentication was intended — took the rule from 7 to 10 labels for 19 to 29 findings. **+3 true positives for +7 false ones, so it was reverted.** `docs/what-we-miss.md` keeps saying what it has said since the class was first measured: what decides these is a relation the business-logic pass adjudicates, not a shape a structural rule can widen its way into. [2026-08-18]
- **`await` and a conditional are how every async framework writes an ordinary binding.** `structural/routes._bound_values` unwraps both before a rule pattern-matches an assigned value; without it `payload = await request.json()` was not a request read to any structural rule. [2026-08-18]
- **The noise floor moved 0.27 → 0.31 findings per 1,000 lines** — fifteen more findings across 382,057 lines of maintained code, for +331 true positives on the labelled corpus. Published as always, because a recall round that does not state its cost is half a measurement. [2026-08-18]

### Fixed
- **Four of the five rows in the tech-debt ledger, closed rather than restated.** (1) `Detector.superseded_by` lets a rule declare that another is its precise form, so `SEC-SECRET-GENERIC` no longer doubles every `SECRET_KEY = "<literal>"` the signing-key rule already reports — the existing dedupe could not, because it groups by CWE and the two carry different ones on purpose. (2) `taint.code_view` learned HTML: comments are blanked with a lexer, offsets preserved, so a POST form inside a multi-line `<!-- … -->` block is no longer reported as a live hole and three fixed-width lookbehinds are gone. (3) All thirteen quadratic ReDoS matchers in this engine's own JavaScript front ends are linear, each verified match-for-match against 7 MB of real JavaScript, and the `REDOS-PY` ceiling of 13 in the dogfood gate is deleted rather than lowered. (4) The taint tier's superlinear cost: two per-file caches took `lodash@4.17.21` from 11.6s to 2.3s on one machine, after profiling showed 5.7 of 12.7 seconds going into splitting the same file into lines 5,633 times. [2026-08-18]
- **Writing the tests found two claims the code did not honour, which is the argument for writing them.** Nineteen cases were added to `kit/tests/test_structural.py`, every new rule asserted in both directions, and two failed on the first run. `EXPOSE-PY-EXCEPTION` documented that `{"kind": exc.__class__.__name__}` discloses nothing a status code does not — and reported it anyway, because `ast.walk` reaches the same `Name` through the attribute chain; the narrowing that was supposed to buy precision had bought two findings out of seventy. And `PLAINTEXT-PY-STORAGE`'s docstring offered a raw invite `token` as its example when a bare `token` column is not in its vocabulary at all. Adding it was measured before it was rejected: two more labels for seventeen more reports, because `token` is what an application calls the value in its session table and its CSRF field. The rule is unchanged and **the docstring is what got fixed**, which is the right direction for that repair to run. [2026-08-18]
- **Only `SEC-TPL-FORM-NO-CSRF` moved to the blanked view, and the gate is why.** A rule scanned against `code_view` cannot be exported to the Semgrep pack, because `pattern-regex` there runs on raw text. Moving all five template rules would have withheld four more rules from the pack to fix something measured on exactly one of them. [2026-08-18]
- **`langs.is_vendored_asset` gained a fifth signal** — a UMD/AMD preamble or an `@license`/`@preserve` pragma, which is what a distributed release writes and application code does not. It catches `lodash.js` and changed nothing on the 62-repository corpus, so it is recorded in the ledger as an unmeasured improvement rather than claimed as a measured one; the remaining case (an unminified library whose banner is prose) stays open, because the obvious widening would drop application source carrying a corporate licence header. [2026-08-18]

### Added
- **Launch copy for all six channels, and the four conditions that make it postable** (`.claude/LAUNCH-POSTS.md`). Show HN, r/netsec, OWASP Slack, the two plugin directories, the RealVuln leaderboard PR and the CRA post — each written for its own audience rather than one announcement pasted six times, because r/netsec removes product launches and HN loses interest at "AI security tool". Every draft leads with the deterministic engine and the blind number, not with the plugin. It opens with a **do-not-post list**, since each item makes a specific sentence in a draft false: CI has never been observed green, `pip install secaudit-kit` does not resolve because the PyPI name is not reserved, the site has never deployed, and `self-scan.yml`'s `continue-on-error` means a green run does not prove the SARIF upload works. Kept out of `docs/` deliberately — the site generator fails the build on any `docs/*.md` nothing links, and a visitor has no reason to read our Show HN draft. **Stated in the file and in the launch checklist: nothing gates these figures.** They are prose no check reads, which makes them the one place in this repository where a number can go stale in silence. [2026-08-17]

### Removed
- **The site is 49 pages down to 31, and no content was lost.** Seventeen of those pages were the Turkish documentation tree — and the documents are English in *both* trees, which is this project's locked choice and is stated on the docs index. So `/tr/docs/getting-started/` served the byte-identical English body as `/docs/getting-started/`: seventeen pages of duplicate content at a second URL, a language switcher that changed the chrome and nothing the reader came for, and a crawler invited to treat the pair as translations. The roadmap had already settled this principle when it cut a separate "what it is" page — *the same content at a second URL is the thing to remove* — and the docs tree was the largest instance of it in the repository. The Turkish docs **index** stays, because it is genuinely translated, and links into the English documents; its note now says there is one copy of each rather than one per tree. `docs/launch-checklist.md` left the site entirely (→ `.claude/LAUNCH-CHECKLIST.md`): it is internal project management, and until launch it published the PyPI, DNS and repository-visibility TODO list to anyone who found it. [2026-08-17]

### Fixed
- **Sixteen of the seventeen documentation pages were missing from the sitemap.** Found while counting pages for the cut above. `doc` sits in the page table like any other page, so the sitemap loop emitted it once per language — and `page_href("doc", …)` resolves the slug from the module handle the *build loop* leaves behind, so the two URLs it produced both pointed at whichever document happened to render last. Arbitrary, and invisible in a diff, in the rendered site and in every gate: the pages all exist, all link correctly, and only reading the sitemap and counting shows it. Documents are enumerated explicitly now, one URL each. [2026-08-17]
- **`gen_site.py` deletes the pages it no longer builds.** It wrote into `site/dist/` and never pruned, so a build that removed eighteen pages left all eighteen on disk. It cannot reach the published site — `site/dist/` is gitignored and CI builds from a clean checkout — but locally it means the change you just made is invisible to the next `ls`, which is how a removed page gets rediscovered as still present. Scoped deliberately to `index.html` files and the directories that held them, the class that actually goes stale; assets are left alone, because deleting something the function does not know it wrote is a worse failure than keeping it. [2026-08-17]
- **The first CI run anyone watched went red, and it caught something no local gate could.** Real Semgrep rejected the exported form-CSRF rule: `regular expression is too large`. The pattern is valid Python, the YAML is well-formed, and the pack's equivalence test compares the exported regex against the detector's *using Python's engine*, which compiles both without complaint — so every local check was green and correct. **Python's `re` walks a bounded repetition; Semgrep's engine unrolls it**, and `{0,6000}` copies of a four-alternative group is past its size limit. That bound is not incidental: it is what lets the rule scan a form body without a nested quantifier, in a repository that ships a ReDoS detector and reports exactly that shape in other people's code. Lowering it to fit would change what the rule detects in both engines, so the rule is **withheld from the pack** through the mechanism that already exists for this (52 exported, 51 withheld, each with a published reason). The predicate is the shape rather than the detector id, so the next rule that needs a big bound is caught by construction. Two guards followed: `test_no_exported_rule_needs_unrolling` asserts the invariant locally, and this round's fix was verified against **the same pinned `semgrep==1.140.0` CI runs** before pushing rather than after. **The transferable half: two regex engines can disagree about a construct neither calls unusual, and no amount of testing one of them finds it.** The test file's docstring had claimed the CI step covered "whether Semgrep accepts the YAML envelope"; the narrower wording is what made the gap invisible, and it now says what actually got caught. [2026-08-17]
- **CI was observed for the first time, and two of its four workflows had never actually run.** The pipeline has been green on every push for weeks and nobody had ever looked, because `gh` was not authenticated on the build machine — so "44 gates green" was a local claim wearing a CI badge. It holds: `Validate plugin` runs `scripts/run_checks.py` on **Linux and Windows** and both report all 44 green, in 15 seconds on the Linux runner. What the run history also showed is why *green* and *ran* are different words. `Publish site` succeeds in 10 seconds because its `build` job runs and its **`deploy` job has only ever skipped**, guarded on the repository being public — known, and now confirmed rather than assumed. `CodeQL` is a 1-second skip on every push and every schedule: it is gated behind a repository variable nobody ever set, and the guard's own comment said it was *"tracked with the other launch steps in ROADMAP.md"* when it was tracked neither there nor in the launch checklist. **A launch step that exists only as a comment inside the file it gates is a launch step nobody performs**; it is now step 4c, and the comment points at the checklist instead of at a promise. [2026-08-17]
- **The SARIF claim splits in two, and only one half was ever true.** `self-scan.yml` carries `continue-on-error: true` on the upload because code scanning needs Advanced Security on a private repo, and the honest reading of that has always been "a green run does not prove the upload works". The run log is more specific than that and more useful: the action reaches `Validating secaudit.sarif` and `Adding fingerprints`, so **GitHub's own SARIF validator accepts the renderer's output** — proven, on 59 findings from a live self-scan of this repository — and then fails with `Resource not accessible by integration`, so **ingestion into code scanning has never happened**. Both halves are now written into the checklist and into the launch drafts, with the line the drafts may not use until the repo is public: *accepted by GitHub code scanning*. Until then the defensible claim is *emits valid SARIF*. [2026-08-17]
- **Check 43 — the unflattering half of the RealVuln range has to be derived too, and it had already drifted.** The results page publishes a *range*, `strict_micro` to `micro`, because four benchmark repositories are gone from GitHub and the strict aggregate is the reading where their 141 labels count as misses. That paragraph exists precisely so the lower number cannot be quietly dropped — and check 27, which holds every other figure on the page to `result.json`, did not cover the one inside it. The round that raised the headline updated the range to **38.7 – 41.6** and left the sentence four lines above it holding the *previous* round's strict figures (36.5, recall 0.3463, 659 TP / 277 FP): two disagreeing numbers in the same paragraph, in the passage whose entire job is honesty about the worse reading. Worse than the drift is how the new range got there — it was inferred from the old one's shape rather than read out of the file, and it happened to be right. Check 43 now reads the strict F3, its recall, both ends of the range, the stated points-lower delta and the shared TP/FP counts straight from `result.json`; proven non-vacuous against four mutations. **The lesson is where it grew: a page that derives 95% of its figures sprouted its one typed number in the self-critical paragraph, because that is the paragraph nobody thinks to doubt.** [2026-08-17]
- **The published SecBench.js recall was a coin flip, and the engine digest could not have caught it.** Chasing a one-label drop after a Python-only round — which should have moved nothing on a JavaScript corpus — turned up something worse than the drop: `taint/jsanalysis.py` attributed a taint path by walking `set(_JS_IDENT.findall(expr))` and returning on the first tainted identifier it reached. Python randomises string hashing per process, so **which source a finding was attributed to, and therefore the line it was reported at, changed between runs of identical code**. Measured on one package, six runs across two engines: `TAINT-JS-PATH` in `git@0.1.5` landed on line 739 four times and 743 twice, and 743 sits outside the scorer's ±10 window. Recall read **0.5410 or 0.5393 depending on the run**, and every figure this project has published from that corpus carried the same ±1-label flicker. The digest seal is the control that is supposed to make a number describe an engine, and it is structurally blind here: the code genuinely was identical. `dict.fromkeys` replaces the set — same cost, first-occurrence order, so the attributed source is now the leftmost identifier in the expression, which is also the more defensible answer. Verified deterministic over six consecutive runs, and the recall came back to **0.5410** exactly. The guard is a test that scans one fixture in four separate processes under different `PYTHONHASHSEED` values and asserts one finding set; it is non-vacuous by construction — the fixture is the interprocedural shape that actually broke, and a simpler one-tainted-name snippet is deterministic on the *pre-fix* engine and would have made the test prove nothing. **Transferable, and it is the reason this entry is first: a reproducibility seal over the inputs of a computation says nothing about the determinism of the computation.** A project whose entire claim is *measured, not asserted* needs both, and had only one. [2026-08-17]

### Added
- **Thirteen rules for the config, credential, CSRF and template-context shapes, and RealVuln F3 39.2 → 41.6.** The 1,103 missed labels were cross-tabulated by the shape of the line they sit on: 387 (46%) are handler, decorator or class lines — properties of what a handler intends, which no pattern decides and which stay listed in `docs/what-we-miss.md`; 144 are labels naming lines absent from the checkout; **307 are ordinary statements with no rule at all**, and that is what this round took. Security headers withdrawn (`Strict-Transport-Security: max-age=0`), a CSP that re-permits inline script, autoescaping switched off in code and the harder half — a hand-built Jinja2 `Environment`, which defaults escaping **off** while Flask quietly turns it on — debug enabled as a settings-mapping entry, a signing key passed straight into `jwt.decode`, CSRF middleware commented out of a `MIDDLEWARE` list, SQL statement tracing wired to stdout, `md5` called through a bare import, a Compose `environment:` secret, a POST form with no CSRF token in it, exception internals rendered into a page, and a template variable interpolated into an `onclick` handler — where HTML escaping is not JS escaping, because the browser HTML-decodes an attribute before the JavaScript parser sees it. Two widenings alongside: the signing-key rule's eight-character floor (two labelled credentials are four and six characters long; a short key is a worse key, not a non-key) and the keyword secret rule's requirement that the keyword touch the `=`, which made `ACCESS_TOKEN_SALT` read as a different word. **Predicted +23 labels before running; measured +45.** F3 **39.2 → 41.6**, recall 0.3740 → 0.3995, and for the first time **0 of 62 repositories score 0.0**. [2026-08-17]
- **Every one of the thirteen new rules fires zero times on 382,057 lines of maintained code.** The noise floor moved 96 → 105 findings (0.25 → 0.27 per 1,000 lines) with **High+Critical unchanged at 25**, and the entire rise is attributable to one of the two widenings: letting the keyword secret rule match a suffixed name also made it match `SECRET_KEY`, which the precise signing-key rule already reports — 10 of the 12 added lines are a second finding on a line that already had one. That duplication is a ledger row, not a silent cost, because the pack has no cross-detector suppression and the fix is a schema field rather than a regex. The form-CSRF rule, the one predicted most likely to be noisy, fires **0 times here** against 39 unmatched findings on the vulnerable corpus — which is the shape that says the corpus forms really are missing tokens rather than that the rule is loud. [2026-08-17]
- **Precision fell 0.7033 → 0.6718, and the 68 additional unmatched findings were read rather than absorbed.** Reading them is what produced the two narrowings this round shipped: a **commented-out** `<form>` reported as a live hole (fixed with fixed-width lookbehinds, which cover a comment opened on the same line and explicitly not a multi-line `<!-- … -->` block — that needs an HTML lexer, and the bound is in the ledger), and `class Environment(BaseEnvironment):` in **Flask's own** `templating.py` read as a Jinja environment built without escaping — a declaration of the type, not a construction of one. Of the rest: all 12 unmatched `set_trace_callback(print)` findings are the identical line the benchmark labels nine times elsewhere in the same repository, and both unmatched event-handler XSS findings are the identical shape to the labelled one. Unlabelled instances of a labelled bug are not false positives, but they *are* counted as such by the benchmark's own scorer, and the published precision is the scorer's — so the number stands as measured and the reading is recorded beside it. [2026-08-17]
- **`X-XSS-Protection: 0` is a benchmark label this pack deliberately does not implement.** Two RealVuln labels call it a misconfiguration; the OWASP Secure Headers Project recommends exactly that value, because the header is deprecated and its filter was itself an XSS vector in the browsers that shipped it. Writing the rule would have bought two points by firing on correct modern code everywhere else, which is the corpus-fitting this whole measurement discipline exists to refuse. HSTS `max-age=0` ships instead: withdrawing a pin the browser already holds is a downgrade whatever the year. Two further refusals are recorded with their reasons in `docs/what-we-miss.md` rather than left as silent gaps — `{{ … }}` inside a `<script>` block (locating the enclosing element from the interpolation is an unbounded lookbehind; matching forward from `<script` reports the wrong line) and plaintext credential storage (a bcrypt digest is also an ordinary string column, so the declaration does not carry the fact and any rule here is a guess with a CWE printed next to it). [2026-08-17]
- **Which function `exec` is depends on what the file imported, and resolving that is worth command injection 41 → 62 of 101 and code injection 19 → 23 of 33.** The two classes nobody had read. Reading all 44 unsealed command-injection misses says the taint tier follows every *value* shape these libraries use — concatenation, template literal, a local, `.join(' ')`, a call into a helper — and could not **recognise the call it was looking at**. The sink pattern anchored on a bare `exec(` or the literal receiver `child_process`, and that lookbehind is load-bearing, because `pattern.exec(string)` is the RegExp method and the most common `.exec(` in the language. So `cp.exec`, `childProcess.exec`, `child_process_1.exec` (the TypeScript emit), `require('child_process').execSync`, a `promisify`d alias and `shell.exec` from shelljs were all invisible: 14 of the 44. Receivers are resolved from the file's own imports now — **both wider and narrower than a name list**, because `sh.exec` is a shell in a file that imported `child_process` as `sh` and `re.exec` is not one in a file that did not, which is the property a name list cannot have. Two more from the same reading: a method in an object literal binds parameters (`const utils = { exec (cmd, cb) { … } }` is how a utility module is written), and so does `function(a, b)` with no space after `function` — the header regex required one. And two sink families were simply absent from the catalog: the `Function` constructor **without** `new`, which is what shipped code writes, and Node's `vm` (`runInContext`, `runInNewContext`, `compileFunction`, `new Script`), plus indirect `(0, eval)(…)`. **Cost: no change at all on RealVuln** — 659 / 278 / 1103, precision 0.7033 to four digits, which is what a JavaScript-only round should do to a Python corpus and was checked rather than assumed — and **one** additional Medium finding across 382,057 lines of the noise floor. The unmatched-finding ratio rose again, 0.0910 → 0.0919. [2026-08-17]
- **`vm` is resolved from imports too, and lodash is the reason.** The first version of that sink matched a bare `runInContext(` as well as `vm.runInContext(` — and lodash exports its own `runInContext`, an unrelated function that rebuilds the library against another global object. One package into the corpus it produced a false positive that no amount of taint reasoning would have refused, because the call really does take a parameter-derived argument. **A name is not an identity**; an import is. The negative is now a test. [2026-08-17]
- **`structural/js._functions` can delimit the functions it has been silently losing, and that single fix is worth 35 of SecBench.js's 113 unsealed prototype-pollution misses.** Every JavaScript structural analysis — authorization, rate limiting, upload, mass assignment, prototype pollution — is scoped by this one helper, and it decided where a function's body began by taking the first `{` on the matching line. So `function unflatten(obj = {}) {` was **one line long**, because the default parameter value opened and closed a block inside the parameter list; a brace on the next line was not found at all; and neither were `module.exports = function reduce(…)`, `exports.merge = (a, b) => {`, `merge: function (a, b) {` or a class method. Five rules read empty or absent bodies and reported nothing, which is the failure mode that looks exactly like a clean scan. It walks out of the parameter list by counting parentheses now, then takes the first `{` within three lines, and refuses a `;` at depth zero so a TypeScript overload signature does not adopt the next function's brace. **The transferable half: a shared piece of infrastructure that under-delivers is invisible in every individual rule's numbers**, and the only reason this surfaced is that a labelled corpus asked one rule a question 113 times. [2026-08-17]
- **Prototype pollution 25 → 68 of 185, from two rule changes that the same reading produced.** A callback's parameters carry whatever the iterated value carries — `_.each(source, function (value, key) …)`, `each.call(sources, function (source) …)` — which is decidable at the call site and **retires the limitation this module had documented as permanent**, `js-extend@0.0.1`, the one labelled bug it could name and not reach. The rule never needed the callback's span; it needed that one fact. And a **walk** is now a key binder in its own right: `cur = cur[part]` in a loop followed by a caller-chosen key at the end of it is `set(obj, 'a.b.__proto__', v)`, the half of CWE-1321 no iteration binder can ever see, and the walk is exactly what separates it from `store[name] = value` — a plain setter with a parameter key, one of the commonest functions in the language, which must stay silent and has a test that fails the moment it does not. **Cost, on all three instruments: one false positive on RealVuln** (precision 0.7041 → 0.7033, traps unmoved at 248, and the one is a vendored `foundation.js` that `is_vendored_asset` does not recognise), **three on the noise floor** (0.24 → 0.25 per 1,000 lines, all in `axios`, all High), **and the unmatched-finding ratio went up** — 0.0895 → 0.0910, the first round in three where recall rose without noise rising faster. [2026-08-17]
- **ReDoS analysis decides quadratic backtracking as well as exponential, and SecBench.js's ReDoS class went 11 → 28 of 87.** The JavaScript front end had taken that class from 0 to 8 and this project said plainly that eight was the honest size of criteria aimed at *exponential* blowup. So all 79 remaining labels were read one at a time, and they say the published advisories are overwhelmingly **quadratic**: `^\S+@\S+$` (the `@` is itself an `\S`, so the split point slides), `(?:\d+)?\.?\d+`, `(.*)\s*\*\/`. The criterion is deliberately narrower than "two quantifiers in a row", which describes most regular expressions ever written — the boundary between the repeats has to be able to *move* (`\d+\.\d+` is pinned by a dot that is not a digit, and overlap is decided by running each single-character construct against a sample alphabet rather than by a hand-written table of what `\S` means), and something after them has to be able to reject a split. **That second condition is the one that nearly did not ship correctly:** without it the criterion reported 28 regular expressions in this repository's own source, because `^(#{1,6})\s+(.*)$` is ambiguous and costs nothing — the first division it tries is accepted and nothing walks the others. It also had no test until a mutation showed the condition could be deleted with the suite still green, which is the second time a load-bearing narrowing here has been found unfalsifiable rather than wrong. Reported at Medium where exponential is High, with the reason in the finding: quadratic cost is a denial of service where the subject is attacker-supplied and unbounded, and a performance note where it is not, and this analysis reads regexes rather than subjects. [2026-08-17]
- **A JavaScript pattern is reported where it runs, not only where it is written.** The Python front end has reported the call site since the day it was written — a pattern is an ordinary string until `re.search` runs it, so there was nothing else to report — and the JavaScript front end reported the literal, because a literal is already a regex. Same analysis, two answers to *where is the defect*, and the difference was an implementation detail rather than anything about the languages: twenty-five labelled sinks in this corpus sit on a `RGX.test(input)` line whose `const RGX = /…/` is elsewhere in the file. A use site is a line where the pattern is actually applied (`.test`/`.exec` on the name, or the name handed to `.match`/`.replace`/`.split`/`.search`), never a mention — reporting every reference would turn one defect into as many findings as the file has lines naming it. Worth +1 label alone and **+19 together with the quadratic criterion**, because seven labels are a quadratic pattern reported at its use site; attributed by re-running the analysis on the labelled files with each half disabled. [2026-08-17]
- **Check 42 — a published result file has to agree with itself.** Check 27 holds the prose to `result.json`; check 32 holds `result.json` to the engine that produced it; nothing held `result.json` to `result.json`, and it is assembled from two of the benchmark's own outputs written by two commands. On 2026-08-16 they disagreed and the flattering half was published (below). The check now requires `overall` to equal the sum of `by_repo`, the `by_family` totals to cover exactly the labels the headline was computed over — which is what catches a family table summed twice, since a doubled table looks perfectly ordinary — every historical run's stated precision to match its own TP and FP, and on the SecBench.js side the class table and the sealed/unsealed split to add up to the headline. Proven by three mutations, and `collect_result.py` refuses to write a file that would fail it. **Generalises: a file assembled from two sources needs a check that the two agree, and "they are both the scorer's output" is not that check.** [2026-08-17]
- **The SecBench.js scorer resolves a labelled path to a file that exists.** Eighty-two of the 573 labels name a file the package does not have at that path — SecBench.js records `util.js:143` where the tarball holds `lib/compile/util.js`, or `merge/dist/lib/merge.js` where it holds `dist/lib/merge.js` — and the scorer compared strings, so every one of those was filed under *"no rule fired at the sink"*. It resolves them now: the stated path if it exists, else the unique file matching it on component boundaries in either direction, and only if that file is long enough to hold the labelled line; the rest are counted as misses under causes of their own (*not in the published package*, *ambiguous*). Worth +6 true positives on an unchanged engine and, more to the point, it moves 36 misses out of a cause that had been aiming rounds at detection when the file was never being opened. This is the second time a comfortable explanation for a miss on that page turned out to be the thing worth testing, after `dist/`. [2026-08-17]
- **`--engine-kit` on the SecBench.js runner and the RealVuln collector, because reproducing a published figure means running the engine that produced it.** `score.py` had recorded that the blind run's engine "no longer exists in this tree", which was true of the tree and false of the repository: it is a `git worktree add` away. Believing it nearly published two matchers in one table. The blind run was re-measured through the corrected matcher from a worktree at its own commit — 594 packages freshly scanned, 0 reused — and reproduced **128 / 573 and recall 0.2234 exactly** under the old matcher, which is what makes 131 / 573 a comparable column rather than a second instrument. [2026-08-17]
- **The held-out seal produced its first verdict, and it was the one worth having.** The `req.url` round is the first change measured against `eval/HELDOUT.md`'s sealed fifth of SecBench.js, and **both slices moved**: sealed recall 0.2975 → 0.3967, unsealed 0.2279 → 0.3407. The unsealed slice moved further in relative terms (+49% against +33%), which is the expected shape — the diagnosis was made by reading unsealed misses, so that is where the fit is. What matters is that the sealed half moved substantially at all: a change fitted to the corpus would have moved the half that was read and left the half that was not. That is a claim neither blind figure could support again, and the policy produced it one round after being written. [2026-08-16]
- **A third number, for the question the other two never answered: how much of your time does this waste?** **0.21 findings per 1,000 lines**, 0.05 of them High or Critical, over 382,057 lines across eight maintained projects pinned by commit SHA (`eval/noisefloor/`). Recall and precision both describe corpora where roughly one line in forty is a planted flaw; neither says what a healthy repository produces, and a tool at forty findings per thousand lines gets switched off in a week whatever its F3. In the unit that decides adoption: a 100k-line codebase gets about 21 findings, 5 actionable. Published as a **floor, not a precision** — nobody adjudicated these and some may be real — for the same reason SecBench.js's unmatched ratio is `precision_lower_bound`. The per-detector cut is the part worth keeping: `REDOS-JS` produces **8 of the 21 actionable findings from one repository**, so an aggregate of 0.05 was hiding that a third of the triage queue is one rule. Gated by check 40, which caught the first version of the per-repository table having four of its eight cells typed rather than derived. [2026-08-16]
- **A held-out policy with an enforcement mechanism, because every corpus here had been read.** RealVuln was blind at 12.5 and is 39.3 after four rounds of reading its false negatives; SecBench.js was blind at 0.2234 and is 0.2426 after acting on what that run said. Both disclose the gap and both end the same way — *the honest successor is a benchmark this repository has not read* — and as of this round there wasn't one left. That is not about any single figure: it means no future improvement can be defended as generalising. So a fifth of SecBench.js is now **sealed** (`eval/HELDOUT.md`, `eval/heldout.json`): scored like everything else, never inspected, reported as its own column. Selection is `sha256(name)` in the bottom fifth of the space, so *"did you pick a flattering slice?"* is answerable by recomputation instead of by trust. **Check 41 is what makes it more than a promise:** it fails the build if a sealed identifier appears anywhere in the tree except the register, because you cannot diagnose against a package without writing its name in a commit message, a comment or a test. It caught a real leak the first time it ran — `result.json`'s `missed_samples` was publishing the names of missed packages, sealed ones included. **Stated plainly: today's sealed score is a baseline, not a blind figure.** Those packages were present for the blind run and both tuned rounds; sealing stops future targeted tuning and cannot unread the past. Its value arrives next round — if `unsealed` moves and `sealed` does not, that round bought corpus fit rather than detection, and the two columns say so without anyone having to be honest in prose. [2026-08-16]
- **`eval/realvuln/tier1_subsample.py` — the LLM tier can have a number for roughly the price of a coffee.** Measuring it across all 62 repositories was declined and that was the right call, but "no full run" quietly became "no number at all", and a repository whose entire argument is *measured, not asserted* ships one whole tier with nothing behind it — against its own rule that an unmeasured tier is not coverage. Ranking the corpus by labels in the four families Tier 0 structurally cannot reach puts **31% of them in 12 repositories**: 48 model calls rather than ~250. The selection is computed from the committed scorecards rather than chosen by hand, and the script prints the exact commands plus the sentence any resulting figure must be published with — *"Tier 1, 12-repository subset, N of M labels"*, never as a corpus number. Not run here: no key is present on this machine, and spending someone's money is not a thing to do unasked. [2026-08-16]
- **`docs/threat-model.md`, the last document P6 asked for and the one that found a bug.** Boundary by boundary: the scanned repository as an untrusted author, the report's readers, external scanners as subprocesses, the network (KEV downloads the whole feed and sends nothing; EPSS sends CVE ids, which does disclose what you are looking up — stated rather than glossed), the LLM tier that sends source code and the prompt injection it cannot stop, the MCP server's **absent path confinement**, the active-testing hook and its documented bypasses, and a release pipeline that has never run. Every section says what the control does **not** stop, because a threat model that only lists mitigations is marketing. Writing the first section is what turned up the evidence-sanitisation defect below — the document had to answer "what does the scanned repo control?" and the honest answer was "the strings you print". [2026-08-16]
- **ReDoS analysis reads JavaScript and TypeScript, and it is worth 8 of 87.** The criteria were always properties of the regex rather than of the language, so `catastrophic_reason` is untouched and only the extraction is new: a regex-literal lexer, plus the string argument to `new RegExp` with one layer of string escaping taken off (`"(\\d+)+"` is the pattern `(d+)+` in JavaScript, and reading that the other way finds nothing). The one ambiguous character in the language is `/`, told apart from division by the token before it — the standard heuristic, and the negative cases in the tests are the load-bearing half. The gap was written into the roadmap **before** the SecBench.js run that measured it at zero, so the port is not corpus-fitting; what the run then showed is how little it buys. Eight of 87 is the size of a deliberate under-report: the two criteria describe *exponential* backtracking and most published ReDoS advisories are *polynomial*. Stated rather than smoothed over. [2026-08-16]
- **`secaudit --version`, which until now printed a usage error.** The first thing anybody types after `pip install`, and it matters more here than in most tools: every published figure in this project is tied to the code that produced it, and a user comparing their output to a number on the site had no way to say which build they were holding. Check 38 holds it to `pyproject.toml` — the release workflow only ever checked the git tag against the manifest, so a drifted `__version__` would have shipped silently. [2026-08-16]
- **The install path is now a gate, because nobody had ever walked it.** `scripts/check_install.py` builds the wheel, installs it into an empty virtualenv with `--no-index`, and runs the console script, the module entry point and the MCP server against a directory outside this repository — then asserts that the imported `secaudit_core` did *not* resolve to the checkout. Everything else here tests the code where it lives, on `sys.path`, beside its own fixtures, which is not how a single user receives it. The install itself turned out to work; walking it by hand is what surfaced the README defect below. Offline by construction (`--no-build-isolation`, `--no-index`), which is only possible because the package declares zero runtime dependencies — so the gate is also a second, independent statement of that claim. It very nearly proved nothing: `run_checks.py` puts `kit/` on `PYTHONPATH` for every gate it launches, so the child virtualenv imported `secaudit_core` from the checkout and the gate went green on the repository rather than on the wheel. Caught because the standalone run passed and the same gate failed under `run_checks.py` — the useful direction for that discrepancy to point. It now strips `PYTHONPATH`, `PYTHONHOME` and `VIRTUAL_ENV`, and asserts the resolved import path is outside this repository. [2026-08-16]
- **`check_consistency.py` check 36 — the first command a new user types must be the one that works.** The README's opening block said `/plugin install secaudit` and the walkthrough forty lines below said `/plugin install secaudit@secaudit-kit`; `docs/getting-started.md` agreed with the second. Both identifiers live in `.claude-plugin/marketplace.json` and nowhere else, so the check reads them from there and holds every documented occurrence to them. The site was already right about this, for the reason the site is right about most things: it derived the command instead of typing it. The home page's copy of it is now derived too — it was the one page still holding a literal, and the page most people see first. [2026-08-16]

- **Check 39 — the run history holds rounds, not save points.** `collect_result.py` pushes the current figures into `previous_runs` every time it runs, which is right once per round and wrong the second time inside one. Collecting a round twice — because a rule was adjusted after the first measurement, which is the ordinary way a round goes — leaves the intermediate state in the history as though it had been published, and `--previous-label` stamps it with the *previous* round's name, so it is wrong twice over: a save point wearing someone else's label. This has now happened three times and been caught three times by reading the file rather than by anything failing. Duplicate *figures* are not the signal — two consecutive rounds legitimately scored 35.9 — so the check is on the label, which is the one thing a round has to itself. [2026-08-16]
- **Check 37 — the strict reading of the RealVuln figure must actually be stricter.** The published number is a range, **33.4 – 35.9**, and the low end is the whole reason it is honest: four benchmark repositories are gone from GitHub, all four are dense teaching apps, and `strict_micro` is the reading where their 141 labels count as misses rather than as nothing. It is computed by the benchmark's own dashboard from the directories under `scan-results/`, which means a `rm -rf scan-results/` between two runs destroys it — the grid loses the four, their labels leave the denominator, and `strict_micro` silently becomes a copy of `micro`. Nothing errors and the file keeps its shape; the number that survives is the flattering one. That happened here, mid-round, and the check exists because the failure produces a *plausible* result file rather than a broken one. Documented as note 5 in `eval/realvuln/README.md` as well, because a gate that only fails after the fact still costs a run. [2026-08-16]

### Changed
- **The published RealVuln figure is 39.2 / 0.7071, not 39.3 / 0.7086, and the correction is filed as its own round.** The reproduction step this project runs before every change — re-score the previous engine on the same clone — reported "digit for digit" for eleven rounds and then did not. The *engine* reproduced exactly: 932 findings, no repository differing, byte for byte. The scorer returned **273 false positives where the committed file published 271**. The first explanation was that 271 was a phantom, and it was wrong: re-running the two engines from before that round, from worktrees, emits 930 findings and 271 false positives exactly as published. The round that shipped 271 emits 932, and the two extra are `PROTO-JS-WRITE` on one vendored `static/js` file — the `hasOwnProperty` guard that round removed on purpose. **So it is not a number nobody produced; it is a round that changed the engine and republished the previous engine's headline**, because `dashboard.py` was never re-run after that round's `score.py`, while the per-repository table in the same file was fresh and already said 273. That matters past two false positives, because the round's own argument leaned on it: it said the change was safe partly because RealVuln's false positives were "271 before and after". They were 271 before and 273 after; the instrument that genuinely did not move is the labelled **trap** count, 248 either way, and that is the one the argument needed. Both pages are corrected rather than quietly restated. [2026-08-17]
- **The quadratic ReDoS criterion cost precision on RealVuln and volume on the noise floor, and both are published where they happened.** RealVuln: **+4 false positives, no true positive**, precision 0.7071 → 0.7041 — all four are the same email regex, `^[^@\s]+@[^@\s]+\.[^@\s]+$`, in four seeded FastAPI applications, correctly read as quadratic and labelled by nobody. Noise floor: **0.21 → 0.24 findings per 1,000 lines**, twelve findings over 382,057 lines, none of them High, so a reader who triages by severity sees no change. **This is the first round in eight where precision fell, which this project's own acceptance test calls the signal to stop and narrow rather than publish.** It was kept, and the argument is the held-out slice rather than any of the three costs: the 79 labels read to design the criterion were all unsealed, so a round fitted to them would move unsealed and leave sealed flat — and sealed moved *further*, 0.4215 → 0.4545 against 0.3739 → 0.4027. A reader who weighs the precision series above that is entitled to reject the round, which is why all of it is in `eval/secbenchjs/README.md` and `eval/HELDOUT.md` rather than summarised. [2026-08-17]
- **`hasOwnProperty` is not a prototype-pollution guard and was being treated as one; prototype pollution went 12 → 24 of 185.** The idiom it appears in is the canonical *vulnerable* merge — `for (const k in src) { if (src.hasOwnProperty(k)) target[k] = src[k] }` — which asks whether the key is the source's own rather than inherited, and a `__proto__` that arrived via `JSON.parse` **is** an own property. The check passes, the write happens, and what it excludes is exactly the set of keys nobody was going to send. It silenced 10 of the 115 unsealed labelled misses. `constructor` and `prototype` are now matched only as **quoted strings**, for the same reason: a guard is a comparison against a key *name*, and a name is a string — `if (key === 'constructor')` is one, `Object.prototype.hasOwnProperty.call(src, key)` is a property access that merely contains the word. That second spelling had been hiding the first, and it had also made the *test* pass for the wrong reason, which is the failure a test is least likely to notice about itself. **This round tripped this repository's own stop signal and was kept anyway, which is stated rather than smoothed:** the unmatched-finding ratio fell 0.1006 → 0.0903, +12 true positives against +349 unmatched findings. It was kept because the two instruments that can actually identify a false positive both said zero — RealVuln's labelled traps did not move (271 FP before and after) and the noise floor across 382,057 lines of maintained code did not move (0.21 per 1,000 lines) — while the instrument reporting +349 explicitly cannot tell a false positive from an unlabelled real one, on a corpus of 185 packages selected for containing prototype pollution. The argument is written out in `eval/secbenchjs/README.md` so a reader can reject it. **What the sample did show is a real defect, and it is named rather than buried:** `args[i] = sortArrs[i]` and `sortFlag[j] = 0` are array index writes reaching the rule through `for (i in arr)`. They were firing before too — the over-broad guard was masking some of them. A filter for it was tried and rejected: excluding functions that mention `.length`/`.push`/`Array.isArray` would catch 284 of 450 and would also kill real merge helpers, since jQuery-style `extend` calls `isArray` on purpose. [2026-08-16]
- **`req.url` is a taint source now, and SecBench.js recall went 0.2426 to 0.3525 because of it.** The JavaScript diagnosis turned out to be the exact mirror of the Python one in the same round. On Python a whole sink library was unmodelled; here the *sinks* were already comprehensive — twenty-odd `fs` entries including the `promises` forms — and the **source** was missing. `JS_REQUEST_SOURCES` had `req.query`, `req.params`, `req.body`, `req.headers`, `req.cookies` and `req.files`, and not `req.url`: the single most common source in Node. This corpus is full of small static file servers built on `http.createServer`, where no Express router exists and the request *is* `req.url` — `loadFile(req.url, …)` into `path.join(base, file)` into `fs.readFile(file)`, where joining onto a base directory is not a containment check. **`path-traversal` 59 → 122 of 167, +63 true positives for +12 unmatched findings**, RealVuln unmoved (Python corpus), and the noise floor on eight maintained projects unmoved at 0.21 per 1,000 lines. The catalog's *Python* source list carries a comment saying that list is the entry point to the whole analysis, so an omission switches the engine off for a framework idiom rather than for one rule. Nobody had carried the sentence across. [2026-08-16]
- **`pathlib` is a sink family now, and `path_traversal` went 3 → 22 of 39 because of it.** This class had been written off twice. The roadmap's recorded conclusion was that its misses were "about which values are believed attacker-controlled" — a claim nobody had tested, and being wrong it aimed two rounds at the source list. Reading all 36 labelled misses says the opposite: the sources were **already** modelled, and the engine proves it by reporting SSRF, SSTI, XSS and open-redirect in the very same handlers from the very same route parameters. What was missing was that the catalog modelled the standard library's entire filesystem surface as one entry — the builtin `open` — while the code under test writes `(BASE / name).read_text()`. That needed something no sink here had needed: taint arriving through the **receiver** rather than an argument position, since `read_text()` has no argument 0 to inspect. Nine sinks added across two rounds moved nothing because all nine were more ways to spell `open`, and nobody checked whether the misses spelled it at all. **F3 35.9 → 39.3, recall 0.3405 → 0.374, `other` 228 → 268, +59 true positives against +24 false ones, precision 0.7084 → 0.7086 — which is to say it did not move.** Largest recall gain since the second round. The other side of the trade was then checked rather than assumed: on the new noise-floor corpus the pathlib sinks fire **zero** times across 382k lines of eight maintained projects — all 11 `TAINT-PY-PATH` findings there are the builtin `open()` that was already modelled. +19 true positives for no measured noise. **Generalises: a recorded conclusion about why a class misses is a claim, and an unexamined one costs more than the misses, because it aims everything that comes after it.** [2026-08-16]
- **Prototype pollution now requires the key to have come from the caller.** `PROTO-JS-WRITE`'s own title says *attacker-named key*, and it was firing on keys the function had invented — `Object.keys(filters)` over React state built from a literal has the shape of the bug and none of its substance, because nothing outside the function can put `__proto__` in there. That exact line (`AdminAudit.tsx:18`) was the rule's only false positive across 62 RealVuln repositories. The iterated object must now trace back to a parameter — through a **bounded fixpoint over local bindings**, not a single-hop check, because a query-string parser is two bindings from its argument (`str.split('&')`, then `p.split('=')`) and is the real shape of a `qs`-family prototype-pollution bug; a one-hop rule would have traded one false positive for that whole class. **Precision 0.7075 → 0.7084 on RealVuln, one false positive removed, no true positive lost — and on SecBench.js it cost a labelled sink, 13 → 12 of 185.** Both halves belong in the same sentence. The narrowing initially lost three; two were a defect in the walk rather than in the idea and are recovered (see below), and the third is `js-extend@0.0.1`, which binds its key from the parameter of an anonymous callback — invisible to any rule that decides caller-supplied inside one named function body, and exactly the limitation the module already declared. So the round trades one true positive for one false positive and 54 unmatched findings on the JavaScript corpus; a reader who wants to disagree with that trade now has the numbers to. The first version of this also inherited the parameter lists of enclosing functions, for the recursive-merge-in-a-closure case; it was deleted when no mutation of it could be made to fail a test — the enclosing function's span already covers the inner body, so its own pass reports the same write. Four lines nothing can falsify do not belong in a measured engine. [2026-08-16]
- **`SEC-JS-PROTO` is retired and prototype pollution is a structural analysis now.** The old rule matched `for (… in …)` — the most ordinary loop in JavaScript — and on 594 real npm packages that produced roughly **950 findings and 9 of the 185 labelled bugs**, the worst ratio anything in this pack has measured. A `for…in` loop is not a vulnerability. The vulnerability is the *write* one line further in, and what makes it one is visible there: the target is indexed by a variable, that variable is a **key** rather than an array position (bound by `for…in`, by `Object.keys`, or by walking a `split()` path — the `set(obj, 'a.b.c', v)` helper is the other half of this class), and nothing in the enclosing function refuses `__proto__`, `constructor` or `prototype`. All three are facts about one function body, which is why it is `structural/protopollution.py` and not a pattern. It reports the assignment, so the finding lands on the line an author has to change. **13 of 185 now, and 200 fewer unmatched findings overall** — better, and still the worst class here. Two details worth keeping: the guard is read from the *raw* source while the writes are read from the comment-and-literal-blanked view, because the guard is nearly always a string literal (`if (key === '__proto__')`) and reading both from the blanked view erases every hand-written protection in the ecosystem; and a guard covers inner functions lexically, or a `merge()` that checks once and recurses in a local `walk()` gets reported for being careful. [2026-08-16]
- **`dist/` and `build/` are scanned when the package's own `package.json` publishes them — and the reason this was expected to matter turned out to be wrong.** Build output is skipped by default and that is right for an application: it is generated from the source beside it, and a finding in one is addressed to a file nobody edits. It is wrong for a *published package*, where `dist/` is the JavaScript that runs on the installing machine and often the only JavaScript in the tarball. The manifest is what tells the two apart (`main`, `module`, `exports`, `bin`, `files`), read per directory so a monorepo answers per package; nothing else in `SKIP_DIRS` is ever un-skipped, whatever a manifest claims, and the report says when it read build output and why. SecBench.js had reported 35 labelled sinks lost this way, and `eval/secbenchjs/README.md` called them *"a scoping decision, not a detection failure"*. The change made **29 of the 35 reachable and found two**. The other 27 moved to *no rule fired at the sink*: they were two problems stacked, and the flattering half of that claim was the wrong one. The scorer was wrong in the same direction — it decided "skipped as build output" from the path alone, so it would have gone on filing detection failures under a scoping cause — and now asks the engine. [2026-08-16]
- **Check 32 now covers the SecBench.js figures too, and the scorer refuses a mixed-engine scan tree.** The check exists because a published RealVuln precision of 0.5419 once described an engine that actually returned 0.4711 — and it was written to guard one file. The SecBench.js numbers are published in the README, the Turkish README, the roadmap and the site, and `result.json` carried no digest at all: the identical gap, one directory over from the check that closes it. `score.py` stamps the digest now, taken from **the scan results it read** rather than from the working tree, because those answer different questions — the tree says what the code is now, the results say what actually emitted the findings. A second guard falls out of collecting it per package: scoring a directory that holds scans from two engines is refused outright, since that aggregate is a number no engine ever produced. Same family as the cache defect, one step later, and it looks like a result rather than like a mistake. [2026-08-16]
- **The SecBench.js per-package timeout is 300s, because at 120s the corpus changed size depending on machine load.** `react-native@0.63.0-rc.0` is 30 MB and sits within seconds of the old bound: three runs of this round abandoned it and the fourth finished it, which moved the package count 593 → 594 and the unmatched-finding total by 110 with nothing in any diff to explain it. A timeout is a backstop against a runaway scan; when it fires routinely it is a participant in the measurement, and a benchmark whose denominator depends on what else the machine was doing cannot support a reproducibility claim. Recall was never affected — that package's own labelled sink is a miss either way — which is precisely why it could have gone unnoticed. [2026-08-16]
- **`eval/secbenchjs/run.py` keys its result cache on the engine digest.** It caches one scan per package so an interrupted fifteen-minute run can resume, and the first version keyed that cache on the package name alone — which meant it silently stopped measuring. The JavaScript ReDoS front end landed, fired on this benchmark's own sink files when called directly, and moved the published recall by **exactly zero**, because all 593 results came off disk. Every result now carries the `engine_digest` of the code that wrote it, a result whose digest is not the current one is rescanned, and every run prints how many were reused against how many were fresh. `--rescan` forces the whole corpus. The digest itself moved out of `check_consistency.py` into `scripts/engine_digest.py` so both consumers read one definition of "the engine that produced this figure". [2026-08-16]
- **`eval/realvuln/collect_result.py` stamps the engine digest and writes `indent=2`.** The digest field said "never the digest alone" and relied on a person to honour it, which meant the failure mode was updating the figures, leaving the digest, and getting a check-32 mismatch that reads like a stale digest rather than what it is. The digest is a property of the run, so the run writes it. The indent was 1 while every other measurement file in this repository — and the committed copy of this one — uses 2, so every collected run reformatted the whole file and buried a five-line change in a two-thousand-line diff. [2026-08-16]
- **`kit/examples/example-report.md` is generated from a live scan instead of written by hand.** It is the artefact a reader opens to decide whether to install the tool, and it had drifted almost completely: it advertised **21 findings and one tool**, from a scan taken before the taint tier, the structural analyses and the ReDoS analysis existed, and it named a detector that has since been retired. It is now 71 findings across four tools, produced by `scripts/gen_example_report.py` and gated with `--check`. Same rule as the language matrix, the what-we-miss page and the semgrep pack: if it describes the engine, the engine writes it. [2026-08-16]

### Security
- **A scanned repository could write control characters into the report describing it.** Evidence lines and file paths are authored by the code being scanned, and they reached the terminal and the markdown report verbatim. Three consequences, all real: an ANSI escape repaints the terminal the report is printing into (`\x1b[2J` clears it, `\r` overwrites the line just printed); a bidi override is **Trojan Source, CVE-2021-42574** — the evidence line renders in an order the file does not have, in the one place a reader is trusting the display; and a single backtick closes the inline code span, so everything after it becomes live markdown in a document that gets pasted into a pull request. `to_html` had worked this out for HTML and says so in its own docstring — *"an unescaped evidence line is a scanner that plants XSS in its own findings page"* — and the same sentence is true one renderer over. Fixed at the `Finding` constructor, not in a renderer, because every tier builds its own findings and a rule written into one renderer holds for exactly that one; `Cc`/`Cf` characters become `<U+XXXX>`, **named rather than deleted**, since for Trojan Source the character's presence is the finding. The markdown renderer now picks a fence longer than any backtick run in the content. **The shipped `kit/examples/example-report.md` had three broken code spans**, all JavaScript template literals — the defect was visible in this repository's own published artefact and nobody had looked. [2026-08-16]
- **The authorization gate did not know about Metasploit.** `ACTIVE_TOOLS` listed 26 offensive tools — including `joomscan`, `tplmap` and `arjun` — and none of the exploitation frameworks, so `msfconsole`, `msfvenom`, `msfdb`, `beef-xss` and `sqlninja` ran against a live target without an asserted authorization. Added, with the self-test extended in both directions: the frameworks must block, and a bare `beef` must not, because a blocking gate that fires on an ordinary word is worse than one that misses a tool — the operator switches it off, and a switched-off gate catches nothing. Both directions proven by mutation. `SECAUDIT_ACTIVE=1` and an untracked `scope.yaml` still unlock them; this is a gate, not a ban. [2026-08-15]

### Fixed
- **Two regexes written for the function finder were catastrophic, and the dogfood gate caught them within minutes of them being written.** `(?:[A-Za-z_$][\w$]*\s*=\s*)*` and `(?:static\s+|async\s+|\*\s*)*` are quantifiers over groups that themselves repeat — star height two — and the ReDoS criterion that landed hours earlier reported both at High on this repository's own source, which the gate fails on outright. Rewritten as bounded and non-nested forms, and a third pair narrowly avoided the same fate by being quadratic rather than exponential. The round adds no new entries to the ceiling: 13 before, 13 after. **A rule catching its own author on the day it ships is the only evidence that it works which cannot be arranged.** [2026-08-17]
- **The JS taint tier was re-reading each file once per function per summary round — `lodash` 99.9s → 12.9s.** `_JsScope` stripped comments from the whole file every time it was constructed, and a scope is constructed once per function per round, twice over (`_js_summaries` runs for the file's own pass and again for the cross-module one). Adding a second per-file computation — the import scan that resolves `exec` — made a five-figure count of full-text scans visible by pushing a corpus run past the point where anyone would wait for it. Both halves are memoised per file now: **`lodash@4.17.15` 99.9s → 12.9s and `total.js@3.4.6` 21.5s → 8.3s, with the findings asserted identical**. This repository's rule that *performance is a correctness property* is exactly why: the harness abandons a package at 300 seconds, and a package abandoned is a label silently counted as missed. [2026-08-17]
- **A dead guard in the prototype-pollution walk rule, deleted rather than tested.** `_write_into_a_walk` refused numeric literal indexes on the grounds that `cur[0] =` is an array position — and mutation testing showed nothing could be written that failed without it, because the set it guards against holds identifiers and a digit string can never be in it. This module deleted four unfalsifiable lines once before for the same reason. **Two mutation-harness failure modes were found on the way, and both read as "SURVIVED":** a stale `.pyc` served the unmutated code, because CPython validates bytecode on (mtime, size) and `depth += 1` → `depth += 0` changes neither; and three conditions survived because no test isolated them, which is a fact about the tests. Both are now habits — invalidate bytecode, and treat a survivor as "write the test that would catch it, then decide whether the code is dead". [2026-08-17]
- **This repository shipped a catastrophic regex in its own markdown renderer, and its own new criterion found it.** `scripts/md.py` matched a horizontal rule with `^\s*(?:\*\s*){3,}$` — a `\s*` inside a `{3,}` is star height two, so a line of stars and spaces that ends up not matching backtracks exponentially. The subject is this project's own documentation, so it was never an incident; a scanner that ships one is still not in a position to report one. Rewritten so the whitespace is outside the loop. Thirteen more, all in the engine's own JS/TS line matchers, are **real and capped rather than excused**: by this project's threat model the scanned repository is attacker-authored, `langs.is_vendored_asset` bounds them only partially (it inspects a fixed number of leading lines), and rewriting thirteen matchers inside the measured path would move the engine digest and every published figure in the same commit that introduced the criterion which found them. They are in `.claude/TECH-DEBT.md` with that reasoning and a ceiling in the dogfood gate. [2026-08-17]
- **`collect_result.py` doubled every per-family total on a benchmark checkout scored on two different days.** `score.py` writes `scorecard-<date>.json`, so two days of scoring leave two cards per repository, both carrying an entry for the same scanner. The per-repository dictionary was overwritten and stayed right; the family counters accumulated, so `open_redirect 37 / 40` came out as `74 / 80` while the table beside it was correct. Caught by check 27 the first time a second date existed — and only because the prose was already gated, since nothing in the collector would have noticed a table that doubles uniformly. It reads one card per repository now: the one matching the run date, else the newest. [2026-08-17]
- **The RealVuln collector stamped the working tree, not the run.** `engine_digest` was computed at collection time, so editing a docstring between the scan and the collection produced a stamp that matched the tree, matched check 32, and described an engine that had not produced the figures — the failure mode that check exists to prevent, arriving through the one door it does not watch. `run.py` records the digest beside the results it writes (outside the scanner directory, because the benchmark's dashboard reads every `*.json` in there as another run) and the collector reads that. The SecBench.js side has worked this way since its cache was fixed; this was the same gap one directory over, which is now twice that this pair of harnesses has needed the same lesson carried across. [2026-08-17]
- **The roadmap said SBOM signing was still open for two rounds after it shipped.** `release.yml` has an `attest` job writing SLSA build provenance and an SBOM attestation over the wheel and the sdist, OIDC-signed and SHA-pinned, in a job deliberately separate from `build` so the step that produces an artefact and the step that vouches for it do not share a credential. The line under CycloneDX/SPDX still read "signing/attestation is still open". A stale *open* marker is the quieter half of the drift this repo gates against — a stale figure gets caught by check 27, but a status claim about a workflow that only runs on a `v*` tag is checked by nobody, and it is how a future session gets sent to rebuild something finished. [2026-08-16]
- **The caller-supplied walk only followed declarations, and every pre-ES6 merge helper is written the other way.** `var options, name;` up front, then `options = arguments[i]` inside the loop — a bare assignment to a hoisted `var` is where the caller's object actually arrives, and requiring `const`/`let`/`var` on it meant the chain to the key was broken before it started. That silenced `extend@3.0.1` and `objtools@3.0.0`, two labelled SecBench.js bugs, and recovering them took prototype pollution from 10 back to 12 of 185. Worth recording how it was diagnosed, because the first attempt was wrong: seeding the parameter set with `arguments` was reasoned out from JavaScript semantics, asserted in a comment to have recovered three true positives, and measured across 593 packages to move **nothing at all** — the helpers it was aimed at never reached the seeding. The claim was in the tree for one run before the measurement contradicted it. The test that was supposed to cover the shape used `var src = arguments[i]`, a declaration, which is why it passed throughout; the corpus had the other shape and no test did. [2026-08-16]
- **A test defined in `test_structural_js.py` but absent from its `main()` never runs, and a mutation over it looks like the mutation surviving.** This is what check 33 exists for and it caught it the moment it was run — recorded here because the failure presents as a *false negative in the mutation check*, which reads as "the code is unfalsifiable, delete it" rather than "the test never executed". The two are opposite conclusions from the same evidence. [2026-08-16]
- **Re-measuring a round put a run in the history that never happened, three times.** `collect_result.py` pushes the current head onto `previous_runs` on every call, which is right the first time and wrong every time after: a fix lands, the corpus is re-run, and the second collection files the head as a completed round wearing the *previous* round's `--previous-label`. The history is the argument that each delta is attributable to one change, so a save point in it is not clutter, it is a false claim. `--amend` replaces the head and leaves the history alone, and it refuses a `--previous-label` because there is nothing to push. Check 39 already caught the duplicate label; this removes the way to produce one. [2026-08-16]
- **Half the pack was answering the wrong question about test files, and it cost 61 false positives.** A rule either describes TEXT that is present in a file or BEHAVIOUR the shipped application performs, and the two answer differently in a test, a fixture, a migration or a seed script. A test that calls `os.remove` on its own temp file, disables TLS verification against a local stub, or hashes a fixture with MD5 is not the application doing any of those things — while a credential is committed whatever directory it sits in, and `git log` does not care that the file was a test. So `about_committed_text` splits them: every shape-based secret rule sets it and keeps scanning everything (the case the older, coarser decision existed to protect, intact), and everything else is scoped to production source. `structural/routes.py` had written this reasoning down for its own rules from the start; it was simply never applied to the pattern pack or the taint tier. Measured: **0 true positives and 22 false ones** sat in non-production paths. [2026-08-16]
- **The seeder is where a codebase deliberately writes fake credentials, and it was being reported.** Django puts it in `management/commands/seed*.py`, Rails in `db/seeds.rb`, Laravel in `database/seeders/`. Across 62 external repositories those paths held **36 false positives and not one true positive**, and the false ones were all the same line — a `DEMO_PASSWORD` for a local database. Added to the same non-production list as the tests, for the same reason, rather than special-cased in a rule. [2026-08-16]
- **`@csrf_exempt` on a GET-only handler was reported as a CSRF hole.** CSRF defends against a *state-changing* request the user did not intend, so an exemption on a handler the framework has already restricted to `GET`/`HEAD` is the correct annotation on a read-only endpoint — one of the benchmark repositories says exactly that in a comment beside it. **11 of the rule's 19 false positives** were this, and none of its true positives. The lookahead is bounded to the next three lines rather than written with a nested quantifier, because an unbounded one over a decorator stack is a ReDoS and this repository ships a detector for that. [2026-08-16]
- **The vendored-asset filter narrowed the scan's scope without saying so.** Skipping a third-party bundle is right; letting the reader assume it was covered is not, and it is the same defect as the "NO FILES WERE READ" case one size smaller — the more dangerous size, because the report still looks complete. Every scan now states how many vendored or minified assets it did **not** analyse and names the first three, with the reason and the remedy: the fix for a flaw in a bundle is a dependency upgrade, and nobody upgrades what they were never told they are shipping. Found by asking what this session's own change had quietly bought, one commit after adding "no silent caps" to this file. Figures unmoved — 600 / 309 / 1162 re-measured identical, since a note is not a finding. [2026-08-16]
- **The Turkish headline was served with its descenders sliced off.** Each hero line is its own `overflow:hidden` window so it can rise out of a mask, and the room below the baseline was `.1em` — sized against the English headline, whose deepest glyph is the `p` of "proof". Turkish reaches further: `Açığı` carries a `ç` cedilla and a `ğ` descender on the same line, and the mask cut **4.8px of them at 56px**. Now `.3em`, which measures clear across the whole `clamp()` range (40px → 84.8px) in both languages, and is layout-neutral — the negative margin cancels it and the `h1` is 98.92px before and after. The reveal's start position moved with it: a deeper window would otherwise have shown the tops of the glyphs before the line had risen, which is the same bug pointing the other way. Worth recording how it was found, because the first measurement was wrong: `getBoundingClientRect` on a text range returns the font's ascent/descent box, so it reported an identical 11px overflow for English — the language that renders correctly. Canvas `actualBoundingBoxDescent` measures the ink the glyphs actually put down, and it separated the two immediately. [2026-08-16]
- **A React or Next.js codebase received zero pattern detectors, and nothing reported it.** Thirty-one rules named `.js` and `.ts`; the taint tier named `.jsx`, `.tsx`, `.mjs` and `.cjs` as well; the structural tier named all eight including `.mts` and `.cts`. Four places answered "which extensions are JavaScript" independently and gave three different answers, so the same file byte for byte produced `SEC-JS-MD5` as `vuln.ts` and **nothing at all** as `vuln.tsx` — and with it went every other `SEC-JS-*` rule and the JavaScript half of the secret pack. The mirror image was live too: `.mts` and `.cts` were advertised as analysed, the generated language matrix published the claim, and `code_view` had no lexical group for either — so every structural analysis took the `view is None` path and returned nothing for a file type the documentation promised. Neither showed up as a failure; both showed up as silence, which is the only failure mode a security scanner has that matters. `langs.py` now holds the families and all four tiers derive from it, proven on a file written out under all eight extensions, before and after. [2026-08-16]
- **Findings inside vendored front-end bundles were reported as the application's own — 117 of 525 false positives, against one true positive.** `node_modules/` was skipped wholesale and that covers the JavaScript convention and none of the others: a Django or Flask project vendors its front end by copying `jquery.min.js` into `static/`, which no directory rule saw. `SEC-JS-RANDOM` (33 FP), `SEC-JS-PROTO` (30) and `SEC-JS-EVAL` (10) were scoring **zero** true positives on the external corpus and were, essentially in their entirety, reports about jQuery and Bootstrap. Every finding in one is addressed to the wrong maintainer. Four signals now answer *whose code is this*: a minifier's filename, a vendor directory, a `/*!` licence banner (the preserved-comment marker build tools keep precisely because it carries a third-party artifact's licence), and a line no human wrote. Deliberately not a list of library names, which is wrong the moment a project vendors the next thing — and deliberately not applied to Python, because `/lib/` is ordinary application structure there and an earlier version that treated it as a vendor directory cost five real findings in application code. It also stops handing the exponential-traversal input to the analysis that once hung on `materialize.js`. Costs exactly one true positive: a labelled flaw inside minified jQuery 3.2.1, at column forty thousand of a single line. [2026-08-16]
- **The generic secret rule scored 0 true positives and 104 false ones in test and fixture paths, across 62 repositories.** It guesses from a *keyword* — `password = "…"` — rather than from a credential's shape, and a seeded login in a test is a fixture every time. Its own remediation text already admitted this ("ignore obvious placeholders"), which is a rule offloading its precision problem onto the reader. Confined to production source, and narrowed so an interpolation (`'{password}'`), a format slot or an angle-bracket stand-in no longer counts as a value — the clearest case being an f-string SQL query that merely contains the word. The shape-based secret rules (AKIA…, `ghp_`…, provider tokens) still scan everything, because those recognise a credential by what it *is*, and one of those in a test file is a real leak. That distinction is why this is a per-detector flag and not a change to how the pack walks the tree. [2026-08-16]
- **A model reply with no JSON in it read as a Tier-1 pass that confirmed nothing.** `_parse_json` returned `{}` for any reply without an object in it — a refusal, a truncated stream, an error page in the response body — so nothing merged, no exception reached the caller's error path, and the header still said the backend had run. "The model confirmed none of these findings" and "the model said something we could not read" rendered identically, which for a tier whose entire output is verdicts are the two answers that must never look alike. Unreadable replies are counted now, not swallowed and not raised on: the chunks that did come back are kept, the report says how many did not, and the backend is labelled `(unreadable: n/m)` or `(fallback: none)`. The test that pinned the old behaviour said junk must not crash the scan — it never did; the caller catches, keeps what merged and labels the run. What `{}` bought was a false success. [2026-08-15]
- **A target that does not exist was audited as a clean tree.** `os.walk` yields nothing for a path that is not there and raises nothing either, so `secaudit ./src --min low` on a typo'd or moved path produced a full report with every count at zero, the closing line that says no findings, and exit 0 — a CI gate that passed forever while scanning nothing. The CLI already refused a URL target for exactly this reason, and the MCP server already refused a missing path; the plain case, which is the one a typo produces, was the one left open. Refused in the engine now, so no caller can ask the question. [2026-08-15]
- **The shipped pre-commit hooks failed on every commit that touched more than one file.** Both declare `pass_filenames: true`, so pre-commit appends the staged files as separate arguments — and the CLI took a single positional, so `secaudit --min high a.py b.py` died on `unrecognized arguments`. A developer saw a broken hook, not a security result. The CLI takes several targets now and analyses them as one set, so taint crossing two staged files is still followed; `--since`, `--watch` and `--suggest-patches` are refused with more than one, because each is about a tree. The gate that was written for this surface passed one file and so only ever proved the flags parse; it now invokes the hooks the way pre-commit does. [2026-08-15]
- **Every report states how many files it read.** Its own closing sentence was "across the files that were scanned" and it never said how many that was — so a scan that read nothing (a tree whose code sits under `build/` or `node_modules/`, an `--only` group nothing matches) rendered identically to one that read nine hundred files and found nothing. Zero files now says so, in capitals, above the counts. [2026-08-15]
- **`--patch-tests` without `--suggest-patches` was silently ignored, and `--suggest-patches` without a backend exited 0.** Both are the shape the CLI refuses everywhere else: the user asked for a step, the step did not happen, and the exit code said it went fine. [2026-08-15]
- **The two panels the landing page exists to compare were reporting on two different scales.** RealVuln's scorer emits F-scores on 0–100 and precision and recall as fractions; this repository's own scorecard emits all three as fractions. Both were passed through verbatim, so the section that asks a reader to weigh the external result against the internal one showed F3 31.5 beside F3 0.986 and recall 0.301 beside recall 98% — one metric rendered as two quantities, on the one comparison the page is built to invite. Every ratio on the landing page is now a percentage: 31.5% / 54.2% / 30.1% against 98.4% / 100.0% / 98.6%. The benchmark page keeps the scorer's own units, because it mirrors the benchmark's published tables and has to stay comparable to them, and it now says so. [2026-08-15]
- **A published baseline figure was typed into the landing copy, three hundred lines from the table it was copied out of.** "Published rule-based SAST scores 17.7 on the same corpus" is the sentence that makes 31.5 mean anything to a reader who has never seen this benchmark, and it was the only figure on the site not derived from its source. It now comes from the same parse that builds the baselines table, with the system's name, and the build fails if that row disappears. [2026-08-15]
- **Six of the eight meta descriptions and two titles were longer than a search result can show** — one description by a hundred characters, written as prose in a file full of prose, beside sentences that have no limit at all. Rewritten to fit, and the limits are now a build gate measured after formatting, because a description that interpolates a figure is only as long as the figure makes it. [2026-08-15]
- **Printing the site produced a mostly blank document.** The reveal system leaves every section it has not seen at `opacity: 0` and print renders the page in whatever state it is in, so a reader who printed from the top got the hero and a dozen empty pages; what did print was near-white text on white paper, because browsers drop background colours. There is a print stylesheet now — the palette inverted at the token level, every displaced state restored, chrome removed, the hero's full-viewport centring dropped, and external link targets printed after the link text. The counters snap to their measured value on `beforeprint`, so a page printed mid-animation cannot state a number that is not the measurement. [2026-08-15]
- **The lead figure ran into its neighbour at 360px, and by four pixels on a desktop.** Putting both corpora on one scale turned `31.5` into `31.5%`, and a monospace stat in an auto-fit column is exactly as wide as the measurement happens to be. Sized against its own cell now rather than against a breakpoint, so the next digit cannot do it again — `100.0%` is already the widest thing in the block and an F-score is one carry away from being wider. [2026-08-15]
- **The four evidence-document cards were `h4` under an `h2`**, the only place on the site where navigating by heading level skipped a rung. Now `h3`, set at the same size — the level is the outline's business, the size is the card's. [2026-08-15]
- **The skip link moved the viewport but not the keyboard focus.** A fragment link only moves focus if the target can hold it, and a plain `main` cannot: in Firefox and Safari the next Tab continued from the header, landing the reader back in the navigation they had just asked to skip. [2026-08-15]

### Added
- **A demo page whose transcript is a real scan, run at build time.** `/demo/` shows one command against the shipped fixture and the output *this build* produced — 23 files, 70 findings — with the reachability lines accented, because the path from untrusted input to the dangerous call across a function boundary is the thing this tool has that a pattern scanner does not. **Deliberately not asciinema**, and the reason is the reason for the rest of the site: a recording is correct on the day it is made and silently wrong afterwards, it needs an external host and a player script, and this site's CSP is `default-src 'none'` because it fetches nothing from anywhere. A demo that required loosening that would be advertising a property the page then stopped having. [2026-08-16]
- **The "what it is" page is closed rather than deferred.** It has been on the list since before the landing page was cut from twelve sections to eight — and the landing page *is* that page. A second one would be the same content at a second URL, which is precisely what the cut was for. [2026-08-16]
- **The documentation is on the site: 16 documents, rendered from the files the repository ships.** `/docs/` and one page each, in both language trees — the chrome translated, the documents in English, which is this project's standing rule and is stated on the Turkish index rather than left to be discovered by clicking. Each page links back to its source file, and links *between* documents are rewritten to the rendered pages while links out of `docs/` go to the repository, because a reader sent to a `.md` gets a raw download or a 404 depending on the host. [2026-08-16]
- **A markdown renderer that refuses what it does not implement.** ~300 lines, no dependency, covering exactly the constructs a survey of `docs/` found — headings, tables, fences, lists with one level of nesting, blockquotes, inline code, emphasis, links — and raising with the file and line on anything else. The temptation with a hand-written parser is to pass through what it does not recognise, and the result is a document that renders *almost* right: a table missing its last column, an unclosed emphasis that swallows a paragraph. Those ship and nobody re-reads them. It found one bug in itself immediately — an escaped pipe inside a table cell (`/secaudit <url\|path>`) was split as a cell boundary, which the inline renderer then reported as a document error rather than the parser bug it was. [2026-08-16]
- **Two more build gates, both from defects this work introduced.** Every page must have exactly one `h1` — the hero named the document and the document named itself, so sixteen pages shipped with two, and the one heading rule every accessibility checklist agrees on was broken by generating pages instead of writing them. And `DOC_ORDER` must list every file in `docs/`: a document the index does not name is a document nobody reads, which is the same failure as the orphaned page one commit earlier, one level down. Both proven by mutation. [2026-08-16]
- **Both READMEs published one external number while two existed.** Same omission the site had, in the place most people read first. They now name the language each figure describes, carry the SecBench.js per-class table with its two zeros, and state plainly why precision is not published for that corpus. Check 35 was extended to hold those figures in all three documents on the day they started being stated — check 27 learned that lesson the expensive way about the other benchmark, where four sentences kept a previous round's F3 through a green build. Proven by mutation. [2026-08-16]
- **README v2 was already done and the roadmap had not noticed.** Its four requirements — the one sentence, the differentiator against the official plugins, the benchmark number with its caveat first, a 15-second install, in both languages — were met in `f52e654`. Confirmed against the line rather than rewritten, and the line now records what was actually missing, which was the second number. [2026-08-16]
- **A CRA page, four weeks before the duty starts, and every date on it is read out of the engine.** `/cra/` and `/tr/cra/`: the three reporting deadlines with the trigger that decides whether any of them run — the clock starts on an *actively exploited* vulnerability, which is a fact about the world and can become true on a morning when nothing in the repository changed — the seven Annex I clauses the scan emits evidence for, the one command that produces the pack, and four things the pack **cannot** establish. The deadlines and the article moved into `compliance.py` rather than being typed onto the page: three durations in marketing copy are three durations nobody re-reads, and being wrong about a regulation in public is a different category of mistake from being wrong about a feature. [2026-08-16]
- **Copy is written in markdown and the page rendered four asterisks around its most important phrase.** `md_code` handled backticks and nothing else, so `**actively exploited**` shipped as literal punctuation. Emphasis is applied now, in pairs only — an odd `**` is left exactly as written rather than opening a `<strong>` the page never closes — and nothing else is interpreted, because a page that half-renders markdown is worse than one that renders none. [2026-08-16]
- **A comparison page, and every claim on it about somebody else's product is a quotation with a date.** `/compare/` and `/tr/compare/`: the capability table the landing page stopped carrying, the two sentences Anthropic's own documentation uses about its scope, and — because a comparison page that lists only advantages is an advertisement — four things SecAudit deliberately is not, each pointing at where on this site the limit is measured. The recommendation is **install both**. Two cells state a figure rather than a tick, because "published score ✅" is a claim a reader cannot check and "35.9% / 22.3%" is one they can; a new `FIGURES` gate holds those cells against the measurement, and its first version passed with the cell mutated to a tick because the same number is quoted in the paragraph below — a gate the prose could satisfy was not gating the table. [2026-08-16]
- **The build now checks that a published page can be *reached*, not only that its links resolve.** The comparison page shipped orphaned: rendered, published, in the sitemap, and arrivable only by typing the address, because every check in the generator was pointed the other way round. Two earlier versions of the fix passed while the bug was live — counting "linked from anywhere" is satisfied by the footer linking every page from every page including itself, and excluding self-links is satisfied by the language switcher, which makes any two orphans link to each other. A pair of unreachable pages that vouch for one another is exactly the shape a count cannot see, so it walks from the home pages instead. Proven by deleting the footer entry. [2026-08-16]
- **The site published one external number while two existed, which is overstating by omission.** The landing page said "external corpus" and meant Python; the benchmark page had no room for JavaScript at all. Both now say which language they describe, and the benchmark page carries a `#javascript` section with the SecBench.js recall, the five classes worst-first, and the reason the two figures are not comparable in either direction — that corpus is applications, this one is libraries, and a library has no request handler for the reachability analysis to start from. Read from `result.json` like every other figure on the site, so it cannot go stale on its own. [2026-08-16]
- **The JavaScript side has an external number for the first time, it is blind, and it is humbling: recall 0.2234 on SecBench.js.** 128 of 573 labelled sinks across 594 real npm packages, Tier 0, scored by [`eval/secbenchjs/`](eval/secbenchjs/README.md). No rule in this engine was written or selected by reading a SecBench.js label — the first blind external measurement since RealVuln's first two runs, and the answer to a gap that had widened three times while every published figure described Python. Per class: code injection 19/33, command injection 41/101, path traversal 59/167, prototype pollution 9/185, ReDoS 0/87. **Precision is deliberately not published as a precision** — the benchmark labels one vulnerability per package, so the unmatched-finding ratio is a lower bound on noise and putting it beside RealVuln's 0.708 would compare two different measurements that share a name; the field is called `precision_lower_bound` for that reason. Gated by check 35 on the day it landed rather than after its first figure went stale, proven non-vacuous by mutation. [2026-08-16]
- **Both predictions written down before the run arrived, which is the point of writing them down.** ReDoS scored **0 of 87** because `redos.py` is Python-only — stated in the roadmap before a single package was fetched, so it could not afterwards be presented as a discovery. The two results that were *not* predicted are now the top of the roadmap rather than a footnote: **prototype pollution 9 of 185**, the largest class, where `SEC-JS-PROTO` matches a shape the real bugs do not have (they are recursive merges and path assignment, reachable by analysis and not by that pattern) — the clearest "this rule does not do what its name says" result the project has; and **35 sinks under `dist/` or `build/`**, which the scanner skips as build output. That default is right for an application repository and wrong for a published npm package, where `dist/` is not a by-product but the artifact that runs on the installing machine. Changing it touches the measured RealVuln path, so it is recorded rather than done mid-measurement. [2026-08-16]
- **A benchmark harness that cannot hang, and says what it dropped.** The first attempt at the run stopped on `react-native@0.63.0-rc.0` — 30 MB across 586 JavaScript files — because the taint tier reads a whole tree before analysing it and a Python loop cannot be interrupted from outside. Each package now scans in a child process under a 120-second bound, and any package that does not finish is **named** in the output and counted as a miss, because a harness that silently drops what it cannot finish reports a recall computed over the easy half of the corpus. One package hit the bound. The underlying cost is in `.claude/TECH-DEBT.md` with the measurement that produced it: 44.7s for a single 17,000-line file where the pattern tier takes 1.2s. [2026-08-16]
- **The corpus fetches with the standard library and no npm, and tells you about your own network.** A machine advertising an unreachable IPv6 address turned one 2.3 MB download into **181 seconds** through `urllib` against 2.8 through `curl` — nothing failed, `urllib` was waiting out a TCP timeout per connection while curl raced the families. Six hundred of those is thirty hours instead of ten minutes. The fetcher probes the v6 address specifically (the first version used `create_connection`, which falls back to v4 on its own and cheerfully reported a route that did not exist), disables only what is actually broken, and prints which it chose. [2026-08-16]
- **A precision round that lost nothing: F3 35.9, precision 0.660 → 0.708, 61 false positives removed and 600 true positives kept exactly.** Sixth consecutive round where precision rose; the first where it rose without recall moving at all, which is the shape a pure narrowing should have. Strict range 33.4 – 35.9. [2026-08-16]
- **The second benchmark is chosen and named: [SecBench.js](https://github.com/cristianstaicu/SecBench.js).** Recorded in the roadmap with what it costs rather than left as "find one someday", because two problems close on the same run. It would be **blind** — every JS/TS rule here was written against this repository's own fixtures and none was selected by reading SecBench.js labels, which is the one property RealVuln can no longer offer at any price. And it lands on the largest unmeasured surface in the repository: 32 pattern rules, four structural analyses and a taint tier on JavaScript that nobody outside this project has scored. 600 real npm vulnerabilities with `file:line` sink locations, five classes that map onto rules which already exist. Written down with the costs first: no scorer ships with it, the licence is unstated and must be established before any figure is published, and **ReDoS is 98 of the 600 labels while `redos.py` is Python-only**, so a sixth of the benchmark scores zero on arrival — stated here before the run so it cannot later be framed as a discovery. [2026-08-16]
- **The JavaScript gap is now stated at its real size, in the place the number is published.** It had widened three times — the structural front end, then 31 pattern rules reaching `.jsx`/`.tsx`/`.mjs`/`.cjs` for the first time, then the template rules — and the disclosure had not moved with it. Every widening is now named, with the instruction that follows from it: read every figure on that page as a statement about Python. [2026-08-16]
- **The external number moved to F3 35.8, and precision moved more than recall did.** 600 TP / 309 FP / 1162 FN on the same 62 repositories, same scorer, same clone, ground-truth digest unmoved — precision **0.542 → 0.660**, recall **0.301 → 0.341**, strict range now 33.3 – 35.8. The previous engine was re-scored on the fresh checkout first and reproduced 530 / 448 / 1232 digit for digit, so every delta is the engine. The precision jump is three times the size of any previous round's and came from the provenance filter above rather than from a rule. Three recall gains came from reading labels: `xss` **11 → 47 of 98**, `sql_injection` **11 → 36 of 71**, `hardcoded_credentials` **6 → 16 of 52**. `other` moved 229 → 228 — the jQuery true positive — and that is stated next to the gains rather than netted off against them. Fifth consecutive round where precision rose alongside recall, which remains this repository's acceptance test for a detection change. [2026-08-16]
- **Python had no SQL-concatenation rule, and it is the one language the published number is measured on.** JavaScript, PHP, Java and C# each had one from the beginning; Python relied entirely on the taint tier, which needs a path rooted in `request.*` — and most of the missed labels are a handler that takes the value as an ordinary function parameter and builds the statement from it, so there was no request root to find and the class went unreported by both tiers at once. **33 TP / 4 FP**, `sql_injection` 11 → 36 of 71. The rule turns on one distinction: `execute("… WHERE id = %s", (uid,))` is a bind placeholder and correct, `execute("… WHERE id = %s" % uid)` is injection, and they differ only in whether the `%` is an operator applied after the closing quote. All four string-building routes are the same bug in different spellings — `+`, `%`, `.format()`, f-string. [2026-08-16]
- **Templates are scanned at all now, which is where 39% of the benchmark's XSS labels live.** No detector had ever named `.html` or `.jinja2`, so the engine reported on the view that *builds* a response and never on the document that renders it. Three rules, each with what it actually scored: an explicit `|safe` on a template variable, **16 TP / 12 FP**, above the engine's own precision; DOM XSS written into the document, **3 TP / 0 FP**, where the concatenation *is* the rule (`innerHTML = "<li>" + comment` is the bug, `innerHTML = template` is Tuesday) — a code-shape rule in a `.js` file and raw text in an `.html` one, which it gets for free because `code_view` returns nothing for a format it cannot model; and a block-level `{% autoescape off %}`, which fired **zero times on the whole corpus**. The third is kept and its zero is published rather than quietly folded into the other two: it is textbook, it is strictly wider than `|safe` on one variable because it covers every variable somebody adds to the block next year, and this benchmark simply has no label for it. A rule with no measurement is not the same as a rule with a good one. [2026-08-16]
- **Two Python XSS shapes the pack had no rule for, both found by reading the labelled source.** A Jinja template compiled from a literal that switches escaping off for the value it is about to be handed — `Template("{{ card|safe }}").render(card=card)` — scored **14 TP / 0 FP**. A signing key written into the source outright scored **10 TP / 2 FP**: the pack already owned a rule for `SECRET_KEY = os.environ.get("KEY", "fallback")` and had none for `SECRET_KEY = "literal"`, which is the larger shape by a wide margin. Two lessons already in this repository's ledger, both again: check the *source* shapes before adding sinks, and a rule that handles the elaborate version of a bug is not evidence that the plain version is handled. `HTMLResponse` was added beside Django's `HttpResponse` in the taint catalog for the same reason — the FastAPI half of the corpus had no HTML response sink at all. [2026-08-16]
- **Check 34: a tier that analyses one member of a language family must analyse all of it.** Written after the disagreement it gates cost two live defects, and it covers the case a one-time fix does not: a detector added next year. Both halves proven by mutation — a detector that names half a family, and a tier whose extension list drifts from `langs.py`. [2026-08-16]
- **A home-screen icon, drawn from the same mark geometry as everything else.** An SVG favicon covers every browser that reads one and nothing else; iOS bookmarks a screenshot of the page when there is no `apple-touch-icon`, and a screenshot of a dark landing page is a grey rectangle. 180², byte-checked by the same gate as the social cards. The build's link check now knows which assets ship, so an icon reference nothing publishes fails the build rather than a phone. [2026-08-15]
- **The 404 reads the address that failed, which is the only language-awareness a single static file can have.** GitHub Pages serves one `404.html` for the whole site and cannot pick one by path, so `/tr/typo/` and `/typo/` land on the same document. It is bilingual for that reason — but `location.pathname` still carries the cue: under `/tr/` the Turkish half moves first and the Turkish button becomes the primary one. Nothing is hidden either way, because the guess can be wrong. Two `lang` attributes were missing while this was checked: the Turkish headline line and the Türkçe button sat inside `<html lang="en">` unmarked, so a screen reader read both with English phonetics. Verified against a local server that reproduces the Pages behaviour, since `python -m http.server` returns its own page for a missing path and never reaches this file. [2026-08-15]
- **A 404 page, and a build gate that makes its one claim true.** Until now any mistyped address got GitHub's generic 404 — no branding, no language, no way back. `/404.html` is now rendered from the same shell as everything else: bilingual, no nav capsule and no language segment (it asks one question and offers two buttons), `noindex`, excluded from the sitemap, and every link on it root-absolute because the server hands it to the browser at whatever address failed. It says a link on this site cannot have brought you here — and the build now resolves every internal href and fragment against the pages it just rendered, so that is a gate rather than a hope. Proven on three failure modes: a link to a page that does not exist, a renamed section id, and a cross-page fragment that is not on the target. [2026-08-15]
- **A Content-Security-Policy whose script hash is computed from the script it describes.** GitHub Pages cannot set response headers, so this is the meta form — `frame-ancestors` and `report-uri` are header-only and deliberately absent rather than written and silently ignored. `default-src 'none'`, because the page fetches nothing from anywhere; `img-src` for the data-URI icon; `style-src 'unsafe-inline'` because the stagger delays are `style="--i:N"` attributes that no practical number of hashes covers. Verified non-vacuous in the browser: the page's own script runs, and a script injected into the DOM at runtime does not. A marker left unsubstituted would ship a policy that blocks the page's own script, so `verify` fails on it. [2026-08-15]
- **A skip-to-content link.** WCAG 2.4.1: a keyboard user had to tab the brand, the language segment and eight nav entries before reaching the page, on every page. [2026-08-15]
- **An install page, and not one command on it is typed.** `/install/` and `/tr/install/`: the six
  surfaces at full size, because the landing page's `#install` is two commands and its `#where`
  grid is six one-liners, and neither is what someone who has already decided came for. Each
  surface is read out of the file that defines it — the plugin and marketplace ids from the
  manifest Claude Code itself loads, the package name, version, Python floor and console scripts
  from `kit/pyproject.toml`, all seven Action inputs with their defaults from `action.yml`, the
  hook ids and the flags they actually run from `.pre-commit-hooks.yaml`, the five client configs
  and the tool descriptions from `docs/mcp.md`, the build and run lines from `docs/ci.md`, the
  base digest and uid from the `Dockerfile`, and the optional scanners from the `_has()` guard
  inside each adapter. A stale figure on a marketing page is embarrassing; a stale *command* on an
  install page is broken, in the reader's terminal, and what they conclude from a security
  scanner whose install line does not work is not that the line is old. [2026-08-15]
- **A gate on the menu: every nav entry must name a section the page actually has.** An entry
  pointing at a missing id is the quietest broken link there is — it still looks like a link, it
  still highlights, it simply does nothing when clicked, and the scroll-spy skips it without a
  word. Checked against the rendered page, in the union across languages so a translated label
  can never drift the anchor with it. Proven by renaming an id and by pointing one page's menu
  at another page's section. [2026-08-15]
- **Three cross-file gates that fell out of writing it, each one a disagreement nothing was
  watching.** `marketplace.json` and `kit/pyproject.toml` must state the same version — the tag
  `release.yml` will accept is derived from the second and the plugin advertises the first, so a
  drift between them ships a plugin and a wheel that disagree about which release they are. The
  `rev:` in `.pre-commit-hooks.yaml`'s own example must be that same tag, because it is a comment
  and no tool validates it; an example pinning a tag the project never publishes fails on the
  reader's machine with an error about a missing revision, which reads as abandonment. And the
  tool table in `docs/mcp.md` must name exactly the tools `secaudit_mcp.server` serves: a tool in
  the server and not the document is a capability nobody can discover, one in the document and
  not the server is a promise the server will refuse. [2026-08-15]
- **A release-state section that says which surfaces need a tag and which do not, before anyone
  finds out the hard way.** Three of the six are gated on the first `v*` tag and three are not,
  and each of the three has a from-source path on the page that needs no release at all. It also
  states the hazard rather than leaving it to be discovered: a pending PyPI trusted publisher does
  not reserve a name, so before the first upload `pip install secaudit-kit` is not a command that
  fails but a command that might succeed with something else. Written as a property of each
  surface rather than as a date or a boolean about the world, so none of it goes stale the day the
  tag is pushed. [2026-08-15]

### Fixed
- **Three colours failed WCAG AA contrast, and one of them was the biggest number on the site.** `--faint` measured 2.81:1 on the dark ground and 3.30:1 on the light one against a 4.5:1 floor, and it carries the stat labels, the panel captions, the card meta lines, the per-language percentages and the note under the hero buttons. The light theme's `--accent` sat at 4.36:1, just under, at 0.68–0.75rem. Worst of all, `--grad-head` still ran through #4a3a2a (1.83:1) and #6b4327 (2.33:1) — below even the 3:1 large-text floor — and it paints the F3 figure the whole page is built around. That is the same defect that got the headline gradient removed a few commits ago; it survived on `.stat.big b` and `.gapside.now b` because nobody went looking for the second instance. All measured, all raised, and the worst small-text token in either theme is now 4.86:1. [2026-08-15]
- **Applying a mask to a heading clipped its own descenders, and Turkish is where that shows.** `mask-clip` defaults to `border-box`, so the moment an element carries a mask its paint is cut to its own box however large the mask image is — and with `line-height: 1.04` the last line's descenders sit below that box. Every ğ, y and p on a heading came out sheared flat. It arrived with the mask that fixed the reveal in the same release, and it went unseen in English for a day because English headings mostly end in letters that do not descend. Fixed with the padding/negative-margin pair `h1 .hl` already uses: the box grows to contain the descenders and the space is given straight back, so nothing below moves. `mask-clip: no-clip` is deliberately not used — Chrome takes it unprefixed but not as `-webkit-mask-clip`, so it would fix one engine and leave the other broken. [2026-08-15]
- **`.tail` was losing to every component that resets its own margin, and three of the six on the landing page had no top margin at all.** `.surfaces`, `.langgrid`, `.stats`, `.miss`, `.reg` and `.famgrid` all zero their margin with the shorthand, all are declared after `.tail`, and all have the same specificity — so `class="surfaces tail"` quietly rendered against the paragraph above it. `.minor.tail` had already had to restate the value for this exact reason, which was the clue nobody followed. `.tail.tail` fixes the whole family in one line and leaves `.minor.tail`'s own override winning on source order. [2026-08-15]
- **A section heading you arrived at from the menu never appeared, and the cause was that it was
  clipped.** Click `Disclosure` and that section's title stayed invisible for good — a blank band
  above the paragraph where the largest text on screen should be. `clip-path` changes the
  element's box, and the box is what IntersectionObserver measures: a heading hidden behind
  `inset(0 0 108% 0)` reports an empty intersection rectangle however much of it is on screen, so
  the ratio threshold that would reveal it can never be met. Lowering the threshold to zero was
  tried in the previous round and did not help; with the ratio pinned at zero there is no
  crossing to fire on either. The reveal is now a mask, which hides the same pixels and leaves
  the geometry alone. Verified on the case that was reported, and on a nav click into
  `/install/#action`. [2026-08-15]
- **`minmax(21rem, 1fr)` is a floor, not a preference — 48px of the landing page hung off a
  320px screen.** `repeat(auto-fit, minmax(21rem, 1fr))` reads as "at least 21rem, share what is
  left", but the minimum is unconditional: the track stays 336px in a container narrower than
  336px and the panel simply leaves the page. The failure is invisible until someone opens it on
  a small phone, because every width wide enough to hold the minimum looks perfect. Every
  `auto-fit` grid on the site now wraps its floor in `min(…, 100%)`, which says what was meant.
  Found by sweeping the six pages at seven widths after fixing the button below — the same sweep
  then found the eyebrow capsule hanging past both edges at 280px, for the same reason as the
  button: three segments that refuse to wrap add up to a fixed width. Re-measured after: 54
  page × width combinations from 280 to 1440, none scrolling sideways. [2026-08-15]
- **A button was carrying `white-space: nowrap` unconditionally, and on a 390px screen the
  Turkish landing page came out 400px wide.** In a wrapping flex row a button that does not fit
  beside its neighbour already moves to its own line, so the nowrap only ever decided what
  happens to a label wider than the container itself — and there it guaranteed an overflow. Not
  hypothetical on a bilingual site: "All 6 runs, and what each cost" fits a phone and the Turkish
  sentence that means the same does not. The label now wraps to two lines inside the pill, which
  is what a button too long for the screen should do. (The Turkish label was shortened as well,
  so it fits on one line anyway.) [2026-08-15]
- **The Turkish landing page read like a translation, because it was one.** It mixed *siz* and
  *sen* in the same page, and several sentences were English word order with Turkish words in it
  — "Repo kadar çalışan hedef için de", "Dürüst devamı, bu deponun okumadığı bir kıyaslamadır".
  Rewritten as Turkish rather than mapped from the English: one register throughout, one word per
  concept across all three pages (`skorlayıcı` and `puanlayıcı` were the same object on two
  pages), and a headline that lands the way Turkish syntax actually lands instead of forcing the
  English split. The limitations list got the same treatment; it was the worst of it. [2026-08-15]
- **One paragraph of the Turkish benchmark page was still in English.** The reason four
  repositories are missing is read out of the benchmark's own README, so it cannot be translated
  without turning a derived fact into typed prose that goes stale silently. It now says so, in
  Turkish, one sentence earlier — as does the install page, where the commands, Action inputs and
  tool descriptions are quoted from the manifests for the same reason. Verbatim on purpose reads
  very differently from half-translated. [2026-08-15]
- **Every glass panel had a bad corner, and it was the construction rather than the colour.** The
  outline was a pseudo-element ring: a gradient painted into a 1.4px pad, then hollowed out with
  `mask-composite: exclude` between a content-box mask and a border-box mask. That is exact only
  where the two clips are axis-aligned — along the four straight edges. At the corners it
  subtracts one antialiased curve from another, and the difference of two coverage ramps is not
  the coverage of a ring, which is why the artefact appeared at four places and nowhere else. An
  earlier round tuned the gradient and reached the brightness but not this; no gradient value
  can. The outline is now three inset shadows behind one token, `--edge`, painted against the
  element's own rounded clip: one curve, no subtraction, nothing to get wrong at a corner. The
  bevel survives as lit-from-above, faintly-lit-from-below, flat on the sides. It also takes
  `mask-composite` off the top of `backdrop-filter` — the most expensive pairing on the page —
  and deletes twenty lines including two light-theme overrides. [2026-08-15]
- **A card losing its outline for exactly as long as the pointer was on it.** `.surface:hover`
  and `.card:hover` replace `box-shadow` wholesale, which was harmless while the outline was a
  pseudo-element and would have quietly deleted it now that it is a shadow. Both hover states
  carry `--edge` — which is the reason the three layers are a token and not three literals.
  [2026-08-15]
- **The GitHub Action told the marketplace we had 79 detectors. There are 85.** Check 08 exists to
  stop exactly this and its file list was `README.md`, `kit/README.md`, `ROADMAP.md` — three
  documents. `action.yml` is a manifest, nobody reads it as prose, and its `description` is the
  copy GitHub Marketplace prints next to the install button: the most-read sentence in the
  repository and the least-edited one. It is in the list now, and the gate was proven by putting
  79 back and watching the build go red. A count is a count wherever it is typed. [2026-08-15]
- **On a phone the install page was 715 pixels wide inside a 371-pixel viewport.** A grid item's
  automatic minimum size is its min-content, and a `pre` holding a 70-character git URL has a
  min-content of about 600px — so the column grew to fit the command instead of the command
  scrolling inside the column, and took the page with it. `overflow-x: auto` on the `pre` does not
  help, because the exception applies to the scroll container itself and the box being measured is
  the plain div wrapping it. `min-width: 0` on the columns of `.split` and `.snips`; verified at
  390, 414, 768, 1024 and 1180 across all six pages, in both languages, with nothing overflowing
  anywhere. [2026-08-15]
- **`class="minor tail"` had no top margin, and could not have had one.** `.minor` sets `margin`
  as a shorthand and is declared after `.tail`, so all four sides were reset and the subheading
  sat against the block above it. Two classes beat one. [2026-08-15]
- **The hero had no side padding, and had not had any for as long as it has existed.** Its inner
  wrapper set `padding: 2.5rem 0 1.5rem`, and the `0` in the middle of that shorthand quietly
  cancelled the 2rem gutter every other section on the site gets from the same wrapper class. At
  390px the lede ran to the physical edge of the screen. Only the vertical padding was ever the
  hero's business; the horizontal belongs to the wrapper and now stays there. [2026-08-14]
- **The two hero columns were dragging each other wider than the page.** Stacked on a phone they
  share one grid track, and a grid item may not shrink below its own min-content, so the demo
  panel's longest chip was setting the width of the headline above it and pushing the whole column
  21px out through the page's gutter. The panel already knew how to be narrow; it just had to be
  allowed to. [2026-08-14]
- **Every glass panel read as four bright brackets floating at its corners.** The gradient
  hairline that gives the panels their bevel passed through *fully transparent* across the middle
  of its travel, which put its only lit bands at the very top and the very bottom of the box —
  exactly where the four corner arcs are. The straight sides went invisible and the corners did
  not, so nothing read as one outlined object. Diagnosed by rendering the recipe against three
  alternatives at real size rather than by zooming into a screenshot, which upscales a composited
  layer and shows you the blur instead of the bug. The gradient now has a floor and never reaches
  zero: same bevel, continuous outline. [2026-08-14]
- **The finding's three chips were invisible without JavaScript.** `.chip` was hidden
  unconditionally and only un-hidden by a class the script adds, so a reader without JS got the
  vulnerable code and the caption explaining it and nothing in between — no CWE, no taint path, no
  reachability verdict, which is the entire claim the panel exists to make. The taint rail had the
  same shape of bug and simply never drew. Both displaced states are now scoped to `.js`, which is
  what the script's own comment already promised: *"the page is finished without it."* Under
  reduced motion the two also carried hardcoded delays the universal duration reset could not
  reach, so the chips still arrived a second and a half late — instantly, but late. [2026-08-14]

### Changed
- **The social card was leading with the wrong numbers, and there is now one per language.** It showed recall 98.4%, F3 0.986 and 0/62 traps — the *internal fixture* figures, the ones the site itself says are not a claim about anyone else's code. The first thing a reader ever sees was making the flattering claim the rest of the site spends a section walking back. It leads with the external F3 now, and the figures come from `gen_site.facts()` rather than a second reading of the scorecard, so the card and the page cannot disagree. Redrawn around that one number: an oversized mark ghosted behind the composition, tighter tracking, a four-count strip, the domain. `og.tr.png` is the Turkish card, and the filename and alt text in the meta tags are read from the renderer that draws them — a Turkish page linking the English card is invisible until somebody shares the link. Six Turkish letters had to be added to the stroke font (Ç Ğ İ Ö Ş Ü), each composed from its base glyph plus a mark rather than redrawn. [2026-08-15]
- **Three new gates on the card, because a stroke font fails silently.** `draw` raised nothing for an unknown character — it skipped it, which would have shipped GÜVENLİK as GVENLK with every gate green. It raises now. A line that runs past the margin has no ellipsis and simply loses its tail off the edge, so the renderer refuses to draw one; same for a strip label that runs into the next column. All three proven by mutation. Punctuation also stopped carrying a full six-unit advance, which had been putting a 50px hole either side of the dot in `31.5` and making the domain read as three words. [2026-08-15]
- **The social and locale metadata a scraper actually reads.** `og:site_name`, `og:locale` and `og:locale:alternate` (derived from the language list, so a third language is a nav entry and nothing else), `twitter:image:alt`, a `referrer` policy, and a light-scheme `theme-color` beside the dark one. The sitemap now declares `xhtml:link` alternates on every entry, so a crawler that reaches one language learns about the other without fetching and parsing the page. [2026-08-15]
- **Every string on the site moved to a formal register, in both languages.** The copy addressed the reader directly and reassured them — "so you can check the finding instead of trusting it", "take the surface your workflow already has", "Installed. Now what?", "Durumunuz buysa / Şunu alın" — which reads as a person talking rather than as a product describing itself. Statements are now about the tool rather than about the reader: "SecAudit audits a source repository, and a running target where ownership has been asserted." Second-person address is gone from every heading, table header, card and caption on all three pages except the call-to-action buttons, where an imperative is the convention. Nothing factual was dropped: every disclosure, caveat and limitation survives, stated formally rather than confessionally. [2026-08-15]
- **The hero lede is three sentences shorter, because `#what` now carries what it was carrying.** Rewriting it to describe the product made it describe all of the product — the taint path, the live target, the SBOM, the CRA pack and the published score, in one seven-line block with three em-dashes in it. Every one of those has a section below, and the new `#what` cards state the three-step version, so the lede is back to one job: what you point it at, and what comes back. Seven rendered lines to four. [2026-08-15]
- **The landing page now says what the tool does before it argues about it.** Read end to end,
  the page answered every question except the first one. The headline named a property of the
  output — "The security audit you can hand over" — and the lede opened on a *different*
  product: "Claude Code's built-in tools secure the code Claude is writing." Three sentences in,
  a stranger still did not know that this thing reads your source and prints vulnerabilities.
  Underneath that was a habit: almost every heading was an epigram of the form *not X, but Y* —
  "Measured, not asserted", "Two numbers, both true", "A gate, not a good intention",
  "reachability, not pattern matching" — each one taking a position on a noun the reader had not
  been given yet. So: the headline is a verb ("Finds the flaw. / Shows the proof."), the lede is
  a description, and the headings state the thing before arguing about it. `#what` is a new
  first section and the only one on the page that takes no position — what you type, what runs,
  what comes back, in three cards. The metrics are glossed once in plain words, because a page
  that prints `0.301 recall` at someone who does not know what recall is has printed nothing.
  And the landing page now states plainly, rather than by implication, that it can audit a
  running site and not only a checkout. Both languages. [2026-08-15]
- **The two links that leave the landing page stopped looking like the ones that scroll it.**
  Both were pill buttons, identical to every in-page control on the site, so the label was the
  only thing telling you the click cost a page load — which is how a link gets pressed by
  accident and skipped on purpose. They are one component now: a glass panel naming the
  destination, what it is, and a third line of three figures the destination is actually made of
  — `4 commands · 6 MCP tools · 0 dependencies` and `6 runs · 62 repositories · 1762 labels`.
  Every one of those is already derived and already gated, so the card cannot promise a page
  that has changed underneath it. The arrow leans into the destination on hover, and carries the
  accent from the start where there is no pointer to lean into. [2026-08-15]
- **The footer is one row: the mark, and who made it.** The link row and the small print are
  gone. Everything the links pointed at — getting started, the external result, what we miss,
  compliance, the security policy, the disclaimer, the licence — is one click into the repository
  and the button that goes there is on every page twice. Worth recording rather than
  rediscovering: the small print carried the only "not affiliated with Anthropic or OWASP" on the
  site, and the only "defensive use only" outside the landing page's own eyebrow, so neither is
  stated anywhere on the site now. If either comes back it belongs in the footer as one line
  under the row, not as a third block. [2026-08-15]
- **The footer signs itself on the row the mark is on, and the signature lost its capsule.** It
  was the brand alone at the top with the links, and the signature at the bottom beside the
  licence line — which put the two things with nothing to do with each other on the same row and
  left the mark with no counterpart. Three rows now, in the order a reader wants them: who made
  it, where else to go, and the small print. The pill around the signature went with it: beside
  an unbordered wordmark it was a bordered box on the same row, so the smaller of the two was the
  one asking to be clicked. A signature is a line of text. [2026-08-15]
- **The landing page is now exactly what its menu says it is: four sections cut, twelve down to
  eight.** The four were the four the menu never listed, which is the tell. `Capabilities` was
  four cards restating the hero demo, the dependency section, the evidence section and the
  authorization gate — the same four arguments a second time, in shorter form, immediately after
  making them. The OpenVEX register duplicated what the evidence section already covers. `--since`
  and the comparison against the two official plugins are real, but they are a feature detail and
  a positioning argument, and the lede already carries the positioning in two sentences. What is
  left is the argument with nothing repeated in it: what it is, why you should believe it, what it
  covers, why it is safe, what you get out, where it falls short, how to get it. The other two
  pages keep every section they have — a reference page is read by someone who came for the
  detail, and completeness is the point there. [2026-08-15]
- **The menu lists the sections of the page you are on, and nothing else.** It used to be one
  list for the whole site with two kinds of entry in it: `Measured` scrolled, `Benchmark`
  navigated, same capsule, same styling, no way to tell which was which until you clicked. The
  worse half only showed up on the other two pages — the list was written for the landing page,
  so standing on `/install/` five of its seven entries pointed *off* the page, it described
  somewhere you were not, and it offered no entry for where you were. The scroll-spy was dead
  there for the same reason: with nothing on the page to spy on, the indicator sat still. Each
  page now carries its own six or seven anchors, every entry does the same thing, and the
  indicator follows the reader on all three pages instead of one. The way home is the brand
  mark, which it already was; the way between pages is the button in the section that just made
  the case for it — the disclosure hands over the full run history, the install section hands
  over all six surfaces, and each sub-page's closing block links to the other. A link in a
  sentence that just argued for it beats a word in a menu bar. [2026-08-15]
- **The hero's second button goes to the benchmark page rather than to a README on GitHub.**
  That link was the best answer available before this site had a page for the measurement, and
  stopped being one the day it did. [2026-08-15]
- **The second line of every headline is now set in the face the rest of the site writes code
  in, and that is the whole effect.** It replaced a gradient sweeping across the type, which had
  two problems. The visible one was legibility: the ramp ran through `#4a3a2a`, near enough to
  the page for *you can* to read as a smudge — the brightest treatment on the site was also its
  least readable text. The quieter one was that it said nothing. A shine is decoration; a
  headline whose promise is in prose and whose deliverable is in code is the argument this
  product makes, made in type. No animation at all now, which also settles a conflict the motion
  system was already losing: the sweep looped forever underneath a hero whose own entrance is a
  line rising out of a mask, and two gestures at once is the single thing that system exists to
  prevent. Set at `.86em` because a monospace face at the display face's size reads a size
  larger, in solid `--accent` so it follows the theme and has no stop that can wash out. The
  grain filter went with the gradient it textured. Checked in both languages and both themes at
  1440, 1024 and 390 — Turkish keeps its diacritics in the mono stack, nothing overflows.
  [2026-08-15]
- **The finding's three chips are one statement, so they are on one row.** CWE, taint path,
  verdict — and the third was dropping to a second line at every desktop width, because the three
  wanted 570px and the hero's right column never gave more than 562. Three things moved rather
  than one: the column went from 1.08fr to 1.22fr (the panel is the denser half and the claim
  beside it is capped at 15ch anyway), the chips lost a little letter-spacing and horizontal
  padding, and the middle chip dropped to `L12 → L13 · argument 0` — the source expression it
  used to repeat is highlighted in the code directly above it, with the rail drawn between the
  two lines. One row now from 768px up; below 460px they stack, which is the only honest option
  when the panel is 269px wide. Not truncation: a taint path with an ellipsis in it is not a
  taint path. [2026-08-15]
- **The hero waits two more rem before splitting in two.** Between 64rem and 66rem it had room
  for two columns and not enough for what goes in them — the chips broke, and the claim was down
  to about 390px. It stacks there now, which is what a narrow laptop wanted. The generic `.split`
  rule had to stop matching the hero for the hero's own breakpoint to mean anything: it was
  reaching in at 64rem and handing over a layout the hero's media query had deliberately
  declined. [2026-08-15]
- **The landing page showed you the same six surface cards you were about to be shown again.**
  `#where` was written when the landing page was the only page; the install page now opens with
  that grid, so a reader met it twice — once on the way to the page it belongs to. The section is
  gone and `#install` absorbed what the landing page actually owes: the two commands most people
  want, and the way to the other four. The run-history bars went the same way, to the benchmark
  page that can show all six runs as a table with what each one cost. **What did not go is the
  blindness disclosure.** Cutting the section that held it was the first attempt and it was
  wrong: that paragraph is the reason the number is quotable, it is not run history, and a
  visitor who reads only the landing page has to meet it. It keeps its own section, minus the
  chart. Fourteen sections to thirteen, and no reader is told anything twice. [2026-08-15]
- **The landing page was never as long as it looked, and the earlier measurement was mine to
  correct.** Counting from `<main>` to the end of the document swept in the footer and the inline
  script: 2,540 "words" of which about 600 were neither. Measured to `</main>`, the three pages
  are 1,854 / 2,102 / 2,247 — the landing page was already inside the length a page like this
  should be, and the defect was duplication rather than bloat. [2026-08-15]
- **Six cards in a five-wide grid left the sixth alone on a row of its own.** `auto-fit` fitted
  five across at 1440px, and the one it orphaned was the pre-commit hook — the surface that runs
  earliest of all of them, reading as an afterthought. There are six of them and there is a
  correct shape for six: 3×2, then 2×3, then one column. [2026-08-15]
- **The nav's `Install` goes to the install page rather than scrolling to a summary of it.** The
  landing section and its two commands stay where they are; an entry that scrolls to the summary
  when the full page exists is an entry that hides it. The `#where` grid gained a way onward for
  the same reason. [2026-08-15]
- **"Same engine, six ways in" now counts.** The heading spelled the number while the number was
  a list in the generator that nothing held it to — the same shape of decay this site exists to
  prevent, sitting in a heading. It reads `{surfaces}` now, and a seventh surface renames the
  section by itself. The install page's own headline deliberately carries no count: `One engine.
  6 ways in.` spells one number and sets the other as a numeral, in two lines of one sentence.
  [2026-08-15]
- **`table.grid` and `.minor` moved from the benchmark page's stylesheet into the shell.** The
  install page wanted a data table, and the alternative was a second copy — which is a copy right
  up until someone fixes one of them. What stayed behind is what only a sixty-two-row table needs:
  a scroll ceiling and a header that survives it. [2026-08-15]
- **The first screen is the hero and nothing else, and the arithmetic says so.** The section
  starts under the fixed bar and ends at its own bottom padding, so exactly those two come out of
  the viewport height — the next section now begins at the fold instead of 40px above it. Below
  62rem the pinned nav capsule floats over the bottom of the viewport too, so it comes out of the
  same budget rather than covering the hero's last rows. [2026-08-14]
- **The way back up now shows how far down you are.** A ring closes around the back-to-top button
  as the document scrolls, drawn on the button's own edge so it reads as the border filling in
  rather than as a second circle around it. It is not decoration bolted onto a control: the button
  that returns you to the start is the natural place to say how far from the start you are, so one
  object answers both. Progress is measured against what is actually scrollable rather than
  against document height — on a page barely taller than the window those differ by a whole
  viewport and the ring would never close. The script writes one custom property per frame and the
  dash offset follows in CSS. [2026-08-14]
- **The eyebrow is three claims, so it is drawn as three.** *Open source · MIT · Defensive use
  only* was a capsule with two middots in it; it is now three divided segments, the first tinted
  and carrying the live pulse because it is a state, the two after it plain because they are
  facts. A middot cannot make that distinction and a divider can. The split happens in the
  generator, so the copy stays one translatable string: a translator who writes two claims or four
  gets two or four segments and nothing in the CSS has to know. The benchmark page's eyebrow —
  *RealVuln 2.0.0 · Tier 0 · run 2026-08-13* — is the same component and got it for free.
  [2026-08-14]
- **Both hero headlines are uncovered a line at a time.** They used to be one string with a `<br>`
  in the middle, which cannot be revealed line by line — a line break is not a box, and only a box
  can be masked — so each line is now its own element and rises out of its own mask on a 100ms
  stagger. That is the gesture the section titles already use, which is the point: the page reads
  as one page. The heading itself is pinned still while this happens, because a block fading up
  while its own lines rise out of a mask is two gestures at once, which is the single thing this
  motion system exists to prevent. [2026-08-14]
- **The hero is two columns: the claim on the left, the finding on the right.** The demo panel used
  to sit below the fold-filling statement, so the promise and the proof were one scroll apart and
  the panel's job was to peek over the fold and say *there is more*. Side by side they are read
  together, and the fold stops being something to design around. Below 64rem they stack — the old
  arrangement, and the only one a phone has room for — and the entrance changes with the layout
  rather than being kept for consistency's sake: side by side the halves arrive from their own
  sides, stacked they rise, because a centred stack sliding in from the left is moving along an
  axis the layout no longer has. Verified at 390, 768, 1024, 1180 and 1440: the panel stays inside
  its column at every width, the code never needs to scroll sideways, and nothing overflows the
  page. [2026-08-14]
- **New mark: a shield carrying an S whose lower half is the tick — and the card, the favicon and
  the page finally carry the same one, in the same orange.** They did not before, and the code
  said otherwise: the social card drew a generic shield-and-tick while the site drew something
  else entirely, and the function drawing the card claimed in its own docstring that it was *"the
  favicon's mark, scaled — same silhouette so the tab icon and the card agree."* It had not been
  true for a long time. The card was also painting itself a second brand orange (`#b34a1f`) that
  existed nowhere else, so the card and the page it links to were two different colours; it now
  uses the site's own accent.
  **The designed vector is the source, and the site derives from it at build time.** The artwork
  ships as `site/mark-source.svg` and `gen_site.py` reads it, flattens the cubics and fits them to
  the box on every build — the sixty-seven coordinate pairs are not transcribed into the
  generator, because sixty-seven pasted numbers are sixty-seven chances for the mark on the site
  to stop being the mark in the artwork. That is the rule this generator already enforces for
  measurements, applied to geometry. Redraw the SVG and the page, the favicon and the card all
  move together, or the build stops.
  The flattening is bounded rather than eyeballed: subdivide until both control points sit within
  0.35 source units of the chord, which at this scale is 0.017 of a viewBox unit — a sixtieth of a
  pixel at the mark's nominal size. Checked by rasterising source and conversion to 512×512 and
  differencing the masks: **108 pixels of 56,432 disagree (0.19% of the area)** and every one has
  a neighbour that agrees, so the worst boundary error is a single pixel at 512. That is antialias
  rounding, not shape error.
  Four properties the renderers depend on are asserted at build time rather than assumed, and each
  was mutation-tested to confirm it is not a vacuous check: exactly two subpaths, only path
  commands the parser actually understands (a silently skipped curve is a mark that is subtly
  wrong everywhere at once), the mark fitting inside its box, and no ring crossing itself — the
  card's canvas fills even-odd and would render a hole at the crossing.
  **The box is cut to the mark.** It is portrait, 20.6 × 28.8, so the viewBox is 24 × 32 and
  consumers size by height. A square box would have parked three empty units either side of the
  glyph, and since the CSS sizes the box, at 22px in the bar the shield would have rendered 16px
  wide next to a 22px wordmark and read as the smaller thing.
  **The lower half of the shield is the tick** — one shape doing both jobs, so there is no second
  colour to keep in step and **no separate favicon variant**, because it survives 16px intact.
  Judged by rasterising at 16, 22, 28, 40 and 72px and reading the actual pixels rather than the
  vector. The artwork's gradient is deliberately not reproduced: its top stop measures 2.3:1
  against the light theme's paper, under the 3:1 WCAG 1.4.11 asks of a meaningful graphic, so
  light mode would need a second pair of stops maintained in step with the first; a gradient
  across 22 rows of pixels is a colour nobody can name; and the card's canvas cannot draw one. The
  mark takes the theme accent instead, and darkens with everything else in light mode.
  **Stated plainly because it is a real trade-off:** this is the shape the category already uses.
  An earlier note in the generator argued against exactly that — a mark that could belong to any
  security product is not a mark — and that note has been rewritten rather than deleted, so what
  was traded (distinctiveness) for what was bought (instant recognition) stays on the record.
  [2026-08-14]
- **The site's navigation, header and footer were rebuilt.** The links now live in a glass capsule
  with a single indicator that slides to whichever section you are actually in, so the bar answers
  *where am I* and not only *where can I go*. The capsule is the same object at every width: below
  62rem it detaches and pins to the bottom of the viewport, in reach of a thumb, and scrolls
  sideways. **That replaces nothing, which was the problem** — before this the links simply
  vanished below 62rem and no menu took their place, so the site had no navigation at all on a
  phone. A pinned bar also avoids a panel that would need a focus trap, an Escape handler and a
  label to get back to where a visible bar already is.
  The bar itself is transparent until something scrolls under it, and its separator is a hairline
  that fades out at both ends rather than a rule drawn edge to edge — the treatment the footer
  already used, so the page now opens and closes the same way. The two fixed vertical rules at
  ±40rem are gone, and so is the GitHub button, which appeared three times on one page.
  The footer went from five blocks of grey text to two: the mark with one row of links, and one
  line of small print. Changelog, roadmap and the MCP page were dropped from it — one click into
  the repository — while everything that is a *commitment* stayed: the security policy, the
  disclaimer, the licence, and the page that says what the tool misses. [2026-08-14]
- **The language control now says which language you are reading.** It was a single link showing
  the *other* language — "TR" on the English page — which never stated the current one and read
  equally well as a label and as a switch. It is a two-item segment with `aria-current` on the
  open one, and it points at the counterpart of the page you are on rather than at the home page.
  [2026-08-14]
- **The first screen is one composition again.** The hero was a stack of five things followed by a
  panel, and on an ordinary laptop the fold landed inside the panel's code — the first thing
  anyone saw was a page cut in half. The statement now fills the viewport minus the bar and is
  centred in it, and what shows below it is the panel's top edge, which reads as *there is more*
  rather than as *this was cropped*. `svh` rather than `vh`, so a phone's collapsing address bar
  does not move it. [2026-08-14]
- **Motion is a system rather than a set of effects.** One easing curve and one duration band
  throughout; what varies between sections is the gesture, chosen to match what the section shows.
  Headings are uncovered by a mask lifting instead of sliding in, a two-column section moves the
  way it is built (argument from the left, evidence from the right), a grid of cards scales up
  together on a short stagger, and each kicker draws its own rule outward from the accent dot.
  All of it is transform, opacity or clip-path only, so none of it touches layout, and all of it
  is switched off in one place under `prefers-reduced-motion`. [2026-08-14]
- **The caveat blocks became cards.** A paragraph with a coloured stripe down its left edge and
  two square corners is the shape of a quote, not of a card — on a page whose whole argument is
  *read the limits*, the limits looked like an aside. They are now surfaces in the same family as
  everything else, with the accent kept as a short mark at the top-left. The feature cards, which
  had no surface at all, got one. [2026-08-14]

### Added
- **A back-to-top control**, absent until the first screen has been left behind. On a phone it
  sits above the pinned capsule rather than beside it, because two floating controls sharing a
  corner is how a thumb hits the wrong one. [2026-08-14]

### Fixed
- **Internal links stopped being absolute.** Every navigation href pointed at the production
  origin, so the built site could not be opened anywhere else — not from a local server, not from
  a preview deployment, not from a branch. Machines still get the absolute form where they need
  it (canonical, hreflang, sitemap, structured data) and people get the relative one; those are
  two different questions and one function was answering both. [2026-08-14]
- **A `backdrop-filter` on the bar was capturing the capsule's `position: fixed`.** A filtered
  ancestor becomes the containing block for fixed descendants, so on a phone the capsule pinned
  itself to the bottom of the 64px bar instead of to the bottom of the viewport — landing on top
  of the brand and hiding it. Found by rendering the built page inside a 390px iframe rather than
  by reading the CSS. The capsule is now a sibling of the bar, which also gets the semantics
  right: a `<header>` for the banner, a `<nav>` for the navigation. [2026-08-14]

### Added
- **A benchmark page, in both languages, holding the whole external result instead of a summary
  of it.** `/benchmark/` and `/tr/benchmark/`: the confusion matrix the aggregates are computed
  from, all six runs with what each round cost rather than only what it scored, the benchmark's
  own published baselines, every CWE family ordered by labelled pool size, **all 62 repositories
  rather than a top five**, both digests, the reproduction sequence with its four gotchas, and the
  disclosure that the number stopped being blind three rounds ago given a section of its own
  rather than a footnote. The landing page had room for two stat blocks and a row of bars, and
  this measurement is the product's one differentiating claim; the parts that do not flatter it —
  four families still near zero, two repositories where nothing labelled was found — are on the
  page for the same reason the rest is. Nothing is typed: every figure is read from
  `result.json`, and the two things RealVuln publishes as prose rather than as data (the
  baselines table, the reproduction commands) are **parsed out of `eval/realvuln/README.md`**,
  which check 27 already holds against the scorer output — so the site and the README cannot
  disagree, and a baselines table that stops having four rows, or whose SecAudit row stops
  agreeing with `result.json`, fails the build instead of rendering a stale comparison. All six
  new failure modes were proven by mutation. [2026-08-14]
- **The site generator now builds pages, not one page.** `site/template.html` became
  `site/shell.html` plus `site/page-index.html` and `site/page-benchmark.html`, with per-page
  rules in `site/css-NAME.css` and per-page structured data (the landing page is a
  `SoftwareApplication`; a measurement of it is a `Dataset`). The alternative was a second copy of
  470 lines of CSS, and a copy of a stylesheet does not stay a copy — the drift is invisible until
  the two pages look like two products. Navigation resolves per page, so a landing-page anchor
  carries the way home with it when it is rendered anywhere else. `sitemap.xml` and `robots.txt`
  are generated from the same page list the files are written from, so neither can describe a page
  that was not published. [2026-08-14]

### Fixed
- **Copy written in markdown was being substituted into the document verbatim, and one sentence
  lost its subject.** The landing page's pull-request section explained `--since <ref>` and the
  browser read `<ref>` as an unknown element and swallowed it, so the sentence about the gate was
  missing the argument it is about; backticks elsewhere stayed backticks. Body copy is now escaped
  and its backticks rendered as code, head copy is escaped but never marked up (a `<code>` element
  inside a `content` attribute is not a code element, it is broken markup), and the unmarked text
  is what the structured-data block still sees so nothing is escaped twice. [2026-08-14]
- **The recall bar was a component styled in one place and inert in the other.** `.track` and
  `.fill` were scoped to the language rows, so the benchmark page's per-family bars would have
  rendered at zero width — which on a page about measurements reads as "this family scores
  nothing" rather than as a layout bug. [2026-08-14]
- **A seventh navigation entry overflowed the bar at the width where the links first appear.**
  Measured rather than eyeballed: at 62rem the brand, seven links and the button needed 947px of
  the 928px inside the wrap, in English and Turkish alike. The gap tightens there and widens again
  once there is room. [2026-08-14]
- **The site deploy stopped failing on every push.** Pages on a private repository needs a paid
  plan, so `site.yml`'s `deploy` job could not succeed before launch and went red on every single
  push — the same defect `self-scan.yml` was fixed for one workflow over, and missed here. It now
  skips itself while the repository is private (`if: github.event.repository.private == false`).
  A skip rather than `continue-on-error`, deliberately: on a job whose entire purpose *is* the
  deploy, `continue-on-error` would report green whether it published or not, including after the
  repository goes public — trading a visible non-problem for an invisible real one. Unlike
  launch step 4b there is nothing to delete later; the condition flips on its own. What the
  checklist now says to do instead is verify the first real run, because a job that has only ever
  skipped has never been proven. [2026-08-14]
- **`--since` could compare the working tree against itself and call it clean.** `gitref` mixed
  two spellings of one directory: `os.path.abspath(target)` as the caller wrote it, and git's
  `rev-parse --show-toplevel`, which is always fully resolved. Whenever those differ — an 8.3
  short name, a junction, a symlink — `relpath` between them returned a traversal instead of `.`,
  so the "baseline" path climbed out of the extracted archive and landed back on the **live
  working tree**. `os.path.exists` agreed, nothing raised, and every finding compared equal to
  itself: `--since` printed *"Nothing new"* for a change that introduced a Critical, and the pull
  request gate this feature exists to be passed green. Both sides go through `realpath` now, and
  the containment check `extract()` already applied to every tar member is applied to the scoping
  step too — that asymmetry is where the bug lived, so anything `realpath` cannot reconcile now
  fails loudly instead of silently scanning some other directory.
  **Found by CI, not here:** a GitHub Windows runner's `TEMP` is `C:\Users\RUNNER~1\...` and this
  machine's is not, so the suite was green locally and red there. Reproduced on purpose by
  pointing `TEMP` at an 8.3 alias, and the regression test now builds its own alias
  (`GetShortPathNameW` on Windows, a symlink on POSIX) so the case is covered on any machine
  rather than only on one whose temp directory happens to have the right shape. Proven by
  reverting the fix and watching it go red. [2026-08-14]
- **The Kubernetes rules stopped reporting this repository's own Semgrep pack.** `.yaml` is a
  container format, not a language, and the four K8s rules fired on any document containing the
  word — including `rules/secaudit/k8s.yaml`, where `hostPath:` is the *quoted pattern of the rule
  that looks for hostPath*. A new detector field, `requires_in_file`, is the mirror of
  `suppress_if`: `suppress_if` says a control is present so this is fixed, this says the file is
  not the kind of document the rule is about. The four now require a manifest header
  (`apiVersion`/`kind`, or `services` so a Compose stack — the only place the Dockerfile-keyed
  rules cannot see — stays in scope). `literal=False` could not do this job: YAML has no lexical
  shape this engine models, and blanking its scalars would also blank the value half of
  `privileged: true`. The four rules are now withheld from the exported Semgrep pack with a
  published reason (39 exported, 46 withheld), because `patterns:` conditions must all match the
  same range and `paths:` filters by filename, so an exported copy would carry the pattern
  without the precondition. **Measured, not assumed:** both engines were run on one fresh
  benchmark clone in the same session — the pre-change engine reproduced 530 TP / 448 FP / 1232 FN
  and F3 31.5 digit for digit, and the changed engine returned the same, so `result.json` moves
  only its engine digest. [2026-08-14]
- **The authorization hook's self-test went red on a machine without git instead of skipping.**
  Two of its four `scope.yaml` trust cases need a real git index and are *unreachable* without one
  — the guard correctly refuses an undecidable assertion, which is what case 4 tests — but only
  one of the two was guarded, so a fresh clone reported two defects that were not defects. Both
  are now skipped with a note naming exactly what did not run, and the skip is refused when `CI`
  is set, because a gate that can skip in CI is not a gate. [2026-08-14]

### Changed
- **Positioning moved off the LLM tier, and measuring it is now a stated non-goal.** The README
  led with *"SecAudit uses Claude to triage, verify, and explain"* — so the shop window was the
  one tier with no number, and the one that competes head-on with a multi-agent scanner Anthropic
  ships free inside the product. Measuring it needs paid inference across 62 repositories and
  this project does not carry that cost, so it is not backlog: it is not planned, and the ROADMAP
  says so explicitly (🚫) to stop it being re-opened as debt every few sessions. The tier is
  unchanged in code — off by default, shipped, harness included, one command for anyone who wants
  to produce the number. What changed is the claim: the hero, the feature bullets, the standalone
  section and the Turkish README now lead with the deterministic engine and the things that have
  no competitor (live target, authorization gate, offline / no key / no paid plan, a published
  reproducible score, SBOM + OpenVEX + CRA, MCP), and a new
  *"The LLM tier: optional, unmeasured, and staying that way"* section states the narrowed claim
  in one place — including that a general-purpose model scores 51.7 on this same corpus with no
  harness at all, 20 points above this engine. `docs/what-we-miss.md` already said *"an
  unmeasured tier is not coverage"*; the rest of the documentation now agrees with it. No figure
  moved. [2026-08-14]
- **The dogfood gate now enforces what its docstring claimed.** It gated on High/Critical only
  while saying "require it to stay quiet"; thirteen Medium findings sat under that gate and could
  have become thirty without a build going red. Three gates now: no High/Critical, **no
  HIGH-confidence finding** (on this engine that means a framework-request-rooted taint path, and
  this codebase is a CLI with no requests — so one would be the analysis inventing a source, not a
  debatable lead), and a per-detector ceiling pinned to the measured count, set to what is
  measured rather than to a round number above it. The thirteen are parameter-rooted paths into
  `open()` and `urlopen()` — a scanner opening the file it was handed — and each ceiling entry
  carries the reason it is a false positive here. All three proven by mutation. [2026-08-14]
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
