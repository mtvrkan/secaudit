# SecBench.js — the JavaScript number

**Result: recall 0.5445 — 312 of 573 labelled sinks, across 575 npm packages.**
Run 2026-08-18, Tier 0. Raw output committed as [`result.json`](result.json); every figure below
is read from it.

> **The corpus shrank between this run and the last, and that is most of the difference.** The
> 2026-08-17 run fetched 594 of 600 packages; this one fetched 575, because **nineteen more have
> been removed from npm** in the meantime — a 404 on a real name and version. Their labels count
> as misses, so 0.5445 and 0.5410 are not the same measurement and the drop is not a regression
> to hunt. The figure that IS comparable is the one that describes the engine rather than the
> registry: **misses caused by "no rule fired at the sink" went 213 → 201** on a corpus with
> nineteen fewer packages in it. Stated here rather than left for a reader to reconstruct,
> because a recall figure that fell is exactly the kind of number a page like this is tempted to
> explain away.

**The first run of this benchmark was blind and every one since is not.** Recall 0.2286 was
measured against rules none of which had been written or selected by reading a SecBench.js label.
That run said three things were wrong, this repository fixed them, and the figures since are
corpus-informed in exactly the way RealVuln's have been since its third run. The blind figure is
the one to quote when the question is *how does this engine do on code it has never seen*;
**0.2286 is that number and it does not improve.** What the later runs are good for is the
opposite question: whether the diagnosis was right.

Two of the first three were, and the third was wrong in an interesting way — see
[What the first run's three findings turned into](#what-the-first-runs-three-findings-turned-into).

> **Read this before comparing any two rows of the history below.** Every figure on this page
> measured before 2026-08-17 was produced by an engine that was **not deterministic**, and the
> uncertainty is about one label wide. Taint attribution walked a hash-ordered set of identifier
> names and returned on the first tainted one it reached, so the line a finding was reported at
> could change between runs of identical code — `TAINT-JS-PATH` in `git@0.1.5` landed on line 739
> or line 743 depending on the run, and 743 is outside the ±10 scoring window. This corpus reads
> **0.5410 or 0.5393** on the same commit, which is why a one-label move between two rounds was
> never evidence of anything on its own. It is fixed and gated as of the round that found it
> (four processes, four hash seeds, one finding set required), so figures from 2026-08-17 onward
> are reproducible in the strong sense. The earlier ones are not being restated — re-running them
> means re-running every historical engine, and the honest thing is to say the error bar out loud
> rather than to quietly repair the record.

| Class | Found / labelled | Recall | Previous round | Blind run |
|---|---|---|---|---|
| `code-injection` | 22 / 33 | **66.7%** | 23 / 33 | 19 / 33 |
| `command-injection` | 62 / 101 | **61.4%** | 62 / 101 | 41 / 101 |
| `path-traversal` | 128 / 167 | **76.6%** | 129 / 167 | 61 / 167 |
| `prototype-pollution` | 72 / 185 | 38.9% | 68 / 185 | 10 / 185 |
| `redos` | 28 / 87 | 32.2% | 28 / 87 | 0 / 87 |
| **All** | **300 / 573** | **52.4%** | 310 / 573 | 131 / 573 |

**The held-out slice, scored separately as `eval/HELDOUT.md` requires.** 121 of the 573 labels are
in packages sealed on 2026-08-16 and never inspected since: they score **70 / 121, recall 0.5785**,
against **230 / 452, recall 0.5088** on the rest. The sealed slice scoring *higher* is the most
useful thing on this page and also the one to state most carefully — sealing stops future targeted
tuning, it cannot unread the past, and these packages were present for both corpus-informed
rounds. It is a baseline for the next round, not a blind figure. The blind figure is still
0.2286.

**The round that recovered these packages moved the unsealed slice and NOT the sealed one, and
that is written here rather than explained away.** Unsealed 0.5088 → 0.5354,
sealed 0.5785 → 0.5785 — unchanged to four decimals.
`eval/HELDOUT.md` says exactly what that pattern means: *a round that moves the unsealed number
and not the sealed one has fitted the corpus, and says so in its own output rather than in
someone's judgement afterwards.* The judgement, for whatever it is worth, is that this round took
no input from any label — it is a scoping fix, found by noticing that a package's own `index.js`
was never opened, and it recovers files by asking a manifest rather than by asking the ground
truth. But the policy exists precisely because that argument is always available to the person
making it, so the number stands as the record and this paragraph does not overrule it.

## The two classes nobody had read, and what reading them said

`command-injection` and `code-injection` had never been diagnosed — three rounds of work had gone
into the other three classes. Reading all 44 unsealed command-injection misses says the taint
tier was not failing to *follow* anything. It follows a parameter through concatenation, through
a template literal, through a local, through `.join(' ')`, and across a call into a helper. What
it could not do was **recognise the call it was looking at**:

* **`exec` is whatever the file imported.** `JS_SINKS` anchored on a bare `exec(` or the literal
  receiver `child_process`, and that lookbehind is load-bearing — `pattern.exec(string)` is the
  RegExp method and the most common `.exec(` in the language. So `cp.exec`, `childProcess.exec`,
  `child_process_1.exec` (what TypeScript emits), `require('child_process').execSync`, a
  `promisify`d alias and `shell.exec` from shelljs were all invisible: **14 of the 44 misses**.
  The receiver is resolved from the file's own imports now, which is both wider and narrower
  than a name list — `sh.exec` is a shell in a file that imported `child_process` as `sh`, and
  `re.exec` is not one in a file that did not.
* **A method in an object literal binds parameters.** `const utils = { exec (cmd, cb) { … } }` is
  how a utility module is written, and the taint tier's function-header regex did not know the
  shape, so `cmd` was not a source. Neither was any parameter of `function(a, b)` written without
  a space after `function` — the regex required one. Between them these two are the largest part
  of the round.
* **Two whole sink families were missing from the catalog.** The `Function` constructor *without*
  `new` (`Function('obj', 'return ' + expr)`, which is what the shipped code writes), Node's
  `vm` (`runInContext`, `runInNewContext`, `compileFunction`, `new Script`), and indirect eval
  (`(0, eval)(code)`). Three of the ten unsealed code-injection misses were `vm` alone.

**`vm` is resolved from the imports too, and lodash is why.** The first version matched a bare
`runInContext(` as well as `vm.runInContext(` — and lodash exports its own `runInContext`, an
unrelated function that rebuilds the library against another global object. One package into the
corpus, the rule had a false positive that no amount of taint reasoning would have refused,
because the call really does take a parameter-derived argument. A name is not an identity.

**What it cost.** RealVuln: **nothing at all** — 659 / 278 / 1103, precision 0.7033, unchanged to
four digits, which is what a JavaScript-only round should do to a Python corpus and is worth
checking rather than assuming. The noise floor: **one** additional Medium finding across 382,057
lines. And the unmatched-finding ratio rose again, 0.0910 → 0.0919 — two rounds in a row where
recall went up without noise going up faster.

## Prototype pollution: 25 → 68 of 185, and this one did not cost noise

The worst class on this page for three rounds, and the previous round's write-up named what it
could not reach: *"writes inside anonymous callbacks, merges split across modules, and functions
whose guard is an imported helper."* Reading all 113 unsealed misses one at a time says the first
of those was real and the diagnosis underneath it was incomplete. Three separate things were
wrong, and only one of them was the rule:

* **Thirty-five of the misses were in a function the analysis could not see.** Every JavaScript
  structural rule is scoped by `structural/js._functions`, and it delimited a function by finding
  the first `{` on the matching line. A default parameter value (`function unflatten(obj = {}) {`)
  made the body *one line long*; a brace on the next line, an export assignment
  (`module.exports = function reduce(…)`) and a method in an object literal or class made it
  invisible. **This is the most transferable finding of the round: a shared piece of
  infrastructure that silently under-delivers costs every rule built on it**, and the cost is
  invisible from any single rule's numbers.
* **A callback's parameters carry whatever the iterated value carries.** This module's docstring
  had declared the anonymous-callback limitation from the day it was written, with the labelled
  instance that proved it (`js-extend@0.0.1`). Reading it again, the rule never needed the
  callback's *span* — only that fact, which is decidable at the call site. `js-extend` is found
  now.
* **A set-by-path helper walks, and no iteration binder can ever see the key at the end of it.**
  `cur = cur[part]` in a loop, then `cur[parts[n - 1]] = value` — the `set(obj, 'a.b.__proto__',
  v)` half of CWE-1321, which this module's own header had described as covered by the `split()`
  binder and which in practice usually is not. The walk is what separates it from a plain setter:
  `store[name] = value` with a parameter key is one of the commonest functions in the language and
  must stay silent, which is the test the walk requirement exists to pass.

**The cost, on the three instruments, and it is the smallest of the day.** The unmatched-finding
ratio went **up** — 0.0895 → 0.0910 — which is the first time in three rounds that recall rose
without noise rising faster, and the only combination this page has ever called unambiguously
good. RealVuln: **one** false positive across 62 repositories, precision 0.7041 → 0.7033, traps
unmoved at 248; it is `PROTO-JS-WRITE` inside `static/js/foundation/foundation.js`, a vendored
front-end library that `is_vendored_asset` does not recognise. The noise floor moved 0.24 → 0.25
per 1,000 lines: three findings, all in `axios`, all High, all correct readings of a generic
helper writing a caller-chosen key.

**And the held-out slice moved further than the slice whose labels were read, again.** All 113
misses read for this round were unsealed; sealed went **0.4545 → 0.5455** and unsealed
**0.4027 → 0.4735**. Two rounds, two answers in the same direction, on packages nobody involved
has opened — which is the entire argument for [`eval/HELDOUT.md`](../HELDOUT.md) existing before
anybody needed it.

## Two things happened in the round before it and only one was an engine change

## The scorer was looking up paths that are not in the package

Eighty-two of the 573 labelled sinks name a file that does not exist at the path the label
states. SecBench.js records a sink as `util.js:143` or `merge/dist/lib/merge.js:12` — sometimes a
bare basename, sometimes carrying a monorepo prefix the published tarball does not have. `ajv`'s
`util.js` is `lib/compile/util.js` on disk; `viking04-merge`'s `merge/index.js` is `index.js`.
The scorer compared the two strings and filed every one of those misses under *"no rule fired at
the sink"*.

It resolves them now — the stated path if it exists, otherwise the unique file matching it on
component boundaries in either direction, and only when that file is long enough to contain the
labelled line. Everything else is counted as a miss under its own name rather than blamed on
detection. **That is worth +6 true positives on an unchanged engine** (214 → 220) and, far more
importantly, it moves 36 misses out of a cause that had been aiming rounds at the wrong problem.
This is the second time this page has recorded a miss filed under a comfortable cause — the first
was `dist/`, below — and both were found by testing the explanation rather than repeating it.

The blind run was re-measured through the same matcher so the columns stay comparable: a worktree
at the commit that produced it, all 594 packages rescanned, `128 / 573` reproduced exactly under
the old matcher and `131 / 573` under the new one. The claim in this scorer that the blind
engine "no longer exists" was simply false — it is a `git worktree add` away, and believing
otherwise nearly published two matchers in one table.

## ReDoS: 11 → 28 of 87, and it cost something

Giving the analysis a JavaScript front end last round took ReDoS from 0 to 8, and this page said
plainly that eight was the honest size of criteria aimed at **exponential** backtracking. So the
other 79 labels were read one at a time. Two things were wrong, and they compound:

* **Most published ReDoS advisories are quadratic, not exponential.** `^\S+@\S+$` (the `@` is
  itself an `\S`, so the split can slide), `(?:\d+)?\.?\d+`, `(.*)\s*\*\/`, `[+-]?\d*[.]?\d+` —
  two unbounded repeats over overlapping characters, followed by something that can fail. The
  criterion added for that is narrower than "two quantifiers in a row", which describes most
  regular expressions ever written: the boundary between the repeats has to be able to *move*
  (`\d+\.\d+` is pinned by a dot that is not a digit), and something after them has to be able to
  reject a split (`\s+(.*)$` is ambiguous and costs nothing, because the first split it tries
  wins). Leaving that second condition out reported 28 regexes in this repository's own source.
* **The sink is where the pattern runs, not where it is written.** Twenty-five labels sit on a
  `RGX.test(input)` or `str.replace(RGX, '')` line whose `const RGX = /…/` is elsewhere in the
  file. The Python front end had reported the call site since the day it was written — a pattern
  is an ordinary string until `re.search` runs it, so there was nothing else to report — and the
  JavaScript front end reported the literal, because a literal is already a regex. Same analysis,
  two answers to "where is the defect", and the difference was an implementation detail.

Attributed by re-running the analysis on the labelled files with each change disabled: the
quadratic criterion alone is worth +11, use-site reporting alone +1, and **together +19** — seven
labels need both, being a quadratic pattern reported where it runs.

**The cost, on all three instruments, because two of them moved.** The noise floor over 382,057
lines of maintained code went **0.21 → 0.24 findings per 1,000 lines**, twelve findings, all
Medium; High-and-above is unchanged for a reader who triages by severity. On RealVuln it is **+4
false positives and no true positive** — the same email regex in four seeded applications —
taking that precision 0.7071 → 0.7041, which this project publishes as a stop signal. And here,
the unmatched-finding ratio fell 0.0929 → 0.0895.

It was kept, and the argument is the sealed slice rather than any of those three. **A fifth of
this corpus has never been inspected** ([`eval/HELDOUT.md`](../HELDOUT.md)), and this is the first
round where that could say anything: the labels read for this work were unsealed ones, so a round
that merely fitted them would move unsealed and leave sealed flat. Sealed went **0.4215 → 0.4545**
and unsealed **0.3739 → 0.4027**. The sealed slice moved *further*. Whatever else this round is,
it is not corpus fit.

**`path-traversal` 59 → 122 of 167 is this round, and it came from one missing source.** The
filesystem sinks were already modelled comprehensively — `fs.readFile`, `createReadStream`,
`writeFile`, the `fs.promises` forms, twenty-odd entries. What was missing was **`req.url`**, the
single most common source in Node, absent from `JS_REQUEST_SOURCES` while `req.query`,
`req.params` and `req.body` were all present. This corpus is full of small static file servers
built on `http.createServer`, where there is no Express router anywhere and the request *is*
`req.url`:

```js
function handleRequest(req, res) { loadFile(req.url, …) }
var loadFile = function (file, …) { file = path.join(config.dir, file)
                                    fs.readFile(file, …) }
```

`path.join` onto a base directory is not a containment check — `../` walks straight out of it.
The sink was modelled, the source was not, and the two never met. **+63 true positives for +12
unmatched findings**, and zero change to the noise floor on eight maintained projects.

The catalog's Python source list carries a comment saying this list is the *entry point* to the
whole analysis, so an omission switches the engine off for a framework idiom rather than for one
rule. That was written about Python. Nobody carried it across.

**One package makes the totals in `result.json` read 1,793 rather than 1,683, and it is worth
knowing why.** `react-native@0.63.0-rc.0` is 30 MB and sits within seconds of the harness's
per-package timeout: three runs of this round abandoned it at 120s and the final one finished it,
which added 110 unmatched findings in the `redos` class and moved the package count from 593 to
594. Its own labelled sink is a miss either way, so recall is unaffected — but a *corpus* that
depends on how busy the machine was is not a corpus, so the timeout now defaults to 300s, where
nothing here reaches it. The comparison above is stated on the 593 packages common to every run;
`result.json` reports the full 594 it actually scanned.

## Read this before the number

**Recall is the sound metric here. Precision is not, and is not published as one.** Each entry is
one npm package at one pinned version with *one* labelled sink; the benchmark says nothing about
the rest of the package. Counting every other finding as a false positive gives 0.0848, and that
figure is a **lower bound on noise, not a precision** — some of those 3,368 unmatched findings are
real flaws in unaudited npm packages that SecBench.js simply never labelled. RealVuln labels many
findings per repository and ships false-positive traps, which is what makes a precision number
mean something there. **Do not put 0.0848 beside RealVuln's 0.658.** They share a name and measure
different things. `result.json` calls the field `precision_lower_bound` for that reason.

It is still worth watching *across runs of the same corpus*, where the denominator is fixed and
only the engine moves: **0.0606 → 0.1006 → 0.0903 → 0.0895 → 0.0910 → 0.0919 → 0.0918 → 0.096 → 0.0845 → 0.0848**. It fell in two
rounds while recall rose, which this page has always said means the recall was bought with noise,
and rose in the two after them, which is the only shape that means a rule got better rather than
louder. Neither fall is smoothed over: the first is
[The guard round](#the-guard-round-and-the-stop-signal-it-tripped) and the second is
[ReDoS](#redos-11--28-of-87-and-it-cost-something), where the held-out slice is the reason the
round was kept. Read the first with the timeout note above in hand — that run scanned a package
the earlier ones abandoned, so part of the gap is corpus, not engine.

**This number is not comparable to the RealVuln one in the other direction either.** That corpus
is applications; this one is libraries, and the rules that carry the Python number are aimed at
request handlers.

This paragraph used to end differently, and the way it was wrong is worth keeping: it said *"a
library has no request handler, so the taint tier's sources are mostly absent by construction."*
That was an explanation for a low number which nobody had checked, and it was false. These
libraries are full of request handlers — they are `http.createServer` handlers rather than Express
routes, and the source they read is `req.url`, which this engine did not model. Adding it moved
`path-traversal` from 59 to 122 of 167. **The second time in this file that a comfortable
explanation for a miss turned out to be the thing worth testing**, after the `dist/` claim below.
A sentence that explains away a bad number is a hypothesis, and this page has now been wrong twice
in the same direction.

## What the first run's three findings turned into

**ReDoS: 0 → 8 of 87.** `redos.py` was Python-only, which was stated in `ROADMAP.md` before a
single package was fetched, precisely so it could not afterwards be presented as a discovery. It
now has a JavaScript front end — a regex-literal lexer plus the string argument to `new RegExp`,
feeding the *unchanged* `catastrophic_reason`. The interesting part is how little that bought.
Eight of 87 is what the criteria are worth on real reports: star height above one and overlapping
alternation under a quantifier catch **exponential** blowup, and most published ReDoS advisories
are **polynomial** — an unanchored `\s*` scan, a `(a+)b` retried from every offset — which is a
real performance bug and is not what those two criteria describe. The analysis was built to
under-report and this is the size of that decision, measured. Widening it is a separate piece of
work with its own precision cost, not a tweak.

That separate piece of work is the round above, and the sentence predicting its cost was right:
28 of 87 for +12 findings per 382,057 lines on the noise-floor corpus and +4 false positives on
RealVuln.

**Prototype pollution: 9 → 12 of 185, and the rule that produced the 9 is gone.** `SEC-JS-PROTO`
matched `for (… in …)` — the most ordinary loop in the language — and scored 9 true positives
against roughly 950 findings. The defect is not the loop, it is the *write* inside it, and a write
is decided by facts about the whole function: where the key came from, and whether anything
refuses `__proto__`. That is `structural/protopollution.py` now (`PROTO-JS-WRITE`), reporting the
assignment line an author has to change. Three more found, 844 → 790 unmatched findings in this
class — and **12 of 185 is still the worst class here.** What it does not reach: writes inside
anonymous callbacks, merges split across modules, and functions whose guard is an imported helper.

**The rewrite scored 13 before it was narrowed, and the narrowing is the honest 12.** Requiring
the written key to be one the *caller* chose is what the rule claims in its title, and it removed
54 unmatched findings here and the rule's only false positive on RealVuln. It also cost three
labelled sinks, which is the part worth reading. Two were the same defect in the narrowing rather
than in the idea — `extend@3.0.1` and `objtools@3.0.0` declare their locals up front and fill them
with a bare `options = arguments[i]`, and the binding walk only followed `const`/`let`/`var`, so
the caller's object arrived by a route nothing was watching. Both are back. The third,
`js-extend@0.0.1`, binds its key from the parameter of an *anonymous callback*
(`each.call(sources, function (source) { … })`), which no rule deciding caller-supplied inside one
named function body can see. That one is a real loss and it stays lost: it is the limitation the
module's docstring already declared, now with the instance that proves it.

**`dist/` and `build/`: the diagnosis was wrong, and this is the useful result.** The blind run
reported 35 sinks under build output and this page called them *"a scoping decision, not a
detection failure"* — the scanner could not see code it would otherwise have flagged. The engine
now reads those directories when the package's own `package.json` publishes them
(`main`/`module`/`exports`/`bin`/`files`), which made **29 of the 35 reachable**. Two became true
positives. The other 27 moved to *no rule fired at the sink*: they were two problems stacked, and
removing the scoping one only revealed that the rules would not have fired anyway. The claim that
they were "not a detection failure" was the flattering reading, and it was wrong.

The scorer was wrong about this too, in the same direction, and is fixed: it decided
"skipped as build output" from the path alone, so after the engine change it would have kept
filing detection failures under a scoping cause. It now asks the engine's own
`_published_build_dirs` whether that directory was actually skipped.

## The guard round, and the stop signal it tripped

`prototype-pollution` **12 → 24 of 185** came from deleting two things from the guard list, and
this round is the one on this page where the honest answer is *it depends what you weight*.

**`hasOwnProperty` was treated as a guard and is not one.** The idiom it appears in is the
canonical **vulnerable** merge:

```js
for (const k in src) { if (src.hasOwnProperty(k)) target[k] = src[k] }
```

It asks whether the key is the source's own rather than inherited — and a `__proto__` that arrived
through `JSON.parse('{"__proto__": …}')` **is** an own property. The check passes, the write
happens, and what it excludes is precisely the set of keys nobody was going to send. It silenced
10 of the 115 unsealed labelled misses.

**`constructor` and `prototype` are now matched only as quoted strings**, because a guard is a
comparison against a key *name* and a name is a string. `if (key === 'constructor')` is a guard;
`Object.prototype.hasOwnProperty.call(src, key)` and `Foo.prototype.bar = …` are property accesses
that merely contain the word. That second spelling had been hiding the first: while a bare
`prototype` counted, the `Object.prototype.hasOwnProperty` form was silenced by the wrong token
entirely.

**And the unmatched-finding ratio fell, 0.1006 → 0.0903.** This page has always said that a round
where it falls while recall rises means the recall was bought with noise. It fell. +12 true
positives against **+349 unmatched findings**, essentially all of them this one rule firing more
(`prototype-pollution` 790 → 1,034, plus 79 in `redos` packages where the same rule fires).

It was kept anyway, and here is the argument, so a reader can reject it:

* The **two instruments that can actually identify a false positive both said zero.** RealVuln
  ships labelled false-positive traps and its count did not move: **248 before, 248 after**. The
  noise floor across 382,057 lines of eight maintained projects did not move either (0.21 per
  1,000 lines, identically).

  *Corrected 2026-08-17, and the correction is the reason this bullet is worth re-reading.* It
  used to say RealVuln's false positives were "271 before, 271 after". They were 271 before and
  **273** after — the round changed the engine and republished the previous engine's aggregate,
  because `dashboard.py` was never re-run after that round's scoring
  ([`eval/realvuln/README.md`](../realvuln/README.md)). The two extra findings are this very
  rule, on one vendored `static/js` file. The argument survives because the instrument it needed
  is the labelled *trap* count, which is what can distinguish a false positive from an unlabelled
  real one and which genuinely did not move — but it was making a stronger claim than it had
  measured, which is exactly the failure the rest of this page is written against.
* The instrument that said +349 **cannot tell a false positive from an unlabelled real one** —
  that is why it is published as a lower bound — and this corpus is 185 packages *selected for
  containing prototype pollution*. An unguarded merge helper in one of those is not obviously
  wrong.
* The change is not a heuristic tradeoff. `hasOwnProperty` does not prevent prototype pollution;
  keeping it would mean the rule deliberately declines to fire on the shape it was written for.

**What the sample did show, and it is a real defect:** among the new findings are
`args[i] = sortArrs[i]` and `sortFlag[j] = 0` — array index writes, which this module's own
docstring calls out as "the most common line in JavaScript and it is not this bug". They reach the
rule through `for (i in arr)`, which is legal and yields indices. They were firing before too; the
over-broad guard was accidentally masking some of them. **That is the next thing to fix here**, and
it is named rather than left in the aggregate.

A filter was tried and rejected rather than shipped: excluding writes in functions that mention
`.length` / `.push` / `Array.isArray` would have caught 284 of 450, and it would also have killed
real merge helpers — jQuery-style `extend` calls `isArray` on purpose. A proxy that removes true
positives to remove noise is not a narrowing, it is a worse rule.

## Where the misses actually are

| Cause | Count | Blind run |
|---|---|---|
| No rule fired at the sink | 201 | 396 |
| Labelled file is not in the published package | 27 | 32 |
| Package could not be fetched from npm at all | 25 | 6 |
| Labelled file is ambiguous — the package holds more than one of that name | 4 | 4 |
| Sink is in a file type no detector claims | 2 | 2 |
| Sink is under `build/`, skipped as build output | 1 | 1 |
| Sink is under `dist/`, skipped as build output | 1 | 1 |

Both columns are scored with the corrected path matcher, so they can be read against each other.
Thirty-six of the labels in the middle two rows used to sit in the top one, which is the whole
argument for having fixed it: *no rule fired* is a to-do list, and a third of it was not.

The 32 in the second row are labels naming a file the tarball does not ship — a TypeScript source
for a package that publishes only its build, most often. They are counted as misses, because from
an installer's point of view a labelled vulnerability nobody can look at is one nobody found; they
are named separately because no rule will ever fix them. Two sinks remain genuinely unscanned:
packages that ship a build directory without declaring it in their manifest, where nothing in the
tarball says that is the code that runs.

## Bounds of this run

* **594 of 600 packages fetched.** Five are gone from npm (404 on a real name and version) and one
  pins a version range rather than a version. Their labels count as misses.
* **27 entries carry no sink location** and are excluded from the denominator rather than counted
  as missed — there is nothing to match against.
* **All 594 fetched packages finished, and the largest one only just does.**
  `react-native@0.63.0-rc.0` is 30 MB across 586 JavaScript files and lands within seconds of the
  old 120-second-per-package bound: it was abandoned on three runs of this round and completed on
  the fourth, purely on how loaded the machine was. That is a corpus changing size between runs,
  so the bound is 300s now — a backstop against a runaway scan rather than a participant in the
  measurement. The cost that puts one package near any bound at all is real and unchanged: the
  taint tier reads a whole tree before analysing it, so its cost grows with the repository rather
  than with the file being reported. Recorded in `.claude/TECH-DEBT.md` with the measurement that
  produced it: 44.7s for a single 17,000-line file where the pattern tier takes 1.2s.
* Matching is file, then class, then line within ±10 — the same tolerance RealVuln's own scorer
  uses, adopted so the two runs are at least internally consistent.

## Reproducing it

```bash
git clone https://github.com/cristianstaicu/SecBench.js ../SecBench.js
python3 eval/secbenchjs/fetch_packages.py --benchmark ../SecBench.js --out ../secbench-pkgs
python3 eval/secbenchjs/run.py   --packages ../secbench-pkgs --timeout 120
python3 eval/secbenchjs/score.py --packages ../secbench-pkgs --run-date YYYY-MM-DD
```

The fetcher downloads tarballs from the registry with the standard library rather than shelling
out to npm, so the reproduction needs Python and nothing else. Two things it will tell you about
your machine, both learned here: it names which IP family it used (a host advertising an
unreachable IPv6 address turned one 2.3 MB download into **181 seconds** through `urllib` against
2.8 through `curl`, and six hundred of those is thirty hours instead of ten minutes), and it names
any package it could not fetch.

**`run.py` caches one scan per package and keys that cache on the engine.** Every result file
carries the `engine_digest` of the code that produced it — the same digest check 32 uses to tie
`eval/realvuln/result.json` to a tree — and a result whose digest is not the current one is
rescanned rather than reused. Every run prints how many were reused and how many were fresh.

That is not a nicety. The first version keyed the cache on the package name alone, and it made
the harness silently stop measuring: the JavaScript ReDoS front end landed, fired on this
benchmark's own sink files when called directly, and moved the published recall by **exactly
zero**, because all 593 results came off disk. A resumable run is worth having — this is fifteen
minutes — but a cache that can serve a scan from an engine nobody is running is worse than no
cache at all. `--rescan` forces the whole corpus regardless of digest.

On Windows, `git clone` of SecBench.js leaves two files unchecked-out — `incubator/ioredis_4.0.0./`
ends in a dot, which is not a legal path there. Neither is part of the scored corpus.

## Licence

SecBench.js is **ISC** (declared in its root `package.json`). Established before the run rather
than after, because a benchmark whose terms are unknown is one whose figures cannot be published.
Cite it as: *SecBench.js: An Executable Security Benchmark Suite for Server-Side JavaScript*,
ICSE 2023 — [github.com/cristianstaicu/SecBench.js](https://github.com/cristianstaicu/SecBench.js).
