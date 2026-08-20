# Noise floor — what a clean checkout costs you to read

**Result: 0.42 findings per 1,000 lines. 0.09 of those are High or Critical; 0.03 are
HIGH-confidence.** Run 2026-08-20, Tier 0, over 2,674,253 lines across fifteen maintained projects.
Raw output committed as [`result.json`](result.json); every figure below is read from it.

**0.28 → 0.42, and the corpus grew a kind of code it had never held: an application that mounts
routes.** `TryGhost/Ghost` (JavaScript, Express) and `directus/directus` (TypeScript, Express)
joined on 2026-08-20 for the reason phpMyAdmin joined a round earlier — the JavaScript structural
rules ask what a request HANDLER does, and an HTTP framework, an HTTP client, a date library and
a promise library mount nothing at all. Those rules had been measured against a corpus that could
not contain their subject, and reported zero for it.

They report 730 findings between them, and the first read of that number found **two defects
worth more than the figure**:

* **A project's own auth middleware was invisible.** `mw.authAdminApi` cannot be in any marker
  list — it is Ghost's name for its own guard, used 220 times — so every route carrying it was
  reported as unauthenticated. `_AUTH_NAMING` reads the *convention* instead: `auth` followed by
  a capital. That is also its precision, and a fixture pins it — `author` and `authority`
  continue in lower case and do not match.
* **Ember's Mirage mock server was production code.** `mirage/config/posts.js` mounts
  `server.post('/posts', …)` with no authentication because it *is* the fake backend a test
  talks to. 26 findings, every one about a fixture.

Together they took the corpus from 1,252 findings to 1,119 and the High+Critical count from 376
to 243. **On the thirteen trees measured before them the figure is unchanged: 389 findings, 0.28
per 1,000 lines, 117 actionable.**

**0.42 → 0.42, and the zero is the point.** `RATELIMIT-PY-AUTHVIEW` reads a Django URL conf and
reports the framework's own `LoginView` where nothing in the project bounds attempts. It bought
**12 labelled cases on RealVuln** and fired **not once** across these fifteen trees, which is
what a rule scoped to one framework's own auth views should do — and also what this corpus can
still not disprove, because it holds no Django project at all. The silence is real and its
instrument is narrow; both belong in the same sentence.

**0.26 → 0.28: the PHP taint tier, and it is the cheapest recall this repository has bought.**
Following a superglobal through one assignment inside one file took CVEfixes' PHP recall
**11.7% → 15.7%** and the headline **13.2% → 15.7%**, for **32 findings here** — all of them in
phpMyAdmin, none in Laravel, Symfony or PHPMailer. The comparison that justifies it is the rule
it replaced: SQL built by interpolation, reported without asking where the value came from, was
measured at **1,225 matched lines inside `laravel/framework` alone** and rejected for it. The
same sink with a taint requirement in front of it is silent there.

**0.35 → 0.26, and that fall was the round that answered the rise below.** A suppression that
reads the **matched line** instead of the whole file dropped 121 findings here — 80 of them the
escaped and catalogue-shaped lines named in the paragraph below — and cost **6 labelled files**
on CVEfixes, against the 27 a file-scoped suppression would have cost. The High+Critical count
did not move at all: 99 before, 99 after. What fell is exactly the part a reader would have
skipped.

**0.16 → 0.35, and the rise was one rule reporting on one project — a rule this file had already
published as costing two findings.** `phpmyadmin/phpmyadmin` joined on 2026-08-19, and 310 of its
findings are `SEC-JS-HTML-CONCAT`: 260 of them in `js/src/`, most on lines like
`details += '<div>' + Functions.escapeHtml(...) + '</div>'` — markup concatenation whose value
**is** escaped, one call away, on the same line. The round that shipped that rule measured it
here and reported two findings across 382,057 lines, and that number was true and useless: the
corpus it was measured on held an HTTP framework, an HTTP client, a date library and a promise
library, and **not one page that builds DOM**. The instrument was blind to the shape the rule is
about. It is not any more, and the fix — a line-scoped suppression, which this pack did not have — is
the round above rather than a paragraph explaining the number away.

**0.33 → 0.16 is not an improvement, and reading it as one would be the single easiest mistake to
make on this page.** The corpus grew: four PHP projects joined on 2026-08-19 and PHP is verbose,
so the denominator went 382,057 → 1,046,779 lines while the numerator went 127 → 168. **On the
same eight trees as every earlier run the figure was unchanged — 127 findings, 0.33 per 1,000
lines, 28 actionable, to the digit.** Quote the whole-corpus figure for what a mixed checkout
costs and the eight-tree one for what changed between rounds; they are different questions and
this file answers both rather than letting the flattering one stand alone.

**It went up twice on 2026-08-17, from 0.21, and both rises are the price of a detection round.**
No earlier round had moved this number at all, and the third round of the same day moved it by one
finding — which is the comparison this page exists to make possible.

* **0.21 → 0.24**: the ReDoS analysis learned to report quadratic backtracking as well as
  exponential — the shape most published ReDoS advisories actually have, worth 11 → 28 of 87
  labelled sinks on [SecBench.js](../secbenchjs/README.md). Twelve findings, **none of them above
  Medium**, so a reader who triages by severity saw no change.
* **0.24 → 0.25**: prototype pollution learned three things it could not see — functions the
  finder could not delimit, keys bound by an iteration callback, and the walk a set-by-path helper
  performs. Three findings, **all three High**, all three in `axios`, and that is the rise worth
  arguing about: the actionable count went 22 → 25.
* **PHP joined the corpus (2026-08-19), and it arrived because of what it could not measure.**
  PHP is 64% of the labels in [CVEfixes](../cvefixes/README.md) and scores worst of the four
  languages there, so it is the largest gap this engine has — and there was no corpus anywhere in
  this repository that could say what a PHP rule costs on code that is not vulnerable. RealVuln
  is Python, SecBench.js is JavaScript, and this floor had none. The instrument went in **before**
  the rules, and it immediately reported that two of the three PHP rules already shipping were
  wrong: `SEC-PHP-EXEC` counted `$redis->eval(` and `Process::exec(` as PHP's `eval` (125 matched
  lines in Laravel, 21 after the receiver exclusion) and `SEC-PHP-UNSER` counted both
  `function unserialize(` declarations and calls already carrying PHP's own
  `['allowed_classes' => false]` control. Neither could have been found by the corpora this
  repository had. **41 findings across 664,722 lines of PHP**, 36 of them Laravel's cache and
  queue paths calling `unserialize` on state the framework serialised itself — a MEDIUM-confidence
  rule with no source evidence, published as such.
* **0.33 → 0.33**: HTML built by string concatenation, the JavaScript XSS shape whose sink is
  usually in another function. Two findings across 382,057 lines, both on adjacent lines of one
  Express function, neither above Medium and neither actionable — read the `expressjs/express`
  paragraph below for what they are and why the rule ships without a suppressor. It bought
  CVEfixes' JavaScript recall 11.5% → 18.1%.
* **0.27 → 0.33**: nine rule families the external corpus had none for — CSV formula
  injection, account enumeration, client-trusted access decisions, cleartext storage,
  caller-sized allocation, response exposure, CORS reflection, disabled security headers
  and the stdlib spellings of disabled TLS verification. Fifteen more findings across
  382,057 lines of maintained code, against +331 true positives on the labelled corpus.
* **0.25 → 0.27**: the config and credential round — thirteen new rules for security headers,
  a weak CSP, autoescaping off, a signing key passed as a literal, SQL statement tracing, a form
  with no CSRF token, and a template variable inside an event handler. **All thirteen fire zero
  times here.** The entire rise is one widening: letting the keyword secret rule match a
  credential whose name carries a suffix (`ACCESS_TOKEN_SALT`) also made it match `SECRET_KEY`,
  which a more precise rule already reports — 10 of the 12 added lines are a second finding on a
  line that already had one, and that duplication is now in the tech-debt ledger. The actionable
  count did not move: **25 before, 25 after.**
* **0.25 → 0.25, one finding**: the injection round — shell sinks resolved from a file's own
  imports, method and anonymous-function parameters seeded as sources, and the `Function`
  constructor, Node's `vm` and indirect `eval` added to the catalog. One more Medium in `axios`
  across 382,057 lines, and the actionable count did not move at all — worth stating beside the
  two rises above, because it is the difference between *recognising a construct* and *widening a
  criterion*. What that round bought is on the benchmark page; what it charged a maintained
  codebase is one line.

In the unit that decides adoption: **a 100,000-line codebase now gets about 25 findings, 7 of them
High or Critical**, against 21 and 5 before the day started. The three new ones are generic
helpers writing a caller-chosen key into an object the library owns — the rule's claim is exactly
right about the code and the exploitability depends on a caller this analysis cannot see.

The other two benchmarks in this repository answer *does it find the bug*. Neither answers the
question anybody actually asks before adopting a scanner: **how much of my time will this waste?**

Precision on RealVuln is 0.704 — but that is precision over a corpus where roughly one line in
forty is a planted flaw. It says nothing about what a healthy repository produces. A tool at
forty findings per thousand lines gets switched off in a week whatever its recall, and no amount
of F3 saves it.

| | Findings | Per 1,000 lines | What it means |
|---|---|---|---|
| All findings | 1119 | **0.42** | everything the scan emitted, informational included |
| High + Critical | 243 | **0.09** | what a triage queue would actually hold |
| HIGH confidence | 82 | **0.03** | request-rooted paths — what the engine claims, not what it suspects |

In the unit a reader can act on: **a 100,000-line codebase gets about 42 findings, 9 of them
High or Critical** — and a real Express application is the upper half of that, at 0.47 (Ghost)
and 0.75 (Directus) per 1,000 lines against 0.28 across the libraries. That is an afternoon, not a project — and the figure is dominated by one rule
on one project, which the paragraph at the top of this page names rather than averages away.

The bottom row has not moved through either round, and it is the one that carries the engine's
strongest claim: HIGH confidence means a request-rooted path, and neither ReDoS nor prototype
pollution can produce one.

## Read this before the number

**A finding here is not automatically a false positive, and this page will not pretend
otherwise.** Nobody has adjudicated these 105 findings. These are real, widely deployed projects;
some of the findings may be real, and `flask` and `fastapi` are libraries whose job includes
handling exactly the shapes these rules look for. What the figure bounds is **volume** — the
reading a user is asked to do on code nobody planted anything in.

So it is a **floor**, not a precision, for the same reason SecBench.js's unmatched-finding ratio
is published as `precision_lower_bound` and not as precision. Do not put 0.27 beside 0.672; they
have different denominators and answer different questions.

**Eight repositories is a small corpus.** It is enough to rule out the failure mode that matters
(a scanner that buries you), and not enough to characterise a distribution. The set was chosen
before anything was scanned, and it is pinned by commit SHA in [`repos.json`](repos.json) so the
number is reproducible rather than a snapshot of whatever `main` was that day.

## Per repository

| Repo | Language | Lines | Findings | Per 1k | High+Crit |
|---|---|---|---|---|---|
| `pallets/flask` | python | 18,428 | 27 | 1.47 | 3 |
| `psf/requests` | python | 12,069 | 14 | 1.16 | 0 |
| `directus/directus` | typescript | 421,471 | 315 | 0.75 | 24 |
| `phpmyadmin/phpmyadmin` | php | 325,732 | 221 | 0.68 | 53 |
| `TryGhost/Ghost` | javascript | 880,271 | 415 | 0.47 | 102 |
| `encode/httpx` | python | 17,813 | 8 | 0.45 | 2 |
| `fastapi/fastapi` | python | 114,593 | 52 | 0.45 | 10 |
| `axios/axios` | javascript | 42,510 | 11 | 0.26 | 5 |
| `date-fns/date-fns` | javascript | 110,419 | 11 | 0.1 | 8 |
| `expressjs/express` | javascript | 21,619 | 2 | 0.09 | 0 |
| `laravel/framework` | php | 554,306 | 39 | 0.07 | 36 |
| `PHPMailer/PHPMailer` | php | 19,630 | 1 | 0.05 | 0 |
| `sindresorhus/got` | javascript | 44,606 | 2 | 0.04 | 0 |
| `guzzle/guzzle` | php | 58,969 | 1 | 0.02 | 0 |
| `symfony/http-foundation` | php | 31,817 | 0 | 0.0 | 0 |

`expressjs/express` returned zero for six rounds, and the sentence that stood here said why: it
is ~21k lines of a library that neither reads the filesystem from request data nor builds SQL, so
there is very little for these rules to be right or wrong about. It now returns **two**, and both
are worth naming rather than rounding away.

Both are `SEC-JS-HTML-CONCAT` on the two lines of `lib/response.js` that build the redirect body,
and the value in them **is** escaped — `var u = escapeHtml(address)`, one line above. The rule
ships without a suppressor on purpose and the cost is exactly this: the pack's suppression is
per FILE, and at that scope a module which escapes four values and forgets the fifth would go
silent, which is the shape the bug actually comes in. It was measured both ways on CVEfixes —
suppressing costs 27 labels, not suppressing costs these two lines here. The trade is published
rather than tuned away, and this is the whole of what it bought in noise across 382,057 lines.

The Python side is louder than the JavaScript side, which is the expected direction: the pattern
pack, the taint tier and all five structural analyses have Python front ends, and the JavaScript
half has fewer rules pointed at it. That asymmetry is the same one
[`docs/language-coverage.md`](../../docs/language-coverage.md) publishes, showing up in the noise
instead of in the coverage.

## The loudest rules

| Detector | Findings |
|---|---|
| `EXPOSE-PY-INTERNALS` | 18 |
| `REDOS-JS` | 12 |
| `SEC-PY-COOKIE-FLAGS` | 12 |
| `RATELIMIT-PY-AUTH` | 12 |
| `TAINT-PY-PATH` | 11 |
| `REDOS-PY` | 9 |
| `SEC-SECRET-GENERIC` | 6 |
| `SEC-PY-EVAL` | 6 |
| `SEC-SECRET-JWT` | 6 |
| `SEC-PY-MD5` | 5 |
| `SEC-PY-COOKIE-NO-SECURE` | 5 |
| `SEC-PY-SECRET-KEY-LITERAL` | 5 |

Three of these are worth naming rather than leaving in a table.

`RATELIMIT-PY-AUTH` and `SEC-SECRET-JWT` fire heavily inside `fastapi`, whose test suite and
tutorial sources are full of login handlers and example tokens — the shapes those rules exist to
find, in a repository where they are fixtures.

**`TAINT-PY-PATH` at 11 is the rule this round widened, and the widening contributed none of the
11.** Modelling `pathlib` took `path_traversal` on RealVuln from 3 of 39 to 22 of 39, so the
obvious question is what it cost here — and the answer, checked rather than assumed, is nothing:
every one of these 11 is a builtin `open()` or `os.remove()`, the sink that was already modelled.
Not one is a `pathlib` receiver call. Eight maintained projects, 382k lines, and the new sink
family fires zero times. The first draft of this paragraph said the opposite — it presented the
11 as "the other side of that trade" — because the number was next to the change and the
inference was cheap. Re-running the corpus against the pre-widening catalog gave 11 as well.

**`REDOS-JS` is the one to look at first, and it is concentrated rather than spread.** Ten of its
twelve findings are High — the exponential ones — and eight of those are in `date-fns` alone, so
that single rule in that single repository produces **8 of the 25 actionable findings in the
whole corpus**: a third of the triage queue from one rule against 2% of the line count. A date library
is a plausible place for a genuinely slow regex, so this is not asserted to be noise; it is
asserted to be the first thing worth adjudicating, and the reason a per-detector breakdown belongs
on this page. An aggregate of 0.07 High-per-1k that is really one rule in one repository is an
aggregate hiding its own shape.

**The quadratic criterion added twelve findings and none of them are in that queue.** Nine are
`REDOS-PY` and three are the Medium half of `REDOS-JS`; every one is a correct reading of a
genuinely ambiguous regular expression and none of them is an incident, which is the whole reason
quadratic is reported at Medium and exponential at High. This is what the criterion costs a
reader who triages by severity: nothing. What it costs a reader who reads everything is three
findings per 100,000 lines.

**`PROTO-JS-WRITE` at 3 is the round that *did* reach the queue, and all three are in `axios`.**
The prototype-pollution round widened three things at once and this is what they cost on
maintained code: `http2Headers[name] = header`, and two `[key] =` writes in `lib/utils.js`
helpers. Each is a correct reading — the key comes from an object the caller passed — and none is
an incident in `axios`, because the objects being written are the library's own and the callers
are its own code. That distinction is not decidable from the function, which is why the rule
reports it and the severity is High: CWE-1321 through a generic helper is how most of the
labelled corpus is written too. Three findings per 382,057 lines is the measured price of taking
that class from 25 to a third of its labels; a reader who thinks a generic setter is not worth a
High is reading the same evidence and weighing it differently, which is why the number is here.

## Reproducing it

```bash
python3 eval/noisefloor/run.py --workdir /tmp/noisefloor
python3 eval/noisefloor/score.py --workdir /tmp/noisefloor --run-date YYYY-MM-DD
```

`run.py` fetches exactly one commit per repository — pinned by SHA, so a moved branch cannot
change the corpus underneath a comparison — scans each in a subprocess, and counts the physical
lines of the source the engine claims (`.py` plus the JS/TS family, `.git` excluded).

The denominator is deliberately not `cloc`: a reproducible figure cannot depend on a tool the
reader may not have installed, and it has to count **what was scanned** rather than what a
language census would report.

Both scripts refuse to aggregate results produced by more than one engine, and `result.json`
carries the engine digest, which check 32 holds against this tree. A noise floor that outlives
the engine that produced it is the same defect as a recall figure that does — and this repository
has already shipped that defect once.
