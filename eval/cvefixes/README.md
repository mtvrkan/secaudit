# CVEfixes — the corpus adopted to get a blind number back

`eval/HELDOUT.md` states the problem this directory exists to fix, and states it against this
project rather than for it:

> **As of 2026-08-16 there was no such benchmark left.** Every corpus in `eval/` has been read.
> […] it means that from here, **no improvement can be defended as generalising**.

RealVuln and SecBench.js have both been read: their false negatives were diagnosed, and rules
were chosen by what those labels said. Their figures still mean something — they are scored by
somebody else's scorer on somebody else's code — but neither can answer *how does this engine do
on code it has never seen*, because the engine has now seen both.

[CVEfixes](https://doi.org/10.5281/zenodo.13118970) is the third corpus, and the first one this
repository has adopted **under the seal from the first minute**. No rule here was written or
selected by reading any entry in it, and a fifth of it is sealed permanently.

> Bhandari, G., Naseer, A. & Moonen, L. *CVEfixes: Automated Collection of Vulnerabilities and
> Their Fixes from Open-Source Software.* PROMISE 2021. Dataset CC-BY-4.0,
> DOI [10.5281/zenodo.13118970](https://doi.org/10.5281/zenodo.13118970).

## What the labels are, and what they are not

CVEfixes joins real CVEs to the commits that fixed them. Two of its columns make it scannable
without reconstructing anything: `file_change.code_before` is the **whole vulnerable file** as it
stood before the fix, and `file_change.diff_parsed` carries the **line numbers the fix deleted**,
numbered in that file. A labelled region is a contiguous run of those deleted lines.

**A line removed by a security fix is evidence about where the vulnerability was, not a
definition of it.** Three ways that is wrong, none of them cleaned away, because the cleaning
would be this repository deciding what its own corpus says:

1. Fix commits also refactor, rename and reformat. Some deleted lines are not the bug.
2. A CVE's fix can touch files that were never vulnerable. Non-production paths are dropped by
   the engine's own `is_production_source`; the rest stay.
3. NVD's CWE describes the *vulnerability*, not the line.

So **recall is the sound metric and precision is a lower bound**, exactly as on SecBench.js and
for the same reason: only the fixed lines are labelled, and a finding elsewhere in a file that
genuinely carried a CVE is not evidence of a false positive. The scorer prints that count under
the name `unmatched`, not `false positives`.

## Three readings, and which one to quote

| Reading | What it asks |
|---|---|
| **Per file** (the headline) | did anything fire at any hunk the fix touched, in this vulnerable file |
| Per file, strict | …and does the finding carry a CWE the label accepts |
| Per hunk (the floor) | every deleted hunk scored separately |

**Quote the per-file figure**, because it is what RealVuln and SecBench.js count. Per-hunk is
kept as a floor rather than as the headline for a specific reason: a fix that rewrites every
query in a file deletes twenty hunks and describes *one* vulnerability, so per-hunk turns finding
that vulnerability into 1/20 and the number stops meaning recall.

The strict column exists because of a fixture written to test this scorer, where a
**command-injection label was scored by a SQL-injection finding nine lines away** — vulnerable
files hold more than one bug, so location alone hands out credit for finding a different one. The
gap between the loose and strict columns is how much credit the ten-line tolerance is giving
away, which is why both are published rather than whichever is kinder.

## The seal

Per `eval/HELDOUT.md`, sealed **iff** `int(sha256(cve_id).hexdigest()[:8], 16) < 2**32 // 5` —
the bottom fifth of the hash space. A function of the identifier and nothing else, so anybody
with the corpus can recompute the slice and confirm it was not chosen for how it scores.

`build_corpus.py` writes that slice into `eval/heldout.json` **as part of building the corpus**,
not as a later step somebody could take after a first look. From that moment check 41 fails the
build if any sealed CVE id appears anywhere in the tree except the register. You cannot tune
against an entry without writing its identifier down, and every place you could write it is in
the tree.

Unlike the SecBench.js slice — sealed after two corpus-informed rounds, and therefore a baseline
rather than a blind figure — **this slice is blind on its first run and stays blind.**

## The number, and it is a bad one

**Run 2026-08-19, Tier 0, engine `sha256:f95c1011…`. 3,576 CVEs, 12,619 vulnerable files,
37,019 labelled hunks.**

| Reading | Value |
|---|---|
| **Vulnerable files where anything fired at a fixed hunk** | **15.7%** (1,976 / 12,619) |
| Same, with a CWE the label accepts | 7.4% |
| **CVEs with at least one file detected** | **24.5%** (875 / 3,576) |
| Per-hunk floor (not comparable to RealVuln — see below) | 11.43% (4,230 / 37,019) |

| Language | Files | Recall |
|---|---|---|
| Python | 1,207 | **19.9%** |
| JavaScript | 2,159 | 18.1% |
| TypeScript | 1,531 | 8.8% |
| PHP | 7,722 | **15.7%** |

**What moved it, and it is the only round so far that was aimed at this corpus.** `SEC-JS-HTML-CONCAT`
reports HTML assembled by concatenating a runtime value into markup, wherever the assembly
happens rather than only where the DOM is written. The shape was read out of the *unsealed*
misses here — `out += '<tr><td>' + opt + '</td>'` with its sink in another function — which is
what these labels are for. **JavaScript 11.5% → 18.1%, TypeScript 6.0% → 9.0%, the headline
6.7% → 8.2% and the strict reading 1.9% → 3.3%.** The bill was paid on RealVuln, a Python
corpus that can only count this rule against it: F3 60.6 → 60.5.

**The round that moved this page hardest is the one aimed at the language it scores worst in.**
PHP is 64% of these labels and was at 3.4% with three rules against it. Six more went in, and
what makes them possible without a taint tier is a property of the language rather than a trick:
**PHP spells the source inside the sink.** `$_GET`, `$_POST`, `$_REQUEST` and `$_COOKIE` are
superglobals — no import, no binding, no parameter to resolve — so a rule that sees one inside
`echo`, a query call, an `include`, a filesystem call or a `header()` has seen the whole path.
A seventh rule takes the other half of PHP's XSS surface, `<?= $row['title'] ?>`, in a language
that escapes nothing on the way out. **PHP 3.4% → 11.7%, the headline 8.1% → 13.2%, the CVE
reading 15.9% → 20.9% and the strict reading 3.3% → 6.2%.**

Two candidates were measured and **rejected** in the same round, and they are the reason the
number is not higher. SQL built by interpolation (`"SELECT … WHERE id=$id"`) reaches **+1,100
labelled files on its own — recall 3.7% → 21.3% within PHP** — and matches **1,225 lines inside
`laravel/framework`**, because a query builder's own source is full of SQL with variables in it.
A rule that fires 1,225 times on the framework everybody uses is a rule nobody keeps switched on;
it needs the PHP taint tier that does not exist yet. A shell sink with a superglobal argument
added nothing, because `SEC-PHP-EXEC` already reports those lines.

**The round before it narrowed two PHP rules and this page paid 9 files for it, knowingly.**
`SEC-PHP-EXEC` was reading `$redis->eval(` and `Process::exec(` as PHP's `eval`, and
`SEC-PHP-UNSER` was reporting `function unserialize(` declarations along with calls already
carrying PHP's own `['allowed_classes' => false]` control. Excluding both cost **PHP 3.5% →
3.4%** here — 167 labelled files to 159 for the first rule, 77 to 74 for the second — and saved
**125 matched lines to 21** in one Laravel checkout. Neither number could be seen before
2026-08-19, because until then no corpus in this repository contained PHP that was not
vulnerable. The headline moved 8.2% → 8.1% and the CVE reading 16.1% → 15.9%; both are stated
rather than absorbed into the round above them.

**The seal did its job, and it is the one result here worth being pleased about.** Sealed slice
**17.06%**, unsealed **15.32%** — the held-out fifth scores *slightly higher* than the part that
was not held out. Nothing in this engine was fitted to this corpus, and now there is a
measurement saying so rather than an assurance.

It says it twice now, which is the part that could not be arranged. The round above was
diagnosed by reading unsealed misses and nothing else, and the sealed slice moved **further**
than the unsealed one — 8.14% → 9.87% against 6.36% → 7.78%. A rule fitted to the labels it was
read from produces the opposite shape, and `eval/HELDOUT.md` commits to publishing that shape
when it appears: it did appear, one round earlier, on SecBench.js.

### One commit can be a hundred labels, and it cuts both ways

A CVE fixed by a repository-wide refactor deletes lines in hundreds of files, and **every one of
them becomes a labelled entry here**. So a per-language cell can look like a broad detection
failure while being three commits wearing many filenames — and, just as easily, a flattering one
can be a single commit that happened to be caught. `result.json` now carries a `concentration`
block computed from the labels rather than from the scan, so a reader can weigh the tables above
without taking anyone's word for it:

| Cell | Labels | CVEs | Largest single CVE | Which |
|---|---|---|---|---|
| `TypeScript CWE-1284` | 106 | 1 | **100%** | CVE-2022-21208 |
| `JavaScript CWE-707` | 264 | 1 | **100%** | (sealed entry — see eval/HELDOUT.md) |
| `TypeScript CWE-285` | 241 | 4 | **98%** | CVE-2023-52139 |
| `PHP CWE-400` | 272 | 5 | **98%** | (sealed entry — see eval/HELDOUT.md) |
| `PHP CWE-829` | 223 | 4 | **98%** | CVE-2023-2551 |
| `TypeScript CWE-269` | 42 | 3 | **95%** | CVE-2023-51386 |
| `TypeScript CWE-770` | 395 | 5 | **94%** | (sealed entry — see eval/HELDOUT.md) |
| `Python CWE-476` | 76 | 3 | **93%** | (sealed entry — see eval/HELDOUT.md) |

Read the two directions together. **TypeScript's 8.8% is partly this**: its three biggest cells —
CWE-918, CWE-20 and CWE-285 — are 372, 372 and 237 labels from *one commit each*, in projects
that reorganised themselves while fixing a bug. And **`JavaScript CWE-707` at 90.7% recall, the
best number on this page, is one CVE too** — 264 labels, one commit, one shape this engine
happens to match. Neither figure is wrong; both are narrower than they look, and the block above
is what makes that checkable instead of a thing somebody has to notice.

### Why this is so far below F3 61.1 on RealVuln

Stated as a hypothesis with the evidence next to it, not as an excuse. Both numbers are real and
they measure different things.

RealVuln is 62 **applications** — routes, request handlers, an HTTP entry point. This engine's
two strongest tiers need exactly that: taint starts at a request source (`req.query`,
`request.args`), and the structural analyses are scoped by a route decorator. CVEfixes is mostly
**libraries and frameworks** at the commit that fixed a CVE, and a library has no request. Taint
from a function parameter is deliberately MEDIUM-confidence there, for the reason
`docs/what-we-miss.md` already gives: whether a parameter carries untrusted data depends on
callers this analysis does not have.

The per-language table is consistent with that reading — Python at 19.9% against PHP at 15.7%,
where the PHP support is a pattern pack with no taint or structural tier behind it, and PHP is
64% of the labels. So the headline is dragged down by the language this engine covers least, and
that is not a reason to drop PHP from the corpus. It is the finding.

Three measurement caveats that all push the number **down**, and are left in:

0. **22% of the labelled JavaScript files here are never opened at all, and that is this
   corpus's construction rather than the engine's judgement.** `build_corpus.py` materialises
   one file per entry, so a package's `index.js` arrives with no `package.json` beside it — and
   without a manifest the engine cannot tell a library's own release from a library copied into
   somebody's application, so a file opening with a `/*!` banner is skipped as third-party. In a
   real checkout the manifest is there and `engine._is_own_release` answers correctly; here there
   is nothing to ask. 475 of 2,159 JavaScript files and 44 of 1,531 TypeScript files. **Not
   fixed by writing a manifest next to them:** that would be inventing evidence the dataset does
   not contain, and the figure would then describe a corpus nobody can reproduce.


1. **1,051 of 12,667 materialised files were never read** by the engine — skipped as vendored,
   minified or over the size limit. They count as misses.
2. **A deleted line is not always the bug.** Fix commits refactor; the label is the evidence the
   dataset has, not a definition.
3. **A file can carry a CVE the engine has no rule for at all** — a memory bug, a protocol flaw,
   a version comparison. There is no filter here that keeps only the classes the pack models,
   because choosing which CVEs count is the thing an external corpus exists to stop us doing.

What this number is good for is the question it was adopted to answer: **on code this engine has
never seen, and was never shaped by, how much does it find?** On application code the answer is
RealVuln's. On the open-source CVE population at large, it is 25% of CVEs and 15.7% of files.

## Running it

```bash
python3 eval/cvefixes/fetch.py          # 12.7 GB, resumable, MD5-checked before unpacking
python3 eval/cvefixes/build_corpus.py   # corpus/ + ground-truth.json + the seal
python3 eval/cvefixes/run.py            # Tier 0 scan, cached on the engine digest
python3 eval/cvefixes/score.py --run-date YYYY-MM-DD
```

Nothing here is committed except the scripts and `result.json`. The archive, the database and
the materialised corpus live outside the repository (`../corpora/` by default): a corpus this
repository ships is a corpus this repository owns, and the whole value of an external number is
that somebody else owns the labels.

The scan cache is keyed on the **engine digest**, not on the entry. A cache keyed on the entry
serves results produced by code that no longer exists — which has already cost this repository
one silently unmeasured round on SecBench.js, where a new front end moved the published recall by
exactly zero because every result came off disk.
