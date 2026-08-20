# Launch posts — drafts for the accounts only you have

Six pieces, one per channel from ROADMAP P6. Not documentation and deliberately not under
`docs/`: the site generator fails the build on any `docs/*.md` nothing links, and a visitor to the
site has no reason to read our Show HN draft.

Every figure below is copied from a committed result file. **If a round moves a number, these
drafts go stale silently — nothing gates them.** Re-read against `eval/*/result.json` before
posting. Current basis: RealVuln F3 **59.5** (precision 0.6760, recall 0.5874), SecBench.js recall
**0.5236** / blind **0.2286**, noise floor **0.31** per 1,000 lines, 105 detectors, 15 languages,
44 gates, engine `sha256:eb56d4b4…`.

---

## Do not post until these four are true

These are not polish items. Each one makes a specific sentence in the drafts below false.

1. ~~**CI has been observed green at least once.**~~ **Done 2026-08-17.** `Validate plugin` runs
   `scripts/run_checks.py` on Linux and Windows and both report *All 44 gates green*; the badge is
   honest. Two things the run history also showed, both now steps 4b/4c of the checklist: the
   `Publish site` deploy job has only ever **skipped** (it is guarded on the repo being public),
   and `CodeQL` has **never run at all** — it is gated behind a repository variable nobody set.
2. **`pip install secaudit-kit` actually resolves.** The PyPI name is *not* reserved — a pending
   trusted publisher does not hold it — and every draft uses that command as the "no Claude Code
   needed" proof. Publish `v1.0.0` first, or cut the line.
3. **The repo is public and the site is live.** Pages needs public for a free plan, `site.yml`'s
   deploy job has only ever skipped itself, and the DNS CNAME is not set. Watch the first push
   after going public and confirm the deploy actually ran.
4. **Delete `continue-on-error: true` from `self-scan.yml`, and split the claim it masks.** The
   2026-08-17 run log settles half of it: the upload action reaches `Validating secaudit.sarif`
   and adds fingerprints, so **GitHub's SARIF validator accepts the renderer's output** on 59
   findings from a live self-scan. Then it fails with `Resource not accessible by integration` —
   code scanning needs Advanced Security on a private repo — so **ingestion has never happened**.
   Until the repo is public and that line is gone, do not write "accepted by GitHub code
   scanning" in any draft; "emits valid SARIF" is the claim you can currently defend.

**One framing rule across all six.** Lead with the deterministic engine, not with the plugin. It
is the part that is measured, the part that runs without a key, and the part these audiences can
check. The Claude Code integration is a surface, not the product — and on Show HN and r/netsec,
opening with "AI security tool" loses the room before the numbers get read.

---

## 1. Show HN

**Title** (80 char limit; the first is the recommendation):

> Show HN: A security scanner that publishes its own miss rate

Alternates, in order of preference:

> Show HN: SecAudit – scored on two public benchmarks, including the bad number
> Show HN: My scanner's published recall turned out to be a coin flip

Use the third only if you want the determinism bug to be the whole story — it is a good story, but
it makes the post about a bug rather than about a tool.

**Body:**

> SecAudit is an offline security scanner: a regex/taint/structural engine in Python with zero
> runtime dependencies, no API key, and no network calls. It runs as a Claude Code plugin, an MCP
> server, or `secaudit .` on its own.
>
> The part I actually want feedback on is the measurement, not the scanner.
>
> Most scanners publish no detection number at all. I scored this one on two benchmarks I did not
> build, using their scorers rather than mine:
>
> - **RealVuln** (66 real vulnerable Python repos): F3 **59.5**, precision 0.68, recall 0.59. The
>   benchmark's published Semgrep baseline is 17.7 and its general-purpose-LLM row is 51.7; its
>   best purpose-built entrant is 73.0.
> - **SecBench.js** (573 labelled sinks across 575 npm packages): recall **0.5236**.
>
> Both numbers are corpus-informed and I would rather say so than have it found. The first
> RealVuln run was blind and scored **12.5**; SecBench.js was blind at **0.2286**. Everything
> since came from reading those benchmarks' own false negatives, which is textbook rule-writing
> and also exactly the thing that makes a number stop generalising. **0.2286 is the number to
> quote if you want to know how it does on code it has never seen.** The gap between 12.5 and 59.5
> is the size of the advantage that disclosure is about.
>
> Because recall on a vulnerability corpus says nothing about whether you would actually run this,
> there is a third number: **0.27 findings per 1,000 lines** across 382,057 lines of eight
> maintained projects that are not a vulnerability corpus (flask, fastapi, requests, httpx, axios,
> got, date-fns, express). 0.07 of those are High or Critical. It is published as a noise floor,
> not a precision — nobody adjudicated them and some are probably real.
>
> There is also a page listing what it structurally cannot find, per class, with the reason.
> Business-logic flaws, race conditions, second-order injection, plaintext credential storage,
> template variables inside `<script>` blocks — each with why a lexical pass cannot decide it.
>
> **The thing I did not expect to be writing.** A batch of Python-only rules dropped exactly one
> label on the *JavaScript* benchmark, which should be impossible. Chasing it found that taint
> attribution iterated a `set` of identifier names and returned on the first tainted one — and
> Python randomises string hashing per process. The same engine, on the same file, reported the
> same bug at line 739 or line 743 depending on the run, and 743 was outside the scorer's ±10
> window. Every SecBench.js figure this project had published — including the blind one it tells
> you to trust most — carried that flicker: **0.5410 or 0.5393 on the same commit.**
>
> Every result file carries a sha256 of the engine that produced it and CI fails if they diverge —
> and that seal is structurally blind to this, because the code genuinely was identical. A
> reproducibility seal over the *inputs* of a computation says nothing about the determinism of
> the computation. The fix is one line; the test scans a fixture in four processes under different
> `PYTHONHASHSEED` values.
>
> Repo: <link> · Numbers and how to re-run them: <link>/eval · What it misses: <link>/docs/what-we-miss
>
> Anthropic ships two security plugins for Claude Code that are good and free, and this does not
> compete with them — they review code as it is written and scan a checkout. This does live
> targets, an authorization gate, offline operation, and an EU CRA evidence pack. Install both.

**Notes for the thread.** Expect three questions and have these ready rather than improvising:
*"isn't this just regexes"* — no, there is a taint tier with cross-module summaries and every
finding ships its source→sink path; but yes, Tier 0 is lexical and the what-we-miss page says
where that ends. *"why is precision only 0.67"* — the benchmark scores unlabelled findings as
false positives and 12 of ours are the identical construct it labels elsewhere in the same repo;
the number stands as their scorer reports it. *"where is the LLM"* — optional, off by default,
**unmeasured**, and deliberately not what any published number describes.

**Timing.** Tuesday–Thursday, 08:00–10:00 ET. Do not post the same day as the r/netsec thread.

---

## 2. r/netsec

r/netsec removes product launches. It does not remove technical write-ups that happen to have a
repo at the bottom. **Link to the eval directory or the what-we-miss page, not to the repo root**,
and let the tool be a consequence of the content. Read the subreddit rules again the day you post
— they change.

**Title:**

> Scoring a lexical + taint SAST engine against two public benchmarks, including the numbers that
> did not flatter it

**Body:**

> I have been building an offline SAST engine (Python, no runtime dependencies, no API key) and
> the more interesting half of the work turned out to be measuring it honestly. Writing up what
> the benchmarks actually said, including the parts I would rather they had not.
>
> **Setup.** Two external corpora, each scored by its own scorer, raw output committed:
> RealVuln (66 vulnerable Python repos, F3 with recall weighted 9×) and SecBench.js (573 labelled
> sinks across 594 npm packages). Plus a third instrument that is not a benchmark at all: eight
> maintained OSS projects pinned by commit SHA, measuring findings per 1,000 lines.
>
> **Results.** RealVuln F3 59.5 / precision 0.67 / recall 0.40, against the benchmark's published
> Semgrep baseline of 17.7. SecBench.js recall 0.5236. Noise floor 0.31 findings per 1,000 lines
> over 382,057 lines, 0.07 of them High or Critical.
>
> **The caveat that matters more than the results.** Only the first run of each was blind — 12.5
> and 0.2286. Every improvement since came from reading those benchmarks' false negatives. The
> rules added are ones any SAST ships (weak PRNG for tokens, cookie flags, CSRF exemptions, open
> redirect, a committed fallback signing key), so none is fitted to a fixture — but the *selection*
> was corpus-informed, and that is enough to stop a number generalising. A fifth of SecBench.js is
> now sealed by `sha256(name)`: scored every round, never inspected, reported as its own column,
> so future rounds can be checked for corpus fit rather than trusted.
>
> **Four things the measurement taught me that transfer to anyone doing this:**
>
> 1. **Check whether a rule exists for the language before adding sinks to one that does.** Python
>    had no SQL-concatenation rule while four other languages did. Widening the *source* list was
>    the single highest-leverage change of the whole project and added no sinks at all — a missing
>    source switches the engine off for an entire framework idiom, not for one rule.
> 2. **A shared helper that under-delivers is invisible in every individual rule's numbers.** One
>    function decided where a JavaScript function body began, and got it wrong for default
>    parameter values, arrow assignments and class methods. Five analyses read empty bodies and
>    reported nothing — which looks exactly like a clean scan. It surfaced only because a labelled
>    corpus asked one rule the same question 113 times.
> 3. **An unmatched finding is not automatically a false positive, and you still have to count it
>    as one.** The benchmark's scorer is the published precision; our reading of the misses goes
>    beside it, not instead of it.
> 4. **A reproducibility seal over inputs says nothing about determinism.** Every result file
>    carries a hash of the engine that produced it. That did not stop the published recall from
>    being a coin flip for months: taint attribution walked a hash-ordered set, so the same bug was
>    reported at line 739 or 743 depending on the process, and one label drifted in and out of the
>    scorer's ±10 window. The seal cannot catch it — the code really is identical.
>
> Also published: a per-class page of what the engine structurally cannot find and why.
>
> Numbers, raw scorer output and reproduction steps: <link>/eval
> What it misses: <link>/docs/what-we-miss

**Do not** mention the Claude Code plugin above the fold. If someone asks, answer plainly; leading
with it in this subreddit reads as an AI product launch and gets removed.

---

## 3. OWASP Slack (`#project-asvs`, `#cyclonedx`, or the local chapter)

Short, collegial, and asking for one specific thing. Slack posts that ask for nothing get no
replies.

> Hi all — I have been mapping scanner findings to **ASVS 5.0** chapters and to the **EU CRA**
> Annex I clauses, and I would value a sanity check from people who read the control text more
> carefully than I do.
>
> The tool is an offline SAST engine (MIT, zero dependencies). It emits a CycloneDX 1.6 SBOM, an
> OpenVEX register with import-reachability status, and each finding tagged with an ASVS chapter
> and a CRA clause. Two mapping decisions I would especially like challenged:
>
> - Several CWEs are deliberately **unmapped** rather than approximated, with the reason recorded
>   per CWE. I would rather be told the mapping exists than ship a blank.
> - PCI DSS requirements that a *source scan cannot assert* are listed separately from ones it can,
>   because "we mapped it" and "we evidenced it" are different claims and most tools blur them.
>
> Mapping tables: <link>/docs/compliance · the "not assertable" list is in the same page.
> Happy to be told I have a chapter wrong — that is the point of asking here.

---

## 4. Plugin directories (claudemarketplaces.com, skillsllm)

Directory listings are read in about four seconds. One sentence, three bullets, one command.

**Short description (one line, ~140 chars):**

> Offline security audit engine with a published detection score — live targets, an authorization
> gate, and an EU CRA evidence pack.

**Long description:**

> SecAudit audits a running URL or a source repository and produces a report you can hand to an
> assessor. The deterministic tier needs no API key, no paid plan, no network and has zero
> dependencies — and unlike most scanners it publishes what it detects: F3 59.5 on the RealVuln
> benchmark and recall 0.5236 on SecBench.js, both scored by their own scorers with raw output
> committed. It also publishes a noise floor (0.27 findings per 1,000 lines on maintained code)
> and a page listing what it cannot find.
>
> - **Two modes** — a live target or a checkout, with an authorization gate enforced by a
>   PreToolUse hook rather than by model discipline.
> - **Compliance output** — CycloneDX SBOM, OpenVEX reachability verdicts, EU CRA and ASVS 5.0
>   mapping from the same scan.
> - **Works everywhere** — Claude Code plugin, MCP server for Codex/Cursor/OpenCode, or a plain
>   CLI.
>
> ```
> /plugin marketplace add mtvrkan/secaudit
> /plugin install secaudit@secaudit-kit
> ```

**Tags:** security, sast, taint-analysis, sbom, vex, compliance, owasp, cra, mcp, offline

---

## 5. RealVuln leaderboard PR

The benchmark's maintainers care about reproducibility, not about the tool. Give them the commands
and the seal, and keep the prose out.

**PR title:**

> Add SecAudit (Tier 0) to the leaderboard — F3 59.5, reproducible in ~15 minutes

**PR body:**

> Adding results for SecAudit's deterministic tier. No LLM, no network, no API key — `--backend
> none`, which is the configuration every figure we publish describes.
>
> | Metric | Value |
> |---|---|
> | F3 | 59.5 |
> | F2 | 43.5 |
> | Precision | 0.6718 |
> | Recall | 0.3995 |
> | TP / FP / FN | 704 / 344 / 1058 |
> | Repos scored | 62 of 66 |
>
> **Four repositories could not be scored** — `owasp-web-playground`, `pygoat`, `python-app` and
> `vulnerable-api` are gone from GitHub. All four are dense teaching applications, so their
> absence *lowers* our score rather than raising it; we also publish the stricter reading in which
> their 141 labels count as misses, which puts the honest range at **55.5 – 59.5**.
>
> **Reproduction** (~15 minutes end to end):
>
> ```
> python3 clone_repos.py
> python3 <secaudit>/eval/realvuln/run.py --benchmark . --scanner secaudit
> for r in repos/*/; do python3 score.py --repo "$(basename "$r")" --scanner secaudit; done
> python3 dashboard.py --scanners secaudit
> ```
>
> Windows needs `PYTHONUTF8=1`. `compute_gt_hash.py` needs LF line endings and forward slashes to
> reproduce the published ground-truth digest.
>
> **Disclosure, because it affects how the number should be read.** Our first run against this
> benchmark was blind and scored **12.5**. Runs since were made after reading this benchmark's own
> false negatives, so rule *selection* is corpus-informed even though every rule added is a
> standard one. We state this on our own results page and would rather it were on yours too.
>
> Every figure is tied to a sha256 of the engine that produced it (`sha256:602e2b9c…`), and our CI
> fails if the prose and the scorer output diverge.

---

## 6. The CRA post — the one with a deadline

**Timing: publish 2026-09-01 through 2026-09-08.** The Cyber Resilience Act's
vulnerability-handling obligations apply from **2026-09-11**. Before the date it is useful; after
it, it is one of a hundred.

**Working title:**

> The CRA's vulnerability-handling duty starts on 11 September. Here is what a scan can and cannot
> evidence for you.

**Shape** — this is the one long-form piece, ~1,200 words, and it should be genuinely useful to
someone who will never install the tool. Sections:

1. **What actually applies on 11 September**, in plain language, with the clause references
   (Annex I Part II (1)/(2)/(3)). Not the whole regulation — only the vulnerability-handling
   obligations, because that is what a scanner touches.
2. **The four things the duty asks for that a scanner genuinely produces**: an inventory of
   components (SBOM), a vulnerability register, a status per vulnerability with reasoning
   (OpenVEX), and a record that you looked. Show the actual output, not a screenshot of a
   dashboard.
3. **The larger part it does not produce**, stated as plainly: coordinated disclosure policy,
   reporting timelines to ENISA, update distribution, end-of-support declarations. A tool that
   implies otherwise is selling you a liability. This section is why the post is worth reading and
   why it is not marketing.
4. **Why reachability matters for this specifically** — a register where every transitive CVE is
   `affected` is not evidence of diligence, it is evidence you ran a scanner. Explain
   `not_affected` with a justification, and why we leave transitive dependencies
   `under_investigation` rather than clearing them.
5. **A short "run this on your own repo" ending.** One command, no signup.

**Publish to:** your own site first (canonical), then a link post to r/devsecops and the OWASP
Slack, and a LinkedIn version cut to ~300 words with the same clause references. Do **not**
Show-HN this one — HN already saw the tool, and a compliance post is a different audience.

**Accuracy note.** Every clause reference in this post needs re-reading against the regulation
text the week you publish, not trusted from the mapping table. `docs/compliance.md` is a mapping,
and a mapping is a claim about a scanner's output, not a legal reading.
