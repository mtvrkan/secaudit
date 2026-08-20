# The held-out policy — how this repository keeps a number it has not tuned against

Every external figure here started blind and stopped being blind. RealVuln scored 12.5 and 13.3
before anybody read its labels; it scores 39.2 now, after four rounds of reading its false
negatives. SecBench.js scored 0.2286 blind and 0.5410 after acting on what that run said. Both
gaps are disclosed in the pages that publish them, and both disclosures end the same way: *the
honest successor is a benchmark this repository has not read.*

**As of 2026-08-16 there was no such benchmark left.** Every corpus in `eval/` had been read.
That is a worse position than it sounds, and it is not about any single number: it means that
from here, **no improvement can be defended as generalising**. It can only be defended as
"the two corpora we tune against went up", which is the claim every abandoned SAST rule pack
could also make.

**Closed on 2026-08-18 by adopting a third corpus under the seal from its first minute.**
[`eval/cvefixes/`](cvefixes/) — real CVEs joined to the commits that fixed them, 3,576 of them,
with 674 sealed by `build_corpus.py` *as part of building the corpus* rather than as a later
step somebody could take after a first look. It is the one slice here that is blind on its first
run instead of a baseline.

The first run is also the first evidence that the mechanism works rather than merely exists:
**sealed 17.06%, unsealed 15.32%.** The held-out fifth scored slightly *higher* than the rest,
which is what "nothing was fitted to this corpus" looks like when it is measured instead of
asserted. The headline itself is poor — 24.5% of CVEs, 15.7% of vulnerable files — and
`eval/cvefixes/README.md` says why without excusing it.

Buying a third corpus does not fix this — it postpones it by one benchmark. The fix has to be a
rule that survives adopting new corpora, so:

## The policy

**A slice of every detection corpus is sealed before its first diagnosis, and never read.**

*Sealed* is specific, and the specificity is the point:

* **Scored, not inspected.** Sealed entries are scanned and scored like everything else — the
  headline recall covers the whole corpus. What is forbidden is *looking at them to decide what
  to build*: opening their source, reading their per-entry results while diagnosing, or naming
  them in an issue, a commit message or a comment.
* **Reported separately, every round.** Each scorer reports the sealed slice's recall next to the
  unsealed slice's. A round that moves the unsealed number and not the sealed one has fitted the
  corpus, and says so in its own output rather than in someone's judgement afterwards.
* **The seal is permanent.** There is no unsealing step. A corpus whose seal is broken is retired
  from making blind claims; it does not get resealed, because a reseal is just a delay.

## What makes it enforceable rather than aspirational

A policy nobody can check is a promise, and this repository has a rule about those. The seal is
enforced by **check 41**, which fails the build if any sealed identifier appears anywhere in the
committed tree except the register itself.

That works because of how corpus-informed tuning actually happens: you cannot diagnose against a
package without writing its name down. It goes into a commit message, a test fixture, a comment
explaining why a rule was narrowed, a CHANGELOG entry, a note in a README. Every one of those is
in the tree, and every one of them fails the check. The mechanism does not detect intent — it
makes the ordinary act of using a sealed entry leave a mark that the build refuses.

It is not airtight. Someone could read a sealed package, form a hypothesis, and write it up using
only unsealed examples. What the check removes is the *accidental* and the *casual* path, which
is how all four of this repository's corpus-informed rounds actually happened — nobody set out
to overfit; they read the misses because the misses were right there.

## The register

[`eval/heldout.json`](heldout.json) holds the sealed identifiers, the corpus they belong to, the
date sealed, and the selection rule.

**Selection is deterministic and verifiable, so "did you pick a flattering slice?" is answerable
without trusting whoever ran it.** An entry is sealed if the first eight hex digits of
`sha256(name)` fall in the bottom fifth of the space. Anyone with the corpus can recompute the
set exactly; nobody can choose it.

| Corpus | Sealed | Of | Labelled sinks inside the seal | Date |
|---|---|---|---|---|
| SecBench.js | 125 packages | 596 | 121 | 2026-08-16 |

## What this figure is not, yet

**The sealed slice of SecBench.js is not a blind figure today, and calling it one would be the
exact dishonesty this file exists to prevent.** Those 125 packages were inside the corpus for the
blind run and for both corpus-informed rounds; three of them may well have contributed to the
aggregate that guided a decision. Sealing them stops *future* targeted tuning. It cannot
retroactively unread anything.

So the number the scorer prints for the sealed slice today is a **baseline**, not a blind score.
Its value arrives at the next round: if the unsealed slice moves and the sealed one does not,
that round bought corpus fit rather than detection, and the two columns will say so side by side
without anybody having to be honest about it in prose.

The genuinely blind figures remain the ones already published — RealVuln 12.5 and
SecBench.js 0.2234 — and this policy does not improve them. It stops the next corpus from
joining them.

## The baseline, recorded on the day of sealing

| Slice | At sealing | Now | Labelled sinks |
|---|---|---|---|
| Sealed | 36 (0.2975) | **71 (0.5868)** | 121 |
| Unsealed | 103 (0.2279) | **239 (0.5288)** | 452 |

**The sealed slice scores higher, and that means nothing.** With 121 labels against 452 the
difference is comfortably inside what a random split produces, and reading it as "the engine
generalises better than it fits" would be the same error this file was written to prevent, run in
the flattering direction. It is recorded because a baseline you write down *before* it can matter
is worth more than one reconstructed afterwards.

What to watch is the *gap*, next round and every round after: if the unsealed recall moves and
the sealed recall does not, the work bought corpus fit rather than detection.

## What it said in its first round

The `req.url` round is the first change measured against this seal, and it is the answer the
policy was built to produce: **both slices moved, and the sealed one moved with the unsealed one.**
Sealed recall 0.2975 → 0.3967, unsealed 0.2279 → 0.3407.

The unsealed slice moved further in relative terms (+49% against +33%), which is the expected
shape rather than a problem: the diagnosis was made by reading unsealed misses, so unsealed is
where the fit is. What matters is that the sealed slice moved substantially at all. A change that
had been fitted to the corpus would have moved the half that was read and left the half that was
not — and this one did not.

That is a claim the two blind figures could never support again, and it took one round to make it.

## What it said in its second round, which is the one it was really built for

The `req.url` round moved both slices, but it was a *source* the engine had never modelled — the
kind of change that obviously generalises. The quadratic-ReDoS round is the harder case, and it is
the one where a reader is entitled to be suspicious: the criterion was designed after reading 79
labelled misses one at a time, which is as corpus-informed as this repository gets.

Every one of those 79 was unsealed. So if the criterion were shaped to the examples rather than to
the defect, unsealed would move and sealed would not.

| Slice | Before | After | Labelled sinks |
|---|---|---|---|
| Sealed | 51 (0.4215) | **55 (0.4545)** | 121 |
| Unsealed | 169 (0.3739) | **182 (0.4027)** | 452 |

**The sealed slice moved further than the unsealed one** — +3.3 points against +2.9, on packages
nobody involved has ever opened. That does not make the round free (it cost four false positives
on RealVuln and three findings per 100,000 lines on the noise floor, both published where they
happened), and it does not make the sealed number a blind one. What it does is answer the only
question the reading of those 79 labels put in doubt, with an instrument that was set up before
the answer was known.

## And in its third round, which read more labels than either of the others

The prototype-pollution round is the most corpus-informed piece of work in this repository: all
113 unsealed misses in that class were read one at a time, and three separate changes came out of
them. If reading labels produces rules that fit those labels, this is the round where it shows.

| Slice | Before | After | Labelled sinks |
|---|---|---|---|
| Sealed | 55 (0.4545) | **66 (0.5455)** | 121 |
| Unsealed | 182 (0.4027) | **214 (0.4735)** | 452 |

**+9.1 points sealed against +7.1 unsealed.** Twice in a row the half nobody read moved further
than the half that was read, which is worth one sentence of interpretation and no more: it is
evidence that what the reading produced were *rules* rather than *fits*, and it is not evidence
that the sealed figure is blind. Those packages were in the corpus before the seal existed.

There is a mechanism behind it rather than luck, and naming it is more useful than the number:
the largest single change of that round was not a rule at all. It was the **function finder**
every JavaScript structural analysis is scoped by, which could not delimit four ordinary shapes.
An infrastructure fix cannot be fitted to the labels that revealed it — it applies wherever those
shapes occur, which on this corpus is everywhere.

## And a fourth, where the unsealed slice moved more — which is also the expected answer

| Slice | Before | After | Labelled sinks |
|---|---|---|---|
| Sealed | 66 (0.5455) | **71 (0.5868)** | 121 |
| Unsealed | 214 (0.4735) | **239 (0.5288)** | 452 |

+4.1 points sealed against +5.5 unsealed: the read half moved further this time, and that is not
a warning sign. It is what a round should look like when part of it *is* specific to what was
read — one of the three changes was a catalog addition (`Function`, `vm`, indirect `eval`), and a
sink you add because a corpus showed you it exists will always land hardest on that corpus. The
other two were shapes (`cp.exec` after an import, a method's parameters), and those generalise,
which is why the sealed half moved substantially at all.

**Four rounds, four times the sealed slice moved with the read one.** What that supports is a
narrow claim and it is worth stating narrowly: the work of these rounds has been recognising
constructs the engine could not see, and that kind of work does not fit a corpus even when a
corpus is what revealed it. It says nothing about rounds that tune thresholds, and the day one of
those leaves the sealed column flat is the day this file earns its keep in the other direction.

