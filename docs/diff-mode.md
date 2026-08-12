# Diff mode — `--since <ref>`

What a change introduced, what it resolved, and what it left open.

```bash
secaudit . --since main                       # report the difference
secaudit . --since main --min high            # ...and fail CI on a new High or Critical
secaudit . --since main --format json         # machine-readable, for a PR comment
```

## Why a security gate needs this

An absolute gate — *"fail if any Critical exists"* — is unusable on a repository that has any
history. It fails the first PR, it fails every PR after that, and none of those failures are
about the change being reviewed. What happens next is not that the debt gets paid; it is that
someone adds `continue-on-error: true`, and the gate stops catching the new Critical as well.

`--min` with `--since` gates on **introduced** findings only. A PR that adds a command injection
fails. A PR that renames a variable in a file that already had one passes — and the pre-existing
finding is still printed, under its own heading, because a diff that hides open findings to keep
the build green is doing the same damage more quietly.

## Both trees are scanned in full

The obvious implementation is to scan only the files `git diff --name-only` reports. It is
wrong, and it fails silently.

Taint analysis resolves across import edges. Editing a helper can create a finding whose
*source* is a route in a file the commit never touched:

```
commit touches:  src/util.js          ← builds a shell string from its parameter
finding reported at:  src/server.js:2 ← the route that passes req.query.label into it
```

A changed-files scan never looks at `server.js`, so it never sees the source, so it reports
nothing and the PR reads as clean. Scanning both trees costs one extra pass and removes the
whole class of miss. On this repository that pass is under a second.

## How findings are matched

By rule, file, and the text of the matched line — not by line number, with an occurrence index
so two identical dangerous lines in one file stay two findings.

Line numbers are the least stable thing about a finding. Adding an import at the top of a file
moves everything below it; a line-keyed diff then reports every one of those findings as
resolved *and* re-introduced, on a commit that changed nothing about them. A tool that cries
wolf on a no-op commit is a tool whose output people learn to skip.

A finding that moved without changing is counted as unchanged and noted separately.

## Dependency findings are reported but not diffed

`npm audit` reads `node_modules`. A git baseline does not contain `node_modules`, so the
baseline scan has nothing to reproduce those findings from — and if they were diffed anyway,
every advisory would read as newly introduced on every run.

They are printed under **Dependency findings (not diffed)** with that reason stated. Dropping
them silently was the other option: it would have made a PR that adds a vulnerable package look
clean, which is precisely the case a security diff must not be quiet about.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No finding at or above `--min` was introduced (or `--min` was not given) |
| `1` | The change introduced a finding at or above `--min` |
| `2` | The comparison could not be made — not a git repository, unknown ref, or a `--format` that describes a single scan rather than a comparison |

`2` is separated from `1` on purpose: *"this change is unsafe"* and *"I could not tell you
whether this change is safe"* must never be the same signal to a CI job.

## Notes

- The baseline is read from your own object store. `--since` does **not** fetch — in CI, check
  out enough history for the ref to exist (`fetch-depth: 0`, or fetch the base branch).
- The ref is resolved before any scanning starts, so a typo costs a second, not a full run.
- The baseline tree is materialised into a temporary directory with `git archive`, so your
  working tree, index and stash are never touched, and nothing is left behind if the run dies.
- Scoping works: `secaudit src --since main` compares `src` against `src`. A path that did not
  exist at the baseline is treated as empty, so everything in a newly added directory is new.
