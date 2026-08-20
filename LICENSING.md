# Licensing

**SecAudit is MIT-licensed in its entirety.** See [LICENSE](LICENSE). One license, every file:
Python, Markdown, YAML, JSON, fixtures, references, report templates.

## Why not a code/content split?

Several projects in this ecosystem dual-license — MIT for code, CC BY (or CC BY-SA) for skills,
methodology prose, wordlists and rubrics. We considered that and deliberately did not do it.

**In a Claude Code plugin the Markdown is the program.** `SKILL.md` and everything under
`references/` are instructions the model executes, not documentation *about* something that
executes. A split would force every downstream user to decide, per file, whether a `.md` is
"code" or "content" — and there is no honest line to draw when the `.md` *is* the control flow.

Two further reasons:

- Creative Commons itself [recommends against using CC licenses for software](https://creativecommons.org/faq/#can-i-apply-a-creative-commons-license-to-software),
  because they do not address source/object distribution, patents, or warranty disclaimers the
  way software licenses do.
- MIT already requires attribution. The practical protection people reach for CC BY to get is
  already there, and MIT is strictly more permissive, which matters for adoption in a space
  where the alternatives are free and official.

## What this means for you

- Use it commercially, fork it, embed it, rebrand it — keep the copyright notice.
- Vendored or derived material from other projects, if any is ever added, will be recorded in
  a `NOTICE` file with its own terms. There is none today.

## What is *not* a licensing question

SecAudit is a defensive tool. The [DISCLAIMER](DISCLAIMER.md) and the authorization gate bind
how you may use it regardless of what the license permits: audit only what you own or are
explicitly authorized to test.
