# Security Policy

## Reporting a vulnerability in SecAudit

If you discover a security issue in SecAudit itself (for example, a way the skill could be
coerced into unsafe behavior, or a flaw in the safety gating), please report it privately:

- Use GitHub's **[Private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)**
  ("Security" tab → "Report a vulnerability"), **or**
- Open an issue that contains **no exploit details** and ask for a private channel.

Please do **not** open a public issue with exploit details before a fix is available.

We aim to acknowledge reports within a few days and to address confirmed issues promptly.

## Scope

This policy covers the SecAudit plugin, skill, agents, and documentation in this
repository. It does **not** cover:

- Vulnerabilities in the third-party scanners SecAudit can invoke (report those upstream).
- Issues in targets you scan with SecAudit (that's what SecAudit is for — fix them in your
  own project).

## Responsible use

SecAudit is a defensive tool. Reports describing how to misuse it for unauthorized testing
are out of scope; see [DISCLAIMER.md](../DISCLAIMER.md).
