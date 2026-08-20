# Disclaimer & Responsible Use

SecAudit is a **defensive security tool** intended to help developers and owners find and
fix vulnerabilities in **their own** systems, or systems they have **explicit, written
authorization** to test.

## You are responsible for authorization

Scanning, probing, or testing computer systems, networks, or applications that you do not
own and are not authorized to test is **illegal** in most jurisdictions (e.g. the US
Computer Fraud and Abuse Act, the UK Computer Misuse Act, and equivalent laws worldwide),
and may violate the terms of service of hosting and cloud providers.

By using SecAudit you represent and warrant that:

- You own the target, **or** have explicit authorization from the owner to perform the
  testing you initiate.
- You will respect the scope, rate limits, and excluded actions you define.
- You will not use SecAudit to attack, disrupt, or gain unauthorized access to any system.

## What SecAudit will not do

- Run denial-of-service, stress, or high-volume fuzzing attacks.
- Brute-force passwords, tokens, or OTPs.
- Exfiltrate, copy, or display real user data, PII, or secrets.
- Exploit beyond the minimum safe proof needed to confirm an issue.
- Produce weaponized exploit code, malware, command-and-control tooling, or
  detection-evasion techniques.

Its live-target default is **passive** (checks a normal browser would make). Active testing
is gated behind an explicit authorization step.

## No warranty

SecAudit performs a **best-effort** assessment. It does **not** guarantee that all
vulnerabilities are found, nor that findings are free of false positives. Results depend on
scope, access, source availability, time, and tooling. A clean SecAudit report is **not** a
certification of security. Always complement automated auditing with professional manual
review for high-risk systems.

The software is provided "AS IS", without warranty of any kind. The authors and
contributors accept **no liability** for any damage, loss, legal consequence, or misuse
arising from the use of this software. See [LICENSE](LICENSE).

## Reporting misuse or vulnerabilities

To report a vulnerability in SecAudit itself, see [.github/SECURITY.md](.github/SECURITY.md).
