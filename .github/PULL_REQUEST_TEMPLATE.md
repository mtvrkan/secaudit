## What does this PR do?

<!-- Brief description. Reference OWASP/CWE IDs for new checks. -->

## Type

- [ ] New vulnerability check
- [ ] Tool integration
- [ ] Language / framework coverage
- [ ] Bug / false-positive fix
- [ ] Docs / example
- [ ] Other

## Checklist

- [ ] This change is **defensive** — no weaponized exploits, malware, DoS, or brute-force.
- [ ] Anything active (payloads/probes) stays behind the authorization gate.
- [ ] Manifests still validate (`claude plugin validate .` and `./plugins/secaudit`).
- [ ] No real target names, tokens/cookies, IPs, or PII committed (examples are sanitized).
- [ ] Reference files kept tight/skimmable; mapped to OWASP + CWE where relevant.
- [ ] Tested in a Claude Code session against a target I own.
