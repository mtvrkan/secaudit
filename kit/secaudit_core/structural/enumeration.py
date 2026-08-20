"""Account enumeration — a response that says which half of the credential was wrong.

40 labels on the external corpus, none found. The bug is not in what the handler does; it is in
what it *says*. Two requests, one with a registered address and one without, come back different,
so the login form becomes a query interface for "is this person a customer" — which is the whole
attack against a password reset, and the reconnaissance step before credential stuffing.

The evidence is unusually direct, and that is what makes this decidable without guessing at
intent: the codebase writes the discrimination out in English.

    except User.DoesNotExist:  message = "Email incorrect!"
    ...                        message = "Password incorrect!"

    when the account exists but the secret does not match:  "Password is not correct for the
                                                             given username."
    when there is no such account:                          "Username does not exist"

    if handle not in known:  {"detail": "unknown handle"},  status=404
    if verifier != known[…]: {"detail": "bad verifier"},    status=403

So the rule reads the strings a handler can return and asks whether two of them name *different
factors*: one that names the identity, one that names the credential. A handler that answers
"invalid username or password" to both branches — the fix — says nothing about the identity and
is not reported, which is the property that keeps this from firing on every login form.

The second clause is the reset flow, where the discrimination is not two errors but an error and
a success: *"An email was sent"* against *"We do not have the email in our system"*. That one
needs a bound, because "not found" is the most ordinary message in any application, so it is
asked only of functions whose own name places them in a credential flow — reset, forgot, recover,
login, register, verify, invite, otp.

What it does **not** decide is timing. A handler that returns one message and hashes a password
only when the account exists is still enumerable through the clock, and nothing here measures
that; `docs/what-we-miss.md` keeps saying so.
"""
from __future__ import annotations

import ast

from ..schema import Confidence, Finding, Severity, Verdict
from .routes import AnyFunc, _evidence, EXTS, module_functions

# The two factors a message can name.
_IDENTITY_NOUNS = ("user", "username", "user name", "e-mail", "email", "account", "handle",
                   "login", "identity", "member", "subscriber", "customer", "phone")
_CREDENTIAL_NOUNS = ("password", "passcode", "pass phrase", "passphrase", "pin", "otp",
                     "verifier", "credential", "secret", "one-time", "security code")

# ...and the two ways a message says something was wrong with it.
_ABSENCE = ("not exist", "doesn't exist", "does not exist", "unknown", "no such", "not found",
            "do not have", "don't have", "no account", "not registered", "unregistered",
            "not recognised", "not recognized", "never registered", "isn't registered")
_INVALIDITY = ("incorrect", "invalid", "wrong", "bad ", "mismatch", "not correct", "not match",
               "does not match", "failed", "denied")

# The outcome half of the reset-flow clause.
_SUCCESS = ("sent", "queued", "check your", "we have emailed", "on its way", "dispatched",
            "delivered", "mailed")

# Function names that place a handler in a credential flow, which is the only place the second
# clause is asked. "Not found" is otherwise the most ordinary message an application writes.
_CREDENTIAL_FLOW = ("login", "signin", "sign_in", "log_in", "auth", "reset", "forgot", "recover",
                    "register", "signup", "sign_up", "verify", "invite", "otp", "password",
                    "session", "token", "confirm", "activate")


def _messages(func: AnyFunc) -> list[tuple[int, str]]:
    """Every string literal in the function, with its line. Deliberately not just the returned
    ones: the corpus binds the message to a local (`message = "Email incorrect!"`) as often as it
    returns it inline, and following the binding buys nothing a rule about *vocabulary* needs."""
    out: list[tuple[int, str]] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value.strip()
            if 3 < len(text) < 200:
                out.append((node.lineno, text.lower()))
    return out


def _names_factor(text: str) -> str:
    """Which factor this message names — "identity", "credential" or "" for neither.

    A message naming BOTH factors is only the fix when it names them as *alternatives* — the
    safe message is the disjunctive one, "invalid username or password", which is true whichever
    half was wrong. "Password is not correct for the given username" names both and discriminates
    completely: it asserts the username was right. So the disjunction is the test, not the
    co-occurrence, and getting that wrong cost this rule the one label it missed on first
    measurement.
    """
    if not any(m in text for m in _ABSENCE + _INVALIDITY):
        return ""
    first_identity = min((text.find(n) for n in _IDENTITY_NOUNS if n in text), default=-1)
    first_credential = min((text.find(n) for n in _CREDENTIAL_NOUNS if n in text), default=-1)
    if first_identity < 0 and first_credential < 0:
        return ""
    if first_identity >= 0 and first_credential >= 0:
        lo, hi = sorted((first_identity, first_credential))
        if " or " in text[lo:hi + 12]:
            return ""                      # "username or password" — names no single factor
        return "identity" if first_identity < first_credential else "credential"
    return "identity" if first_identity >= 0 else "credential"


def _absence(text: str) -> bool:
    return (any(n in text for n in _IDENTITY_NOUNS) and any(m in text for m in _ABSENCE)) \
        or text in ("unknown handle", "unknown user", "unknown account")


def _in_credential_flow(func: AnyFunc) -> bool:
    name = func.name.lower()
    return any(m in name for m in _CREDENTIAL_FLOW)


def analyze_file(rel: str, text: str) -> list[Finding]:
    if not rel.lower().endswith(EXTS):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []

    lines = text.splitlines()
    findings: list[Finding] = []
    for func in sorted(module_functions(tree).values(), key=lambda f: f.lineno):
        messages = _messages(func)
        factors = [(line, _names_factor(t)) for line, t in messages]
        identity = [line for line, f in factors if f == "identity"]
        credential = [line for line, f in factors if f == "credential"]

        why = ""
        if identity and credential:
            line = min(identity + credential)
            why = ("two of its messages name different factors — one the identity, one the "
                   "credential — so the two are distinguishable from outside")
        elif _in_credential_flow(func):
            absent = [line for line, t in messages if _absence(t)]
            success = [line for line, t in messages if any(s in t for s in _SUCCESS)]
            if absent and success:
                line = min(absent)
                why = ("one branch reports that the address is not on file and another reports "
                       "that a message was sent, so the response tells the caller whether the "
                       "account exists")
        if not why:
            continue
        findings.append(Finding(
            detector_id="ENUM-PY-RESPONSE",
            title="Account enumeration — the response says whether the account exists",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            cwe="CWE-204", owasp="A01",
            file=rel, line=line,
            evidence=_evidence(lines, line),
            fix=f"`{func.name}` answers differently depending on whether the account exists: "
                f"{why}. Return one message and one status for every failure — \"invalid "
                f"username or password\" — and for a reset flow answer \"if that address is "
                f"registered we have sent a link\" whether or not it is.",
            source="structural", verdict=Verdict.UNVERIFIED))
    return findings


def limitations() -> list[str]:
    return [
        "Account-enumeration analysis reads the message vocabulary a handler can return and "
        "reports one that names the identity in one branch and the credential in another, or "
        "one that discloses account existence inside a named credential flow. It decides "
        "nothing about timing: a handler with a single message that only hashes a password when "
        "the account exists is still enumerable, and is not reported here.",
    ]
