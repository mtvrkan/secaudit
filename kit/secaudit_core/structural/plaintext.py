"""Sensitive data written where anything can read it — CWE-312, cleartext storage.

62 labels and one of them found, and the class is genuinely a grab-bag: a password column with no
hash, a DSN with the password formatted into it, an SSN in a JSON blob, a template context
carrying a password hash. What this rule takes is the half that is decidable from one function —
**a write whose payload names something sensitive, in a module that encrypts nothing**:

    target = BASE_EXPORT_DIR / f"{ref}.json"
    target.write_text(json.dumps({"ref": ref, "ssn": …, "card": …}))

The second half of that sentence is what keeps it honest. Naming a sensitive field is not a
finding — every application handles one. The finding is that the field reaches durable storage
and **nothing anywhere in the module encrypts, hashes or wraps it**, which is the same
absence-of-a-control shape the rest of this package reports and carries the same obligation: err
toward silence. A module that imports Fernet, calls a KMS, or hashes with bcrypt is left alone
even if this particular write is the unencrypted one.

**The second clause is the column, not the write.** Half of these labels are not a call at all —
they are a model field: `secret = models.CharField(max_length=64)`, a webhook signing secret
persisted as plain text next to the row it authenticates. A declaration is durable storage stated
in advance, and it is the more useful of the two to report, because the fix is a schema decision.

A bare `token` column is **not** in the vocabulary, and the exclusion was measured rather than
reasoned: adding it took the clause from 19 labels to 21 and from 60 findings to 77 — two true
positives for seventeen more reports, because `token` is what every application calls the value
in its session table, its CSRF field and its API client row, and most of those are opaque by
design. `secret`, `ssn`, `api_key`, a card number: those are names where the name IS the value.
Protection is judged per field there rather than per module: a `models.py` that hashes passwords
correctly and stores a raw invite token beside them is exactly the file this clause is for, so a
module-wide suppression would silence it precisely when it matters. An `EncryptedCharField` or a
`HashedField` excludes itself by its own type name.

The sink list is durable storage only — a file, a dump, a pickle, an object store. A sensitive
value in a *response* is a different bug with a different fix (CWE-200), and a sensitive value in
a *log* is a third (CWE-532, which `TAINT-PY-LOG-SENSITIVE` already reports). Keeping the three
apart matters more than catching all of them here: a report that calls everything cleartext
storage teaches a reader to skip the class.

What it does not decide is whether the storage is actually reachable. A file written under a
directory the deployment never serves is reported the same as one under `static/`. The fix —
encrypt the field, or do not persist it — does not depend on the answer.
"""
from __future__ import annotations

import ast

from ..schema import Confidence, Finding, Severity, Verdict
from .routes import AnyFunc, _dotted, _evidence, EXTS, module_functions

# Field names that make a payload sensitive. Deliberately concrete: a rule that accepted
# "data" or "info" would report every write in every application.
_SENSITIVE_FIELDS = (
    "ssn", "social_security", "socialsecurity", "national_id", "passport", "tax_id", "taxid",
    "card_number", "cardnumber", "credit_card", "creditcard", "card", "cvv", "cvc", "iban",
    "bank_account", "bankaccount", "routing_number", "account_number", "sort_code",
    "password", "passwd", "pwd", "secret", "api_key", "apikey", "private_key", "privatekey",
    "access_token", "refresh_token", "session_token", "credential", "pin_code",
    "date_of_birth", "birth_date", "dob", "driver_license", "drivers_license",
    "medical_record", "diagnosis", "prescription", "patient_note", "phi",
)

# Durable storage. Responses and logs are deliberately absent — see the module docstring.
_STORAGE_CALLS = ("write_text", "write_bytes", "writelines", "dump", "dumps_to", "put_object",
                  "upload_file", "upload_fileobj", "to_csv", "to_json", "to_pickle", "savefig",
                  "write")

# Anything that means the module already protects what it stores.
_PROTECTION_MARKERS = ("encrypt", "fernet", "aes", "cipher", "kms", "vault", "seal", "envelope",
                       "bcrypt", "argon", "scrypt", "pbkdf2", "make_password", "hash_password",
                       "generate_password_hash", "password_hasher", "nacl", "sodium", "gpg",
                       "sha256", "sha512", "hmac", "redact", "mask", "tokenis", "tokeniz")


def _names_and_strings(node: ast.AST) -> list[str]:
    out: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, (ast.Name, ast.Attribute)):
            dotted = _dotted(child)
            if dotted:
                out.append(dotted.lower())
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            out.append(child.value.lower())
        elif isinstance(child, (ast.Import, ast.ImportFrom)):
            out.extend((a.asname or a.name).lower() for a in child.names)
    return out


def _protected(tree: ast.AST) -> bool:
    return any(any(m in n for m in _PROTECTION_MARKERS) for n in _names_and_strings(tree))


def _sensitive(node: ast.AST) -> bool:
    """Whether this expression names a sensitive field, as a key or as an identifier."""
    for name in _names_and_strings(node):
        for field in _SENSITIVE_FIELDS:
            if field == name or field in name.replace("-", "_").split("_") \
                    or ("_" in field and field in name):
                return True
    return False


# Field names that say, in the name, that the column does NOT hold the raw value. Measured
# rather than guessed: on 62 repositories the column clause produced 130 findings for 20 labels
# until these were excluded, and `password` alone accounted for 18 of them with none labelled —
# a `password` column is hashed by the framework that owns it, and the name cannot tell you
# otherwise. What survives is the vocabulary where the name IS the value: a webhook `secret`, a
# raw `token`, an `ssn`, a card number.
_ALREADY_PROTECTED_NAMES = ("hash", "last4", "last_4", "masked", "encrypted", "redacted",
                            "salt", "digest", "fingerprint", "expires", "must_change",
                            "set_", "_at", "changed", "updated", "created", "verified")

# Names too generic to carry the claim on their own, for the reason above.
_TOO_GENERIC_FOR_A_COLUMN = ("password", "passwd", "pwd", "credential", "card", "dob")

# Column types that store what they are given. A field type naming its own protection
# (`EncryptedCharField`, `HashedTextField`) is excluded by the marker test, not by this list.
_PLAIN_FIELD_TYPES = ("charfield", "textfield", "binaryfield", "jsonfield", "slugfield",
                      "emailfield", "urlfield", "column", "string", "text", "varchar",
                      "mapped_column")


def _plaintext_fields(tree: ast.AST) -> list[tuple[int, str]]:
    """Model field declarations whose name is sensitive and whose column stores it as given."""
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for stmt in node.body:
            targets = ([t for t in stmt.targets if isinstance(t, ast.Name)]
                       if isinstance(stmt, ast.Assign)
                       else [stmt.target] if isinstance(stmt, ast.AnnAssign)
                       and isinstance(stmt.target, ast.Name) else [])
            value = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign)) else None
            if not targets or value is None or not isinstance(value, ast.Call):
                continue
            name = targets[0].id.lower()
            if any(m in name for m in _ALREADY_PROTECTED_NAMES):
                continue
            fields = tuple(f for f in _SENSITIVE_FIELDS if f not in _TOO_GENERIC_FOR_A_COLUMN)
            if not any(f == name or f in name.split("_") or ("_" in f and f in name)
                       for f in fields):
                continue
            declared = _dotted(value.func).lower()
            if any(m in declared for m in _PROTECTION_MARKERS):
                continue
            if any(t in declared for t in _PLAIN_FIELD_TYPES):
                out.append((stmt.lineno, targets[0].id))
    return out


def _storage_writes(func: AnyFunc) -> list[ast.Call]:
    out: list[ast.Call] = []
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        tail = _dotted(node.func).rsplit(".", 1)[-1].lower()
        if tail == "open":
            continue                       # opening is not writing; the `.write` below is
        if tail in _STORAGE_CALLS and node.args and any(_sensitive(a) for a in node.args):
            out.append(node)
    return out


def analyze_file(rel: str, text: str) -> list[Finding]:
    if not rel.lower().endswith(EXTS):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    lines = text.splitlines()
    findings: list[Finding] = []
    # The column clause judges protection per field, so it is asked even of a module that
    # protects something else — see the docstring for why that is the point rather than an
    # inconsistency. The write clause keeps the module-wide reading.
    sites: list[tuple[int, str, str]] = [
        (line, name, "column") for line, name in _plaintext_fields(tree)]
    if not _protected(tree):
        for func in sorted(module_functions(tree).values(), key=lambda f: f.lineno):
            writes = _storage_writes(func)
            if writes:
                sites.append((writes[0].lineno, func.name, "write"))
    for line, where, kind in sorted(sites):
        findings.append(Finding(
            detector_id="PLAINTEXT-PY-STORAGE",
            title="Sensitive value stored in cleartext",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            cwe="CWE-312", owasp="A02",
            file=rel, line=line,
            evidence=_evidence(lines, line),
            fix=(f"`{where}` is declared as a plain column, so the value is stored exactly as "
                 f"it arrives — anyone with the database, a backup or a dump reads it. Store a "
                 f"hash if the value only ever needs comparing, or an encrypted column if it "
                 f"needs reading back."
                 if kind == "column" else
                 f"`{where}` writes a payload naming a sensitive field, and nothing in this "
                 f"module encrypts, hashes or redacts it — anyone who reads the file, the "
                 f"backup, or the bucket reads the value. Encrypt the field before it is "
                 f"written (an application-level envelope, or a KMS key), or store an opaque "
                 f"reference and keep the value in a secret store."),
            source="structural", verdict=Verdict.UNVERIFIED))
    return findings


def limitations() -> list[str]:
    return [
        "Cleartext-storage analysis reports a write to durable storage whose payload names a "
        "sensitive field, in a module where nothing encrypts, hashes, redacts or tokenises. It "
        "covers files and object stores only: a sensitive value in a response is CWE-200 and one "
        "in a log is CWE-532, both reported elsewhere or not at all. It does not decide whether "
        "the storage is reachable, and it goes silent for a whole module that protects any "
        "value anywhere in it.",
    ]
