"""Unrestricted file upload — a handler that writes what it was sent without deciding what it is.

47 labels, none found. The shape the corpus keeps showing is the same one every guide warns
about and every codebase reproduces:

    file = request.files['file']
    filename = file.filename            # attacker-controlled, extension included
    file.save(os.path.join(UPLOAD_FOLDER, filename))

The bug is not the save and not the filename — it is that nothing between them decides whether
this file is allowed. So the rule is a relation, not a token: an upload is read, a write happens,
and no validation stands between them.

**Validation is anything that narrows the set of acceptable files**, and it is deliberately read
generously — an allowlist test, an extension check, a content-type or MIME test, a magic-byte
sniff, a size bound, or a call to a module-local helper that does any of those. Erring generous
is right here for the same reason it is in the authorization rules: this reports the *absence*
of a check, so it must be sure of the absence.

What it does **not** decide is whether the validation is any good. `if ext in ALLOWED` where the
list contains `.svg`, or an extension check on a filename the server later re-derives, both read
as validated. That is a real bound and `limitations()` says so — a rule that claimed to judge the
quality of a check would be claiming to know what the deployment does with the file.
"""
from __future__ import annotations

import ast

from ..schema import Confidence, Finding, Severity, Verdict
from .routes import AnyFunc, _dotted, _evidence, EXTS, module_functions

# Reading an uploaded file out of the request.
_UPLOAD_READERS = ("request.files", "request.form.files", "self.request.files",
                   "request.FILES", "files.get", "uploadfile", "upload_file",
                   "request.file", "form.file")
# Attribute names an upload object carries. Only consulted on a value that already came from a
# request read — on its own, `.filename` matches a config object, a test fixture and a CLI
# script, which is exactly what it did: three of the first fourteen false positives were a test
# module and a password-list generator, neither of which is a handler at all.
_UPLOAD_ATTRS = ("filename", "content_type", "stream", "file")

# Writing it somewhere durable.
_WRITE_CALLS = ("save", "write", "copyfileobj", "writelines", "write_bytes", "write_text",
                "put_object", "upload_file", "upload_fileobj", "store", "persist")

# Anything that narrows what is acceptable. Read generously — see the module docstring — but
# `splitext` and `suffix` are deliberately absent. They *extract* an extension; the Tornado
# handler in the corpus splits the extension off precisely so it can keep it on the file it
# writes, and counting extraction as validation cost that true positive.
_VALIDATION_MARKERS = (
    "allowed", "allowlist", "whitelist", "permitted", "accept", "valid", "validate",
    "extension", "mimetype", "mime_type", "content_type", "magic",
    "imghdr", "filetype", "sniff", "max_size", "maxsize", "size_limit", "content_length",
    "secure_filename", "check_file", "verify_file", "is_image", "is_allowed", "endswith",
)


def _names_in(node: ast.AST) -> list[str]:
    out = []
    for child in ast.walk(node):
        if isinstance(child, (ast.Name, ast.Attribute)):
            dotted = _dotted(child)
            if dotted:
                out.append(dotted.lower())
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            out.append(child.value.lower())
    return out


def _reads_an_upload(func: AnyFunc) -> bool:
    names = _names_in(func)
    if any(any(r.lower() in n for r in _UPLOAD_READERS) for n in names):
        return True
    # `def upload(file: UploadFile = File(...))` — FastAPI puts the upload in the signature.
    for arg in list(func.args.args) + list(func.args.kwonlyargs):
        annotation = _dotted(arg.annotation).lower() if arg.annotation is not None else ""
        if "uploadfile" in annotation or "filestorage" in annotation:
            return True
    # An upload attribute counts only on something reached from the request. Without that
    # anchor the test matches any object with a `.filename`, and a handler is not the only
    # thing that has one.
    return any("request" in n and n.endswith(tuple("." + a for a in _UPLOAD_ATTRS))
               for n in names)


def _write_calls(func: AnyFunc) -> list[ast.Call]:
    out = []
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        tail = _dotted(node.func).rsplit(".", 1)[-1].lower()
        if tail in _WRITE_CALLS:
            out.append(node)
        elif tail == "open" and any(
                isinstance(a, ast.Constant) and isinstance(a.value, str) and "w" in a.value
                for a in node.args):
            out.append(node)
    return out


def _validates(func: AnyFunc, functions: dict[str, AnyFunc],
               seen: frozenset[str] = frozenset()) -> bool:
    """Whether anything in or reachable from the handler narrows what file is acceptable."""
    if any(any(m in n for m in _VALIDATION_MARKERS) for n in _names_in(func)):
        return True
    for node in ast.walk(func):
        name = ""
        if isinstance(node, ast.Call):
            name = _dotted(node.func).rsplit(".", 1)[-1]
        elif isinstance(node, ast.Name):
            name = node.id
        callee = functions.get(name)
        if callee is None or name in seen or callee is func:
            continue
        if _validates(callee, functions, seen | {name}):
            return True
    return False


def analyze_file(rel: str, text: str) -> list[Finding]:
    if not rel.lower().endswith(EXTS):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []

    lines = text.splitlines()
    functions = module_functions(tree)
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for func in functions.values():
        if not _reads_an_upload(func):
            continue
        writes = _write_calls(func)
        if not writes:
            continue
        if _validates(func, functions):
            continue
        line = writes[0].lineno
        if line in seen_lines:
            continue
        seen_lines.add(line)
        findings.append(Finding(
            detector_id="UPLOAD-PY-UNRESTRICTED",
            title="Uploaded file is written without deciding what kind of file it is",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            cwe="CWE-434", owasp="A04",
            file=rel, line=line,
            evidence=_evidence(lines, line),
            fix=f"`{func.name}` reads an uploaded file and writes it, and nothing between the "
                f"two narrows what is acceptable — no extension allowlist, content-type or "
                f"magic-byte check, and no size bound. Validate against an allowlist of "
                f"extensions AND the sniffed content type, cap the size, and store the file "
                f"under a name the server generates rather than the one the caller sent.",
            source="structural", verdict=Verdict.UNVERIFIED))
    return findings


def limitations() -> list[str]:
    return [
        "Upload analysis reports a handler that reads an uploaded file and writes it with no "
        "validation between the two. It judges whether a check is present, never whether the "
        "check is adequate: an allowlist containing a dangerous type, or an extension test on a "
        "name the deployment later re-derives, both read as validated.",
    ]
