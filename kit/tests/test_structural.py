#!/usr/bin/env python3
"""The three structural rules beyond authorization: rate limiting, uploads, mass assignment.

Same discipline as `test_authz.py` — every rule asserted in both directions, because a rule that
reports a missing check is only worth having if it stays silent on code that has one. The cases
marked *(corpus)* are transcriptions of shapes the external benchmark punished or rewarded, and
they are here so a future edit cannot quietly undo what measuring them bought.

`test_authz.py` covers the authorization half and the shared route machinery underneath all four.
"""
from __future__ import annotations

import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KIT)

from secaudit_core import structural                            # noqa: E402
from secaudit_core.structural import massassign, ratelimit, upload  # noqa: E402
from secaudit_core.structural.routes import is_production_source    # noqa: E402

fails: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        fails.append(message)


def expect(rule, code: str, detector: str, present: bool, label: str,
           path: str = "app/main.py") -> None:
    ids = {f.detector_id for f in rule.analyze_file(path, code)}
    if (detector in ids) != present:
        fails.append(f"[{label}] expected {detector} {'present' if present else 'absent'}, "
                     f"got {sorted(ids) or 'nothing'}")


# --------------------------------------------------------------------------- rate limiting

def test_unlimited_login_is_reported() -> None:
    expect(ratelimit, """
@app.post("/api/auth/login")
def login(payload: LoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"token": issue_token(user)}
""", "RATELIMIT-PY-AUTH", True, "ratelimit/unlimited-login")


def test_a_limiter_decorator_silences_it() -> None:
    expect(ratelimit, """
@app.post("/api/auth/login")
@limiter.limit("5/minute")
def login(payload: LoginIn, db=Depends(get_db)):
    return check_password(payload.password, db)
""", "RATELIMIT-PY-AUTH", False, "ratelimit/decorated")


def test_an_app_level_limiter_silences_the_whole_module() -> None:
    """*(corpus)* A limiter installed as middleware protects handlers that never mention it.

    Judging handlers without looking at the module first would report an application that is
    correctly protected — the most expensive kind of false positive, because the team knows it
    is wrong the moment they read it.
    """
    expect(ratelimit, """
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/api/auth/login")
def login(payload: LoginIn, db=Depends(get_db)):
    return check_password(payload.password, db)
""", "RATELIMIT-PY-AUTH", False, "ratelimit/app-level")


def test_a_limiter_reached_through_a_helper_silences_it() -> None:
    expect(ratelimit, """
def _guard(request):
    if attempts_for(request.remote_addr) > 5:
        raise HTTPException(status_code=429, detail="slow down")

@app.route('/login', methods=['POST'])
def login():
    _guard(request)
    return verify_password(request.form['p'], load_user(request.form['u']))
""", "RATELIMIT-PY-AUTH", False, "ratelimit/helper")


def test_a_non_auth_route_is_not_reported() -> None:
    """The narrowness IS the design: every app has unlimited routes, and reporting them all
    would make the rule the first thing a team switches off."""
    expect(ratelimit, """
@app.post("/api/reports")
def create_report(payload: ReportIn, db=Depends(get_db)):
    db.add(Report(**payload.dict()))
    return {"ok": True}
""", "RATELIMIT-PY-AUTH", False, "ratelimit/non-auth-route")


def test_an_auth_named_route_that_tests_no_credential_is_not_reported() -> None:
    """`GET /session` returning the current profile matches the name and tests nothing."""
    expect(ratelimit, """
@app.get("/api/session")
def read_session(current_user=Depends(get_current_user)):
    return {"user": current_user.email}
""", "RATELIMIT-PY-AUTH", False, "ratelimit/name-only")


def test_a_limiter_on_one_route_does_not_silence_the_next() -> None:
    """The suppression branches decided the rule's precision and nothing exercised them, so a
    module-wide silence went unnoticed. All four cases here were silent before the fix.

    This one is the worst of them: `@limiter.limit` on `/login` silenced an unlimited
    `/admin-login` in the same file. "Most endpoints are limited and one was forgotten" is the
    realistic shape of this bug, and the rule was blind to exactly it.
    """
    expect(ratelimit, """
@app.post("/api/auth/login")
@limiter.limit("5/minute")
def login(payload: LoginIn, db=Depends(get_db)):
    return check_password(payload)

@app.post("/api/auth/admin-login")
def admin_login(payload: LoginIn, db=Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email))
    if not bcrypt.checkpw(payload.password.encode(), user.password_hash):
        raise HTTPException(401)
    return {"token": make_token(user)}
""", "RATELIMIT-PY-AUTH", True, "ratelimit/limited-neighbour")


def test_recording_an_attempt_is_not_limiting_one() -> None:
    """`attempt` was a limiter marker on its own, which read the wrong half of the problem:
    writing down a failed login is what an unprotected endpoint does *instead* of bounding it.
    A handler that counts break-ins is the finding, not the fix."""
    for body, label in (("db.record_attempt(payload.email)", "records"),
                        ('log.warning("failed login attempt for %s", payload.email)', "logs"),
                        ("user.login_attempts = user.login_attempts + 1", "counts")):
        expect(ratelimit, f"""
@app.post("/api/auth/login")
def login(payload: LoginIn, db=Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email))
    if not bcrypt.checkpw(payload.password.encode(), user.password_hash):
        {body}
        raise HTTPException(401)
    return {{"token": make_token(user)}}
""", "RATELIMIT-PY-AUTH", True, f"ratelimit/{label}-an-attempt")


def test_a_bound_on_attempts_still_silences_it() -> None:
    """The other direction of the same edit, and the reason it is a narrowing rather than a
    deletion: a handler that *enforces* a bound is protected however it spells it."""
    for guard, label in (
            ("if user.failed >= settings.MAX_ATTEMPTS:\n            raise HTTPException(429)",
             "max-attempts"),
            ("if too_many_attempts(payload.email):\n            raise HTTPException(429)",
             "too-many-attempts"),
            ("if is_locked_out(payload.email):\n            raise HTTPException(423)",
             "locked-out"),
            ("if user.lockout_until and user.lockout_until > now():\n"
             "            raise HTTPException(423)", "lockout-until")):
        expect(ratelimit, f"""
@app.post("/api/auth/login")
def login(payload: LoginIn, db=Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email))
    {guard}
    if not bcrypt.checkpw(payload.password.encode(), user.password_hash):
        raise HTTPException(401)
    return {{"token": make_token(user)}}
""", "RATELIMIT-PY-AUTH", False, f"ratelimit/{label}")


def test_an_unrelated_route_cannot_silence_the_module() -> None:
    """A limiter marker inside any function used to silence the whole file, because the
    module-level check walked the entire tree. A health endpoint logging the word `attempt`
    should have nothing to do with whether the login below it is bounded."""
    expect(ratelimit, """
@app.get("/api/health")
def health():
    log.info("health check attempt")
    return {"ok": True}

@app.post("/api/auth/login")
def login(payload: LoginIn, db=Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email))
    if not bcrypt.checkpw(payload.password.encode(), user.password_hash):
        raise HTTPException(401)
    return {"token": make_token(user)}
""", "RATELIMIT-PY-AUTH", True, "ratelimit/unrelated-mention")


def test_module_level_registration_still_silences_the_module() -> None:
    """What the module-level check is actually for, kept working: a limiter installed for the
    application protects handlers that never mention one. Including behind the `if` that real
    app setup is routinely guarded by — narrowing the walk must not lose that."""
    for setup, label in (
            ("app.add_middleware(RateLimitMiddleware, limit='10/minute')", "middleware"),
            ("app.state.limiter = Limiter(key_func=get_remote_address)", "app-state"),
            ("if not settings.TESTING:\n    app.state.limiter = build_throttle(app)", "guarded"),
            ("try:\n    install_ratelimit(app)\nexcept ImportError:\n    pass", "try-wrapped")):
        expect(ratelimit, f"""
{setup}

@app.post("/api/auth/login")
def login(payload: LoginIn, db=Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email))
    if not bcrypt.checkpw(payload.password.encode(), user.password_hash):
        raise HTTPException(401)
    return {{"token": make_token(user)}}
""", "RATELIMIT-PY-AUTH", False, f"ratelimit/module-{label}")


# --------------------------------------------------------------------------- file upload

def test_an_unvalidated_upload_is_reported() -> None:
    expect(upload, """
@app.route('/upload', methods=['POST'])
def upload_file():
    f = request.files['file']
    filename = f.filename
    f.save(os.path.join(UPLOAD_FOLDER, filename))
    return 'ok'
""", "UPLOAD-PY-UNRESTRICTED", True, "upload/unvalidated")


def test_an_extension_allowlist_silences_it() -> None:
    expect(upload, """
@app.route('/upload', methods=['POST'])
def upload_file():
    f = request.files['file']
    if not allowed_extension(f.filename):
        abort(400)
    f.save(os.path.join(UPLOAD_FOLDER, f.filename))
    return 'ok'
""", "UPLOAD-PY-UNRESTRICTED", False, "upload/allowlist")


def test_splitext_alone_is_not_validation() -> None:
    """*(corpus)* Extracting an extension is not checking it — the handler that splits the
    extension off in order to *keep* it is the vulnerable one, and counting `splitext` as a
    check cost exactly that true positive."""
    expect(upload, """
@app.route('/upload', methods=['POST'])
def upload_file():
    f = request.files['file']
    ext = os.path.splitext(f.filename)[1]
    f.save(os.path.join(UPLOAD_FOLDER, 'x' + ext))
    return 'ok'
""", "UPLOAD-PY-UNRESTRICTED", True, "upload/splitext-is-not-validation")


def test_a_write_with_no_upload_is_not_an_upload_finding() -> None:
    """*(corpus)* An object with a `.filename` is not an upload. Matching the attribute without
    anchoring it to the request reported a password-list generator and a test module."""
    expect(upload, """
def dump_report(report):
    with open(report.filename, 'w') as fh:
        fh.write(report.body)
""", "UPLOAD-PY-UNRESTRICTED", False, "upload/no-request")


# --------------------------------------------------------------------------- mass assignment

def test_a_spread_request_body_is_reported() -> None:
    expect(massassign, """
@app.route('/profile', methods=['POST'])
def update_profile():
    data = request.get_json()
    User.objects.filter(pk=session['uid']).update(**data)
    return 'ok'
""", "MASSASSIGN-PY", True, "massassign/spread")


def test_a_dunder_dict_update_is_reported() -> None:
    expect(massassign, """
@app.route('/profile', methods=['POST'])
def update_profile():
    payload = request.get_json()
    user = load(session['uid'])
    user.__dict__.update(payload)
    user.save()
    return 'ok'
""", "MASSASSIGN-PY", True, "massassign/dunder-dict")


def test_named_fields_are_not_mass_assignment() -> None:
    expect(massassign, """
@app.route('/profile', methods=['POST'])
def update_profile():
    data = request.get_json()
    User.objects.filter(pk=session['uid']).update(email=data['email'], bio=data['bio'])
    return 'ok'
""", "MASSASSIGN-PY", False, "massassign/named-fields")


def test_a_declared_schema_is_the_allowlist() -> None:
    """A Pydantic or DRF handler declares its field set; that IS the decision the vulnerability
    is about, so reporting it would report the correct pattern."""
    expect(massassign, """
@app.post("/profile")
def update_profile(payload: ProfileIn, db=Depends(get_db)):
    data = payload.dict()
    db.query(User).filter(User.id == 1).update(**data)
    return {"ok": True}
""", "MASSASSIGN-PY", False, "massassign/schema")


# --------------------------------------------------------------------------- shared behaviour

def test_non_production_sources_are_out_of_scope() -> None:
    """Every rule here describes what a deployed handler fails to do; a test module is not one.

    The detector pack still scans these files — a committed secret in a test is a real secret.
    That is a different question from "this endpoint has no rate limit".
    """
    for path in ("app/tests/test_upload.py", "crm/tests.py", "scripts/seed.py",
                 "app/migrations/0001_initial.py", "tests/conftest.py"):
        check(not is_production_source(path), f"{path} was treated as production code")
    for path in ("app/main.py", "app/views.py", "api/routes/auth.py", "src/handlers.py"):
        check(is_production_source(path), f"{path} was treated as non-production")

    code = ("from flask import request\n"
            "@app.route('/upload', methods=['POST'])\n"
            "def up():\n"
            "    f = request.files['file']\n"
            "    f.save('/tmp/' + f.filename)\n")
    check(structural.analyze_file("app/tests/test_upload.py", code) == [],
          "a structural rule fired inside a test module")
    check(structural.analyze_file("app/upload.py", code) != [],
          "the same code in production source produced nothing — the scope guard is too wide")


def test_unparseable_and_non_python_files_say_nothing() -> None:
    check(structural.analyze_file("app/main.py", "def broken(:\n") == [],
          "a file that does not parse produced findings")
    check(structural.analyze_file("app/main.js", "app.post('/x', h)") == [],
          "a non-Python file was analysed")
    # Python 2 does not parse under a Python 3 `ast`, and the corpus contains such files. The
    # rules say nothing rather than guessing; `limitations()` owns the disclosure.
    check(structural.analyze_file("app/legacy.py", 'print "hello"\n') == [],
          "a Python 2 source produced findings from an ast-based rule")


def test_every_rule_contributes_its_own_limitations() -> None:
    text = " ".join(structural.limitations())
    for phrase in ("rate", "upload", "allowlist", "Python"):
        check(phrase.lower() in text.lower(), f"limitations never mention {phrase!r}")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    test_unlimited_login_is_reported()
    test_a_limiter_decorator_silences_it()
    test_an_app_level_limiter_silences_the_whole_module()
    test_a_limiter_reached_through_a_helper_silences_it()
    test_a_non_auth_route_is_not_reported()
    test_an_auth_named_route_that_tests_no_credential_is_not_reported()
    test_a_limiter_on_one_route_does_not_silence_the_next()
    test_recording_an_attempt_is_not_limiting_one()
    test_a_bound_on_attempts_still_silences_it()
    test_an_unrelated_route_cannot_silence_the_module()
    test_module_level_registration_still_silences_the_module()
    test_an_unvalidated_upload_is_reported()
    test_an_extension_allowlist_silences_it()
    test_splitext_alone_is_not_validation()
    test_a_write_with_no_upload_is_not_an_upload_finding()
    test_a_spread_request_body_is_reported()
    test_a_dunder_dict_update_is_reported()
    test_named_fields_are_not_mass_assignment()
    test_a_declared_schema_is_the_allowlist()
    test_non_production_sources_are_out_of_scope()
    test_unparseable_and_non_python_files_say_nothing()
    test_every_rule_contributes_its_own_limitations()

    if fails:
        print("STRUCTURAL TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("STRUCTURAL TESTS PASSED — rate limiting, upload and mass assignment asserted in both "
          "directions, including the app-level-limiter, splitext-is-not-validation and "
          "declared-schema shapes the external corpus decided.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
