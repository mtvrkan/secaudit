#!/usr/bin/env python3
"""The structural rules beyond authorization: rate limiting, uploads, mass assignment, CSV
export, account enumeration, client-trusted access decisions, cleartext storage,
caller-sized allocation and response exposure.

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
from secaudit_core.structural import (clienttrust, csvexport, enumeration,  # noqa: E402
                                      exposure, massassign, plaintext, ratelimit,
                                      resource, upload)
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



# ------------------------------------------------- the framework's own login, wired in a URL conf

_URLCONF = """
from django.contrib.auth import views as auth_views
from django.urls import include, path

urlpatterns = [
    path("accounts/login/", auth_views.LoginView.as_view(template_name="login.html"), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("accounts/password-reset/", auth_views.PasswordResetView.as_view(), name="reset"),
    path("accounts/reset/<uidb64>/<token>/", auth_views.PasswordResetConfirmView.as_view()),
    path("accounts/password-change/", auth_views.PasswordChangeView.as_view()),
]
"""


def expect_project(files: dict, detector: str, count: int, label: str) -> None:
    ids = [f.detector_id for f in ratelimit.analyze_project(files)]
    got = ids.count(detector)
    if got != count:
        fails.append(f"[{label}] expected {count} x {detector}, got {got} ({sorted(set(ids))})")


def test_a_framework_login_with_no_project_limiter_is_reported() -> None:
    # Two findings and not five: `LogoutView` consumes a session the caller already holds,
    # `PasswordResetConfirmView` tests an HMAC Django itself generated, and `PasswordChangeView`
    # is behind the session an attacker would have to own first.
    expect_project({"config/urls.py": _URLCONF,
                    "config/settings.py": "INSTALLED_APPS = ['django.contrib.auth']"},
                   "RATELIMIT-PY-AUTHVIEW", 2, "authview/unprotected")


def test_a_project_level_limiter_silences_the_url_conf() -> None:
    # django-axes is an entry in settings and a middleware line; the URL conf that mounts the
    # login never mentions it, which is exactly why this evidence is read project-wide.
    for label, settings in (("axes", "INSTALLED_APPS = ['axes']"),
                            ("middleware", "MIDDLEWARE = ['django_ratelimit.middleware.X']"),
                            ("lockout", "AXES_LOCKOUT_TEMPLATE = 'locked.html'")):
        expect_project({"config/urls.py": _URLCONF, "config/settings.py": settings},
                       "RATELIMIT-PY-AUTHVIEW", 0, f"authview/limited-{label}")


def test_a_manifest_entry_alone_is_not_a_defence() -> None:
    # And not only because the scanned set holds no manifest: `django-axes` in `requirements.txt`
    # defends nothing until it is in `INSTALLED_APPS` or `MIDDLEWARE`, both of which are Python.
    expect_project({"config/urls.py": _URLCONF, "requirements.txt": "django-axes==6.0"},
                   "RATELIMIT-PY-AUTHVIEW", 2, "authview/manifest-only")


def test_a_word_that_merely_contains_a_marker_is_not_evidence() -> None:
    # The project-wide read is the dangerous one: a substring match would let any file in the
    # tree silence the login. `axesbury` is a word, `axes` is a package.
    expect_project({"config/urls.py": _URLCONF,
                    "config/settings.py": "SITE_NAME = 'axesbury'"},
                   "RATELIMIT-PY-AUTHVIEW", 2, "authview/near-miss-word")


def test_a_projects_own_login_view_class_is_not_the_frameworks() -> None:
    # Nothing here knows what somebody else's `LoginView` does, and a class-based view a project
    # wrote is a handler this engine has no reader for either way — see `limitations()`.
    expect_project({"app/urls.py": """
from django.urls import path
from . import views

urlpatterns = [path("login/", views.LoginView.as_view(), name="login")]
"""}, "RATELIMIT-PY-AUTHVIEW", 0, "authview/own-class")


def test_a_direct_class_import_is_recognised() -> None:
    expect_project({"app/urls.py": """
from django.contrib.auth.views import LoginView
from django.urls import path

urlpatterns = [path("login/", LoginView.as_view(), name="login")]
"""}, "RATELIMIT-PY-AUTHVIEW", 1, "authview/direct-import")


def test_a_module_without_urlpatterns_is_not_a_url_conf() -> None:
    expect_project({"app/helpers.py": """
from django.contrib.auth import views as auth_views

def build():
    return auth_views.LoginView.as_view()
"""}, "RATELIMIT-PY-AUTHVIEW", 0, "authview/not-a-urlconf")


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


def test_unparseable_and_unclaimed_languages_say_nothing() -> None:
    check(structural.analyze_file("app/main.py", "def broken(:\n") == [],
          "a file that does not parse produced findings")
    check(structural.analyze_file("app/main.go", "func main() {}\n") == [],
          "a language with no structural front end was analysed")

    # JavaScript is no longer unclaimed — `structural/js.py` answers the same four questions for
    # it. What must stay true is that the PYTHON rules never see a `.js` file. They are the path
    # the published RealVuln figure comes out of, and handing them a language they cannot parse
    # is a silent no-op today and a wrong answer the first time someone widens their extension
    # check. The dispatch keeps them apart; this asserts the dispatch.
    handler = "app.post('/admin/x', (req, res) => { db.user.create({ data: req.body }); });"
    for rule in (ratelimit, upload, massassign):
        name = rule.__name__.rsplit(".", 1)[-1]
        check(rule.analyze_file("app/main.js", handler) == [],
              f"the Python {name} rule analysed a .js file")
    ids = {f.detector_id for f in structural.analyze_file("app/main.js", handler)}
    check(bool(ids) and all("JS" in i for i in ids),
          f"a .js file must be answered by the JavaScript rules only; got {sorted(ids)}")
    # Python 2 does not parse under a Python 3 `ast`, and the corpus contains such files. The
    # rules say nothing rather than guessing; `limitations()` owns the disclosure.
    check(structural.analyze_file("app/legacy.py", 'print "hello"\n') == [],
          "a Python 2 source produced findings from an ast-based rule")


def test_every_rule_contributes_its_own_limitations() -> None:
    text = " ".join(structural.limitations())
    for phrase in ("rate", "upload", "allowlist", "Python"):
        check(phrase.lower() in text.lower(), f"limitations never mention {phrase!r}")


# --------------------------------------------------------------------------- CSV export

def test_a_csv_export_of_data_is_reported() -> None:
    expect(csvexport, """
import csv

def export_tickets(request):
    response = HttpResponse(content_type="text/csv")
    writer = csv.writer(response)
    writer.writerow(["id", "subject"])
    for t in Ticket.objects.all():
        writer.writerow([t.id, t.subject])
    return response
""", "CSVINJ-PY-EXPORT", True, "csv/export")


def test_a_header_only_row_is_not_a_finding() -> None:
    expect(csvexport, """
import csv

def export_headers(response):
    writer = csv.writer(response)
    writer.writerow(["id", "subject", "status"])
    return response
""", "CSVINJ-PY-EXPORT", False, "csv/header-only")


def test_a_neutralising_helper_silences_the_module() -> None:
    expect(csvexport, """
import csv

def csv_safe(value):
    text = str(value)
    return "'" + text if text.startswith(("=", "+", "-", "@")) else text

def export_tickets(request):
    writer = csv.writer(HttpResponse(content_type="text/csv"))
    for t in Ticket.objects.all():
        writer.writerow([csv_safe(t.id), csv_safe(t.subject)])
""", "CSVINJ-PY-EXPORT", False, "csv/neutralised")


# --------------------------------------------------------------------------- enumeration

def test_two_messages_naming_different_factors_are_reported() -> None:
    expect(enumeration, """
def login(request):
    try:
        user = User.objects.get(email=request.POST["email"])
    except User.DoesNotExist:
        return render(request, "login.html", {"message": "Email incorrect!"})
    if not user.check(request.POST["secret"]):
        return render(request, "login.html", {"message": "Password incorrect!"})
    return redirect("/")
""", "ENUM-PY-RESPONSE", True, "enum/two-factors")


def test_one_message_for_both_branches_is_silent() -> None:
    expect(enumeration, """
def login(request):
    try:
        user = User.objects.get(email=request.POST["email"])
    except User.DoesNotExist:
        return render(request, "login.html", {"message": "Invalid username or password"})
    if not user.check(request.POST["secret"]):
        return render(request, "login.html", {"message": "Invalid username or password"})
    return redirect("/")
""", "ENUM-PY-RESPONSE", False, "enum/one-message")


def test_a_reset_flow_that_discloses_existence_is_reported() -> None:
    expect(enumeration, """
def password_reset(request):
    qs = User.objects.filter(email=request.POST.get("email", ""))
    if len(qs) > 0:
        messages.success(request, "An email was sent to reset your password!")
    else:
        messages.error(request, "We do not have the email in our system")
    return redirect("/")
""", "ENUM-PY-RESPONSE", True, "enum/reset-discloses")


# --------------------------------------------------------------------------- client trust

def test_a_cookie_compared_to_a_literal_gate_is_reported() -> None:
    expect(clienttrust, """
def ops_panel(request):
    badge = request.COOKIES.get("ops_badge") or request.headers.get("x-ops-badge", "")
    if badge == "lead":
        return JsonResponse({"lane": "elevated", "payroll": "full"})
    return JsonResponse({"lane": "standard"})
""", "TRUST-PY-CLIENT-DECISION", True, "trust/cookie-gate")


def test_a_transport_header_comparison_is_not_a_gate() -> None:
    expect(clienttrust, """
def api(request):
    kind = request.headers.get("Content-Type", "")
    if kind == "application/json":
        return JsonResponse({"ok": True})
    return HttpResponse("use json", status=415)
""", "TRUST-PY-CLIENT-DECISION", False, "trust/content-type")


def test_a_verified_header_is_not_a_trusted_one() -> None:
    expect(clienttrust, """
import hmac

def webhook(request):
    signature = request.headers.get("x-signature", "")
    if not hmac.compare_digest(signature, expected(request.body)):
        return HttpResponse(status=403)
    mode = request.headers.get("x-mode", "")
    if mode == "admin":
        return JsonResponse({"scope": "all"})
    return JsonResponse({"scope": "one"})
""", "TRUST-PY-CLIENT-DECISION", False, "trust/verified")


# --------------------------------------------------------------------------- cleartext storage

def test_a_raw_secret_column_is_reported() -> None:
    expect(plaintext, """
class ContactInvite(models.Model):
    contact = models.ForeignKey(Contact, on_delete=models.CASCADE)
    webhook_secret = models.CharField(max_length=64, unique=True)
""", "PLAINTEXT-PY-STORAGE", True, "plaintext/raw-secret")


def test_a_password_column_is_not_claimed() -> None:
    expect(plaintext, """
class Account(models.Model):
    email = models.EmailField()
    password = models.CharField(max_length=128)
""", "PLAINTEXT-PY-STORAGE", False, "plaintext/password-column")


def test_a_name_that_says_it_is_protected_is_not_reported() -> None:
    expect(plaintext, """
class ApiClient(models.Model):
    api_key_hash = models.CharField(max_length=128)
    bank_account_last4 = models.CharField(max_length=4)
""", "PLAINTEXT-PY-STORAGE", False, "plaintext/protected-names")


# --------------------------------------------------------------------------- resource

def test_a_caller_sized_allocation_is_reported() -> None:
    expect(resource, """
@router.get("/spool")
async def spool_fan(count: int = 500):
    rows = [{"idx": idx} for idx in range(count)]
    return {"rows": rows}
""", "RESOURCE-PY-UNBOUNDED", True, "resource/unbounded")


def test_a_declared_bound_silences_it() -> None:
    expect(resource, """
@router.get("/spool")
async def spool_fan(count: int = Query(500, le=1000)):
    rows = [{"idx": idx} for idx in range(count)]
    return {"rows": rows}
""", "RESOURCE-PY-UNBOUNDED", False, "resource/declared-bound")


def test_a_clamp_in_the_body_silences_it() -> None:
    expect(resource, """
@router.get("/spool")
async def spool_fan(count: int = 500):
    rows = [{"idx": idx} for idx in range(min(count, 1000))]
    return {"rows": rows}
""", "RESOURCE-PY-UNBOUNDED", False, "resource/clamped")


# --------------------------------------------------------------------------- response exposure

def test_an_exception_in_the_response_is_reported() -> None:
    expect(exposure, """
@router.get("/pulse")
async def pulse(ref: str = "daily"):
    try:
        raise RuntimeError("pack " + ref + " failed")
    except Exception as exc:
        return JSONResponse({"detail": str(exc)}, status_code=500)
""", "EXPOSE-PY-EXCEPTION", True, "exposure/exception")


def test_a_class_name_alone_is_not_a_disclosure() -> None:
    expect(exposure, """
@router.get("/pulse")
async def pulse(ref: str = "daily"):
    try:
        raise RuntimeError("failed")
    except Exception as exc:
        return JSONResponse({"kind": exc.__class__.__name__}, status_code=500)
""", "EXPOSE-PY-EXCEPTION", False, "exposure/class-name-only")


def test_environment_values_in_a_response_are_reported() -> None:
    expect(exposure, """
@router.get("/trace")
async def trace_panel():
    return {"trace": True, "module": os.environ.get("APP_ENV")}
""", "EXPOSE-PY-INTERNALS", True, "exposure/environment")


def test_a_non_web_module_is_out_of_scope() -> None:
    expect(exposure, """
def load(path):
    try:
        return read(path)
    except OSError as exc:
        return f"could not read {path}: {exc}"
""", "EXPOSE-PY-EXCEPTION", False, "exposure/not-web", path="tool/loader.py")


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
    test_a_framework_login_with_no_project_limiter_is_reported()
    test_a_project_level_limiter_silences_the_url_conf()
    test_a_manifest_entry_alone_is_not_a_defence()
    test_a_word_that_merely_contains_a_marker_is_not_evidence()
    test_a_projects_own_login_view_class_is_not_the_frameworks()
    test_a_direct_class_import_is_recognised()
    test_a_module_without_urlpatterns_is_not_a_url_conf()
    test_an_unvalidated_upload_is_reported()
    test_an_extension_allowlist_silences_it()
    test_splitext_alone_is_not_validation()
    test_a_write_with_no_upload_is_not_an_upload_finding()
    test_a_spread_request_body_is_reported()
    test_a_dunder_dict_update_is_reported()
    test_named_fields_are_not_mass_assignment()
    test_a_declared_schema_is_the_allowlist()
    test_non_production_sources_are_out_of_scope()
    test_unparseable_and_unclaimed_languages_say_nothing()
    test_a_csv_export_of_data_is_reported()
    test_a_header_only_row_is_not_a_finding()
    test_a_neutralising_helper_silences_the_module()
    test_two_messages_naming_different_factors_are_reported()
    test_one_message_for_both_branches_is_silent()
    test_a_reset_flow_that_discloses_existence_is_reported()
    test_a_cookie_compared_to_a_literal_gate_is_reported()
    test_a_transport_header_comparison_is_not_a_gate()
    test_a_verified_header_is_not_a_trusted_one()
    test_a_raw_secret_column_is_reported()
    test_a_password_column_is_not_claimed()
    test_a_name_that_says_it_is_protected_is_not_reported()
    test_a_caller_sized_allocation_is_reported()
    test_a_declared_bound_silences_it()
    test_a_clamp_in_the_body_silences_it()
    test_an_exception_in_the_response_is_reported()
    test_a_class_name_alone_is_not_a_disclosure()
    test_environment_values_in_a_response_are_reported()
    test_a_non_web_module_is_out_of_scope()
    test_every_rule_contributes_its_own_limitations()

    if fails:
        print("STRUCTURAL TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("STRUCTURAL TESTS PASSED — nine rules asserted in both directions, including the "
          "app-level-limiter, splitext-is-not-validation, declared-schema, one-message-login, "
          "verified-header, protected-column-name and declared-bound shapes the external "
          "corpus decided.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
