#!/usr/bin/env python3
"""Authorization analysis tests — the two structural questions, and the traps that punish
answering them carelessly.

Every assertion here comes in pairs: a handler that MUST be reported and a handler that MUST
NOT. A rule about a missing check is only worth having if it is silent on code that has the
check, and the ways a real codebase spells "I checked" — a decorator, an injected dependency, a
helper call, a comparison anywhere in the body — are exactly what a naive version gets wrong.
Three of these cases are transcriptions of shapes that produced false positives on the external
corpus and were fixed; they are here so the fix cannot be undone silently.
"""
from __future__ import annotations

import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KIT)

from secaudit_core import structural                        # noqa: E402
from secaudit_core.structural import authz                  # noqa: E402

fails: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        fails.append(message)


def ids(code: str, path: str = "app/routes.py") -> set[str]:
    return {f.detector_id for f in authz.analyze_file(path, code)}


def expect(code: str, detector: str, present: bool, label: str) -> None:
    found = detector in ids(code)
    if found != present:
        fails.append(f"[{label}] expected {detector} {'present' if present else 'absent'}, "
                     f"got {sorted(ids(code)) or 'nothing'}")


# --------------------------------------------------------------------------- IDOR

def test_idor_reported_when_principal_is_ignored() -> None:
    """The canonical bug: authenticated, then looks the row up by the caller's number."""
    expect("""
from flask import request
@auth_bp.route('/api/update-password', methods=['POST'])
@token_required
def update_password(current_user):
    data = request.get_json()
    user_id = data.get('user_id')
    user = User.query.get(user_id)
    user.set_password(data.get('new_password'))
    db.session.commit()
""", "AUTHZ-PY-IDOR", True, "idor/principal-ignored")


def test_idor_reported_when_the_id_is_read_inline() -> None:
    """No intervening variable. The tersest form of the bug was the one form the rule missed,
    because it looked for locals bound to a request read and this shape never binds one."""
    expect("""
from flask import request
@app.route('/o', methods=['GET'])
@login_required
def o(current_user):
    return Order.query.get(request.args.get('order_id'))
""", "AUTHZ-PY-IDOR", True, "idor/inline-id")


def test_idor_silent_when_the_query_is_constrained() -> None:
    expect("""
from flask import request
@auth_bp.route('/api/order', methods=['GET'])
@login_required
def get_order(current_user):
    oid = request.args.get('order_id')
    order = Order.query.filter_by(id=oid, user_id=current_user.id).first()
    return jsonify(order.as_dict())
""", "AUTHZ-PY-IDOR", False, "idor/query-constrained")


def test_idor_silent_when_ownership_is_compared() -> None:
    expect("""
from flask import request
@auth_bp.route('/api/order', methods=['GET'])
@login_required
def get_order(current_user):
    oid = request.args.get('order_id')
    order = Order.query.get(oid)
    if order.user_id != current_user.id:
        abort(403)
    return jsonify(order.as_dict())
""", "AUTHZ-PY-IDOR", False, "idor/ownership-compared")


def test_idor_silent_when_the_check_is_delegated() -> None:
    """The fetch-then-authorize idiom. This shape produced 48 false positives on the external
    corpus in the first measured round — nearly all of them — because the check is a helper
    call rather than an inline comparison."""
    expect("""
@router.get("/{dispute_id}")
def get_dispute(dispute_id: int, db: Session = Depends(get_db),
                current_user: User = Depends(get_current_user)):
    dispute = db.get(Dispute, dispute_id)
    _require_view(current_user, dispute)
    return dispute
""", "AUTHZ-PY-IDOR", False, "idor/check-delegated")


def test_idor_silent_without_a_principal() -> None:
    """No authenticated caller means no ownership relation to violate — that is the missing
    authentication rule's question, not this one's."""
    expect("""
from flask import request
@app.route('/api/order', methods=['GET'])
def get_order():
    return Order.query.get(request.args.get('order_id'))
""", "AUTHZ-PY-IDOR", False, "idor/no-principal")


# ------------------------------------------------------------------ missing authentication

def test_missing_auth_reported_on_an_open_state_changing_route() -> None:
    expect("""
from flask import request
@app.route('/evaluate', methods=['POST'])
def evaluate():
    expression = request.form['expression']
    return str(eval(expression))
""", "AUTHZ-PY-NOAUTH", True, "noauth/open-post")


def test_missing_auth_silent_behind_a_decorator() -> None:
    expect("""
from flask import request
@app.route('/evaluate', methods=['POST'])
@login_required
def evaluate():
    return str(request.form['expression'])
""", "AUTHZ-PY-NOAUTH", False, "noauth/decorated")


def test_missing_auth_silent_behind_a_local_gate_helper() -> None:
    """The benchmark's 42 deliberate traps, in miniature. The handler carries no auth
    decorator; the gate is a small local helper that compares a header to an environment
    token. A rule that only looked at decorators would report every one of them."""
    expect("""
def _wrk_gate(request):
    gate_value = os.environ.get("INTERNAL_OPS_TOKEN")
    if request.headers.get("x-internal-token") != gate_value:
        raise HTTPException(status_code=403, detail="forbidden")

@app.route('/ops/export', methods=['POST'])
def export(request):
    _wrk_gate(request)
    return do_export(request.form['what'])
""", "AUTHZ-PY-NOAUTH", False, "noauth/local-gate-called")


def test_missing_auth_silent_when_the_gate_is_injected() -> None:
    """FastAPI wires the same gate as a parameter default. It is never called in the body, so
    following only call targets walked straight past it and reported the whole file."""
    expect("""
def _wrk_gate(request: Request) -> None:
    if request.headers.get("x-internal-token") != os.environ.get("INTERNAL_OPS_TOKEN"):
        raise HTTPException(status_code=403, detail="forbidden")

@router.post("/wire/tally")
async def tally(request: Request, gate_ref: None = Depends(_wrk_gate)):
    return {"body": await request.body()}
""", "AUTHZ-PY-NOAUTH", False, "noauth/gate-injected")


def test_missing_auth_silent_on_a_read_only_route() -> None:
    expect("""
from flask import request
@app.route('/search', methods=['GET'])
def search():
    return render(Item.query.filter_by(q=request.args.get('q')).all())
""", "AUTHZ-PY-NOAUTH", False, "noauth/read-only")


def test_missing_auth_silent_on_routes_public_by_design() -> None:
    for path, name in (("/login", "login"), ("/register", "register"), ("/health", "health")):
        expect(f"""
from flask import request
@app.route('{path}', methods=['POST'])
def {name}():
    return check_credentials(request.form['u'], request.form['p'])
""", "AUTHZ-PY-NOAUTH", False, f"noauth/public:{name}")


def test_a_django_view_is_not_public_just_because_its_path_lives_elsewhere() -> None:
    """A Django function view keeps its path in `urls.py`, so `_route_of` has none to record.

    That empty string used to be read as the site root by `Route.public_by_design`, which files
    a handler as deliberately unauthenticated — so every Django view in every codebase was
    exempt from this rule, and the exemption was invisible because it looked like a rule that
    simply found nothing. Measured on the external corpus when it was fixed: missing_auth 4 of
    74 to 7 of 74, with the labelled trap count unmoved at 248.
    """
    expect("""
def employee_create(request):
    if request.method == 'POST':
        employee = Employee.objects.create(name=request.POST['name'])
        return render(request, 'ok.html', {'e': employee})
    return render(request, 'form.html')
""", "AUTHZ-PY-NOAUTH", True, "noauth/django-path-in-urls")


def test_a_public_looking_django_view_is_still_exempt() -> None:
    """With no path to read, the handler's NAME is the only signal left — and it still counts.

    The fix above must not turn into "Django views are never public": `login` is exactly the
    handler this rule must stay quiet on, and it is the one whose report costs a reader's trust.
    """
    expect("""
def login(request):
    if request.method == 'POST':
        return check_credentials(request.POST['u'], request.POST['p'])
    return render(request, 'login.html')
""", "AUTHZ-PY-NOAUTH", False, "noauth/django-login-still-public")


def test_missing_auth_silent_when_the_session_carries_identity() -> None:
    expect("""
from flask import request, session
@app.route('/cart/checkout', methods=['POST'])
def checkout():
    uid = session['user_id']
    return place_order(uid, request.form['sku'])
""", "AUTHZ-PY-NOAUTH", False, "noauth/session-identity")


def test_a_non_identity_session_key_is_not_authentication() -> None:
    """`session["cart"]` authenticates nobody. Treating any session access as authorization
    would silence the rule on most of the code it exists for."""
    expect("""
from flask import request, session
@app.route('/cart/apply-discount', methods=['POST'])
def apply_discount():
    cart = session['cart']
    cart.discount = request.form['code']
    db.session.commit()
    return cart
""", "AUTHZ-PY-NOAUTH", True, "noauth/session-not-identity")


# --------------------------------------------------------------------------- robustness

def test_unparseable_and_non_python_files_say_nothing() -> None:
    check(authz.analyze_file("app/routes.py", "def broken(:\n") == [],
          "a file that does not parse produced findings")
    check(authz.analyze_file("app/routes.js", "app.post('/x', h)") == [],
          "a non-Python file was analysed")


def test_limitations_name_the_language() -> None:
    text = " ".join(structural.limitations())
    check("Python" in text, "limitations do not name the analysed language")
    check(bool(structural.EXTS), "structural.EXTS is empty — the matrix would claim nothing")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    test_idor_reported_when_principal_is_ignored()
    test_idor_reported_when_the_id_is_read_inline()
    test_idor_silent_when_the_query_is_constrained()
    test_idor_silent_when_ownership_is_compared()
    test_idor_silent_when_the_check_is_delegated()
    test_idor_silent_without_a_principal()
    test_missing_auth_reported_on_an_open_state_changing_route()
    test_missing_auth_silent_behind_a_decorator()
    test_missing_auth_silent_behind_a_local_gate_helper()
    test_missing_auth_silent_when_the_gate_is_injected()
    test_missing_auth_silent_on_a_read_only_route()
    test_missing_auth_silent_on_routes_public_by_design()
    test_a_django_view_is_not_public_just_because_its_path_lives_elsewhere()
    test_a_public_looking_django_view_is_still_exempt()
    test_missing_auth_silent_when_the_session_carries_identity()
    test_a_non_identity_session_key_is_not_authentication()
    test_unparseable_and_non_python_files_say_nothing()
    test_limitations_name_the_language()

    if fails:
        print("AUTHZ TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("AUTHZ TESTS PASSED — IDOR and missing-authentication asserted in both directions, "
          "including the delegated-check and injected-gate shapes that the external corpus "
          "punished.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
