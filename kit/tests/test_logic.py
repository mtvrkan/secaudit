#!/usr/bin/env python3
"""Handler-map tests — the scaffold the business-logic pass reasons over.

This map emits no finding, so nothing here is a precision or recall claim. What it *is* claiming
is narrower and checkable: that the fact which distinguishes a vulnerable handler from its
correct twin survives extraction. Every case below is a pair. If the map renders both halves
identically, then whatever reads it later is guessing, and it will guess on the safe one too —
which is how a pass that reports missing checks becomes a pass that reports handlers.

The four pairs are the four classes the pass claims: ownership, authorization, workflow order,
and a value the client chose. Three of the safe twins spell their check *indirectly* — through a
decorator, through an injected dependency, through a helper that receives the principal — because
those are the shapes that punished the structural rules on the external corpus, and a twin that
only checks inline proves nothing about the codebases that factored their checks out.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KIT)

from secaudit_core.structural import handlermap as hm                # noqa: E402

fails: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        fails.append(message)


def one(code: str, path: str = "app/routes.py") -> hm.HandlerFact:
    """The single handler in a snippet, or a loud failure if the snippet has none."""
    facts = hm.of_file(path, code)
    if len(facts) != 1:
        fails.append(f"expected exactly one handler in the snippet, got {len(facts)}")
        return hm.HandlerFact("", 0, 0, "", "", (), (), False, False, False, (), (), False,
                              (), (), (), (), ())
    return facts[0]


# ------------------------------------------------------------------ ownership (the IDOR pair)

IDOR_VULNERABLE = """
from flask import request
@app.route('/orders/<order_id>', methods=['POST'])
@token_required
def update_order(current_user, order_id):
    order = Order.query.get(order_id)
    order.note = request.get_json().get('note')
    db.session.commit()
"""

IDOR_SAFE_INLINE = """
from flask import request
@app.route('/orders/<order_id>', methods=['POST'])
@token_required
def update_order(current_user, order_id):
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()
    order.note = request.get_json().get('note')
    db.session.commit()
"""

IDOR_SAFE_DELEGATED = """
from flask import request
@app.route('/orders/<order_id>', methods=['POST'])
@token_required
def update_order(current_user, order_id):
    order = Order.query.get(order_id)
    _require_owner(current_user, order)
    order.note = request.get_json().get('note')
    db.session.commit()
"""


def test_ownership_pair_is_visible_in_the_map() -> None:
    """The whole ownership question, reduced to one boolean per data operation."""
    vulnerable = one(IDOR_VULNERABLE)
    check(vulnerable.principals == ("current_user",),
          f"vulnerable handler lost its principal: {vulnerable.principals}")
    check(bool(vulnerable.request_ids),
          "vulnerable handler lost the caller-supplied id")
    check(any(not op.constrained_by_principal for op in vulnerable.ops),
          "the unconstrained lookup did not survive extraction — the IDOR pair is now identical")

    for label, code in (("inline filter", IDOR_SAFE_INLINE),
                        ("delegated check", IDOR_SAFE_DELEGATED)):
        safe = one(code)
        check(bool(safe.ops), f"[{label}] the safe twin has no data operation to judge")
        check(all(op.constrained_by_principal for op in safe.ops),
              f"[{label}] the safe twin reads as unconstrained — the map would report it")


# ------------------------------------------------------------ authorization (the missing-auth pair)

NOAUTH_VULNERABLE = """
from flask import request
@app.route('/admin/promote', methods=['POST'])
def promote():
    User.query.get(request.form['user_id']).role = 'admin'
    db.session.commit()
"""

NOAUTH_SAFE_DECORATOR = """
from flask import request
@app.route('/admin/promote', methods=['POST'])
@admin_required
def promote():
    User.query.get(request.form['user_id']).role = 'admin'
    db.session.commit()
"""

NOAUTH_SAFE_INJECTED = """
from fastapi import Depends
def _admin_gate(token: str):
    if token != os.environ['ADMIN_TOKEN']:
        raise HTTPException(status_code=403)

@router.post('/admin/promote')
def promote(payload: dict, gate: None = Depends(_admin_gate)):
    User.query.get(payload['user_id']).role = 'admin'
    db.session.commit()
"""

NOAUTH_SAFE_HELPER = """
from flask import request
def _check_token():
    if request.headers.get('X-Token') != os.environ['ADMIN_TOKEN']:
        abort(403)

@app.route('/admin/promote', methods=['POST'])
def promote():
    _check_token()
    User.query.get(request.form['user_id']).role = 'admin'
    db.session.commit()
"""


def test_authorization_pair_is_visible_in_the_map() -> None:
    vulnerable = one(NOAUTH_VULNERABLE)
    check(vulnerable.state_changing and not vulnerable.public_by_design,
          "the unauthenticated handler no longer reads as a state-changing, non-public route")
    check(not vulnerable.auth_evidence,
          "the unauthenticated handler reads as authorized — nothing would be asked about it")

    for label, code in (("decorator", NOAUTH_SAFE_DECORATOR),
                        ("injected dependency", NOAUTH_SAFE_INJECTED),
                        ("module-local helper", NOAUTH_SAFE_HELPER)):
        safe = one(code)
        check(safe.auth_evidence,
              f"[{label}] the safe twin reads as unauthenticated — the map would report it")


def test_a_login_route_is_marked_public_by_design() -> None:
    """No amount of recall is worth reporting missing authentication on the login endpoint."""
    fact = one("""
from flask import request
@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(email=request.form['email']).first()
    return check_password(user, request.form['password'])
""")
    check(fact.public_by_design, "the login route lost its public-by-design marking")


# ------------------------------------------------------------------- workflow (the state pair)

WORKFLOW_VULNERABLE = """
from flask import request
@app.route('/orders/<order_id>/ship', methods=['POST'])
@token_required
def ship(current_user, order_id):
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()
    order.status = 'shipped'
    db.session.commit()
"""

WORKFLOW_SAFE = """
from flask import request
@app.route('/orders/<order_id>/ship', methods=['POST'])
@token_required
def ship(current_user, order_id):
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()
    if order.status != 'paid':
        abort(409)
    order.status = 'shipped'
    db.session.commit()
"""


def test_workflow_pair_separates_the_transition_from_its_guard() -> None:
    """`state_writes` and `state_checks` are split for exactly this pair: merged into one
    `state_keys` field, the guarded transition and the unguarded one render identically."""
    vulnerable = one(WORKFLOW_VULNERABLE)
    check("status" in vulnerable.state_writes,
          f"the transition did not survive extraction: {vulnerable.state_writes}")
    check(not vulnerable.state_checks,
          f"the unguarded transition claims a guard: {vulnerable.state_checks}")

    safe = one(WORKFLOW_SAFE)
    check("status" in safe.state_writes, "the safe twin lost its transition")
    check("status" in safe.state_checks,
          f"the guard in front of the transition was not extracted: {safe.state_checks}")


# --------------------------------------------------------------- client trust (the money pair)

MONEY_VULNERABLE = """
from flask import request
@app.route('/checkout', methods=['POST'])
@token_required
def checkout(current_user):
    body = request.get_json()
    Charge.create(user_id=current_user.id, amount=body['price'] * body['quantity'])
"""

MONEY_SAFE = """
from flask import request
@app.route('/checkout', methods=['POST'])
@token_required
def checkout(current_user):
    body = request.get_json()
    item = Item.query.filter_by(id=body['item_id']).first()
    Charge.create(user_id=current_user.id, amount=item.price * body['quantity'])
"""


def test_money_pair_shows_which_side_the_price_came_from() -> None:
    vulnerable = one(MONEY_VULNERABLE)
    check("price" in vulnerable.money_from_request,
          f"the client-supplied price did not survive extraction: {vulnerable.money_from_request}")

    safe = one(MONEY_SAFE)
    check("price" not in safe.money_from_request,
          f"the server-computed price reads as client-supplied: {safe.money_from_request}")


# ----------------------------------------------------------------------------- the map itself

CORPUS = {
    "app/orders.py": IDOR_VULNERABLE,
    "app/admin.py": NOAUTH_VULNERABLE,
    "app/checkout.py": MONEY_VULNERABLE,
    "app/ship.py": WORKFLOW_SAFE,
}


def test_the_rendered_map_is_identical_across_walk_orders() -> None:
    """Tier 0's determinism bug was a file-walk order changing which findings appeared. The map
    feeds a prompt rather than a report, which makes the same bug quieter and not smaller: two
    scans of one repository would send two different payloads and get two different answers."""
    corpus = dict(CORPUS, **{"app/zz_broken.py": "def a(:\n", "app/aa_broken.py": "def b(:\n"})
    orders = [list(corpus), list(reversed(list(corpus))),
              sorted(corpus), sorted(corpus, key=len)]
    built = [hm.build({k: corpus[k] for k in order}) for order in orders]

    rendered = {hm.render(m, 100_000).text for m in built}
    check(len(rendered) == 1,
          f"four walk orders produced {len(rendered)} different payloads")

    # The gap list is walked in iteration order and normalised nowhere else, so it is the half of
    # the map that a walk order can still reorder. Two unparseable files, because one cannot be
    # in the wrong order and a single-element list is how this assertion passes vacuously.
    check(len({m.files_unparsed for m in built}) == 1,
          f"the unparseable-file list is walk-order dependent: {[m.files_unparsed for m in built]}")


def test_the_map_ranks_the_two_target_shapes_first() -> None:
    """Ranking is what survives truncation, so it is the ranking that decides what a large
    repository gets asked about."""
    rendered = hm.render(hm.build(CORPUS), 100_000)
    body = [json.loads(line) for line in rendered.text.splitlines()[1:]]
    leading = {row["handler"] for row in body[:3]}
    check("promote" in leading, "the unauthenticated handler did not rank in the first three")
    check("update_order" in leading, "the unconstrained lookup did not rank in the first three")


def test_truncation_is_counted_rather_than_silent() -> None:
    """A payload that quietly dropped half its handlers reads to a model exactly like a codebase
    that has none."""
    full = hm.render(hm.build(CORPUS), 100_000)
    check(full.omitted == 0 and full.included == 4,
          f"the unbudgeted render is already lossy: {full.included} in, {full.omitted} out")

    tight = hm.render(hm.build(CORPUS), 1_200)
    check(tight.omitted > 0, "a 1200-character budget dropped nothing — the budget is not applied")
    check(tight.included + tight.omitted == 4,
          f"handlers vanished from the accounting: {tight.included} + {tight.omitted} != 4")
    check(tight.text.splitlines()[0].startswith('{"files_scanned"'),
          "truncation ate the header, which carries the map's own bounds")


def test_the_map_states_what_it_could_not_read() -> None:
    """An unparseable file is a gap, and a gap that is not named is indistinguishable from a
    file with no handlers in it."""
    built = hm.build({"app/ok.py": IDOR_VULNERABLE, "app/broken.py": "def handler(:\n"})
    check(built.files_unparsed == ("app/broken.py",),
          f"the unparseable file was not reported: {built.files_unparsed}")
    check(len(built.handlers) == 1, "the parseable half of the corpus was lost with the other")


def test_non_python_and_non_production_sources_are_out_of_scope() -> None:
    check(hm.of_file("app/routes.js", "app.post('/x', (req, res) => res.send(1))") == [],
          "a JavaScript source produced Python handler facts")
    check(hm.of_file("app/tests/test_routes.py", IDOR_VULNERABLE) == [],
          "a test module was mapped as if it served traffic")
    check(hm.build({"app/tests/test_routes.py": IDOR_VULNERABLE}).files_scanned == 0,
          "a test module was counted as scanned")


def test_the_handler_span_is_real_and_bounded() -> None:
    """The span is what a citation has to land inside, so an off-by-a-function span is the
    difference between grounding a finding and waving at the right file."""
    fact = one(IDOR_VULNERABLE)
    check(fact.end_line > fact.line, f"span is empty: {fact.line}..{fact.end_line}")
    check(fact.contains(fact.line) and fact.contains(fact.end_line),
          "the span excludes its own endpoints")
    check(not fact.contains(fact.line - 1) and not fact.contains(fact.end_line + 1),
          "the span leaks past the handler")


# ------------------------------------------------------- the map on its way to the model

def _tree(files: dict) -> str:
    """A throwaway source tree, because the context builder reads from disk by design."""
    root = tempfile.mkdtemp(prefix="secaudit-logic-")
    for rel, text in files.items():
        path = os.path.join(root, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return root


def _context(files: dict):
    from secaudit_core import llmcontext
    from secaudit_core.schema import ScanResult
    root = _tree(files)
    try:
        return llmcontext.build(ScanResult(target=root), root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_the_map_reaches_the_context_and_the_note_says_so() -> None:
    ctx = _context(CORPUS)
    check(ctx.handler_count == 4, f"the map lost handlers on the way to the model: "
                                  f"{ctx.handler_count}")
    check("update_order" in ctx.handler_map, "the rendered map is not in the context")
    check(f"map of {ctx.handler_count} request handler(s)" in ctx.note(),
          f"note() does not state the map it sent: {ctx.note()}")


def test_the_note_states_handlers_the_map_budget_dropped() -> None:
    """A payload that quietly described three of a repository's forty handlers, and a payload
    that described all three of them, must not produce the same sentence."""
    from secaudit_core import llmcontext
    original = llmcontext.MAP_BUDGET_CHARS
    try:
        llmcontext.MAP_BUDGET_CHARS = 1_200
        ctx = _context(CORPUS)
    finally:
        llmcontext.MAP_BUDGET_CHARS = original
    check(ctx.handlers_omitted > 0, "a 1200-character map budget dropped nothing")
    check("did not fit the map budget" in ctx.note(),
          f"note() hid the handlers it dropped: {ctx.note()}")


def test_the_reserved_call_is_taken_from_inside_the_ceiling_and_disclosed() -> None:
    """MAX_CHUNKS is quoted as a cost ceiling — four model calls per scan, whatever the
    repository. The business-logic call comes out of that four, and the breadth it costs is
    stated rather than absorbed."""
    from secaudit_core import llmcontext
    budget, ceiling = llmcontext.CHUNK_BUDGET_CHARS, llmcontext.MAX_CHUNKS
    try:
        llmcontext.CHUNK_BUDGET_CHARS, llmcontext.MAX_CHUNKS = 400, 2
        ctx = _context(dict(CORPUS, **{f"app/extra{i}.py": IDOR_VULNERABLE for i in range(8)}))
    finally:
        llmcontext.CHUNK_BUDGET_CHARS, llmcontext.MAX_CHUNKS = budget, ceiling

    check(len(ctx.chunks) + llmcontext.LOGIC_CALLS <= 2,
          f"the scan would make {len(ctx.chunks)} + 1 calls against a ceiling of 2")
    check(ctx.triage_calls_reduced, "the reservation cost a triage call and was not recorded")
    check("One model call was reserved" in ctx.note(),
          f"note() absorbed the narrowed triage instead of stating it: {ctx.note()}")


def test_the_map_budget_leaves_room_for_the_code_beside_it() -> None:
    """The business-logic call carries the map *and* a chunk of source. Both come out of one
    call's budget, so a map budget that is not comfortably inside the chunk budget is a payload
    the backend rejects — and it would be rejected only on the large repositories nobody tests
    against. The relation between the two constants is the invariant, not either number."""
    from secaudit_core import llmcontext
    check(llmcontext.MAP_BUDGET_CHARS < llmcontext.CHUNK_BUDGET_CHARS // 2,
          f"the map budget ({llmcontext.MAP_BUDGET_CHARS:,}) leaves too little of the call "
          f"budget ({llmcontext.CHUNK_BUDGET_CHARS:,}) for the source beside it")
    check(llmcontext.LOGIC_CALLS < llmcontext.MAX_CHUNKS,
          "the reserved call consumes the entire call ceiling, leaving no triage at all")


def test_credential_files_never_reach_the_map() -> None:
    """The map is derived from source the context read, so the withholding policy has to hold
    for it too — otherwise the one payload that is not code becomes the exfiltration path."""
    ctx = _context(dict(CORPUS, **{"secrets/prod.py": NOAUTH_VULNERABLE}))
    check("secrets/prod.py" not in ctx.handler_map,
          "a credential-shaped source file was described in the handler map")
    check(any("prod.py" in w for w in ctx.secret_files_withheld),
          f"the credential file was not withheld at all: {ctx.secret_files_withheld}")


# ------------------------------------------------------------------------ the logic channel

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "llm-logic-response.json")

# Deliberately half and half. `orders.py` and `admin.py` are handlers Tier 0 already reports, so
# the recorded reply naming them must be refused as restatements; `checkout.py` and `ship.py`
# carry the two classes the deterministic tier has no rule for, which is the only place this
# pass can add anything. A corpus of only the second kind would never exercise the suppression,
# and a corpus of only the first would never show the pass doing its job.
LOGIC_CORPUS = {
    "app/orders.py": IDOR_VULNERABLE,
    "app/admin.py": NOAUTH_VULNERABLE,
    "app/checkout.py": MONEY_VULNERABLE,
    "app/ship.py": WORKFLOW_VULNERABLE,
}


def _enriched(files: dict | None = None):
    """A real Tier-0 scan of a throwaway tree, enriched from the recorded reply."""
    from secaudit_core import backends, engine
    root = _tree(files or LOGIC_CORPUS)
    try:
        result = engine.scan(root, run_deps=False, use_scanners=False)
        return backends.ReplayBackend(FIXTURE).enrich(result)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _logic(result) -> dict:
    return {f.detector_id: f for f in result.findings if f.source == "llm-logic"}


def test_the_logic_channel_merges_what_it_can_tie_to_a_handler() -> None:
    """The two merged findings are both in classes Tier 0 has no rule for. That is the claim
    this whole pass rests on, and it is the one assertion here that would still matter if every
    other line of the suite were deleted."""
    merged = _logic(_enriched())
    check("LOGIC-WORKFLOW" in merged,
          f"the workflow-skip finding was not merged: {sorted(merged)}")
    check("LOGIC-CLIENTTRUST" in merged,
          f"the client-trust finding was not merged: {sorted(merged)}")
    workflow = merged.get("LOGIC-WORKFLOW")
    if workflow:
        check((workflow.file, workflow.line) == ("app/ship.py", 7),
              f"the finding landed at {workflow.file}:{workflow.line}, not where it was cited")
        check(workflow.cwe == "CWE-841" and workflow.owasp == "A04",
              f"the class was not mapped to its own weakness: {workflow.cwe}/{workflow.owasp}")
        check(workflow.verdict.value == "plausible" and workflow.confidence.value == "medium",
              "a model claim was merged as something firmer than plausible/medium")
        check("ship" in workflow.evidence,
              f"the finding does not name the handler it was adjudicated on: {workflow.evidence}")


def test_a_model_claim_cannot_outrank_a_proven_finding() -> None:
    """The reply asks for Critical. HIGH confidence and Critical severity are what the engine
    reserves for things it can prove; an unverified claim printed above them re-sorts the whole
    report around a sentence nobody has checked."""
    merged = _logic(_enriched())
    clienttrust = merged.get("LOGIC-CLIENTTRUST")
    if clienttrust:
        check(clienttrust.severity.value == "High",
              f"a Critical model claim was merged unclamped: {clienttrust.severity.value}")


def test_every_refusal_fires_and_says_so() -> None:
    """Four items in the reply are wrong in four different ways. Each must be refused, and each
    refusal must reach `notes` — a filtered register is not evidence anywhere else here either."""
    result = _enriched()
    merged = _logic(result)
    notes = " ".join(result.notes)

    check("LOGIC-AUTHZ" not in merged and "LOGIC-IDOR" not in merged,
          f"the pass restated weaknesses Tier 0 had already reported: {sorted(merged)}")
    check("2 business-logic finding(s) restated a weakness Tier 0 had already reported" in notes,
          f"the restatement was dropped in silence: {notes[-400:]}")
    check("named a class the pass does not define" in notes,
          "an undefined class was dropped without a word")
    check("cited a file that was not in the context sent" in notes,
          "an ungrounded citation was dropped without a word")
    check("cited a line outside every handler in the map" in notes,
          "a citation outside every handler span was dropped without a word")
    check(len(merged) == 2, f"expected exactly two merged logic findings, got {sorted(merged)}")


def test_an_undefined_class_is_never_stamped_with_a_fallback_weakness() -> None:
    """`LLM-LOGIC` stamped CWE-284 on whatever came back. A compliance section that describes a
    weakness nobody found is worse than one that omits it."""
    result = _enriched()
    stamped = [f for f in result.findings
               if f.source == "llm-logic" and f.cwe not in
               {c.cwe for c in __import__("secaudit_core.backends", fromlist=["x"])
                .LOGIC_CLASSES.values()}]
    check(not stamped, f"a logic finding carries a weakness outside the class table: {stamped}")


def test_one_flaw_seen_from_two_calls_is_merged_once_and_not_miscounted() -> None:
    """A repository-wide flaw is visible from more than one call, and the channel appends.

    The second assertion is the one that took a mutation to find: collapsing a duplicate and
    refusing a Tier-0 restatement are the same collision and NOT the same event. Counting the
    pass's own repetitions as restatements inflates the refusal figure with noise the reader
    cannot act on — and the figure exists precisely so that it can be acted on."""
    from secaudit_core import backends
    result = _enriched()
    before = len(_logic(result))
    backend = backends.ReplayBackend(FIXTURE)
    with open(FIXTURE, encoding="utf-8") as fh:
        data = json.load(fh)
    facts = list(hm.build(LOGIC_CORPUS).handlers)
    backend._apply_logic(result, data, set(LOGIC_CORPUS), facts)

    check(len(_logic(result)) == before,
          f"replaying the same reply grew the report from {before} to {len(_logic(result))}")
    restatements = [n for n in result.notes if "restated a weakness Tier 0" in n]
    check(len(restatements) == 2 and all(n.startswith("2 ") for n in restatements),
          f"the pass counted its own repeats as Tier-0 restatements: {restatements}")


def test_discovered_findings_do_not_multiply_across_chunks() -> None:
    """The same bug for the `extra` channel, which had no dedup of any kind."""
    from secaudit_core import llmcontext
    budget = llmcontext.CHUNK_BUDGET_CHARS
    try:
        llmcontext.CHUNK_BUDGET_CHARS = 400
        result = _enriched(dict(CORPUS, **{f"app/more{i}.py": IDOR_VULNERABLE
                                           for i in range(4)}))
    finally:
        llmcontext.CHUNK_BUDGET_CHARS = budget
    discovered = [f for f in result.findings if f.detector_id == "LLM-LOGIC"]
    check(len(discovered) <= 1,
          f"one discovered flaw was merged {len(discovered)} times, once per model call")


def main() -> int:
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    for failure in fails:
        print(f"FAIL {failure}")
    print(f"{'FAIL' if fails else 'PASS'}  handler map: "
          f"{len([n for n in globals() if n.startswith('test_')])} cases, {len(fails)} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
