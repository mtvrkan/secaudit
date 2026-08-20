#!/usr/bin/env python3
"""The four structural questions asked of JavaScript and TypeScript.

Same discipline as `test_structural.py` and `test_authz.py`: every rule asserted in BOTH
directions. A rule that reports a missing check is worth having only if it stays silent on the
code that has one — and on this side that matters more, not less, because there is no external
corpus keeping it honest. RealVuln v1 is Python-only, so these cases are the whole of what stops
the JavaScript rules from drifting into noise.

The negative cases are therefore the point of this file. Each one is an idiom a real Express,
NestJS or Next.js codebase uses to do the right thing — auth middleware in the mount, an
ownership check delegated to a helper, a schema parse, a `fileFilter`, a destructured body — and
each one must produce nothing.
"""
from __future__ import annotations

import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(KIT)
sys.path.insert(0, KIT)

from secaudit_core import structural                    # noqa: E402
from secaudit_core.structural import js                 # noqa: E402
from secaudit_core.structural import protopollution     # noqa: E402

fails: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        fails.append(message)


def expect(code: str, detector: str, present: bool, label: str,
           path: str = "src/routes/users.js") -> None:
    ids = {f.detector_id for f in js.analyze_file(path, code)}
    if (detector in ids) != present:
        fails.append(f"[{label}] expected {detector} {'present' if present else 'absent'}, "
                     f"got {sorted(ids) or 'nothing'}")


# ------------------------------------------------------------------- missing authentication

def test_a_state_changing_route_with_no_caller_is_reported() -> None:
    expect("""
const express = require('express');
const router = express.Router();

router.post('/users/:id/promote', async (req, res) => {
  await db.user.update({ where: { id: req.params.id }, data: { role: 'admin' } });
  res.json({ ok: true });
});
""", "AUTHZ-JS-NOAUTH", True, "no auth anywhere")


def test_auth_middleware_in_the_mount_silences_it() -> None:
    """The whole reason the mount is read: a protected handler never mentions authentication."""
    expect("""
router.post('/users/:id/promote', requireAuth, async (req, res) => {
  await db.user.update({ where: { id: req.params.id }, data: { role: 'admin' } });
  res.json({ ok: true });
});
""", "AUTHZ-JS-NOAUTH", False, "requireAuth in the mount")


def test_a_module_local_guard_is_followed() -> None:
    """Named, never called at the mount — the shape that punishes a rule reading only the body."""
    expect("""
function ensureSession(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'unauthorized' });
  next();
}

router.delete('/posts/:id', ensureSession, async (req, res) => {
  await db.post.delete({ where: { id: req.params.id } });
  res.status(204).end();
});
""", "AUTHZ-JS-NOAUTH", False, "guard resolved through a module-local helper")


def test_a_read_only_route_is_not_reported() -> None:
    expect("""
router.get('/posts/:id', async (req, res) => {
  res.json(await db.post.findUnique({ where: { id: req.params.id } }));
});
""", "AUTHZ-JS-NOAUTH", False, "GET is not state-changing")


def test_login_is_public_by_design() -> None:
    expect("""
router.post('/auth/login', async (req, res) => {
  const user = await db.user.findUnique({ where: { email: req.body.email } });
  res.json({ token: sign(user) });
});
""", "AUTHZ-JS-NOAUTH", False, "login must never be reported as missing auth")


def test_nest_useguards_counts() -> None:
    expect("""
@Controller('orders')
export class OrdersController {
  @UseGuards(AuthGuard)
  @Post(':id/cancel')
  async cancel(@Param('id') id: string) {
    return this.orders.cancel(id);
  }
}
""", "AUTHZ-JS-NOAUTH", False, "NestJS @UseGuards", path="src/orders.controller.ts")


def test_an_unguarded_nest_route_is_reported() -> None:
    expect("""
@Controller('orders')
export class OrdersController {
  @Delete(':id')
  async remove(@Param('id') id: string) {
    return this.orders.remove(id);
  }
}
""", "AUTHZ-JS-NOAUTH", True, "NestJS with no guard", path="src/orders.controller.ts")


# ----------------------------------------------------------------------------------- IDOR

def test_a_caller_id_selected_without_the_principal_is_reported() -> None:
    expect("""
router.get('/orders/:orderId', requireAuth, async (req, res) => {
  const order = await prisma.order.findUnique({ where: { id: req.params.orderId } });
  res.json(order);
});
""", "AUTHZ-JS-IDOR", True, "authenticated, then unscoped lookup")


def test_a_query_scoped_by_the_principal_is_silent() -> None:
    expect("""
router.get('/orders/:orderId', requireAuth, async (req, res) => {
  const order = await prisma.order.findFirst({
    where: { id: req.params.orderId, userId: req.user.id },
  });
  res.json(order);
});
""", "AUTHZ-JS-IDOR", False, "query scoped by req.user.id")


def test_an_ownership_comparison_is_silent() -> None:
    """Fetch-then-authorize is correct, and was the largest false-positive shape on the Python
    side. It must not become one here."""
    expect("""
router.get('/orders/:orderId', requireAuth, async (req, res) => {
  const order = await prisma.order.findUnique({ where: { id: req.params.orderId } });
  if (order.userId !== req.user.id) return res.status(403).end();
  res.json(order);
});
""", "AUTHZ-JS-IDOR", False, "ownership compared after the fetch")


def test_an_unauthenticated_route_is_not_an_idor() -> None:
    """No principal means nothing to ignore. That handler's problem is missing auth, and
    reporting both would be reporting one bug twice."""
    expect("""
router.get('/orders/:orderId', async (req, res) => {
  res.json(await prisma.order.findUnique({ where: { id: req.params.orderId } }));
});
""", "AUTHZ-JS-IDOR", False, "no principal to ignore")


# ---------------------------------------------------------------------------- rate limiting

def test_an_unbounded_login_is_reported() -> None:
    expect("""
router.post('/login', async (req, res) => {
  const user = await db.user.findUnique({ where: { email: req.body.email } });
  if (!user || !(await bcrypt.compare(req.body.password, user.hash))) {
    return res.status(401).json({ error: 'bad credentials' });
  }
  res.json({ token: sign(user) });
});
""", "RATELIMIT-JS-AUTH", True, "credential check with nothing bounding it")


def test_a_limiter_in_the_mount_silences_it() -> None:
    expect("""
router.post('/login', loginLimiter, async (req, res) => {
  const user = await db.user.findUnique({ where: { email: req.body.email } });
  if (!user || !(await bcrypt.compare(req.body.password, user.hash))) {
    return res.status(401).json({ error: 'bad credentials' });
  }
  res.json({ token: sign(user) });
});
""", "RATELIMIT-JS-AUTH", False, "limiter middleware in the mount")


def test_an_app_wide_limiter_at_module_scope_counts() -> None:
    """A limiter installed as middleware protects handlers that never mention it."""
    expect("""
const rateLimit = require('express-rate-limit');
app.use(rateLimit({ windowMs: 60000, max: 10 }));

router.post('/login', async (req, res) => {
  const user = await db.user.findUnique({ where: { email: req.body.email } });
  if (!user || !(await bcrypt.compare(req.body.password, user.hash))) {
    return res.status(401).json({ error: 'bad credentials' });
  }
  res.json({ token: sign(user) });
});
""", "RATELIMIT-JS-AUTH", False, "app-level limiter at module scope")


def test_recording_an_attempt_is_not_bounding_one() -> None:
    """The Python rule's sharpest correction, transcribed. Writing the break-in down is what an
    unprotected endpoint does INSTEAD of bounding it."""
    expect("""
router.post('/login', async (req, res) => {
  const user = await db.user.findUnique({ where: { email: req.body.email } });
  if (!user || !(await bcrypt.compare(req.body.password, user.hash))) {
    logger.warn('failed login attempt for ' + req.body.email);
    return res.status(401).json({ error: 'bad credentials' });
  }
  res.json({ token: sign(user) });
});
""", "RATELIMIT-JS-AUTH", True, "logging an attempt is not a limit")


def test_an_attempt_count_compared_against_a_maximum_is_a_limit() -> None:
    expect("""
router.post('/login', async (req, res) => {
  const attempts = await cache.get('login:' + req.body.email);
  if (attempts > 5) return res.status(429).json({ error: 'too many attempts' });
  const user = await db.user.findUnique({ where: { email: req.body.email } });
  if (!user || !(await bcrypt.compare(req.body.password, user.hash))) {
    return res.status(401).end();
  }
  res.json({ token: sign(user) });
});
""", "RATELIMIT-JS-AUTH", False, "attempts compared against a maximum")


def test_a_route_that_tests_no_credential_is_not_reported() -> None:
    expect("""
router.post('/session/refresh', requireAuth, async (req, res) => {
  res.json({ token: rotate(req.user) });
});
""", "RATELIMIT-JS-AUTH", False, "no credential check happens here")


# --------------------------------------------------------------------------------- uploads

def test_an_unchecked_upload_is_reported() -> None:
    expect("""
router.post('/avatar', requireAuth, upload.single('avatar'), async (req, res) => {
  fs.writeFileSync(path.join('/var/www/uploads', req.file.originalname), req.file.buffer);
  res.json({ ok: true });
});
""", "UPLOAD-JS-UNRESTRICTED", True, "read and written with nothing between")


def test_a_mimetype_check_silences_it() -> None:
    expect("""
router.post('/avatar', requireAuth, upload.single('avatar'), async (req, res) => {
  if (!['image/png', 'image/jpeg'].includes(req.file.mimetype)) {
    return res.status(400).json({ error: 'unsupported type' });
  }
  fs.writeFileSync(path.join('/var/www/uploads', crypto.randomUUID()), req.file.buffer);
  res.json({ ok: true });
});
""", "UPLOAD-JS-UNRESTRICTED", False, "mimetype allowlist present")


def test_a_module_local_validator_is_followed() -> None:
    expect("""
function assertImage(file) {
  if (!ALLOWED_EXTENSIONS.has(extname(file.originalname))) throw new Error('bad type');
}

router.post('/avatar', requireAuth, upload.single('avatar'), async (req, res) => {
  assertImage(req.file);
  fs.writeFileSync(path.join('/var/www/uploads', crypto.randomUUID()), req.file.buffer);
  res.json({ ok: true });
});
""", "UPLOAD-JS-UNRESTRICTED", False, "validator resolved through a helper")


# -------------------------------------------------------------------------- mass assignment

def test_the_whole_body_handed_to_a_write_is_reported() -> None:
    expect("""
router.post('/users', requireAuth, async (req, res) => {
  const user = await prisma.user.create({ data: req.body });
  res.status(201).json(user);
});
""", "MASSASSIGN-JS", True, "req.body straight into create")


def test_named_fields_are_not_mass_assignment() -> None:
    expect("""
router.post('/users', requireAuth, async (req, res) => {
  const { email, name } = req.body;
  const user = await prisma.user.create({ data: { email, name } });
  res.status(201).json(user);
});
""", "MASSASSIGN-JS", False, "body destructured to named fields")


def test_a_destructure_elsewhere_does_not_excuse_a_wholesale_write() -> None:
    """Pulling two fields out and then writing everything is the bug, not the fix.

    An exemption for `const { … } = req.body` was written into this rule, survived a mutation
    run without changing a single test — the signature of a branch that decides nothing — and
    turned out to decide exactly one case, wrongly: this one. Same shape as a limiter anywhere
    in a file counting as protection everywhere in it.
    """
    expect("""
router.post('/users', requireAuth, async (req, res) => {
  const { email, name } = req.body;
  logger.info('creating ' + email + ' ' + name);
  const user = await prisma.user.create({ data: req.body });
  res.status(201).json(user);
});
""", "MASSASSIGN-JS", True, "destructure above, whole body still written")


def test_a_schema_parse_is_the_allowlist() -> None:
    expect("""
const CreateUser = z.object({ email: z.string().email(), name: z.string() }).strict();

router.post('/users', requireAuth, async (req, res) => {
  const data = CreateUser.parse(req.body);
  const user = await prisma.user.create({ data });
  res.status(201).json(user);
});
""", "MASSASSIGN-JS", False, "zod schema parses the body")


# ---------------------------------------------------------------------------------- Next.js

def test_an_app_router_write_with_no_session_is_reported() -> None:
    """`export async function POST` in a `route.ts` — the App Router's whole mounting mechanism.
    Nothing exercised this branch until coverage said so."""
    expect("""
import { prisma } from '@/lib/db';

export async function POST(request: Request) {
  const body = await request.json();
  await prisma.invoice.update({ where: { id: body.invoiceId }, data: { paid: true } });
  return Response.json({ ok: true });
}
""", "AUTHZ-JS-NOAUTH", True, "App Router POST with no session",
        path="app/api/invoices/route.ts")


def test_an_app_router_route_with_a_session_is_silent() -> None:
    expect("""
import { getServerSession } from 'next-auth';

export async function POST(request: Request) {
  const session = await getServerSession(authOptions);
  if (!session) return new Response('unauthorized', { status: 401 });
  const body = await request.json();
  await prisma.invoice.update({
    where: { id: body.invoiceId, userId: session.user.id }, data: { paid: true },
  });
  return Response.json({ ok: true });
}
""", "AUTHZ-JS-NOAUTH", False, "App Router POST behind getServerSession",
        path="app/api/invoices/route.ts")


def test_a_pages_api_handler_is_read_by_the_method_it_branches_on() -> None:
    """A Pages API export serves every verb, so the verb comes from what the body branches on."""
    expect("""
export default async function handler(req, res) {
  if (req.method === 'DELETE') {
    await prisma.comment.delete({ where: { id: req.query.commentId } });
    return res.status(204).end();
  }
  res.status(405).end();
}
""", "AUTHZ-JS-NOAUTH", True, "Pages API branching on DELETE",
        path="pages/api/comments.js")


def test_a_read_only_pages_api_handler_is_not_reported() -> None:
    expect("""
export default async function handler(req, res) {
  const posts = await prisma.post.findMany({ where: { published: true } });
  res.json(posts);
}
""", "AUTHZ-JS-NOAUTH", False, "Pages API that only reads", path="pages/api/posts.js")


# ------------------------------------------------------------------------------- the bounds

def test_non_production_sources_are_out_of_scope() -> None:
    code = """
router.post('/users/:id/promote', async (req, res) => {
  await db.user.update({ where: { id: req.params.id }, data: { role: 'admin' } });
});
"""
    for path in ("src/routes/users.test.js", "src/routes/__tests__/users.js",
                 "cypress/e2e/users.cy.ts", "src/routes/users.spec.ts"):
        got = js.analyze_file(path, code)
        check(not got, f"[scope] {path} is not a deployed handler; got {[f.detector_id for f in got]}")


def test_a_method_call_that_is_not_a_route_is_not_a_route() -> None:
    """The string-literal-path anchor, which is the file's main precision decision."""
    for code in ("const v = cache.get('user:1');\nawait store.delete('key');\n",
                 "emitter.on('data', handler);\nmap.set('a', 1);\n"):
        got = js.analyze_file("src/lib/cache.js", code)
        check(not got, f"[route] a plain method call is not a mount; got "
                       f"{[f.detector_id for f in got]}")


def test_a_file_with_no_route_says_nothing() -> None:
    got = js.analyze_file("src/lib/util.js", "export function add(a, b) { return a + b; }\n")
    check(not got, f"[route] a module with no handler must produce nothing, got {got}")


def test_the_secure_fixture_stays_silent() -> None:
    """The shipped negative control. Every JS/TS file in `secure-app` implements a feature
    correctly, so any finding here is a false positive against code this repository asserts is
    right — the only precision measurement available on this side."""
    secure = os.path.join(REPO, "tests", "fixtures", "secure-app")
    noisy: list[str] = []
    for root, _dirs, names in os.walk(secure):
        for name in names:
            if not name.lower().endswith(js.JS_EXTS):
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, secure).replace("\\", "/")
            with open(full, encoding="utf-8", errors="ignore") as fh:
                for f in js.analyze_file(rel, fh.read()):
                    noisy.append(f"{f.detector_id} at {rel}:{f.line}")
    check(not noisy, f"[precision] the secure fixture must stay silent; got {noisy}")


def test_the_language_matrix_is_derived_not_typed() -> None:
    """Every language in `structural.LANGS` must name the analyses it actually gets, because the
    matrix generator now reads that instead of a sentence written into the generator."""
    for name, spec in structural.LANGS.items():
        check(bool(spec.get("analyses")),
              f"[matrix] {name} claims structural analysis but names no analyses")
        check(bool(spec.get("exts")), f"[matrix] {name} declares no extensions")


def test_js_contributes_its_own_limitations() -> None:
    text = " ".join(structural.limitations())
    for phrase in ("string literal path", "no parser", "RealVuln"):
        check(phrase in text,
              f"[limitations] the JS bounds must state {phrase!r} — an unmeasured analysis that "
              f"does not say so is the claim this repository refuses from anyone else")


# ------------------------------------------------------------------- prototype pollution
#
# This one replaced a pattern rule that scored 9 of 185 with 950 false positives on SecBench.js,
# so the negative cases below are not decoration: they are every idiom that produced one of
# those 950. A `for…in` loop, an array write in a counted loop, and a fixed-property copy are
# all things the old rule reported and this one must not.

def proto(code: str, path: str = "src/lib/merge.js") -> list[int]:
    return [f.line for f in protopollution.analyze_file(path, code)]


def test_an_unguarded_recursive_merge_is_reported() -> None:
    lines = proto("function merge(target, source) {\n"
                  "  for (const key in source) {\n"
                  "    target[key] = source[key];\n"
                  "  }\n"
                  "}\n")
    check(lines == [3], f"the merge write was not reported on its own line: {lines}")


def test_a_proto_check_silences_it() -> None:
    # The guard lives in a string literal, which the blanked code view erases. Reading the guard
    # from the raw text is the difference between this rule working and this rule reporting
    # every hand-written protection in the ecosystem.
    check(proto("function merge(target, source) {\n"
                "  for (const key in source) {\n"
                "    if (key === '__proto__') continue;\n"
                "    target[key] = source[key];\n"
                "  }\n"
                "}\n") == [], "an explicit __proto__ refusal did not silence the rule")


def test_a_key_name_check_or_a_null_prototype_target_silences_it() -> None:
    # A guard is a comparison against a key NAME, and a name is a string literal.
    for guard, label in (
            ("    if (key === '__proto__') continue;\n", "__proto__ name check"),
            ("    if (key === 'constructor') continue;\n", "constructor name check"),
            ("    const out = Object.create(null);\n", "null-prototype target")):
        check(proto("function merge(target, source) {\n"
                    "  for (const key in source) {\n"
                    f"{guard}"
                    "    target[key] = source[key];\n"
                    "  }\n"
                    "}\n") == [], f"a {label} did not silence the rule")


def test_hasownproperty_is_not_a_guard_and_used_to_be_treated_as_one() -> None:
    """`hasOwnProperty` reads like a defence and is the canonical vulnerable merge.

    It asks whether the key is the source's own rather than inherited — and a `__proto__` that
    arrived via `JSON.parse('{"__proto__": …}')` **is** an own property. The check passes, the
    write happens, and it excludes exactly the keys nobody was going to send. Treating it as a
    guard silenced 10 of the 115 unsealed labelled prototype-pollution misses on SecBench.js.

    Both spellings, because the second hid the first: `Object.prototype.hasOwnProperty.call`
    contains the word `prototype`, so while a bare `prototype` counted as a guard this case
    passed for a reason that had nothing to do with `hasOwnProperty` — the right outcome from the
    wrong cause, which is the failure mode a test is least likely to notice about itself.
    """
    for guard, label in (
            ("    if (!source.hasOwnProperty(key)) continue;\n", "src.hasOwnProperty(key)"),
            ("    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;\n",
             "Object.prototype.hasOwnProperty.call")):
        lines = proto("function merge(target, source) {\n"
                      "  for (const key in source) {\n"
                      f"{guard}"
                      "    target[key] = source[key];\n"
                      "  }\n"
                      "}\n")
        check(lines == [4], f"{label} silenced the rule, but it is not a guard: {lines}")


def test_a_guard_in_an_enclosing_function_protects_the_inner_one() -> None:
    # The careful implementation: check once at the entry point, recurse in a local helper.
    # Reporting the helper would mean reporting exactly the codebases that got this right.
    check(proto("function merge(target, source) {\n"
                "  if (Object.keys(source).some(k => k === '__proto__')) return target;\n"
                "  const walk = (dst, src) => {\n"
                "    for (const key in src) {\n"
                "      dst[key] = src[key];\n"
                "    }\n"
                "  };\n"
                "  walk(target, source);\n"
                "  return target;\n"
                "}\n") == [], "a guard in the enclosing function did not protect the inner one")


def test_the_set_by_path_shape_is_reported() -> None:
    lines = proto("function set(obj, path, value) {\n"
                  "  const parts = path.split('.');\n"
                  "  let cur = obj;\n"
                  "  for (let i = 0; i < parts.length - 1; i++) {\n"
                  "    if (!cur[parts[i]]) cur[parts[i]] = {};\n"
                  "    cur = cur[parts[i]];\n"
                  "  }\n"
                  "  cur[parts[parts.length - 1]] = value;\n"
                  "}\n")
    check(lines == [5, 8], f"the set-by-path writes were not both reported: {lines}")


def test_an_array_write_in_a_counted_loop_is_not_prototype_pollution() -> None:
    # The single largest source of noise if the index is not checked: `out[i] = …` is the most
    # ordinary line in JavaScript and `i` is a position, not a property name.
    check(proto("function double(out, values) {\n"
                "  for (let i = 0; i < values.length; i++) {\n"
                "    out[i] = values[i] * 2;\n"
                "  }\n"
                "}\n") == [], "an array write in a counted loop was reported")


def test_a_for_in_loop_that_writes_nothing_is_not_reported() -> None:
    # Precisely what the old pattern rule matched, and on its own it is not a defect.
    check(proto("function describe(source) {\n"
                "  const names = [];\n"
                "  for (const key in source) {\n"
                "    names.push(key);\n"
                "  }\n"
                "  return names;\n"
                "}\n") == [], "a for-in loop that writes nothing was reported")


def test_fixed_property_writes_are_not_reported() -> None:
    check(proto("function copy(target, source) {\n"
                "  for (const key in source) {\n"
                "    target.name = source.name;\n"
                "  }\n"
                "}\n") == [], "a write to a constant property was reported")


def test_object_keys_foreach_is_read_as_a_key_binder() -> None:
    lines = proto("const pick = (src) => {\n"
                  "  const out = {};\n"
                  "  Object.keys(src).forEach(k => { out[k] = src[k]; });\n"
                  "  return out;\n"
                  "};\n")
    check(lines == [3], f"an Object.keys().forEach copy was not reported: {lines}")


def test_the_function_finder_delimits_the_shapes_it_used_to_lose() -> None:
    """Every structural analysis on JavaScript is scoped by `_functions`, so a function it cannot
    delimit is one that none of them look inside — which makes its blind spots worth more than
    any single rule. These four are ordinary JavaScript and all four were invisible: measured on
    SecBench.js's prototype-pollution class, **35 of 113 labelled misses were a sink in a function
    this could not see**.

    The first is the sharpest, because it did not fail loudly. A default parameter value contains
    a brace, `line.find("{")` found *that* brace, and the function came out one line long — so
    every rule read an empty body and reported nothing at all."""
    cases = {
        "default parameter value": ("function unflatten(obj = {}) {\n"
                                    "  const out = {};\n"
                                    "  return out;\n"
                                    "}\n", "unflatten", 4),
        "brace on the next line": ("function reduceObject(target, source)\n"
                                   "{\n"
                                   "  return target;\n"
                                   "}\n", "reduceObject", 4),
        # Named `reduce` rather than `exports`: the `function NAME(` form matches first and the
        # declared name is the better one. What matters is that the span is found at all.
        "export assignment": ("module.exports = function reduce(target, source) {\n"
                              "  return target;\n"
                              "}\n", "reduce", 3),
        "anonymous export assignment": ("exports.merge = (target, source) => {\n"
                                        "  return target;\n"
                                        "}\n", "merge", 3),
        "object-literal method": ("const api = {\n"
                                  "  merge: function (a, b) {\n"
                                  "    return a;\n"
                                  "  }\n"
                                  "};\n", "merge", 4),
        "class method": ("class Store {\n"
                         "  set(key, value) {\n"
                         "    this.data[key] = value;\n"
                         "  }\n"
                         "}\n", "set", 4),
        "typescript return type": ("function pick(o: Record<string, string>): string[]\n"
                                   "{\n"
                                   "  return [];\n"
                                   "}\n", "pick", 4),
    }
    for label, (code, name, end) in cases.items():
        found = js._functions(code.splitlines())
        if name not in found:
            check(False, f"[{label}] `{name}` was not found at all: {sorted(found)}")
            continue
        check(found[name][1] == end,
              f"[{label}] `{name}` ends at line {found[name][1]}, expected {end}")


def test_the_function_finder_does_not_read_control_flow_as_a_function() -> None:
    """The method-shorthand form shares its shape with `if (…) {`, and a wrong span is worse than
    a missing one: it decides which writes every rule believes are inside which body."""
    found = js._functions("if (ready) {\n  go();\n}\nwhile (x) {\n  y();\n}\n".splitlines())
    check(found == {}, f"a control-flow block was read as a function: {found}")
    called = js._functions("doWork(a, b);\nconst x = 1;\n".splitlines())
    check(called == {}, f"a call statement was read as a function: {called}")


def test_a_set_by_path_helper_is_reported_at_the_final_write() -> None:
    """`set(obj, 'a.b.__proto__', v)` is the other half of CWE-1321 and no iteration binder
    reaches it: the key at the end of a walk is never bound by `for…in` or `Object.keys`. What
    makes it this bug is the walk itself — `cur = cur[part]` — plus a final write whose index the
    caller chose."""
    lines = proto("function setDeep(obj, path, value) {\n"
                  "  const parts = path.split('.');\n"
                  "  let cur = obj;\n"
                  "  for (let i = 0; i < parts.length - 1; i++) {\n"
                  "    cur = cur[parts[i]];\n"
                  "  }\n"
                  "  cur[parts[parts.length - 1]] = value;\n"
                  "}\n")
    check(7 in lines, f"the final write of a set-by-path helper was not reported: {lines}")


def test_a_walk_indexed_by_something_the_function_chose_is_not_reported() -> None:
    """The negative half of the walk rule. A cursor moving through a structure and writing at a
    position the function itself chose is ordinary code; only a caller-chosen key at the end of
    the walk is this bug."""
    check(proto("function build() {\n"
                "  const known = ['a', 'b'];\n"
                "  let cur = {};\n"
                "  for (const k of known) {\n"
                "    cur = cur[k];\n"
                "    cur[k] = 1;\n"
                "  }\n"
                "}\n") == [], "a walk keyed by a name the function chose was reported")


def test_a_plain_setter_is_not_prototype_pollution() -> None:
    """The other half of the walk rule, and the more important one.

    `store[name] = value` with `name` a parameter is a generic setter, and it is one of the most
    common functions in the language. Reporting it would be this module's own docstring warning
    come true — the rule is about *this* bug, not about every indexed write — so the walk is what
    separates a path setter from a setter. Delete that condition and this test is what goes red."""
    check(proto("function put(store, name, value) {\n"
                "  store[name] = value;\n"
                "}\n") == [], "a plain setter with a parameter key was reported")
    check(proto("function assign(obj, field, v) {\n"
                "  if (v !== undefined) {\n"
                "    obj[field] = v;\n"
                "  }\n"
                "  return obj;\n"
                "}\n") == [], "a guarded plain setter was reported")
    # A walk licenses the writes into *the object it walked*, not every write in the function.
    # `audit[name] = …` here is an ordinary setter that happens to share a body with a path
    # setter, and the two are told apart by which name is being indexed.
    lines = proto("function record(dest, name, value) {\n"
                  "  const audit = {};\n"
                  "  let cur = dest;\n"
                  "  cur = cur[name];\n"
                  "  audit[name] = value;\n"
                  "}\n")
    check(4 not in lines and 5 not in lines,
          f"a write outside the walked object was reported: {lines}")


def test_a_key_bound_inside_an_anonymous_callback_is_the_callers() -> None:
    """`js-extend@0.0.1`, the labelled SecBench.js bug this module documented as a permanent
    miss: *"the key is bound from `source`, and `source` is the parameter of an anonymous
    callback… invisible to a rule that decides caller-supplied inside one function body."*

    It is visible now, and the change is smaller than the limitation sounded. The rule never
    needed the callback's *span* — it needed to know that a callback's parameters carry whatever
    the iterated value carries, which is decidable at the call site. Take the callback out of
    `_caller_supplied` and this test goes red."""
    lines = proto("function extend(target) {\n"
                  "  var sources = Array.prototype.slice.call(arguments, 1);\n"
                  "  each.call(sources, function (source) {\n"
                  "    for (var key in source) {\n"
                  "      target[key] = source[key];\n"
                  "    }\n"
                  "  });\n"
                  "  return target;\n"
                  "}\n")
    check(lines == [5], f"the write inside an anonymous callback was not reported: {lines}")


def test_a_key_bound_by_a_callback_parameter_is_the_callers() -> None:
    """The limitation this module declared from the day it was written, with the instance that
    proved it (`js-extend@0.0.1`). What the rule needs from a callback is not its span but the
    fact that its parameters carry whatever the iterated value carries."""
    lines = proto("function merge(target, source) {\n"
                  "  _.each(source, function (value, key) {\n"
                  "    target[key] = value;\n"
                  "  });\n"
                  "}\n")
    check(lines == [3], f"a key bound by a lodash-style callback was not reported: {lines}")
    quiet = proto("function tally(rows) {\n"
                  "  const seen = { a: 1 };\n"
                  "  const out = {};\n"
                  "  Object.keys(seen).forEach(function (key) {\n"
                  "    out[key] = seen[key];\n"
                  "  });\n"
                  "}\n")
    check(quiet == [], f"a callback over an object the function built was reported: {quiet}")


def test_a_key_from_an_object_the_function_built_itself_is_not_reported() -> None:
    # The rule's claim is an *attacker-named* key. Iterating state this function constructed
    # from a literal has the shape and none of the substance — nothing outside can put
    # `__proto__` in there. This exact line was the rule's only false positive on RealVuln.
    check(proto("function AdminAudit() {\n"
                "  const [filters, setFilters] = useState({ user_id: '', action: '' });\n"
                "  const q = {};\n"
                "  for (const k of Object.keys(filters)) {\n"
                "    q[k] = filters[k];\n"
                "  }\n"
                "  return q;\n"
                "}\n") == [], "a key from an object the function built itself was reported")
    check(proto("function withDefaults() {\n"
                "  const defaults = { a: 1 };\n"
                "  const out = {};\n"
                "  for (const key in defaults) {\n"
                "    out[key] = defaults[key];\n"
                "  }\n"
                "}\n") == [], "a key from a local object literal was reported")


def test_arguments_counts_as_caller_supplied() -> None:
    # Every pre-ES6 merge helper is written this way, and `arguments` is declared nowhere — so a
    # parameter-list check that does not special-case it silences the whole idiom.
    #
    # This test passes without the `arguments` seeding being worth anything on real code, which
    # is worth saying out loud: it writes `var src = arguments[i]`, a *declaration*, and the
    # helpers in the wild write `src = arguments[i]` against a hoisted `var`. The test below is
    # the one that failed on the corpus. Keeping both, because both shapes are real.
    lines = proto("function extend() {\n"
                  "  var target = arguments[0];\n"
                  "  for (var i = 1; i < arguments.length; i++) {\n"
                  "    var src = arguments[i];\n"
                  "    for (var k in src) {\n"
                  "      target[k] = src[k];\n"
                  "    }\n"
                  "  }\n"
                  "  return target;\n"
                  "}\n")
    check(lines == [6], f"the pre-ES6 `arguments` merge helper was not reported: {lines}")


def test_a_hoisted_var_filled_by_a_later_assignment_still_carries_the_caller() -> None:
    # `extend@3.0.1` and `objtools@3.0.0`, both labelled SecBench.js bugs, reduced to their
    # shape: locals declared up front with no initialiser, then filled inside the loop by a bare
    # assignment. Requiring `const`/`let`/`var` on the assignment loses both — and lost both,
    # measured, when the caller-supplied narrowing first landed.
    lines = proto("function extend() {\n"
                  "  var options, name;\n"
                  "  var target = arguments[0];\n"
                  "  for (var i = 1; i < arguments.length; ++i) {\n"
                  "    options = arguments[i];\n"
                  "    for (name in options) {\n"
                  "      target[name] = options[name];\n"
                  "    }\n"
                  "  }\n"
                  "  return target;\n"
                  "}\n")
    check(lines == [7], f"the hoisted-var merge helper was not reported: {lines}")


def test_a_key_two_bindings_away_from_a_parameter_is_still_the_callers() -> None:
    # A query-string parser: `str.split('&')`, then `p.split('=')`. The key is two hops from the
    # parameter and this is the shape of a real `qs`-family prototype-pollution bug, so a
    # single-hop check would trade one false positive for a whole class of misses.
    lines = proto("function parseQuery(str) {\n"
                  "  const out = {};\n"
                  "  const pairs = str.split('&');\n"
                  "  for (const p of pairs) {\n"
                  "    const parts = p.split('=');\n"
                  "    out[parts[0]] = parts[1];\n"
                  "  }\n"
                  "  return out;\n"
                  "}\n")
    check(lines == [6], f"the query-string parser's write was not reported: {lines}")


def test_a_helper_closing_over_the_outer_parameter_is_still_reported() -> None:
    # The commonest real shape: take `source`, do the work in a local helper that closes over it.
    # It is reported by the *enclosing* function's pass, whose span contains the inner body —
    # which is why the module does not inherit outer parameter lists. That was written first, and
    # deleted when no mutation of it could be made to fail this test.
    lines = proto("function deepMerge(target, source) {\n"
                  "  const walk = (dst) => {\n"
                  "    for (const key in source) {\n"
                  "      dst[key] = source[key];\n"
                  "    }\n"
                  "  };\n"
                  "  walk(target);\n"
                  "}\n")
    check(lines == [4], f"the inner helper's write was not reported: {lines}")


def test_prototype_pollution_is_out_of_scope_in_a_test_file() -> None:
    check(proto("function merge(target, source) {\n"
                "  for (const key in source) {\n"
                "    target[key] = source[key];\n"
                "  }\n"
                "}\n", path="src/lib/merge.test.js") == [],
          "a test file was analysed for prototype pollution")


def test_prototype_pollution_contributes_its_own_limitations() -> None:
    check(any("prototype pollution" in note.lower()
              for note in protopollution.limitations()),
          "the prototype-pollution analysis states no limitation of its own")
    check(any("prototype pollution" in note.lower() for note in structural.limitations()),
          "structural.limitations() does not carry the prototype-pollution note, so a report "
          "would not say what this rule cannot see")



# --------------------------------------------------- what the response says about the server

def test_a_stack_trace_in_a_response_body_is_reported() -> None:
    expect("""
router.get('/orders/:id', async (req, res) => {
  try {
    res.json(await db.order.findUnique({ where: { id: req.params.id } }));
  } catch (err) {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});
""", "EXPOSE-JS-INTERNALS", True, "stack and driver message in the body")


def test_handing_the_error_to_the_framework_is_not_a_disclosure() -> None:
    """`next(err)` is where the decision about what a client sees belongs, so a handler that
    delegates is not building the body this rule is about."""
    expect("""
router.get('/orders/:id', async (req, res, next) => {
  try {
    res.json(await db.order.findUnique({ where: { id: req.params.id } }));
  } catch (err) {
    next(err);
  }
});
""", "EXPOSE-JS-INTERNALS", False, "delegated to the error handler")


def test_an_ordinary_message_is_not_a_disclosure() -> None:
    expect("""
router.get('/orders/:id', async (req, res) => {
  const order = await db.order.findUnique({ where: { id: req.params.id } });
  if (!order) return res.status(404).json({ error: 'Order not found' });
  res.json(order);
});
""", "EXPOSE-JS-INTERNALS", False, "a message the handler wrote")


# ------------------------------------------------------- a decision the caller gets to make

def test_a_branch_on_a_client_header_is_reported() -> None:
    expect("""
router.post('/admin/purge', (req, res) => {
  if (req.headers['x-user-role'] === 'admin') {
    db.purge();
  }
  res.json({ ok: true });
});
""", "TRUST-JS-CLIENT-DECISION", True, "role declared by the caller")


def test_a_transport_header_comparison_is_ordinary_code() -> None:
    """`content-type` exists for the client to declare something about the request. Comparing
    one to a constant is correct code, not a gate — and without this list the rule would fire
    on every content negotiation in every codebase."""
    expect("""
router.post('/upload', (req, res) => {
  if (req.headers['content-type'] === 'application/json') {
    return res.status(415).json({ error: 'send multipart' });
  }
  res.json({ ok: true });
});
""", "TRUST-JS-CLIENT-DECISION", False, "content negotiation")


def test_a_verified_value_is_not_client_trusted() -> None:
    expect("""
router.post('/admin/purge', (req, res) => {
  const claims = jwt.verify(req.headers.authorization.slice(7), SECRET);
  if (req.headers['x-user-role'] === claims.role) {
    db.purge();
  }
  res.json({ ok: true });
});
""", "TRUST-JS-CLIENT-DECISION", False, "the value was verified first")


# ------------------------------------------------------------------ account enumeration

def test_two_different_failure_messages_are_reported() -> None:
    expect("""
router.post('/login', async (req, res) => {
  const user = await db.user.findUnique({ where: { email: req.body.email } });
  if (!user) return res.status(404).json({ error: 'No account found for that email' });
  if (!bcrypt.compareSync(req.body.password, user.hash))
    return res.status(401).json({ error: 'Incorrect password' });
  res.json({ token: sign(user) });
});
""", "ENUM-JS-CREDENTIAL", True, "absence and invalidity answered differently")


def test_one_message_for_both_halves_is_the_fix() -> None:
    expect("""
router.post('/login', async (req, res) => {
  const user = await db.user.findUnique({ where: { email: req.body.email } });
  if (!user || !bcrypt.compareSync(req.body.password, user.hash))
    return res.status(401).json({ error: 'Invalid email or password' });
  res.json({ token: sign(user) });
});
""", "ENUM-JS-CREDENTIAL", False, "one message, one status")


def test_not_found_outside_a_credential_flow_is_ordinary() -> None:
    """"Not found" is the most ordinary message an application writes. The rule is bounded to a
    credential flow for exactly that reason."""
    expect("""
router.post('/orders/:id/cancel', async (req, res) => {
  const order = await db.order.findUnique({ where: { id: req.params.id } });
  if (!order) return res.status(404).json({ error: 'No account found for that order' });
  if (!order.cancellable) return res.status(400).json({ error: 'Incorrect password reset' });
  res.json({ ok: true });
});
""", "ENUM-JS-CREDENTIAL", False, "not a credential flow")



def test_a_projects_own_auth_middleware_is_recognised_by_its_name() -> None:
    """`mw.authAdminApi` is not in any marker list and cannot be — it is one project's name for
    its own guard. 220 occurrences in Ghost, every route carrying it reported as unauthenticated
    until the naming convention was read instead of enumerated."""
    expect("""
router.delete('/labels/:id', mw.authAdminApi, http(api.labels.destroy));
""", "AUTHZ-JS-NOAUTH", False, "project-named auth middleware")


def test_an_author_is_not_an_auth() -> None:
    """The whole precision of that convention: `auth` followed by a capital is a camelCase
    compound about authentication, and `author` continues in lower case."""
    expect("""
router.post('/posts', async (req, res) => {
  await db.post.create({ data: { authorName: req.body.author, body: req.body.body } });
  res.json({ ok: true });
});
""", "AUTHZ-JS-NOAUTH", True, "authorName must not read as auth")


def test_a_mirage_mock_server_is_not_production() -> None:
    """Ember's HTTP mock. It mounts unauthenticated routes because it IS the fake backend a
    test talks to."""
    expect("""
server.post('/posts', function ({posts, users, tags}) {
  return posts.create({ title: 'x' });
});
""", "AUTHZ-JS-NOAUTH", False, "mirage config", path="apps/admin/mirage/config/posts.js")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    test_a_state_changing_route_with_no_caller_is_reported()
    test_auth_middleware_in_the_mount_silences_it()
    test_a_module_local_guard_is_followed()
    test_a_read_only_route_is_not_reported()
    test_login_is_public_by_design()
    test_nest_useguards_counts()
    test_an_unguarded_nest_route_is_reported()
    test_a_caller_id_selected_without_the_principal_is_reported()
    test_a_query_scoped_by_the_principal_is_silent()
    test_an_ownership_comparison_is_silent()
    test_an_unauthenticated_route_is_not_an_idor()
    test_an_unbounded_login_is_reported()
    test_a_limiter_in_the_mount_silences_it()
    test_an_app_wide_limiter_at_module_scope_counts()
    test_recording_an_attempt_is_not_bounding_one()
    test_an_attempt_count_compared_against_a_maximum_is_a_limit()
    test_a_route_that_tests_no_credential_is_not_reported()
    test_an_unchecked_upload_is_reported()
    test_a_mimetype_check_silences_it()
    test_a_module_local_validator_is_followed()
    test_the_whole_body_handed_to_a_write_is_reported()
    test_named_fields_are_not_mass_assignment()
    test_a_destructure_elsewhere_does_not_excuse_a_wholesale_write()
    test_a_schema_parse_is_the_allowlist()
    test_an_app_router_write_with_no_session_is_reported()
    test_an_app_router_route_with_a_session_is_silent()
    test_a_pages_api_handler_is_read_by_the_method_it_branches_on()
    test_a_read_only_pages_api_handler_is_not_reported()
    test_non_production_sources_are_out_of_scope()
    test_a_method_call_that_is_not_a_route_is_not_a_route()
    test_a_file_with_no_route_says_nothing()
    test_the_secure_fixture_stays_silent()
    test_the_language_matrix_is_derived_not_typed()
    test_js_contributes_its_own_limitations()
    test_an_unguarded_recursive_merge_is_reported()
    test_a_proto_check_silences_it()
    test_a_key_name_check_or_a_null_prototype_target_silences_it()
    test_hasownproperty_is_not_a_guard_and_used_to_be_treated_as_one()
    test_a_guard_in_an_enclosing_function_protects_the_inner_one()
    test_the_set_by_path_shape_is_reported()
    test_an_array_write_in_a_counted_loop_is_not_prototype_pollution()
    test_a_for_in_loop_that_writes_nothing_is_not_reported()
    test_fixed_property_writes_are_not_reported()
    test_object_keys_foreach_is_read_as_a_key_binder()
    test_a_key_from_an_object_the_function_built_itself_is_not_reported()
    test_arguments_counts_as_caller_supplied()
    test_a_hoisted_var_filled_by_a_later_assignment_still_carries_the_caller()
    test_a_key_two_bindings_away_from_a_parameter_is_still_the_callers()
    test_a_helper_closing_over_the_outer_parameter_is_still_reported()
    test_the_function_finder_delimits_the_shapes_it_used_to_lose()
    test_the_function_finder_does_not_read_control_flow_as_a_function()
    test_a_set_by_path_helper_is_reported_at_the_final_write()
    test_a_walk_indexed_by_something_the_function_chose_is_not_reported()
    test_a_plain_setter_is_not_prototype_pollution()
    test_a_key_bound_by_a_callback_parameter_is_the_callers()
    test_a_key_bound_inside_an_anonymous_callback_is_the_callers()
    test_prototype_pollution_is_out_of_scope_in_a_test_file()
    test_prototype_pollution_contributes_its_own_limitations()

    test_a_stack_trace_in_a_response_body_is_reported()
    test_handing_the_error_to_the_framework_is_not_a_disclosure()
    test_an_ordinary_message_is_not_a_disclosure()
    test_a_branch_on_a_client_header_is_reported()
    test_a_transport_header_comparison_is_ordinary_code()
    test_a_verified_value_is_not_client_trusted()
    test_two_different_failure_messages_are_reported()
    test_one_message_for_both_halves_is_the_fix()
    test_not_found_outside_a_credential_flow_is_ordinary()
    test_a_projects_own_auth_middleware_is_recognised_by_its_name()
    test_an_author_is_not_an_auth()
    test_a_mirage_mock_server_is_not_production()

    if fails:
        print("JS STRUCTURAL TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("JS STRUCTURAL TESTS PASSED — missing auth, IDOR, rate limiting, uploads, mass "
          "assignment, response exposure, client-trusted decisions and account enumeration "
          "asserted in both directions across Express, NestJS and Next.js shapes, with the "
          "shipped secure fixture silent and the route anchor holding.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
