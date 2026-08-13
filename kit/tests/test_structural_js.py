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

    if fails:
        print("JS STRUCTURAL TESTS FAILED:")
        print("\n".join("  - " + f for f in fails))
        return 1
    print("JS STRUCTURAL TESTS PASSED — missing auth, IDOR, rate limiting, uploads and mass "
          "assignment asserted in both directions across Express, NestJS and Next.js shapes, "
          "with the shipped secure fixture silent and the route anchor holding.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
