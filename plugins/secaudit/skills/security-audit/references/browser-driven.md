# Browser-driven checks — SPA, DOM XSS, and auth-flow walking

`curl` sees the document the server sent. For a large share of modern targets that document is an
empty `<div id="root">` and a bundle, so every phase built on fetching HTML reports a clean, tiny
attack surface for an application with hundreds of routes. This reference covers the checks that
need a real browser, and the ones that are *only* safe because they do not.

**The browser comes from the harness, not from this kit.** `secaudit_core` has zero runtime
dependencies and that is not negotiable; shipping Playwright to get DOM coverage would trade the
kit's best property for one phase. The plugin runs inside Claude Code, which already drives a
browser, so this is a reference the model follows — not a library the package installs. If the
browser tools are not available in the session, say so once and run the rest of the methodology;
never silently skip a phase.

## Impact tier — read before the first navigation

The [authorization gate](../SKILL.md) applies unchanged, and a browser makes the line easier to
cross by accident because a single click can submit a form.

| Action | Tier |
|---|---|
| Navigate to an in-scope URL, read the rendered DOM, read response headers and cookie flags, read the loaded JS | **Passive** |
| Follow a link that is a plain `GET` | **Passive** |
| Type into a field, click a button, submit a form, log in, use the app as a user | **ACTIVE — gate first** |
| Fire a payload of any kind, including a "harmless" XSS canary | **ACTIVE — gate first** |

Reading a page a normal browser would load is the same tier as fetching it. Everything that
*changes state* is active, and a logged-in session is state.

## The rule this phase exists to state: the browser is executing the target's code

A headless browser pointed at the target is running attacker-controllable JavaScript on the
operator's machine. Treat it as hostile:

- **Never reuse the operator's real browser profile or logged-in session.** Use a fresh context.
  A scan that borrows your cookies can act as you on every other site you are signed into.
- **Never navigate off-scope.** The target controls its own redirects and links; a scope file
  that only bounds what you *intend* to visit is not bounding anything. Check the host after
  every navigation, not before.
- **Never enter real credentials.** Use the test accounts named in `scope.yaml`. If none were
  provided, the auth-flow phase does not run — that is a finding about the engagement, not a
  reason to improvise.
- **Never trigger a JavaScript dialog** (`alert`, `confirm`, `prompt`). A modal blocks the
  automation channel completely and the session has to be recovered by hand. This is also why the
  DOM XSS canary below is a DOM write and not `alert(1)` — the classic payload is the one that
  breaks the tool.

## DOM XSS

Server-side XSS is a template question and the code review phase already answers it. DOM XSS never
touches the server: the payload lives in the fragment, the sink is in the bundle, and nothing in
the request log shows it.

**Read the JS before you touch anything.** This is passive and it is where the finding actually
comes from.

| Source (attacker-controllable) | Sink (executes or injects) |
|---|---|
| `location.hash`, `location.search`, `location.pathname` | `innerHTML`, `outerHTML`, `insertAdjacentHTML` |
| `document.referrer` | `document.write`, `document.writeln` |
| `window.name` | `eval`, `Function(...)`, `setTimeout`/`setInterval` with a string |
| `postMessage` handlers that do not check `event.origin` | `location`, `location.href`, `src`/`href` assignment (`javascript:`) |
| `localStorage` / `sessionStorage` written from any of the above | jQuery `.html()`, `.append()`, `$(userInput)` |

A source reaching a sink with no sanitizer between them is the finding. Report it from the code
with the file, the line and the path — the same standard as every other finding here. A canary is
*confirmation*, not discovery, and it is gated.

**If you are authorized to confirm**: navigate to the URL with a marker that writes into the DOM
and reads back, never one that opens a dialog. Set a unique string, then check whether it was
parsed as HTML rather than escaped — e.g. inject a benign element and query for it. One request,
one marker, and record it in the report's evidence section verbatim so the client can reproduce it.

**postMessage deserves its own pass.** A handler with no `event.origin` check is exploitable from
any page that can open a window to the target, and it is invisible to every server-side test. Read
every `addEventListener("message", …)` and record whether the origin is checked and whether the
check is `===` against a fixed value rather than `indexOf`/`startsWith` (which `evil-target.com`
passes).

## Auth-flow walking

Most of this is observation, which means most of it is passive once you have a session — and the
findings are high-value because no static scan can see them.

Record, for the login flow:

- **Does the session identifier change on login?** If the pre-login cookie is still valid
  afterwards, that is session fixation (CWE-384) and it is exploitable whenever an attacker can
  set a cookie.
- **Cookie flags as the browser actually received them**: `HttpOnly`, `Secure`, `SameSite`,
  `Domain` (a cookie scoped to the parent domain is shared with every sibling subdomain), `Path`,
  and expiry. Read them from the browser rather than from the response text — a later
  `Set-Cookie` or a client-side write can override what the login response said.
- **Does logout invalidate server-side?** Log in, capture the session, log out, then replay. A
  logout that only clears the cookie leaves a valid session behind.
- **Password reset**: is the token single-use, does it expire, is it bound to the account, and is
  it delivered in a URL that leaks through `Referer` to third-party scripts on the reset page.
- **MFA**: can the second factor be skipped by navigating straight to the post-login route.

Then walk the **post-login surface**. This is the phase's largest contribution: the routes,
API calls and roles that only exist after authentication, collected from the SPA's router and the
network requests the app actually makes. Feed them into the normal web and API test phases —
they are the endpoints the unauthenticated crawl could never find, and they are where the access
control findings live.

**Roles matter more than routes.** If `scope.yaml` names two test accounts at different privilege
levels, the highest-value check in the whole engagement is: capture a request as the high-privilege
user, replay it as the low-privilege one, and see what comes back. That is broken access control
measured rather than inferred, and it is the class the static tiers explicitly cannot decide.

## Hard limits, restated because a browser makes them easy to forget

- No credential brute force, no OTP guessing, no lockout testing.
- No destructive clicks. "Delete", "Cancel subscription", "Revoke" and their translations are off
  limits even when authorized, unless the scope file names them explicitly.
- Respect the rate limit in `scope.yaml`. A browser doing full page loads is heavier than the
  passive phase's 1–3 req/s, so it needs a lower one.
- Stop at the first sign the target is a shared or production system behaving oddly, and say so.

## What goes in the report

Every browser-driven finding carries the same fields as the rest: the source→sink path for DOM XSS,
the exact request and the observed response for an access-control finding, and the reproduction
steps a developer can follow without this tool. State plainly which checks ran in a browser and
which did not, and — because this phase depends on a capability that may be absent — state when it
did not run at all. A methodology that silently skips its own phase reports a clean surface it
never looked at.
