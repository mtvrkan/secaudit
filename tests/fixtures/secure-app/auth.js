// SECURE COUNTERPART — negative-control fixture. Safe implementations of the auth/web
// classes planted (vulnerably) in vulnerable-app/auth.js (S10–S13 ↔ V10–V13).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// S10 — JWT verification fixed (CWE-347): the algorithm is pinned SERVER-SIDE (never read
// from the token header), the HMAC signature is verified in constant time, and exp/aud are
// checked. `alg:none` and RS256→HS256 confusion are rejected by construction.
function verifyToken(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('malformed token');
  const [h, p, sig] = parts;
  const header = JSON.parse(Buffer.from(h, 'base64url').toString());
  if (header.alg !== 'HS256') throw new Error('unexpected alg');   // pinned; no alg:none
  const expected = crypto.createHmac('sha256', secret).update(h + '.' + p).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error('bad signature');
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) throw new Error('expired');
  if (payload.aud !== 'my-api') throw new Error('bad audience');
  return payload;
}

// S11 — Open redirect fixed (CWE-601): only allowlisted, same-site relative paths.
const REDIRECT_ALLOWLIST = new Set(['/dashboard', '/settings', '/']);
function redirect(req, res) {
  const next = String(req.query.next || '/');
  const dest = REDIRECT_ALLOWLIST.has(next) ? next : '/';
  res.writeHead(302, { Location: dest });
  res.end();
}

// S12 — Path traversal fixed (CWE-22): resolve, then confirm the result stays within the
// docs base directory before reading.
const DOCS_ROOT = path.resolve(__dirname, 'docs');
function readDoc(req, res) {
  const target = path.resolve(DOCS_ROOT, String(req.query.file || ''));
  if (target !== DOCS_ROOT && !target.startsWith(DOCS_ROOT + path.sep)) {
    return res.status(400).end('invalid path');
  }
  fs.readFile(target, 'utf8', (e, data) => res.end(data));
}

// S13 — Mass assignment fixed (CWE-915): copy only an explicit field allowlist, so a caller
// cannot set privileged fields like `role`/`isAdmin`.
const PROFILE_FIELDS = ['displayName', 'bio', 'avatarUrl'];
function updateProfile(user, req) {
  for (const f of PROFILE_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(req.body, f)) user[f] = req.body[f];
  }
  return user;
}

module.exports = { verifyToken, redirect, readDoc, updateProfile };
