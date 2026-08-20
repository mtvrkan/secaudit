// INTENTIONALLY VULNERABLE — SecAudit test fixture. Not real code. Do not deploy.
// Modern auth/identity + web vuln classes, planted for the golden-set eval. Pure code,
// no external deps — each is detectable by static review.
const fs = require('fs');
const path = require('path');

// V10 — Broken JWT verification (CWE-347): trusts the token's own `alg` header and
// accepts `alg:none` (no signature check). Also no exp/aud validation.
function verifyToken(token) {
  const [h, p] = token.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64').toString());
  const payload = JSON.parse(Buffer.from(p, 'base64').toString());
  if (header.alg === 'none') return payload;          // UNSAFE: unsigned token accepted
  // (even otherwise, signature is never actually verified below)
  return payload;                                     // UNSAFE: no signature/exp/aud check
}

// V11 — Open redirect (CWE-601): user-controlled destination, no allowlist.
function redirect(req, res) {
  res.writeHead(302, { Location: req.query.next });   // ?next=https://evil.example
  res.end();
}

// V12 — Path traversal (CWE-22): user input joined into a path with no normalization.
function readDoc(req, res) {
  const file = path.join(__dirname, 'docs', req.query.file);  // ?file=../../etc/passwd
  fs.readFile(file, 'utf8', (e, data) => res.end(data));
}

// V13 — Mass assignment (CWE-915): whole request body copied onto the user record,
// letting a caller set privileged fields like `role`/`isAdmin`.
function updateProfile(user, req) {
  Object.assign(user, req.body);                      // UNSAFE: no field allowlist
  return user;
}

module.exports = { verifyToken, redirect, readDoc, updateProfile };
