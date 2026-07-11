// SECURE COUNTERPART — SecAudit negative-control fixture. Not a running app.
// Mirrors vulnerable-app/server.js feature-for-feature, but each block is the SAFE
// implementation of the same class (S1–S7 ↔ V1–V7). A correct audit should report NO
// critical/high findings here — it is used to measure PRECISION (false-positive rate),
// the complement of the vulnerable fixture's recall check.
const express = require('express');
const { execFile } = require('child_process');
const crypto = require('crypto');
const net = require('net');
const db = require('./db');
const app = express();
app.use(express.json());

// S1 — SQL injection fixed (CWE-89): parameterized query, no string concatenation.
app.get('/users', (req, res) => {
  db.query('SELECT * FROM users WHERE name = ?', [req.query.name], (e, rows) => res.json(rows));
});

// S2 — OS command injection fixed (CWE-78): execFile with an argument array (no shell),
// and the host is validated against a strict allowlist before use.
const HOST_RE = /^[a-z0-9.-]{1,253}$/i;
app.get('/ping', (req, res) => {
  const host = String(req.query.host || '');
  if (!HOST_RE.test(host)) return res.status(400).send('invalid host');
  execFile('ping', ['-c', '1', '--', host], (e, out) => res.send(out));
});

// S3 — Broken access control fixed (CWE-639): authentication required and ownership
// enforced inside the query, so one user cannot read another's invoice.
app.get('/invoice/:id', requireAuth, (req, res) => {
  db.query('SELECT * FROM invoices WHERE id = ? AND owner_id = ?',
    [req.params.id, req.user.id], (e, r) => res.json(r));
});

// S4 — Strong password hashing (CWE-327 fixed): scrypt with a per-password random salt.
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(pw, salt, 32);
  return salt.toString('hex') + ':' + dk.toString('hex');
}

// S5 — No hardcoded secret (CWE-798 fixed): credentials come from the environment.
const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;

// S6 — Strict CORS (CWE-942 fixed): explicit origin allowlist; credentials only for it.
const ALLOWED_ORIGINS = new Set(['https://app.example.com']);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.has(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
  }
  next();
});

// S7 — SSRF fixed (CWE-918): only an allowlisted https host is fetched, and private /
// link-local ranges are refused.
const FETCH_ALLOWLIST = new Set(['api.example.com']);
app.get('/fetch', (req, res) => {
  let u;
  try { u = new URL(req.query.url); } catch { return res.status(400).send('bad url'); }
  if (u.protocol !== 'https:' || !FETCH_ALLOWLIST.has(u.hostname) || isPrivate(u.hostname)) {
    return res.status(400).send('host not allowed');
  }
  require('https').get(u, (r) => r.pipe(res));
});

function isPrivate(host) {
  if (net.isIP(host) === 0) return false; // hostname; the allowlist already constrains it
  return /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host) || host === '::1';
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).send('auth required');
  next();
}

module.exports = { app, hashPassword };
