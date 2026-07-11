// INTENTIONALLY VULNERABLE — SecAudit test fixture. Not real code. Do not deploy.
// Each block plants a specific, labeled vulnerability class for the golden-set eval.
const express = require('express');
const { exec } = require('child_process');
const crypto = require('crypto');
const db = require('./db');
const app = express();
app.use(express.json());

// V1 — SQL injection (CWE-89): user input concatenated into a query.
app.get('/users', (req, res) => {
  const q = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  db.query(q, (e, rows) => res.json(rows));
});

// V2 — OS command injection (CWE-78): user input into a shell.
app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));
});

// V3 — Broken access control / IDOR (CWE-639): no ownership check.
app.get('/invoice/:id', (req, res) => {
  db.query('SELECT * FROM invoices WHERE id = ?', [req.params.id], (e, r) => res.json(r));
});

// V4 — Weak crypto for passwords (CWE-327): MD5, no salt.
function hashPassword(pw) {
  return crypto.createHash('md5').update(pw).digest('hex');
}

// V5 — Hardcoded secret (CWE-798). Uses AWS's DOCUMENTATION example key (not real).
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

// V6 — Permissive CORS reflecting Origin with credentials (CWE-942).
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// V7 — SSRF (CWE-918): fetches a user-supplied URL with no allowlist.
app.get('/fetch', (req, res) => {
  require('http').get(req.query.url, (r) => r.pipe(res));
});

module.exports = { app, hashPassword, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY };
