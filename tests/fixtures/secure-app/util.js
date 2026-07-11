// SECURE COUNTERPART — negative-control fixture. Safe implementations of the injection /
// deserialization classes planted (vulnerably) in vulnerable-app/util.js (S14–S16 ↔ V14–V16).

// S14 — Prototype pollution fixed (CWE-1321): dangerous keys are skipped and each nested
// target is a null-prototype object, so `__proto__`/`constructor` can't reach Object.prototype.
const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);
function merge(target, source) {
  for (const key of Object.keys(source)) {
    if (BLOCKED.has(key)) continue;
    const val = source[key];
    if (val && typeof val === 'object') {
      target[key] = merge(target[key] || Object.create(null), val);
    } else {
      target[key] = val;
    }
  }
  return target;
}

// S15 — Safe deserialization (CWE-502/94 fixed): JSON.parse, never eval — only data, never
// code, is produced from the input.
function deserialize(str) {
  return JSON.parse(str);
}

// S16 — Template injection fixed (CWE-1336/94): user input is passed as DATA to a fixed
// template and HTML-escaped; it is never compiled as code (no `new Function`, no eval).
function render(templateSource, data) {
  return templateSource.replace(/\{\{(\w+)\}\}/g, (_, k) => escapeHtml(String(data[k] ?? '')));
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

module.exports = { merge, deserialize, render };
