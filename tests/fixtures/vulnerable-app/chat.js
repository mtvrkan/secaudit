// INTENTIONALLY VULNERABLE — SecAudit test fixture. Not real code.
// Mirrors the real-world class: LLM/markdown output rendered without sanitization.
const marked = require('marked');

// V8 — Improper output handling → stored/reflected XSS (OWASP LLM05 / CWE-79).
// The AI response (attacker-influenceable via prompt/RAG) is rendered as raw HTML,
// with no DOMPurify. User's own message is escaped (safe) — the AI path is not.
function renderMessage(bubble, msg, isUser) {
  if (isUser) {
    bubble.innerHTML = escapeHtml(msg);            // safe
  } else {
    bubble.innerHTML = marked.parse(msg);          // UNSAFE: raw HTML from model output
  }
}

function loadHistory(el) {
  const raw = el.getAttribute('data-markdown');
  if (raw) el.innerHTML = marked.parse(raw);       // UNSAFE: same sink on history load
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

module.exports = { renderMessage, loadHistory };
