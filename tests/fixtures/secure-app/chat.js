// SECURE COUNTERPART — negative-control fixture. Safe version of the LLM/markdown
// output-handling class planted (vulnerably) in vulnerable-app/chat.js (S8 ↔ V8).
const marked = require('marked');
const DOMPurify = require('dompurify');

// S8 — Output handling fixed (CWE-79 / LLM05): model/markdown output is sanitized with
// DOMPurify before it ever reaches innerHTML, on BOTH the live and history-load paths.
function renderMessage(bubble, msg, isUser) {
  if (isUser) {
    bubble.textContent = msg;                                  // safe: no HTML parsed at all
  } else {
    bubble.innerHTML = DOMPurify.sanitize(marked.parse(msg));  // safe: sanitized HTML
  }
}

function loadHistory(el) {
  const raw = el.getAttribute('data-markdown');
  if (raw) el.innerHTML = DOMPurify.sanitize(marked.parse(raw));
}

module.exports = { renderMessage, loadHistory };
