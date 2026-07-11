// INTENTIONALLY VULNERABLE — SecAudit test fixture. Not real code. Do not deploy.
// Injection/deserialization classes, planted for the golden-set eval. Pure code, no deps.

// V14 — Prototype pollution (CWE-1321): recursive merge of untrusted input with no
// __proto__/constructor guard. `merge({}, JSON.parse('{"__proto__":{"isAdmin":true}}'))`
// poisons Object.prototype.
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = merge(target[key] || {}, source[key]);   // UNSAFE: no key filtering
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// V15 — Insecure deserialization → code injection (CWE-502/CWE-94): eval-based revive
// of untrusted input. Any request that reaches this runs arbitrary JS.
function deserialize(str) {
  return eval('(' + str + ')');                        // UNSAFE: never eval untrusted data
}

// V16 — Server-side template injection (CWE-1336/CWE-94): user input compiled into a
// template function, executed on render.
function render(templateSource, data) {
  const fn = new Function('data', 'return `' + templateSource + '`');  // UNSAFE
  return fn(data);
}

module.exports = { merge, deserialize, render };
