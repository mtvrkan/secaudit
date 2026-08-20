// INTENTIONALLY MINIMAL — SecAudit test fixture DB stub. Not real code. Do not deploy.
// Present only so `server.js`'s require('./db') resolves; the audit is static and the
// app is never executed. No vulnerability is planted here — the SQL-injection sink (V1)
// lives in server.js, which builds the query string before it reaches this stub.
module.exports = {
  query: (sql, params, cb) => {
    const done = typeof params === 'function' ? params : cb;
    if (typeof done === 'function') done(null, []);
  },
};
