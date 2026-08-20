// SECURE COUNTERPART — minimal DB stub so server.js's require('./db') resolves. The audit
// is static and the app is never executed. The parameterized-query call sites live in
// server.js (S1/S3); this stub just accepts (sql, params, cb).
module.exports = {
  query: (sql, params, cb) => {
    const done = typeof params === 'function' ? params : cb;
    if (typeof done === 'function') done(null, []);
  },
};
