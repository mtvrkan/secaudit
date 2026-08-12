<?php
// INTENTIONALLY VULNERABLE — SecAudit test fixture. Not real code. Do not deploy.

// V30 — Command/code execution sink (CWE-78): a query parameter reaches a shell.
function archive($label) {
    return shell_exec("tar -czf /tmp/" . $label . ".tgz /var/log/app");
}

// V31 — Insecure deserialization (CWE-502): a cookie is turned back into PHP objects, which
// runs __wakeup/__destruct on whatever classes the payload names.
function session_from_cookie($raw) {
    return unserialize($raw);
}

// V32 — SQL injection (CWE-89): a superglobal goes straight into the query.
function find_user($conn) {
    return mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
}
