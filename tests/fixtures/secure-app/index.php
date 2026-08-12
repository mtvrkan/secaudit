<?php
// SECURE COUNTERPART — SecAudit negative-control fixture. Not real code.

// S30 — Command execution avoided (CWE-78 fixed): the archive is built through a library call
// with the path constrained, so no shell interprets anything.
function archive($label) {
    if (!preg_match('/^[a-z0-9_-]{1,32}$/i', $label)) {
        return false;
    }
    $zip = new ZipArchive();
    $zip->open("/tmp/{$label}.zip", ZipArchive::CREATE);
    $zip->addFile('/var/log/app/current', 'current');
    return $zip->close();
}

// S31 — Insecure deserialization fixed (CWE-502): JSON decodes to arrays and scalars. A
// payload cannot name a class, so there is no object to construct and no magic method to run.
function session_from_cookie($raw) {
    return json_decode($raw, true);
}

// S32 — SQL injection fixed (CWE-89): a prepared statement with a bound parameter.
function find_user($pdo) {
    $st = $pdo->prepare('SELECT * FROM users WHERE id = :id');
    $st->execute([':id' => (int) ($_GET['id'] ?? 0)]);
    return $st->fetchAll();
}
