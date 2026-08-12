// INTENTIONALLY VULNERABLE — SecAudit test fixture. Not real code. Do not deploy.
package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

// V24 — Disabled TLS certificate verification (CWE-295): any certificate is accepted, so a
// machine-in-the-middle needs no valid chain.
func client() *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

// V25 — SQL injection (CWE-89): the request value is formatted straight into the statement.
func lookup(db *sql.DB, name string) *sql.Rows {
	q := fmt.Sprintf("SELECT id, email FROM users WHERE name = '%s'", name)
	rows, _ := db.Query(q)
	return rows
}

// V26 — OS command execution (CWE-78): a user-supplied host reaches a process invocation.
func ping(host string) []byte {
	out, _ := exec.Command("ping", "-c", "1", host).Output()
	return out
}
