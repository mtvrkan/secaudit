// SECURE COUNTERPART — SecAudit negative-control fixture. Not real code.
package main

import (
	"database/sql"
	"net"
	"net/http"
	"regexp"
	"time"
)

// S24 — TLS verification left on (CWE-295 fixed): the default config validates the chain
// against the system trust store, so no field disables it.
func client() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

// S25 — SQL injection fixed (CWE-89): a placeholder, with the value bound separately.
func lookup(db *sql.DB, name string) *sql.Rows {
	rows, _ := db.Query("SELECT id, email FROM users WHERE name = ?", name)
	return rows
}

// S26 — Command execution avoided entirely (CWE-78 fixed): reachability is answered with a
// library dial rather than by shelling out, so there is no process to inject into. The
// hostname is still validated, because an unbounded value in a network call is its own problem.
var hostRe = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)

func ping(host string) bool {
	if !hostRe.MatchString(host) {
		return false
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "80"), 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}
