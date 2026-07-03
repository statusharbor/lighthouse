// Package database is the agent's read-only introspection collector for
// Postgres and MySQL clusters. It connects to each node via the DSN
// delivered by the Console gate (Option B - no local config), runs a
// normalized bundle of read-only queries, and ships facts (not
// judgments) to the Console. All analysis lives Console-side.
package database

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	// Drivers, registered for database/sql via blank import.
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// open dials a node read-only. introspection is low-QPS, so the pool is
// tiny and every query runs under a short timeout set by the caller.
func open(engine, dsn string) (*sql.DB, error) {
	driver := "pgx"
	if engine == "mysql" {
		driver = "mysql"
		dsn = mysqlDriverDSN(dsn)
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", engine, err)
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxIdleTime(5 * time.Minute)
	return db, nil
}

// mysqlDriverDSN rewrites the operator-facing mysql:// URL (delivered by the
// Console) into go-sql-driver's native user:pass@tcp(host:port)/db form,
// which is what sql.Open("mysql", ...) expects. The Console stays
// driver-agnostic and stores the URL verbatim; the driver quirk lives here.
// Already-native DSNs (legacy rows) and anything without the scheme pass
// through unchanged.
func mysqlDriverDSN(dsn string) string {
	if !strings.HasPrefix(dsn, "mysql://") {
		return dsn
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Host == "" {
		return dsn // let sql.Open surface the error
	}
	pass, _ := u.User.Password()
	out := u.User.Username() + ":" + pass + "@tcp(" + u.Host + ")" + u.Path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// nodeKeyFromDSN extracts a stable "host:port" label for the node. Best
// effort - the Console only uses it as a human label + initial match key
// (server_identity is the real identity).
func nodeKeyFromDSN(engine, dsn string) string {
	if engine == "mysql" {
		// URL form (mysql://user:pass@host:port/db) - what the Console sends.
		if strings.HasPrefix(dsn, "mysql://") {
			if u, err := url.Parse(dsn); err == nil && u.Host != "" {
				return u.Host
			}
		}
		// Legacy native form: user:pass@tcp(host:port)/db.
		if i := strings.Index(dsn, "tcp("); i >= 0 {
			rest := dsn[i+4:]
			if j := strings.Index(rest, ")"); j >= 0 {
				return rest[:j]
			}
		}
		return "mysql-node"
	}
	if u, err := url.Parse(dsn); err == nil && u.Host != "" {
		return u.Host
	}
	return "pg-node"
}
