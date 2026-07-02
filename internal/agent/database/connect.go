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

// nodeKeyFromDSN extracts a stable "host:port" label for the node. Best
// effort - the Console only uses it as a human label + initial match key
// (server_identity is the real identity).
func nodeKeyFromDSN(engine, dsn string) string {
	if engine == "mysql" {
		// user:pass@tcp(host:port)/db
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
