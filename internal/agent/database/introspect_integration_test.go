//go:build integration

// Integration tests for the introspection SQL. Behind the `integration`
// build tag because they need Docker (testcontainers). Run with:
//
//	GOWORK=off go test -tags integration ./internal/agent/database/
//
// These are the only meaningful test of the queries - the SQL is the
// contract with the engine, not logic we can mock. They assert the
// bundle runs without error against a real server and returns
// well-formed facts (identity, role, connections, params).
package database

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcmysql "github.com/testcontainers/testcontainers-go/modules/mysql"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestPostgresIntrospector_Live(t *testing.T) {
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("app"),
		tcpostgres.WithUsername("sh_agent"),
		tcpostgres.WithPassword("secret"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	defer func() { _ = c.Terminate(ctx) }()

	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("dsn: %v", err)
	}
	db, err := open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	snap, err := postgresIntrospector{}.collect(ctx, db, sections{state: true, params: true}, 20)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !snap.Reachable {
		t.Fatal("expected reachable")
	}
	if snap.Role != "primary" {
		t.Errorf("role = %q, want primary", snap.Role)
	}
	if snap.ServerIdentity == "" {
		t.Error("expected non-empty server_identity (system_identifier)")
	}
	if snap.EngineVersion == "" {
		t.Error("expected engine_version")
	}
	// pg_stat_statements is not installed in the stock image - capability
	// detection must report false (and not error the whole collect).
	if snap.Capabilities["pg_stat_statements"] {
		t.Error("expected pg_stat_statements=false on stock image")
	}

	var st normState
	if err := json.Unmarshal(snap.State, &st); err != nil {
		t.Fatalf("state json: %v", err)
	}
	if st.Connections.Max <= 0 {
		t.Errorf("expected max_connections > 0, got %d", st.Connections.Max)
	}

	if snap.Parameters == nil {
		t.Fatal("expected parameters section")
	}
	var vals map[string]string
	if err := json.Unmarshal(snap.Parameters.Values, &vals); err != nil {
		t.Fatalf("params json: %v", err)
	}
	if _, ok := vals["shared_buffers"]; !ok {
		t.Error("expected shared_buffers in params")
	}
	if _, ok := vals["fsync"]; !ok {
		t.Error("expected fsync in params (drives the durability rule)")
	}
}

// TestPostgresIntrospector_SlowQueries boots Postgres with
// pg_stat_statements preloaded so the slow-query path (the one the stock
// image cannot exercise) actually runs.
func TestPostgresIntrospector_SlowQueries(t *testing.T) {
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("app"),
		tcpostgres.WithUsername("sh_agent"),
		tcpostgres.WithPassword("secret"),
		testcontainers.WithCmd("postgres", "-c", "shared_preload_libraries=pg_stat_statements"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	defer func() { _ = c.Terminate(ctx) }()

	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("dsn: %v", err)
	}
	db, err := open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS pg_stat_statements`); err != nil {
		t.Fatalf("create extension: %v", err)
	}
	// Generate some statements to rank.
	for i := 0; i < 3; i++ {
		_, _ = db.ExecContext(ctx, `SELECT count(*) FROM pg_class`)
	}

	snap, err := postgresIntrospector{}.collect(ctx, db, sections{state: true, slow: true}, 20)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !snap.Capabilities["pg_stat_statements"] {
		t.Fatal("expected pg_stat_statements capability=true")
	}
	if snap.SlowQueries == nil {
		t.Fatal("expected slow_queries section when pg_stat_statements is loaded")
	}
	var qs []slowQuery
	if err := json.Unmarshal(snap.SlowQueries, &qs); err != nil {
		t.Fatalf("slow_queries json: %v", err)
	}
	if len(qs) == 0 {
		t.Error("expected at least one ranked query")
	}
}

// TestMariaDBIntrospector_Live validates the MySQL bundle + fork
// detection against MariaDB (version string branch).
func TestMariaDBIntrospector_Live(t *testing.T) {
	ctx := context.Background()
	c, err := tcmysql.Run(ctx, "mariadb:11",
		tcmysql.WithDatabase("app"),
		tcmysql.WithUsername("sh_agent"),
		tcmysql.WithPassword("secret"),
		// MariaDB logs "port: 3306 ... mariadb.org binary distribution",
		// not the MySQL line the module's default wait matches.
		testcontainers.WithWaitStrategy(
			wait.ForLog("port: 3306").WithStartupTimeout(120*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start mariadb: %v", err)
	}
	defer func() { _ = c.Terminate(ctx) }()

	dsn, err := c.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("dsn: %v", err)
	}
	db, err := open("mysql", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	snap, err := mysqlIntrospector{}.collect(ctx, db, sections{state: true, params: true}, 20)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if snap.Fork != "mariadb" {
		t.Errorf("fork = %q, want mariadb", snap.Fork)
	}
	var vals map[string]string
	if err := json.Unmarshal(snap.Parameters.Values, &vals); err != nil {
		t.Fatalf("params json: %v", err)
	}
	if _, ok := vals["innodb_buffer_pool_size"]; !ok {
		t.Error("expected innodb_buffer_pool_size in params")
	}
}

// TestGaleraIntrospector_Live boots a single-node Galera (MariaDB with
// the wsrep provider) so the galera fork-detection path runs.
func TestGaleraIntrospector_Live(t *testing.T) {
	ctx := context.Background()
	c, err := tcmysql.Run(ctx, "mariadb:11",
		tcmysql.WithDatabase("app"),
		tcmysql.WithUsername("sh_agent"),
		tcmysql.WithPassword("secret"),
		testcontainers.WithCmd(
			"--wsrep-new-cluster",
			"--wsrep-on=ON",
			"--wsrep-provider=/usr/lib/galera/libgalera_smm.so",
			"--wsrep-cluster-address=gcomm://",
			"--bind-address=0.0.0.0",
			// Galera requires ROW binlog + autoinc lock mode 2.
			"--binlog-format=ROW",
			"--innodb-autoinc-lock-mode=2",
		),
		testcontainers.WithWaitStrategy(
			wait.ForLog("port: 3306").WithStartupTimeout(120*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start galera: %v", err)
	}
	defer func() { _ = c.Terminate(ctx) }()

	dsn, err := c.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("dsn: %v", err)
	}
	db, err := open("mysql", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	snap, err := mysqlIntrospector{}.collect(ctx, db, sections{state: true}, 20)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if snap.Fork != "galera" {
		t.Errorf("fork = %q, want galera (wsrep detection)", snap.Fork)
	}
}

func TestMySQLIntrospector_Live(t *testing.T) {
	ctx := context.Background()
	c, err := tcmysql.Run(ctx, "mysql:8.0",
		tcmysql.WithDatabase("app"),
		tcmysql.WithUsername("sh_agent"),
		tcmysql.WithPassword("secret"),
	)
	if err != nil {
		t.Fatalf("start mysql: %v", err)
	}
	defer func() { _ = c.Terminate(ctx) }()

	dsn, err := c.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("dsn: %v", err)
	}
	db, err := open("mysql", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	snap, err := mysqlIntrospector{}.collect(ctx, db, sections{state: true, params: true}, 20)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !snap.Reachable {
		t.Fatal("expected reachable")
	}
	if snap.EngineVersion == "" {
		t.Error("expected engine_version")
	}

	var st normState
	if err := json.Unmarshal(snap.State, &st); err != nil {
		t.Fatalf("state json: %v", err)
	}
	if st.Connections.Max <= 0 {
		t.Errorf("expected max_connections > 0, got %d", st.Connections.Max)
	}

	if snap.Parameters == nil {
		t.Fatal("expected parameters section")
	}
	var vals map[string]string
	if err := json.Unmarshal(snap.Parameters.Values, &vals); err != nil {
		t.Fatalf("params json: %v", err)
	}
	if _, ok := vals["innodb_buffer_pool_size"]; !ok {
		t.Error("expected innodb_buffer_pool_size in params (drives the sizing rule)")
	}
}
