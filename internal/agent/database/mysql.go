package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// mysqlIntrospector runs the MySQL/MariaDB/Galera read-only bundle.
// Requires PROCESS, REPLICATION CLIENT + SELECT on performance_schema.
// Fork is detected at collection (MariaDB via VERSION(), Galera via
// wsrep_* status). Integration-tested against a live server.
type mysqlIntrospector struct{}

func (mysqlIntrospector) collect(ctx context.Context, db *sql.DB, sec sections, topN int) (transport.DBNodeSnapshot, error) {
	snap := transport.DBNodeSnapshot{Reachable: true, Fork: "mysql", Capabilities: map[string]bool{}}

	_ = db.QueryRowContext(ctx, `SELECT @@server_uuid`).Scan(&snap.ServerIdentity)
	var version string
	_ = db.QueryRowContext(ctx, `SELECT VERSION()`).Scan(&version)
	snap.EngineVersion = version
	if strings.Contains(strings.ToLower(version), "mariadb") {
		snap.Fork = "mariadb"
	}

	// Galera detection - wsrep provider loaded + node state.
	var wsrepState string
	if err := db.QueryRowContext(ctx, `SHOW STATUS LIKE 'wsrep_local_state_comment'`).Scan(new(string), &wsrepState); err == nil && wsrepState != "" {
		snap.Fork = "galera"
	}

	// Role: read_only replicas report 1. A primary is writable.
	var readOnly bool
	_ = db.QueryRowContext(ctx, `SELECT @@read_only`).Scan(&readOnly)
	snap.Role = "primary"
	if readOnly {
		snap.Role = "replica"
	}

	// performance_schema availability gates slow queries.
	var psOn string
	_ = db.QueryRowContext(ctx, `SELECT @@performance_schema`).Scan(&psOn)
	snap.Capabilities["performance_schema"] = psOn == "1" || strings.EqualFold(psOn, "ON")

	if sec.state {
		if b, err := mysqlState(ctx, db); err == nil {
			snap.State = b
		}
	}
	if sec.params {
		if p, err := mysqlParams(ctx, db); err == nil {
			snap.Parameters = p
		}
	}
	if sec.slow && snap.Capabilities["performance_schema"] {
		if b, err := mysqlSlow(ctx, db, topN); err == nil {
			snap.SlowQueries = b
		}
	}
	if sec.sizing {
		if b, err := mysqlSizing(ctx, db); err == nil {
			snap.Sizing = b
		}
	}
	return snap, nil
}

func mysqlSizing(ctx context.Context, db *sql.DB) ([]byte, error) {
	var sz normSizing
	_ = db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(data_length + index_length), 0)
		FROM information_schema.tables WHERE table_schema = DATABASE()
	`).Scan(&sz.DBBytes)
	rows, err := db.QueryContext(ctx, `
		SELECT table_name, data_length + index_length
		FROM information_schema.tables
		WHERE table_schema = DATABASE()
		ORDER BY data_length + index_length DESC
		LIMIT 5
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var t tableSize
		if err := rows.Scan(&t.Name, &t.Bytes); err != nil {
			return nil, err
		}
		sz.TopTables = append(sz.TopTables, t)
	}
	return json.Marshal(sz)
}

func mysqlState(ctx context.Context, db *sql.DB) ([]byte, error) {
	var st normState
	status := showKeyValue(ctx, db, `SHOW GLOBAL STATUS`)
	st.Connections.Active = atoi(status["Threads_running"])
	st.Connections.Idle = atoi(status["Threads_connected"]) - st.Connections.Active
	if st.Connections.Idle < 0 {
		st.Connections.Idle = 0
	}
	_ = db.QueryRowContext(ctx, `SELECT @@max_connections`).Scan(&st.Connections.Max)
	st.DeadlocksTotal = atoi(status["Innodb_deadlocks"]) // absent on vanilla MySQL -> 0
	// Buffer-pool hit ratio as the cache_hit_ratio analogue.
	reads := float64(atoi(status["Innodb_buffer_pool_reads"]))
	reqs := float64(atoi(status["Innodb_buffer_pool_read_requests"]))
	if reqs > 0 {
		st.CacheHitRatio = 1 - reads/reqs
	} else {
		st.CacheHitRatio = 1
	}
	// Galera node membership state - empty on non-Galera servers.
	_ = db.QueryRowContext(ctx, `SHOW STATUS LIKE 'wsrep_local_state_comment'`).Scan(new(string), &st.WsrepState)
	return json.Marshal(st)
}

func mysqlParams(ctx context.Context, db *sql.DB) (*transport.DBParams, error) {
	values := showKeyValue(ctx, db, `SHOW GLOBAL VARIABLES`)
	return marshalParams(values)
}

func mysqlSlow(ctx context.Context, db *sql.DB, topN int) ([]byte, error) {
	// Timers are picoseconds; convert to ms.
	rows, err := db.QueryContext(ctx, `
		SELECT digest_text, count_star,
		       ROUND(avg_timer_wait/1e9, 3), ROUND(sum_timer_wait/1e9, 3), sum_rows_sent
		FROM performance_schema.events_statements_summary_by_digest
		WHERE digest_text IS NOT NULL
		ORDER BY sum_timer_wait DESC
		LIMIT ?
	`, topN)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []slowQuery
	for rows.Next() {
		var q slowQuery
		if err := rows.Scan(&q.Query, &q.Calls, &q.MeanMs, &q.TotalMs, &q.Rows); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return json.Marshal(out)
}

// showKeyValue runs a SHOW ... two-column statement into a map.
func showKeyValue(ctx context.Context, db *sql.DB, query string) map[string]string {
	out := map[string]string{}
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return out
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return out
		}
		out[k] = v
	}
	return out
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// marshalParams hashes the settings map (so the Console can skip
// re-analysis when unchanged) and packages it as the params section.
func marshalParams(values map[string]string) (*transport.DBParams, error) {
	b, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return &transport.DBParams{Hash: hex.EncodeToString(sum[:]), Values: b}, nil
}
