package database

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// postgresIntrospector runs the Postgres read-only bundle. Requires the
// pg_monitor role (see docs/databases/plan.md). Queries target PG 12+.
//
// ponytail: this is integration-tested against a live Postgres, not in
// unit tests - the queries are the contract with the engine, not logic
// we can meaningfully mock. Version-specific column names (e.g.
// pg_stat_statements total_exec_time is PG13+) are the known ceiling.
type postgresIntrospector struct{}

func (postgresIntrospector) collect(ctx context.Context, db *sql.DB, sec sections, topN int) (transport.DBNodeSnapshot, error) {
	snap := transport.DBNodeSnapshot{Reachable: true, Fork: "postgres", Capabilities: map[string]bool{}}

	// Identity + role + version (cheap, always).
	_ = db.QueryRowContext(ctx, `SELECT system_identifier::text FROM pg_control_system()`).Scan(&snap.ServerIdentity)
	var inRecovery bool
	if err := db.QueryRowContext(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery); err != nil {
		return snap, err
	}
	snap.Role = "primary"
	if inRecovery {
		snap.Role = "replica"
	}
	_ = db.QueryRowContext(ctx, `SHOW server_version`).Scan(&snap.EngineVersion)

	// pg_stat_statements availability.
	var hasPSS bool
	_ = db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname='pg_stat_statements')`).Scan(&hasPSS)
	snap.Capabilities["pg_stat_statements"] = hasPSS

	if sec.state {
		if b, err := pgState(ctx, db); err == nil {
			snap.State = b
		}
		if !inRecovery {
			if b, err := pgReplication(ctx, db); err == nil {
				snap.Replication = b
			}
		}
	}
	if sec.params {
		if p, err := pgParams(ctx, db); err == nil {
			snap.Parameters = p
		}
	}
	if sec.slow && hasPSS {
		if b, err := pgSlow(ctx, db, topN); err == nil {
			snap.SlowQueries = b
		}
	}
	if sec.sizing {
		if b, err := pgSizing(ctx, db); err == nil {
			snap.Sizing = b
		}
	}
	return snap, nil
}

func pgSizing(ctx context.Context, db *sql.DB) ([]byte, error) {
	var sz normSizing
	if err := db.QueryRowContext(ctx, `SELECT pg_database_size(current_database())`).Scan(&sz.DBBytes); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT relname, pg_total_relation_size(relid)
		FROM pg_catalog.pg_statio_user_tables
		ORDER BY pg_total_relation_size(relid) DESC
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

func pgState(ctx context.Context, db *sql.DB) ([]byte, error) {
	var st normState
	if err := db.QueryRowContext(ctx, `
		SELECT
			count(*) FILTER (WHERE state = 'active'),
			count(*) FILTER (WHERE state = 'idle'),
			count(*) FILTER (WHERE state = 'idle in transaction'),
			(SELECT setting::int FROM pg_settings WHERE name = 'max_connections'),
			COALESCE(EXTRACT(EPOCH FROM max(now() - xact_start)), 0)
		FROM pg_stat_activity
	`).Scan(&st.Connections.Active, &st.Connections.Idle, &st.Connections.IdleInTxn, &st.Connections.Max, &st.LongestTxnSeconds); err != nil {
		return nil, err
	}
	_ = db.QueryRowContext(ctx, `SELECT COALESCE(sum(deadlocks), 0) FROM pg_stat_database`).Scan(&st.DeadlocksTotal)
	_ = db.QueryRowContext(ctx, `
		SELECT COALESCE(sum(blks_hit)::float8 / NULLIF(sum(blks_hit) + sum(blks_read), 0), 1)
		FROM pg_stat_database
	`).Scan(&st.CacheHitRatio)
	_ = db.QueryRowContext(ctx, `
		SELECT COALESCE(max(age(datfrozenxid))::float8 / 2000000000.0, 0) FROM pg_database
	`).Scan(&st.TxnWraparoundPct)
	return json.Marshal(st)
}

func pgReplication(ctx context.Context, db *sql.DB) ([]byte, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT
			COALESCE(client_addr::text, application_name),
			COALESCE(EXTRACT(EPOCH FROM (now() - reply_time)), 0),
			(sync_state = 'sync')
		FROM pg_stat_replication
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var rep normReplication
	for rows.Next() {
		var r normReplica
		if err := rows.Scan(&r.NodeKey, &r.LagSeconds, &r.Sync); err != nil {
			return nil, err
		}
		rep.Replicas = append(rep.Replicas, r)
	}
	return json.Marshal(rep)
}

func pgParams(ctx context.Context, db *sql.DB) (*transport.DBParams, error) {
	// SHOW ALL returns human-readable values ("128MB"), which the
	// Console's rules parse directly - unlike pg_settings, which reports
	// memory in internal block units.
	rows, err := db.QueryContext(ctx, `SHOW ALL`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	values := map[string]string{}
	for rows.Next() {
		var name, setting, desc string
		if err := rows.Scan(&name, &setting, &desc); err != nil {
			return nil, err
		}
		values[name] = setting
	}
	return marshalParams(values)
}

func pgSlow(ctx context.Context, db *sql.DB, topN int) ([]byte, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT query, calls, mean_exec_time, total_exec_time, rows, shared_blks_read
		FROM pg_stat_statements
		ORDER BY total_exec_time DESC
		LIMIT $1
	`, topN)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []slowQuery
	for rows.Next() {
		var q slowQuery
		if err := rows.Scan(&q.Query, &q.Calls, &q.MeanMs, &q.TotalMs, &q.Rows, &q.SharedBlksRead); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return json.Marshal(out)
}
