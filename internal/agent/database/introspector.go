package database

import (
	"context"
	"database/sql"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// sections says which snapshot kinds are due this tick (tiered cadence).
type sections struct {
	state  bool
	params bool
	slow   bool
	sizing bool
}

// introspector is the one seam the Postgres/MySQL split lives behind.
// Each implementation runs only read-only queries and returns facts.
type introspector interface {
	// collect fills a node snapshot: identity + role + capabilities
	// always, plus whichever sections are due. db is already open.
	collect(ctx context.Context, db *sql.DB, sec sections, topN int) (transport.DBNodeSnapshot, error)
}

func introspectorFor(engine string) introspector {
	if engine == "mysql" {
		return mysqlIntrospector{}
	}
	return postgresIntrospector{}
}

// normState is the normalized state the Console expects (facts, not
// judgments). Marshalled into DBNodeSnapshot.State.
type normState struct {
	Connections struct {
		Active    int `json:"active"`
		Idle      int `json:"idle"`
		IdleInTxn int `json:"idle_in_txn"`
		Max       int `json:"max"`
	} `json:"connections"`
	LongestTxnSeconds float64 `json:"longest_txn_seconds"`
	DeadlocksTotal    int     `json:"deadlocks_total"`
	CacheHitRatio     float64 `json:"cache_hit_ratio"`
	TxnWraparoundPct  float64 `json:"txn_wraparound_pct"`
	// WsrepState is the Galera node state (e.g. "Synced", "Donor",
	// "Joining"); empty for non-Galera. Drives the member_left signal.
	WsrepState string `json:"wsrep_state,omitempty"`
}

// normReplication mirrors the Console's replication shape.
type normReplication struct {
	Replicas []normReplica `json:"replicas"`
}

type normReplica struct {
	NodeKey    string  `json:"node_key"`
	LagSeconds float64 `json:"lag_seconds"`
	Sync       bool    `json:"sync"`
}

// normSizing is the storage-footprint fact set.
type normSizing struct {
	DBBytes   int64       `json:"db_bytes"`
	TopTables []tableSize `json:"top_tables"`
}

type tableSize struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
}

// slowQuery is one ranked entry.
type slowQuery struct {
	Query          string  `json:"query"`
	Calls          int64   `json:"calls"`
	MeanMs         float64 `json:"mean_ms"`
	TotalMs        float64 `json:"total_ms"`
	Rows           int64   `json:"rows"`
	SharedBlksRead int64   `json:"shared_blks_read,omitempty"`
}
