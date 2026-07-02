package database

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// snapshotSender is the transport surface the controller needs. *transport.Client
// satisfies it; tests can stub it.
type snapshotSender interface {
	SendDatabaseSnapshots(ctx context.Context, req transport.DBSnapshotRequest) error
}

// SealedDSNOpener opens a per-agent sealed DSN (design #10). *agent.AgentKeypair
// satisfies it; a nil opener means the agent registered no public key, so the
// Console sends plaintext DSNs and no node should carry a sealed one. Kept as
// an interface so the database package stays free of an import cycle back to
// the agent package.
type SealedDSNOpener interface {
	OpenSealedDSN(sealedB64 string) (string, error)
}

// DatabaseController mirrors HostMetricsController: it owns the tri-state
// ApplyGate and one goroutine per active cluster. Under Option B the
// gate carries everything - cadences AND the node DSNs - so there is no
// local config; the controller builds collectors entirely from the gate.
// A plan flip or DSN edit on /heartbeat starts/stops/reconfigures
// collection live, no agent restart.
type DatabaseController struct {
	sender       snapshotSender
	agentVersion string
	// opener resolves sealed DSNs to plaintext with the agent's keypair.
	// nil when the agent registered no public key (plaintext-DSN path).
	opener SealedDSNOpener

	mu      sync.Mutex
	running map[string]*clusterRunner
}

type clusterRunner struct {
	cancel context.CancelFunc
	gate   atomic.Pointer[transport.DatabaseGateCluster]
	// slowExpiry is the self-expiry deadline of the slow-query live lease
	// (#24): now()+SlowQueryLiveTTLSeconds computed when a fresh gate was
	// applied. Nil / zero means no active lease, so slow queries are not
	// collected. Recomputed only on a fresh (re-fetched) gate so a
	// superseding lease extends / shortens / stops it; the cached
	// per-heartbeat re-apply leaves it alone, letting the lease count down
	// and expire on the agent's own clock. Atomic so runCluster reads it
	// lock-free.
	slowExpiry atomic.Pointer[time.Time]
}

func (r *clusterRunner) setSlowExpiry(t time.Time) { r.slowExpiry.Store(&t) }

// slowLeaseActive reports whether the slow-query live lease is still open at
// now. False when no lease was set (zero deadline) or the deadline passed.
func (r *clusterRunner) slowLeaseActive(now time.Time) bool {
	d := r.slowExpiry.Load()
	return d != nil && !d.IsZero() && now.Before(*d)
}

// slowExpiryFrom converts a lease TTL (remaining seconds, as the console
// sends it) into an absolute self-expiry deadline from the local clock now.
// Because the TTL is RELATIVE, the deadline is immune to agent<->console
// clock skew (#24). A non-positive TTL means no active lease -> zero time.
func slowExpiryFrom(ttlSeconds int) time.Time {
	if ttlSeconds <= 0 {
		return time.Time{}
	}
	return time.Now().Add(time.Duration(ttlSeconds) * time.Second)
}

// NewController builds the controller. No config - DSNs arrive via the gate.
// opener is the agent keypair used to open sealed DSNs (design #10); pass nil
// when the agent has no keypair, in which case gate nodes are expected to
// carry plaintext DSNs.
func NewController(sender snapshotSender, agentVersion string, opener SealedDSNOpener) *DatabaseController {
	return &DatabaseController{
		sender:       sender,
		agentVersion: agentVersion,
		opener:       opener,
		running:      map[string]*clusterRunner{},
	}
}

// ApplyGate reconciles running collectors against the Console gate. fresh is
// true only when the gate was just re-fetched from /config (a new lease
// epoch); on a fresh gate the slow-query live lease (#24) is reset to
// now()+TTL, while a cached per-heartbeat re-apply (fresh=false) leaves the
// running lease untouched so it expires on schedule.
func (c *DatabaseController) ApplyGate(gate *transport.DatabaseGate, fresh bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	desired := map[string]transport.DatabaseGateCluster{}
	if gate != nil && gate.Enabled {
		for _, gc := range gate.Clusters {
			if len(gc.Nodes) > 0 {
				desired[gc.DatabaseID] = gc
			}
		}
	}

	// Stop clusters no longer desired.
	for id, r := range c.running {
		if _, ok := desired[id]; !ok {
			r.cancel()
			delete(c.running, id)
		}
	}
	// Start new ones, update cadence + DSNs on existing.
	for id, gc := range desired {
		gcCopy := gc
		if r, ok := c.running[id]; ok {
			r.gate.Store(&gcCopy)
			if fresh {
				// Superseding lease (start / extend / shorten / stop) - reset
				// the deadline. Never on a cached re-apply, else the lease
				// would be pushed forward every heartbeat and never expire.
				r.setSlowExpiry(slowExpiryFrom(gcCopy.SlowQueryLiveTTLSeconds))
			}
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		r := &clusterRunner{cancel: cancel}
		r.gate.Store(&gcCopy)
		// Seed the slow-query lease at cluster start from its TTL (a new
		// cluster only ever arrives on a fresh gate).
		r.setSlowExpiry(slowExpiryFrom(gcCopy.SlowQueryLiveTTLSeconds))
		c.running[id] = r
		go c.runCluster(ctx, id, r)
	}
}

// Stop halts all collectors (called on shutdown).
func (c *DatabaseController) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, r := range c.running {
		r.cancel()
		delete(c.running, id)
	}
}

// runCluster is the per-cluster loop. Base ticker at the state cadence;
// params/slow/sizing fire on their own longer intervals ("next due").
func (c *DatabaseController) runCluster(ctx context.Context, databaseID string, r *clusterRunner) {
	dbs := map[string]*sql.DB{} // dsn -> open handle, reused across ticks
	defer func() {
		for _, db := range dbs {
			_ = db.Close()
		}
	}()

	var lastParams, lastSlow, lastSizing time.Time
	for {
		gc := r.gate.Load()
		sec := sections{state: true}
		now := time.Now()
		if due(now, lastParams, gc.ParamsIntervalSeconds) {
			sec.params = true
			lastParams = now
		}
		// Slow queries are lease-gated (#24): collect at the slow cadence
		// only while the live lease is open, and stop once it self-expires.
		// state / params / sizing are unaffected.
		if r.slowLeaseActive(now) && due(now, lastSlow, gc.SlowQueryIntervalSeconds) {
			sec.slow = true
			lastSlow = now
		}
		if due(now, lastSizing, gc.SizingIntervalSeconds) {
			sec.sizing = true
			lastSizing = now
		}

		if err := c.collectAndSend(ctx, databaseID, gc, sec, dbs); err != nil {
			if err == transport.ErrDatabaseGone {
				slog.Info("database dropped by console, stopping collector", "database_id", databaseID)
				return
			}
			slog.Warn("database snapshot failed", "database_id", databaseID, "err", err)
		}

		wait := time.Duration(clampInterval(gc.StateIntervalSeconds)) * time.Second
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (c *DatabaseController) collectAndSend(ctx context.Context, databaseID string, gc *transport.DatabaseGateCluster, sec sections, dbs map[string]*sql.DB) error {
	intro := introspectorFor(gc.Engine)
	req := transport.DBSnapshotRequest{
		DatabaseID:   databaseID,
		CollectedAt:  time.Now().UTC(),
		AgentVersion: c.agentVersion,
	}
	for _, gn := range gc.Nodes {
		dsn, err := c.resolveDSN(gn)
		if err != nil {
			// A node whose sealed DSN won't open is skipped, not fatal -
			// the other nodes in the cluster still collect. No snapshot row
			// is emitted since we never reached the database to know its
			// reachability.
			slog.Warn("skipping database node: sealed dsn open failed",
				"database_id", databaseID, "node_id", gn.NodeID, "err", err)
			continue
		}
		nodeKey := nodeKeyFromDSN(gc.Engine, dsn)
		db, ok := dbs[dsn]
		if !ok {
			opened, err := open(gc.Engine, dsn)
			if err != nil {
				req.Nodes = append(req.Nodes, transport.DBNodeSnapshot{NodeID: gn.NodeID, NodeKey: nodeKey, Reachable: false, Error: err.Error()})
				continue
			}
			db = opened
			dbs[dsn] = db
		}
		qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		snap, err := intro.collect(qctx, db, sec, topN(gc))
		cancel()
		snap.NodeID = gn.NodeID
		snap.NodeKey = nodeKey
		if err != nil {
			snap.Reachable = false
			snap.Error = err.Error()
		}
		req.Nodes = append(req.Nodes, snap)
	}
	return c.sender.SendDatabaseSnapshots(ctx, req)
}

// resolveDSN returns the plaintext DSN for a gate node. A sealed DSN is
// opened with the agent's keypair (held only in memory); an unsealed node
// uses its plaintext DSN as before. A node that carries a sealed DSN but no
// opener (the agent registered no key) is a Console/agent mismatch - report
// it as an error so the caller skips the node rather than dialing an empty
// DSN.
func (c *DatabaseController) resolveDSN(gn transport.DatabaseGateNode) (string, error) {
	if gn.DSNSealed == "" {
		return gn.DSN, nil
	}
	if c.opener == nil {
		return "", errors.New("node carries a sealed dsn but agent has no keypair")
	}
	return c.opener.OpenSealedDSN(gn.DSNSealed)
}

func due(now, last time.Time, intervalSecs int) bool {
	if last.IsZero() {
		return true
	}
	return now.Sub(last) >= time.Duration(intervalSecs)*time.Second
}

func clampInterval(s int) int {
	if s < 15 {
		return 15
	}
	return s
}

func topN(gc *transport.DatabaseGateCluster) int {
	if gc.SlowQueryTopN <= 0 {
		return 20
	}
	return gc.SlowQueryTopN
}
