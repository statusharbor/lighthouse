package requests

import (
	"cmp"
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf"
)

// Limits from the plan.
const (
	MinRequests    = 20  // fewer per interval: no percentiles, no error share (L7-U-F6)
	MaxLatencySecs = 60. // longer requests are streams, not in latency (L7-U-F10)
)

// OBI histogram families and what they are.
var families = map[string]string{
	"http_server_request_duration_seconds": "http",
	"rpc_server_duration_seconds":          "grpc",
	"db_client_operation_duration_seconds": "sql",
}

// gRPC codes that are the server's fault (L7-U-P3, L7-U-F2): UNKNOWN,
// DEADLINE_EXCEEDED, UNIMPLEMENTED, INTERNAL, UNAVAILABLE, DATA_LOSS.
var grpcServerErrors = map[string]bool{"2": true, "4": true, "12": true, "13": true, "14": true, "15": true}

// Health-probe routes are not real traffic (L7-U-F4).
var healthRoutes = map[string]bool{
	"/health": true, "/healthz": true, "/healthcheck": true, "/livez": true, "/readyz": true,
	"/ready": true, "/live": true, "/ping": true,
}

// healthRoute matches a health route and its sub-paths, such as
// /healthz/live or Spring's /health/liveness.
func healthRoute(r string) bool {
	if i := strings.IndexByte(r[min(1, len(r)):], '/'); i >= 0 {
		r = r[:i+1]
	}
	return healthRoutes[r]
}

// CheckTarget is one of Lighthouse's own active checks on this host, whose
// requests are not real traffic (L7-U-F4).
type CheckTarget struct {
	Port string
	Path string
}

// histKey identifies one OBI histogram series after the privacy filter:
// only kind, service, route and outcome survive (L7-U-F11).
type histKey struct {
	kind, service, route string
	outcome              string // "server_error", "client_error" or "ok"
}

type hist struct {
	count   float64
	buckets map[float64]float64 // le -> cumulative count
}

var (
	rawID   = regexp.MustCompile(`^([0-9]+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{36})$`)
	sqlVerb = regexp.MustCompile(`^[A-Za-z]+$`)
)

// templateRoute guards against raw identifiers in routes: numeric, hex and
// UUID segments become {id} (criterion 5).
func templateRoute(r string) string {
	if r == "" {
		return "/"
	}
	segs := strings.Split(r, "/")
	for i, s := range segs {
		if rawID.MatchString(s) {
			segs[i] = "{id}"
		}
	}
	return strings.Join(segs, "/")
}

// withPort appends the server port to a service identity. Client-side
// series (SQL) have none, and OBI reports 0 when it cannot tell; the
// identity then stands alone rather than as "svc:" or "svc:0".
func withPort(id, port string) string {
	if port == "" || port == "0" {
		return id
	}
	return id + ":" + port
}

// classify maps one OBI series to its filtered key, or false to drop it.
// service resolves OBI's instance ("host:pid"), job and port to the plan 03
// service identity.
func classify(name string, l map[string]string, service func(instance, job, port string) string, checks []CheckTarget) (histKey, bool) {
	kind, ok := families[name]
	if !ok {
		return histKey{}, false
	}
	k := histKey{kind: kind, service: service(l["instance"], l["job"], l["server_port"]), outcome: "ok"}
	if k.service == "" {
		return histKey{}, false
	}
	switch kind {
	case "http":
		k.route = templateRoute(l["http_route"])
		if healthRoute(k.route) {
			return histKey{}, false
		}
		for _, c := range checks {
			if c.Port == l["server_port"] && c.Path == k.route {
				return histKey{}, false
			}
		}
		code, _ := strconv.Atoi(l["http_response_status_code"])
		switch {
		case code >= 500 && code <= 599: // L7-U-P2
			k.outcome = "server_error"
		case code >= 400 && code <= 499: // L7-U-F1, F3 (499: client closed)
			k.outcome = "client_error"
		}
	case "grpc":
		k.route = l["rpc_method"]
		if grpcServerErrors[l["rpc_grpc_status_code"]] {
			k.outcome = "server_error"
		}
	case "sql":
		system := cmp.Or(l["db_system_name"], l["db_system"])
		op := strings.ToUpper(cmp.Or(l["db_operation_name"], l["db_operation"]))
		if !sqlVerb.MatchString(op) {
			op = "OTHER" // never let a statement fragment through
		}
		k.route = system + " " + op
		if l["error_type"] != "" {
			k.outcome = "server_error"
		}
	}
	return k, true
}

// snapshot groups one scrape into histograms by filtered key. Series that
// differ only in dropped labels are summed.
func snapshot(samples []sample, service func(instance, job, port string) string, checks []CheckTarget) map[histKey]*hist {
	out := map[histKey]*hist{}
	for _, s := range samples {
		var base, part string
		switch {
		case strings.HasSuffix(s.name, "_bucket"):
			base, part = strings.TrimSuffix(s.name, "_bucket"), "bucket"
		case strings.HasSuffix(s.name, "_count"):
			base, part = strings.TrimSuffix(s.name, "_count"), "count"
		default:
			continue
		}
		k, ok := classify(base, s.labels, service, checks)
		if !ok {
			continue
		}
		h := out[k]
		if h == nil {
			h = &hist{buckets: map[float64]float64{}}
			out[k] = h
		}
		if part == "count" {
			h.count += s.value
			continue
		}
		le, err := strconv.ParseFloat(s.labels["le"], 64)
		if err != nil {
			le = math.Inf(1)
		}
		h.buckets[le] += s.value
	}
	return out
}

// delta returns cur - prev per key. A count that went down means OBI
// restarted: the new totals are the baseline, not a spike (L7-U-F5). Keys
// first seen produce nothing (a scrape gives running totals since OBI
// started). Delta temporality is not used: Prometheus is cumulative, so
// both temporalities upstream give the same rate (L7-U-P5).
func delta(prev, cur map[histKey]*hist) map[histKey]*hist {
	out := map[histKey]*hist{}
	for k, c := range cur {
		p, ok := prev[k]
		if !ok || c.count < p.count {
			continue
		}
		d := &hist{count: c.count - p.count, buckets: map[float64]float64{}}
		for le, v := range c.buckets {
			d.buckets[le] = math.Max(0, v-p.buckets[le])
		}
		out[k] = d
	}
	return out
}

// quantile interpolates within cumulative buckets like PromQL's
// histogram_quantile, over requests up to MaxLatencySecs only.
func quantile(buckets map[float64]float64, q float64) (float64, bool) {
	les := make([]float64, 0, len(buckets))
	for le := range buckets {
		if le <= MaxLatencySecs {
			les = append(les, le)
		}
	}
	sort.Float64s(les)
	if len(les) == 0 || buckets[les[len(les)-1]] == 0 {
		return 0, false
	}
	total := buckets[les[len(les)-1]]
	rank := q * total
	prevLE, prevCount := 0.0, 0.0
	for _, le := range les {
		c := buckets[le]
		if c >= rank {
			if c == prevCount {
				return le, true
			}
			return prevLE + (le-prevLE)*(rank-prevCount)/(c-prevCount), true
		}
		prevLE, prevCount = le, c
	}
	return les[len(les)-1], true
}

type routeKey struct{ kind, service, route string }

type routeStats struct {
	total, serverErr, clientErr float64
	buckets                     map[float64]float64
}

// Series is one output gauge.
type Series struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// convert turns one interval's deltas into gauges: per route (the 50
// busiest per service and kind, the rest as "other") and per service
// ("*"): request rate, server and client error share and p50/p95/p99
// latency in ms. Below MinRequests a point is marked low sample and gets no
// error share or percentiles; zero requests give a zero rate and nothing
// else (L7-U-F7).
func convert(d map[histKey]*hist, elapsed time.Duration) []Series {
	routes := map[routeKey]*routeStats{}
	add := func(k routeKey, h *hist, outcome string) {
		r := routes[k]
		if r == nil {
			r = &routeStats{buckets: map[float64]float64{}}
			routes[k] = r
		}
		r.total += h.count
		switch outcome {
		case "server_error":
			r.serverErr += h.count
		case "client_error":
			r.clientErr += h.count
		}
		for le, v := range h.buckets {
			r.buckets[le] += v
		}
	}
	for k, h := range d {
		add(routeKey{k.kind, k.service, k.route}, h, k.outcome)
	}

	// Service quota: past it, the quietest services are one "other"
	// service. Then the route limit per service and kind (L7-U-P4, L7-U-F9).
	q := ebpf.Quota()
	svcTotal := map[string]float64{}
	for k, r := range routes {
		svcTotal[k.service] += r.total
	}
	if len(svcTotal) > q.Services {
		names := make([]string, 0, len(svcTotal))
		for s := range svcTotal {
			names = append(names, s)
		}
		slices.SortFunc(names, func(a, b string) int { return cmp.Or(cmp.Compare(svcTotal[b], svcTotal[a]), strings.Compare(a, b)) })
		keep := map[string]bool{}
		for _, s := range names[:q.Services] {
			keep[s] = true
		}
		folded := map[routeKey]*routeStats{}
		for k, r := range routes {
			if !keep[k.service] {
				k = routeKey{k.kind, "other", "other"}
			}
			f := folded[k]
			if f == nil {
				f = &routeStats{buckets: map[float64]float64{}}
				folded[k] = f
			}
			f.total += r.total
			f.serverErr += r.serverErr
			f.clientErr += r.clientErr
			for le, v := range r.buckets {
				f.buckets[le] += v
			}
		}
		routes = folded
	}
	type svcKind struct{ kind, service string }
	bySvc := map[svcKind][]routeKey{}
	for k := range routes {
		bySvc[svcKind{k.kind, k.service}] = append(bySvc[svcKind{k.kind, k.service}], k)
	}
	final := map[routeKey]*routeStats{}
	merge := func(into routeKey, r *routeStats) {
		f := final[into]
		if f == nil {
			f = &routeStats{buckets: map[float64]float64{}}
			final[into] = f
		}
		f.total += r.total
		f.serverErr += r.serverErr
		f.clientErr += r.clientErr
		for le, v := range r.buckets {
			f.buckets[le] += v
		}
	}
	for sk, keys := range bySvc {
		slices.SortFunc(keys, func(a, b routeKey) int {
			return cmp.Or(cmp.Compare(routes[b].total, routes[a].total), strings.Compare(a.route, b.route))
		})
		for i, k := range keys {
			merge(routeKey{sk.kind, sk.service, "*"}, routes[k])
			if i < q.Routes {
				merge(k, routes[k])
			} else {
				merge(routeKey{sk.kind, sk.service, "other"}, routes[k])
			}
		}
	}

	secs := elapsed.Seconds()
	var out []Series
	for k, r := range final {
		l := func(extra ...string) map[string]string {
			m := map[string]string{"kind": k.kind, "service": k.service, "route": k.route}
			for i := 0; i+1 < len(extra); i += 2 {
				m[extra[i]] = extra[i+1]
			}
			return m
		}
		out = append(out, Series{"lighthouse_l7_requests_per_second", l(), r.total / secs})
		switch {
		case r.total == 0:
			continue
		case r.total < MinRequests:
			out = append(out, Series{"lighthouse_l7_low_sample", l(), 1})
			continue
		}
		out = append(out, Series{"lighthouse_l7_server_error_ratio", l(), r.serverErr / r.total})
		if k.kind == "http" {
			out = append(out, Series{"lighthouse_l7_client_error_ratio", l(), r.clientErr / r.total})
		}
		for _, q := range []float64{0.5, 0.95, 0.99} {
			if v, ok := quantile(r.buckets, q); ok {
				out = append(out, Series{"lighthouse_l7_latency_ms", l("quantile", strconv.FormatFloat(q, 'f', -1, 64)), v * 1000})
			}
		}
	}
	return out
}
