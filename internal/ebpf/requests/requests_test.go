package requests

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf"
)

func svc(instance, job, port string) string { return "exe:/app/" + job + ":" + port }

// hist builds the text lines of one OBI histogram series with count
// requests spread over the given (le, cumulative) buckets.
func histLines(name, labels string, buckets [][2]float64, count float64) string {
	var b strings.Builder
	for _, bk := range buckets {
		le := fmt.Sprint(bk[0])
		if math.IsInf(bk[0], 1) {
			le = "+Inf"
		}
		fmt.Fprintf(&b, "%s_bucket{%s,le=%q} %v\n", name, labels, le, bk[1])
	}
	fmt.Fprintf(&b, "%s_sum{%s} 1\n%s_count{%s} %v\n", name, labels, name, labels, count)
	return b.String()
}

const httpName = "http_server_request_duration_seconds"

func lbl(route, code string) string {
	return fmt.Sprintf(`instance="h:42",job="api",server_port="8080",http_request_method="GET",http_route=%q,http_response_status_code=%q,url_full="https://x/secret?token=hunter2"`, route, code)
}

func scrape(text string, checks ...CheckTarget) map[histKey]*hist {
	return snapshot(parseText(strings.NewReader(text)), svc, checks)
}

func find(out []Series, name, route string, extra ...string) (float64, bool) {
	for _, s := range out {
		if s.Name != name || s.Labels["route"] != route {
			continue
		}
		match := true
		for i := 0; i+1 < len(extra); i += 2 {
			match = match && s.Labels[extra[i]] == extra[i+1]
		}
		if match {
			return s.Value, true
		}
	}
	return 0, false
}

func TestParseText(t *testing.T) {
	got := parseText(strings.NewReader("# HELP x\n# TYPE x counter\nx_total{a=\"b \\\"q\\\"\",c=\"d\"} 3 1700000000000\nbare 1.5\nbroken{a=\"b\" \n\n"))
	if len(got) != 2 || got[0].labels["a"] != `b "q"` || got[0].value != 3 || got[1].name != "bare" {
		t.Fatalf("got %+v", got)
	}
}

func TestConvert(t *testing.T) {
	base := histLines(httpName, lbl("/ok", "200"), [][2]float64{{0.01, 0}, {0.025, 0}, {0.1, 0}, {math.Inf(1), 0}}, 0) +
		histLines(httpName, lbl("/ok", "500"), [][2]float64{{0.01, 0}, {0.025, 0}, {0.1, 0}, {math.Inf(1), 0}}, 0) +
		histLines(httpName, lbl("/ok", "503"), [][2]float64{{0.01, 0}, {0.025, 0}, {0.1, 0}, {math.Inf(1), 0}}, 0) +
		histLines(httpName, lbl("/ok", "404"), [][2]float64{{0.01, 0}, {0.025, 0}, {0.1, 0}, {math.Inf(1), 0}}, 0)
	// 100 requests: 80 x 200 (40 under 10 ms, 40 at 10-25 ms), 5 x 500, 5 x 503, 10 x 404.
	next := histLines(httpName, lbl("/ok", "200"), [][2]float64{{0.01, 40}, {0.025, 80}, {0.1, 80}, {math.Inf(1), 80}}, 80) +
		histLines(httpName, lbl("/ok", "500"), [][2]float64{{0.01, 5}, {0.025, 5}, {0.1, 5}, {math.Inf(1), 5}}, 5) +
		histLines(httpName, lbl("/ok", "503"), [][2]float64{{0.01, 5}, {0.025, 5}, {0.1, 5}, {math.Inf(1), 5}}, 5) +
		histLines(httpName, lbl("/ok", "404"), [][2]float64{{0.01, 10}, {0.025, 10}, {0.1, 10}, {math.Inf(1), 10}}, 10)
	out := convert(delta(scrape(base), scrape(next)), 10*time.Second)

	if v, _ := find(out, "lighthouse_l7_requests_per_second", "/ok"); v != 10 {
		t.Errorf("rate = %v, want 10", v)
	}
	// L7-U-P2 and L7-U-F1: 500 and 503 are server errors, 404 is not.
	if v, _ := find(out, "lighthouse_l7_server_error_ratio", "/ok"); v != 0.1 {
		t.Errorf("server error ratio = %v, want 0.1", v)
	}
	if v, _ := find(out, "lighthouse_l7_client_error_ratio", "/ok"); v != 0.1 {
		t.Errorf("client error ratio = %v, want 0.1", v)
	}
	// L7-U-P1: 60 of 100 under 10 ms, all under 25 ms.
	if v, _ := find(out, "lighthouse_l7_latency_ms", "/ok", "quantile", "0.5"); math.Abs(v-8.333) > 0.01 {
		t.Errorf("p50 = %v", v)
	}
	if v, _ := find(out, "lighthouse_l7_latency_ms", "/ok", "quantile", "0.95"); math.Abs(v-23.125) > 0.01 {
		t.Errorf("p95 = %v", v)
	}
	if _, ok := find(out, "lighthouse_l7_requests_per_second", "*"); !ok {
		t.Error("no per-service series")
	}
	// L7-U-F11: nothing but the allow-listed labels leaves.
	for _, s := range out {
		for k, v := range s.Labels {
			if (k != "kind" && k != "service" && k != "route" && k != "quantile") || strings.Contains(v, "hunter2") {
				t.Fatalf("label %s=%q leaked", k, v)
			}
		}
	}
}

func TestConvert_Guards(t *testing.T) {
	one := func(route, code string, count float64, buckets [][2]float64) string {
		return histLines(httpName, lbl(route, code), buckets, count)
	}
	zero := [][2]float64{{0.1, 0}, {math.Inf(1), 0}}

	// L7-U-F6: 5 requests: rate only, low sample, no error share or latency.
	out := convert(delta(scrape(one("/few", "500", 0, zero)), scrape(one("/few", "500", 5, [][2]float64{{0.1, 5}, {math.Inf(1), 5}}))), 10*time.Second)
	if _, ok := find(out, "lighthouse_l7_server_error_ratio", "/few"); ok {
		t.Error("error share from 5 requests")
	}
	if _, ok := find(out, "lighthouse_l7_latency_ms", "/few", "quantile", "0.95"); ok {
		t.Error("latency from 5 requests")
	}
	if v, _ := find(out, "lighthouse_l7_low_sample", "/few"); v != 1 {
		t.Error("not marked low sample")
	}

	// L7-U-F7: zero requests: zero rate and nothing else.
	out = convert(delta(scrape(one("/idle", "200", 7, zero)), scrape(one("/idle", "200", 7, zero))), 10*time.Second)
	if v, ok := find(out, "lighthouse_l7_requests_per_second", "/idle"); !ok || v != 0 || len(out) != 2 {
		t.Errorf("idle: %+v", out)
	}

	// L7-U-F5: a counter reset after an OBI restart gives no spike.
	if d := delta(scrape(one("/x", "200", 1000, zero)), scrape(one("/x", "200", 3, zero))); len(d) != 0 {
		t.Errorf("reset produced %v", d)
	}
	// Not a health route: only the first segment counts.
	if h := scrape(one("/healthcare/live", "200", 9, zero)); len(h) != 1 {
		t.Errorf("/healthcare/live dropped: %v", h)
	}
	// L7-U-F8: a series missing from a scrape is no data, not zero.
	if d := delta(scrape(one("/x", "200", 1000, zero)), scrape("")); len(d) != 0 {
		t.Errorf("missing scrape produced %v", d)
	}

	// L7-U-F4: health probes and Lighthouse's own checks are excluded.
	h := scrape(one("/healthz", "200", 9, zero)+one("/healthz/live", "200", 9, zero)+one("/health/liveness", "200", 9, zero)+
		one("/status", "200", 9, zero), CheckTarget{Port: "8080", Path: "/status"})
	if len(h) != 0 {
		t.Errorf("health or check requests kept: %v", h)
	}

	// L7-U-F10: requests over 60 s (streams) are out of the latency.
	streams := [][2]float64{{0.1, 0}, {60, 0}, {600, 0}, {math.Inf(1), 0}}
	streamsNext := [][2]float64{{0.1, 30}, {60, 30}, {600, 40}, {math.Inf(1), 40}}
	out = convert(delta(scrape(one("/ws", "200", 0, streams)), scrape(one("/ws", "200", 40, streamsNext))), 10*time.Second)
	if v, _ := find(out, "lighthouse_l7_latency_ms", "/ws", "quantile", "0.99"); v > 100 {
		t.Errorf("p99 includes streams: %v ms", v)
	}
}

func TestConvert_RouteLimit(t *testing.T) {
	// L7-U-P4 and L7-U-F9: 80 routes, each with i+20 requests.
	var base, next strings.Builder
	zero := [][2]float64{{0.1, 0}, {math.Inf(1), 0}}
	var rest float64
	for i := range 80 {
		route := fmt.Sprintf("/r%02d", i)
		n := float64(i + 20)
		base.WriteString(histLines(httpName, lbl(route, "200"), zero, 0))
		next.WriteString(histLines(httpName, lbl(route, "200"), [][2]float64{{0.1, n}, {math.Inf(1), n}}, n))
		if i < 30 {
			rest += n
		}
	}
	out := convert(delta(scrape(base.String()), scrape(next.String())), time.Second)
	routes := map[string]bool{}
	for _, s := range out {
		if s.Name == "lighthouse_l7_requests_per_second" {
			routes[s.Labels["route"]] = true
		}
	}
	if len(routes) != ebpf.Quota().Routes+2 { // 50, "other" and the per-service "*"
		t.Fatalf("%d route series", len(routes))
	}
	if v, _ := find(out, "lighthouse_l7_requests_per_second", "other"); v != rest {
		t.Errorf("other = %v, want %v", v, rest)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name    string
		labels  map[string]string
		route   string
		outcome string
	}{
		{"rpc_server_duration_seconds", map[string]string{"instance": "h:1", "job": "g", "rpc_method": "/pkg.Svc/Get", "rpc_grpc_status_code": "14"}, "/pkg.Svc/Get", "server_error"}, // L7-U-P3 UNAVAILABLE
		{"rpc_server_duration_seconds", map[string]string{"instance": "h:1", "job": "g", "rpc_method": "/pkg.Svc/Get", "rpc_grpc_status_code": "13"}, "/pkg.Svc/Get", "server_error"}, // INTERNAL
		{"rpc_server_duration_seconds", map[string]string{"instance": "h:1", "job": "g", "rpc_method": "/pkg.Svc/Get", "rpc_grpc_status_code": "5"}, "/pkg.Svc/Get", "ok"},            // L7-U-F2 NOT_FOUND
		{"rpc_server_duration_seconds", map[string]string{"instance": "h:1", "job": "g", "rpc_method": "/pkg.Svc/Get", "rpc_grpc_status_code": "1"}, "/pkg.Svc/Get", "ok"},            // CANCELLED
		{"db_client_operation_duration_seconds", map[string]string{"instance": "h:1", "job": "a", "db_system_name": "postgresql", "db_operation_name": "select"}, "postgresql SELECT", "ok"},
		{"db_client_operation_duration_seconds", map[string]string{"instance": "h:1", "job": "a", "db_system": "mysql", "db_operation": "SELECT * FROM users WHERE pw='x'"}, "mysql OTHER", "ok"},     // never SQL text
		{httpName, map[string]string{"instance": "h:1", "job": "a", "http_route": "/users/12345/orders/0a1b2c3d4e5f", "http_response_status_code": "499"}, "/users/{id}/orders/{id}", "client_error"}, // F3, raw IDs
	}
	for _, c := range cases {
		k, ok := classify(c.name, c.labels, svc, nil)
		if !ok || k.route != c.route || k.outcome != c.outcome {
			t.Errorf("%s %v: got %+v %v, want route %q outcome %q", c.name, c.labels, k, ok, c.route, c.outcome)
		}
	}
}

// Plan 07 services quota: past it, the quietest services are summed into
// one "other" service, so totals stay correct.
func TestConvert_ServiceQuota(t *testing.T) {
	defer ebpf.SetQuotas(nil)
	ebpf.SetQuotas(&ebpf.Quotas{Services: 3})
	d := map[histKey]*hist{}
	for i := range 5 {
		d[histKey{kind: "http", service: fmt.Sprintf("svc%d", i), route: "/", outcome: "ok"}] = &hist{count: float64(10 * (i + 1)), buckets: map[float64]float64{}}
	}
	services := map[string]float64{}
	for _, s := range convert(d, time.Second) {
		if s.Name == "lighthouse_l7_requests_per_second" && s.Labels["route"] == "*" {
			services[s.Labels["service"]] = s.Value
		}
	}
	if len(services) != 4 || services["other"] != 30 || services["svc4"] != 50 {
		t.Fatalf("services: %v", services)
	}
}

func TestWithPort(t *testing.T) {
	for _, tc := range []struct{ port, want string }{
		{"80", "k8s:traefik/traefik:80"},
		{"0", "k8s:traefik/traefik"}, // OBI could not tell the port
		{"", "k8s:traefik/traefik"},  // client-side series (SQL)
	} {
		if got := withPort("k8s:traefik/traefik", tc.port); got != tc.want {
			t.Errorf("withPort(%q) = %q, want %q", tc.port, got, tc.want)
		}
	}
}
