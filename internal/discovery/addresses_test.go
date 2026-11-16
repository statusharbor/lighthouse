package discovery

import (
	"encoding/json"
	"testing"
)

func TestBuildAddressMap(t *testing.T) {
	var services []serviceJSON
	var pods []podJSON
	mustJSON(t, `[
		{"metadata":{"namespace":"db","name":"postgres"},"spec":{"clusterIP":"10.96.0.10","clusterIPs":["10.96.0.10"],"selector":{"app":"pg"}}},
		{"metadata":{"namespace":"db","name":"pg-headless"},"spec":{"clusterIP":"None","selector":{"app":"pg"}}},
		{"metadata":{"namespace":"web","name":"api"},"spec":{"clusterIP":"10.96.0.20","selector":{"app":"api"}}}
	]`, &services)
	mustJSON(t, `[
		{"metadata":{"namespace":"db","name":"pg-0","labels":{"app":"pg"},"ownerReferences":[{"kind":"StatefulSet","name":"pg"}]},"status":{"podIPs":[{"ip":"10.244.1.5"}]}},
		{"metadata":{"namespace":"web","name":"api-7d9c6b5f4b-x2k8q","labels":{"app":"api"},"ownerReferences":[{"kind":"ReplicaSet","name":"api-7d9c6b5f4b"}]},"status":{"podIPs":[{"ip":"10.244.2.7"}]}},
		{"metadata":{"namespace":"web","name":"batch-x","labels":{"app":"batch"},"ownerReferences":[{"kind":"Job","name":"batch"}]},"status":{"podIPs":[{"ip":"10.244.2.9"}]}},
		{"metadata":{"namespace":"kube-system","name":"kube-proxy-abcde"},"spec":{"hostNetwork":true},"status":{"podIPs":[{"ip":"192.168.1.10"}]}}
	]`, &pods)

	got := map[string]AddressEntry{}
	for _, e := range BuildAddressMap(services, pods) {
		got[e.IP] = e
	}
	want := map[string]AddressEntry{
		"10.96.0.10": {IP: "10.96.0.10", Namespace: "db", Service: "postgres"},
		"10.244.1.5": {IP: "10.244.1.5", Namespace: "db", Service: "postgres", Workload: "pg"}, // DSC-U-P6: same Service
		"10.96.0.20": {IP: "10.96.0.20", Namespace: "web", Service: "api"},
		"10.244.2.7": {IP: "10.244.2.7", Namespace: "web", Service: "api", Workload: "api"},
		"10.244.2.9": {IP: "10.244.2.9", Namespace: "web", Workload: "batch"}, // no Service selects it
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries %+v, want %d (headless Service and host-network pod skipped)", len(got), got, len(want))
	}
	for ip, w := range want {
		if got[ip] != w {
			t.Errorf("%s: got %+v, want %+v", ip, got[ip], w)
		}
	}
}

func mustJSON(t *testing.T, s string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(s), v); err != nil {
		t.Fatal(err)
	}
}
