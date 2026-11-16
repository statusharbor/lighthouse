package agent

import (
	_ "embed"
	"encoding/json"
	"slices"
)

// ebpfAllowlistJSON is the published list of what eBPF collectors may send
// (docs/eBPF/09-security-page.md in status-harbor, acceptance criterion
// 2). The sink enforces it, so a collector change cannot send a new field
// without this file changing too.
//
//go:embed ebpf_allowlist.json
var ebpfAllowlistJSON []byte

type ebpfAllowlist struct {
	Series map[string][]string `json:"series"` // name -> allowed label keys
	Events map[string][]string `json:"events"` // kind -> allowed payload fields
}

var allowlist = func() ebpfAllowlist {
	var a ebpfAllowlist
	if err := json.Unmarshal(ebpfAllowlistJSON, &a); err != nil {
		panic("ebpf allow-list: " + err.Error())
	}
	return a
}()

// allowedSeries reports whether a series name and every label key are on
// the allow-list.
func allowedSeries(name string, labels map[string]string) bool {
	keys, ok := allowlist.Series[name]
	if !ok {
		return false
	}
	for k := range labels {
		if !slices.Contains(keys, k) {
			return false
		}
	}
	return true
}

// filterEvent drops payload fields not on the event kind's allow-list; an
// unknown kind sends nothing (ok false).
func filterEvent(kind string, payload []byte) ([]byte, bool) {
	fields, ok := allowlist.Events[kind]
	if !ok {
		return nil, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, false
	}
	for k := range m {
		if !slices.Contains(fields, k) {
			delete(m, k)
		}
	}
	out, err := json.Marshal(m)
	return out, err == nil
}
