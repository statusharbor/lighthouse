package traces

import (
	"regexp"
	"strings"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// The span filter (status-harbor docs/eBPF/11-traces.md, "Filter"): an
// allow-list. A span leaves the host with only these attributes; names
// and paths are templated; events (exception messages), links and status
// messages are dropped. Anything else is dropped and counted.
var allowedSpanAttrs = map[string]bool{
	"http.request.method": true, "http.response.status_code": true, "http.route": true,
	"url.path": true, "url.scheme": true, "server.address": true, "server.port": true,
	"network.protocol.name": true, "network.protocol.version": true,
	"rpc.system": true, "rpc.service": true, "rpc.method": true, "rpc.grpc.status_code": true,
	"db.system": true, "db.system.name": true, "db.operation.name": true, "db.collection.name": true,
	"db.namespace": true, "db.query.summary": true, "db.response.status_code": true,
	"messaging.system": true, "messaging.operation.name": true, "messaging.operation.type": true,
	"messaging.destination.name": true,
	"exception.type": true, "error.type": true,
}

// clientOnlyAttrs are the dependency's address: kept on client spans,
// dropped on server spans, where they are end users' addresses.
var clientOnlyAttrs = map[string]bool{"network.peer.address": true, "network.peer.port": true}

var (
	rawSegment = regexp.MustCompile(`^([0-9]+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{36})$`)
	httpVerb   = regexp.MustCompile(`^[A-Z]+$`)
)

// templatePath turns numeric, hex and UUID segments into {id} and drops
// any query string (plan 06's route templating).
func templatePath(p string) string {
	p, _, _ = strings.Cut(p, "?")
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if rawSegment.MatchString(s) {
			segs[i] = "{id}"
		}
	}
	return strings.Join(segs, "/")
}

// templateName templates "GET /orders/123?x=1" style names; others (SQL
// summaries such as "SELECT orders") pass.
func templateName(n string) string {
	verb, rest, ok := strings.Cut(n, " ")
	if ok && httpVerb.MatchString(verb) && strings.HasPrefix(rest, "/") {
		return verb + " " + templatePath(rest)
	}
	if strings.HasPrefix(n, "/") {
		return templatePath(n)
	}
	return n
}

// filterSpan applies the allow-list in place and returns how many
// attributes it dropped.
func filterSpan(sp *tracepb.Span) int {
	server := sp.Kind == tracepb.Span_SPAN_KIND_SERVER
	dropped := len(sp.Events) + len(sp.Links)
	sp.Events, sp.Links = nil, nil
	sp.DroppedEventsCount, sp.DroppedLinksCount, sp.DroppedAttributesCount = 0, 0, 0
	sp.TraceState = ""
	if sp.Status != nil {
		sp.Status.Message = ""
	}
	sp.Name = templateName(sp.Name)
	kept := sp.Attributes[:0]
	for _, kv := range sp.Attributes {
		switch {
		case allowedSpanAttrs[kv.Key]:
		case clientOnlyAttrs[kv.Key] && !server:
		default:
			dropped++
			continue
		}
		if kv.Key == "url.path" || kv.Key == "http.route" {
			kv = &commonpb.KeyValue{Key: kv.Key, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: templatePath(kv.Value.GetStringValue())}}}
		}
		kept = append(kept, kv)
	}
	sp.Attributes = kept
	return dropped
}
