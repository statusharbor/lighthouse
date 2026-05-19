package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSCheck resolves a DNS record and compares the resolved answer to a set of
// expected value(s). It mirrors the up/down model of tcp/udp/ssl — there is no
// warning tier. A resolution failure OR a drift (an expected value missing from
// the actual results) is a plain `down`.
//
// Target conventions (from the agent's CheckDefinition):
//   - Host carries the record name to resolve (parsed out of CheckDef.URL by
//     the executor).
//   - RecordType is one of A | AAAA | CNAME | MX | TXT | NS | PTR | SOA | SRV |
//     CAA; defaults to "A" when empty. A/AAAA/CNAME/MX/TXT/NS/PTR resolve via
//     the stdlib net.Resolver; SOA/SRV/CAA resolve via a raw miekg/dns query.
//   - ExpectedValues, when non-empty, must every one be found among the
//     resolved results (substring OR exact match).
type DNSCheck struct{}

// DNSParams carries the fields the DNS check needs. ResolverAddr, when set, is
// a `host` or `host:port` (default port 53) that overrides the OS resolver.
type DNSParams struct {
	Host           string
	RecordType     string
	ExpectedValues []string
	ResolverAddr   string // optional; empty = host default resolver
	Timeout        time.Duration
}

// DNSResolver is the subset of *net.Resolver the DNS check depends on. Defined
// as an interface so unit tests can inject a fake and run without real network.
// *net.Resolver satisfies it. It covers the stdlib-backed record types
// (A/AAAA/CNAME/MX/TXT/NS/PTR) only — SOA/SRV/CAA go through rawDNSQuerier.
type DNSResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// rawDNSQuerier performs a raw DNS exchange for one record type and returns the
// answer RRs. SOA/SRV/CAA use this because net.Resolver cannot resolve them.
// Defined as a func type so unit tests can stub it without real network.
type rawDNSQuerier func(ctx context.Context, name string, qtype uint16) ([]dns.RR, error)

// Run resolves the record and compares it against the expected values. Honors
// ctx + timeout throughout.
func (DNSCheck) Run(ctx context.Context, p DNSParams) Result {
	return DNSCheck{}.runWith(ctx, p, buildResolver(p.ResolverAddr), buildRawQuerier(p.ResolverAddr, p.Timeout))
}

// runWith is the testable core — it takes an explicit resolver and raw querier
// instead of constructing them. Run wires in the real ones; tests pass fakes.
func (DNSCheck) runWith(ctx context.Context, p DNSParams, resolver DNSResolver, raw rawDNSQuerier) Result {
	recordType := strings.ToUpper(strings.TrimSpace(p.RecordType))
	if recordType == "" {
		recordType = "A"
	}

	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	results, err := resolveRecord(lookupCtx, resolver, raw, recordType, p.Host)
	rtt := msSince(start)
	if err != nil {
		return Result{
			Up:             false,
			ResponseTimeMs: rtt,
			ErrorMessage:   err.Error(),
		}
	}

	if len(results) == 0 {
		return Result{
			Up:             false,
			ResponseTimeMs: rtt,
			ErrorMessage:   fmt.Sprintf("No %s records found", recordType),
		}
	}

	if missing := missingExpected(p.ExpectedValues, results); len(missing) > 0 {
		return Result{
			Up:             false,
			ResponseTimeMs: rtt,
			ErrorMessage: fmt.Sprintf(
				"Expected %s record(s) %s not found. Actual results: %s",
				recordType, strings.Join(missing, ", "), strings.Join(results, ", "),
			),
		}
	}

	return Result{Up: true, ResponseTimeMs: rtt}
}

// resolveRecord performs the type-specific lookup, returning the resolved
// answers as a flat []string. A non-nil error is itself the final
// down-reason — for an unknown record type it carries the "Unsupported"
// message verbatim.
func resolveRecord(ctx context.Context, resolver DNSResolver, raw rawDNSQuerier, recordType, host string) ([]string, error) {
	switch recordType {
	case "A", "AAAA":
		addrs, err := resolver.LookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DNS %s lookup failed: %s", recordType, err.Error())
		}
		return addrs, nil
	case "CNAME":
		cname, err := resolver.LookupCNAME(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DNS %s lookup failed: %s", recordType, err.Error())
		}
		return []string{cname}, nil
	case "MX":
		records, err := resolver.LookupMX(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DNS %s lookup failed: %s", recordType, err.Error())
		}
		out := make([]string, 0, len(records))
		for _, mx := range records {
			out = append(out, fmt.Sprintf("%s (priority %d)", mx.Host, mx.Pref))
		}
		return out, nil
	case "TXT":
		txt, err := resolver.LookupTXT(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DNS %s lookup failed: %s", recordType, err.Error())
		}
		return txt, nil
	case "NS":
		records, err := resolver.LookupNS(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DNS %s lookup failed: %s", recordType, err.Error())
		}
		out := make([]string, 0, len(records))
		for _, ns := range records {
			out = append(out, ns.Host)
		}
		return out, nil
	case "PTR":
		names, err := resolver.LookupAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DNS %s lookup failed: %s", recordType, err.Error())
		}
		return names, nil
	case "SOA", "SRV", "CAA":
		return resolveRawRecord(ctx, raw, recordType, host)
	default:
		// Capitalised by design — this string is surfaced verbatim as a
		// user-facing check ErrorMessage and must match the backend's
		// DNS prober wording.
		return nil, fmt.Errorf("Unsupported DNS record type: %s", recordType) //nolint:staticcheck // ST1005: user-facing message, exact wire wording
	}
}

// resolveRawRecord runs a raw SOA/SRV/CAA query and formats each answer RR into
// a result string for the expected-value comparison:
//   - SOA → "<mname> <rname> <serial>"          (primary NS, admin mailbox, serial)
//   - SRV → "<target>:<port> (priority N, weight M)"
//   - CAA → "<flag> <tag> <value>"
//
// Multiple SRV/CAA answers yield one result string each.
func resolveRawRecord(ctx context.Context, raw rawDNSQuerier, recordType, host string) ([]string, error) {
	qtype := map[string]uint16{
		"SOA": dns.TypeSOA,
		"SRV": dns.TypeSRV,
		"CAA": dns.TypeCAA,
	}[recordType]

	answers, err := raw(ctx, host, qtype)
	if err != nil {
		return nil, fmt.Errorf("DNS %s lookup failed: %s", recordType, err.Error())
	}

	out := make([]string, 0, len(answers))
	for _, rr := range answers {
		switch v := rr.(type) {
		case *dns.SOA:
			out = append(out, fmt.Sprintf("%s %s %d", v.Ns, v.Mbox, v.Serial))
		case *dns.SRV:
			out = append(out, fmt.Sprintf("%s:%d (priority %d, weight %d)", v.Target, v.Port, v.Priority, v.Weight))
		case *dns.CAA:
			out = append(out, fmt.Sprintf("%d %s %s", v.Flag, v.Tag, v.Value))
		}
	}
	return out, nil
}

// missingExpected returns the expected values that were NOT found among the
// results. An expected value is satisfied when a result contains it as a
// substring OR equals it exactly. With no expected values nothing is missing.
func missingExpected(expected, results []string) []string {
	var missing []string
	for _, want := range expected {
		found := false
		for _, got := range results {
			if got == want || strings.Contains(got, want) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, want)
		}
	}
	return missing
}

// buildResolver constructs the *net.Resolver to use for a check. When addr is
// empty the OS default resolver is used. Otherwise a resolver is built whose
// Dial always targets that exact address (default port 53), bypassing
// resolv.conf — this is how a check's explicit dns_resolver is honoured.
func buildResolver(addr string) DNSResolver {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return &net.Resolver{PreferGo: true}
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, addr)
		},
	}
}

// buildRawQuerier constructs the rawDNSQuerier used for SOA/SRV/CAA. When addr
// is set it queries that nameserver (host or host:port, default port 53);
// otherwise it reads the host's first nameserver from /etc/resolv.conf. The
// exchange is UDP with an automatic TCP retry on a truncated response.
func buildRawQuerier(addr string, timeout time.Duration) rawDNSQuerier {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return func(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
		server, err := resolverServer(addr)
		if err != nil {
			return nil, err
		}

		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(name), qtype)
		msg.RecursionDesired = true

		client := &dns.Client{Net: "udp", Timeout: timeout}
		resp, _, err := client.ExchangeContext(ctx, msg, server)
		if err != nil {
			return nil, err
		}
		if resp.Truncated {
			client.Net = "tcp"
			resp, _, err = client.ExchangeContext(ctx, msg, server)
			if err != nil {
				return nil, err
			}
		}

		switch resp.Rcode {
		case dns.RcodeSuccess:
			return resp.Answer, nil
		case dns.RcodeNameError:
			return nil, errors.New("NXDOMAIN: name does not exist")
		default:
			return nil, fmt.Errorf("server returned %s", dns.RcodeToString[resp.Rcode])
		}
	}
}

// resolverServer resolves the nameserver address for a raw query. addr, when
// set, wins (default port 53 appended when absent). Otherwise the first
// nameserver from /etc/resolv.conf is used.
func resolverServer(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr != "" {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "53")
		}
		return addr, nil
	}

	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("could not read system resolver: %s", err.Error())
	}
	if len(cfg.Servers) == 0 {
		return "", errors.New("no system resolver configured")
	}
	return net.JoinHostPort(cfg.Servers[0], cfg.Port), nil
}
