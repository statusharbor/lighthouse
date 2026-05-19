package checks

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeResolver is a stubbed DNSResolver so the DNS check can be exercised
// without real network. Each Lookup* either returns its configured result or,
// when the matching err field is set, that error. *net.Resolver satisfies the
// same interface in production.
type fakeResolver struct {
	hosts  []string
	cname  string
	mx     []*net.MX
	txt    []string
	ns     []*net.NS
	addr   []string
	lookup error // returned by every Lookup* when non-nil
}

// noRawQuerier is a rawDNSQuerier that fails if called — used by tests that
// exercise only the stdlib record types, so a stray raw query is loud.
func noRawQuerier(_ context.Context, _ string, _ uint16) ([]dns.RR, error) {
	return nil, errors.New("raw querier should not be called for this record type")
}

// fakeRawQuerier builds a rawDNSQuerier that returns the given RRs, or err when
// err is non-nil. It stands in for a real miekg/dns exchange in unit tests.
func fakeRawQuerier(rrs []dns.RR, err error) rawDNSQuerier {
	return func(_ context.Context, _ string, _ uint16) ([]dns.RR, error) {
		if err != nil {
			return nil, err
		}
		return rrs, nil
	}
}

func (f fakeResolver) LookupHost(_ context.Context, _ string) ([]string, error) {
	if f.lookup != nil {
		return nil, f.lookup
	}
	return f.hosts, nil
}

func (f fakeResolver) LookupCNAME(_ context.Context, _ string) (string, error) {
	if f.lookup != nil {
		return "", f.lookup
	}
	return f.cname, nil
}

func (f fakeResolver) LookupMX(_ context.Context, _ string) ([]*net.MX, error) {
	if f.lookup != nil {
		return nil, f.lookup
	}
	return f.mx, nil
}

func (f fakeResolver) LookupTXT(_ context.Context, _ string) ([]string, error) {
	if f.lookup != nil {
		return nil, f.lookup
	}
	return f.txt, nil
}

func (f fakeResolver) LookupNS(_ context.Context, _ string) ([]*net.NS, error) {
	if f.lookup != nil {
		return nil, f.lookup
	}
	return f.ns, nil
}

func (f fakeResolver) LookupAddr(_ context.Context, _ string) ([]string, error) {
	if f.lookup != nil {
		return nil, f.lookup
	}
	return f.addr, nil
}

func TestDNS_AMatch_ReturnsUp(t *testing.T) {
	r := fakeResolver{hosts: []string{"10.0.0.5", "10.0.0.6"}}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:           "api.internal",
		RecordType:     "A",
		ExpectedValues: []string{"10.0.0.5"},
		Timeout:        time.Second,
	}, r, noRawQuerier)
	if !got.Up {
		t.Errorf("expected Up, got Down: %s", got.ErrorMessage)
	}
}

func TestDNS_EmptyRecordType_DefaultsToA(t *testing.T) {
	r := fakeResolver{hosts: []string{"10.0.0.5"}}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:    "api.internal",
		Timeout: time.Second,
	}, r, noRawQuerier)
	if !got.Up {
		t.Errorf("empty record type should default to A and resolve Up, got Down: %s", got.ErrorMessage)
	}
}

func TestDNS_Drift_ExpectedMissing_ReturnsDown(t *testing.T) {
	r := fakeResolver{hosts: []string{"10.0.0.99"}}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:           "api.internal",
		RecordType:     "A",
		ExpectedValues: []string{"10.0.0.5"},
		Timeout:        time.Second,
	}, r, noRawQuerier)
	if got.Up {
		t.Error("expected Down when an expected value is missing from results")
	}
	if !strings.Contains(got.ErrorMessage, "10.0.0.5") || !strings.Contains(got.ErrorMessage, "10.0.0.99") {
		t.Errorf("error message should name the missing expected and actual results, got: %s", got.ErrorMessage)
	}
}

func TestDNS_NoExpected_AnyRecordIsUp(t *testing.T) {
	r := fakeResolver{hosts: []string{"203.0.113.10"}}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:       "api.internal",
		RecordType: "A",
		Timeout:    time.Second,
	}, r, noRawQuerier)
	if !got.Up {
		t.Errorf("with no expected values, any resolved record should be Up, got Down: %s", got.ErrorMessage)
	}
}

func TestDNS_LookupError_ReturnsDown(t *testing.T) {
	r := fakeResolver{lookup: errors.New("server misbehaving")}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:       "api.internal",
		RecordType: "A",
		Timeout:    time.Second,
	}, r, noRawQuerier)
	if got.Up {
		t.Error("expected Down on resolution failure")
	}
	if !strings.Contains(got.ErrorMessage, "DNS A lookup failed") {
		t.Errorf("error message should mention lookup failure, got: %s", got.ErrorMessage)
	}
}

func TestDNS_NoRecords_ReturnsDown(t *testing.T) {
	r := fakeResolver{hosts: nil}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:       "api.internal",
		RecordType: "A",
		Timeout:    time.Second,
	}, r, noRawQuerier)
	if got.Up {
		t.Error("expected Down when zero records resolve")
	}
	if !strings.Contains(got.ErrorMessage, "No A records found") {
		t.Errorf("error message should mention no records, got: %s", got.ErrorMessage)
	}
}

func TestDNS_CNAME_Match(t *testing.T) {
	r := fakeResolver{cname: "edge.cdn.example.com."}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:           "www.example.com",
		RecordType:     "CNAME",
		ExpectedValues: []string{"edge.cdn.example.com"},
		Timeout:        time.Second,
	}, r, noRawQuerier)
	if !got.Up {
		t.Errorf("expected Up — substring match against CNAME, got Down: %s", got.ErrorMessage)
	}
}

func TestDNS_MX_FormatsPriority(t *testing.T) {
	r := fakeResolver{mx: []*net.MX{{Host: "mail.example.com.", Pref: 10}}}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:           "example.com",
		RecordType:     "MX",
		ExpectedValues: []string{"mail.example.com. (priority 10)"},
		Timeout:        time.Second,
	}, r, noRawQuerier)
	if !got.Up {
		t.Errorf("expected Up — MX record formatted with priority, got Down: %s", got.ErrorMessage)
	}
}

func TestDNS_TXT_Match(t *testing.T) {
	r := fakeResolver{txt: []string{"v=spf1 include:_spf.example.com ~all"}}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:           "example.com",
		RecordType:     "TXT",
		ExpectedValues: []string{"v=spf1"},
		Timeout:        time.Second,
	}, r, noRawQuerier)
	if !got.Up {
		t.Errorf("expected Up — substring match against TXT, got Down: %s", got.ErrorMessage)
	}
}

func TestDNS_NS_Match(t *testing.T) {
	r := fakeResolver{ns: []*net.NS{{Host: "ns1.example.com."}, {Host: "ns2.example.com."}}}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:           "example.com",
		RecordType:     "NS",
		ExpectedValues: []string{"ns1.example.com."},
		Timeout:        time.Second,
	}, r, noRawQuerier)
	if !got.Up {
		t.Errorf("expected Up — NS record match, got Down: %s", got.ErrorMessage)
	}
}

func TestDNS_PTR_Match(t *testing.T) {
	r := fakeResolver{addr: []string{"host.example.com."}}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:           "10.0.0.5",
		RecordType:     "PTR",
		ExpectedValues: []string{"host.example.com."},
		Timeout:        time.Second,
	}, r, noRawQuerier)
	if !got.Up {
		t.Errorf("expected Up — PTR record match, got Down: %s", got.ErrorMessage)
	}
}

func TestDNS_CaseInsensitiveRecordType(t *testing.T) {
	r := fakeResolver{txt: []string{"hello"}}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:       "example.com",
		RecordType: "txt",
		Timeout:    time.Second,
	}, r, noRawQuerier)
	if !got.Up {
		t.Errorf("lowercase record type should resolve, got Down: %s", got.ErrorMessage)
	}
}

func TestDNS_SOA_Match(t *testing.T) {
	soa := &dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA},
		Ns:     "ns1.example.com.",
		Mbox:   "hostmaster.example.com.",
		Serial: 2026051901,
	}
	r := fakeResolver{}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:           "example.com",
		RecordType:     "SOA",
		ExpectedValues: []string{"ns1.example.com. hostmaster.example.com. 2026051901"},
		Timeout:        time.Second,
	}, r, fakeRawQuerier([]dns.RR{soa}, nil))
	if !got.Up {
		t.Errorf("expected Up — SOA record formatted as '<mname> <rname> <serial>', got Down: %s", got.ErrorMessage)
	}
}

func TestDNS_SOA_Drift_ReturnsDown(t *testing.T) {
	soa := &dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA},
		Ns:     "ns1.example.com.",
		Mbox:   "hostmaster.example.com.",
		Serial: 2026051901,
	}
	r := fakeResolver{}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:           "example.com",
		RecordType:     "SOA",
		ExpectedValues: []string{"ns9.example.com."},
		Timeout:        time.Second,
	}, r, fakeRawQuerier([]dns.RR{soa}, nil))
	if got.Up {
		t.Error("expected Down when the expected SOA primary NS is absent")
	}
	if !strings.Contains(got.ErrorMessage, "ns9.example.com.") {
		t.Errorf("error message should name the missing expected value, got: %s", got.ErrorMessage)
	}
}

func TestDNS_SOA_LookupFailure_ReturnsDown(t *testing.T) {
	r := fakeResolver{}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:       "example.com",
		RecordType: "SOA",
		Timeout:    time.Second,
	}, r, fakeRawQuerier(nil, errors.New("NXDOMAIN: name does not exist")))
	if got.Up {
		t.Error("expected Down on SOA resolution failure")
	}
	if !strings.Contains(got.ErrorMessage, "DNS SOA lookup failed") {
		t.Errorf("error message should mention lookup failure, got: %s", got.ErrorMessage)
	}
}

func TestDNS_SRV_Match(t *testing.T) {
	srv := &dns.SRV{
		Hdr:      dns.RR_Header{Name: "_sip._tcp.example.com.", Rrtype: dns.TypeSRV},
		Target:   "sip.example.com.",
		Port:     5060,
		Priority: 10,
		Weight:   60,
	}
	r := fakeResolver{}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:           "_sip._tcp.example.com",
		RecordType:     "SRV",
		ExpectedValues: []string{"sip.example.com.:5060 (priority 10, weight 60)"},
		Timeout:        time.Second,
	}, r, fakeRawQuerier([]dns.RR{srv}, nil))
	if !got.Up {
		t.Errorf("expected Up — SRV record formatted as '<target>:<port> (priority N, weight M)', got Down: %s", got.ErrorMessage)
	}
}

func TestDNS_SRV_MultipleAnswers_Drift_ReturnsDown(t *testing.T) {
	srv1 := &dns.SRV{Hdr: dns.RR_Header{Rrtype: dns.TypeSRV}, Target: "sip1.example.com.", Port: 5060, Priority: 10, Weight: 60}
	srv2 := &dns.SRV{Hdr: dns.RR_Header{Rrtype: dns.TypeSRV}, Target: "sip2.example.com.", Port: 5060, Priority: 20, Weight: 40}
	r := fakeResolver{}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:           "_sip._tcp.example.com",
		RecordType:     "SRV",
		ExpectedValues: []string{"sip3.example.com."},
		Timeout:        time.Second,
	}, r, fakeRawQuerier([]dns.RR{srv1, srv2}, nil))
	if got.Up {
		t.Error("expected Down when the expected SRV target is absent from all answers")
	}
	if !strings.Contains(got.ErrorMessage, "sip1.example.com.") || !strings.Contains(got.ErrorMessage, "sip2.example.com.") {
		t.Errorf("error message should list all actual SRV results, got: %s", got.ErrorMessage)
	}
}

func TestDNS_SRV_LookupFailure_ReturnsDown(t *testing.T) {
	r := fakeResolver{}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:       "_sip._tcp.example.com",
		RecordType: "SRV",
		Timeout:    time.Second,
	}, r, fakeRawQuerier(nil, errors.New("server returned SERVFAIL")))
	if got.Up {
		t.Error("expected Down on SRV resolution failure")
	}
	if !strings.Contains(got.ErrorMessage, "DNS SRV lookup failed") {
		t.Errorf("error message should mention lookup failure, got: %s", got.ErrorMessage)
	}
}

func TestDNS_CAA_Match(t *testing.T) {
	caa := &dns.CAA{
		Hdr:   dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCAA},
		Flag:  0,
		Tag:   "issue",
		Value: "letsencrypt.org",
	}
	r := fakeResolver{}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:           "example.com",
		RecordType:     "CAA",
		ExpectedValues: []string{"0 issue letsencrypt.org"},
		Timeout:        time.Second,
	}, r, fakeRawQuerier([]dns.RR{caa}, nil))
	if !got.Up {
		t.Errorf("expected Up — CAA record formatted as '<flag> <tag> <value>', got Down: %s", got.ErrorMessage)
	}
}

func TestDNS_CAA_Drift_ReturnsDown(t *testing.T) {
	caa := &dns.CAA{
		Hdr:   dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCAA},
		Flag:  0,
		Tag:   "issue",
		Value: "letsencrypt.org",
	}
	r := fakeResolver{}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:           "example.com",
		RecordType:     "CAA",
		ExpectedValues: []string{"digicert.com"},
		Timeout:        time.Second,
	}, r, fakeRawQuerier([]dns.RR{caa}, nil))
	if got.Up {
		t.Error("expected Down when the expected CAA issuer is absent")
	}
	if !strings.Contains(got.ErrorMessage, "digicert.com") {
		t.Errorf("error message should name the missing expected value, got: %s", got.ErrorMessage)
	}
}

func TestDNS_CAA_LookupFailure_ReturnsDown(t *testing.T) {
	r := fakeResolver{}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:       "example.com",
		RecordType: "CAA",
		Timeout:    time.Second,
	}, r, fakeRawQuerier(nil, errors.New("read udp: i/o timeout")))
	if got.Up {
		t.Error("expected Down on CAA resolution failure")
	}
	if !strings.Contains(got.ErrorMessage, "DNS CAA lookup failed") {
		t.Errorf("error message should mention lookup failure, got: %s", got.ErrorMessage)
	}
}

func TestDNS_SOA_NoAnswers_ReturnsDown(t *testing.T) {
	r := fakeResolver{}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:       "example.com",
		RecordType: "SOA",
		Timeout:    time.Second,
	}, r, fakeRawQuerier(nil, nil))
	if got.Up {
		t.Error("expected Down when a raw query returns zero answers")
	}
	if !strings.Contains(got.ErrorMessage, "No SOA records found") {
		t.Errorf("error message should mention no records, got: %s", got.ErrorMessage)
	}
}

func TestDNS_UnknownRecordType_ReturnsDown(t *testing.T) {
	r := fakeResolver{}
	got := DNSCheck{}.runWith(context.Background(), DNSParams{
		Host:       "example.com",
		RecordType: "BOGUS",
		Timeout:    time.Second,
	}, r, noRawQuerier)
	if got.Up {
		t.Error("expected Down for an unknown record type")
	}
	if !strings.Contains(got.ErrorMessage, "Unsupported DNS record type") {
		t.Errorf("expected 'Unsupported' message, got: %s", got.ErrorMessage)
	}
}

func TestDNS_BuildResolver_DefaultWhenEmpty(t *testing.T) {
	if _, ok := buildResolver("").(*net.Resolver); !ok {
		t.Error("empty resolver address should yield a *net.Resolver")
	}
}

func TestDNS_BuildResolver_ExplicitAddrHasDialHook(t *testing.T) {
	for _, addr := range []string{"10.0.0.10", "10.0.0.10:53"} {
		res, ok := buildResolver(addr).(*net.Resolver)
		if !ok {
			t.Fatalf("%s: expected *net.Resolver", addr)
		}
		if res.Dial == nil {
			t.Errorf("%s: explicit resolver address should install a Dial hook", addr)
		}
	}
}
