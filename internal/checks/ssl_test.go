package checks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// genCert produces a self-signed leaf certificate valid over [notBefore,
// notAfter]. Returns a tls.Certificate ready to serve. Self-signed by
// design — the SSL executor insecure-dials so the chain is irrelevant.
func genCert(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "lighthouse-ssl-test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        tmpl,
	}
}

// startTLSListener serves the given certificate on a loopback TLS listener,
// accepting connections and completing the handshake. Returns host:port.
func startTLSListener(t *testing.T, cert tls.Certificate) (host string, port int) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				// Force the handshake so the client sees the cert, then idle
				// briefly before closing.
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestSSL_ValidCertIsUp(t *testing.T) {
	now := time.Now()
	// NotAfter ~29.5 days out — mid-bucket so the floor lands on 29
	// regardless of the small clock advance to the executor's time.Now().
	cert := genCert(t, now.Add(-time.Hour), now.Add(29*24*time.Hour+12*time.Hour))
	host, port := startTLSListener(t, cert)

	got := SSLCheck{}.Run(context.Background(), SSLParams{
		Host:    host,
		Port:    port,
		Timeout: 2 * time.Second,
	})
	if !got.Up {
		t.Fatalf("expected Up=true, got Down: %s", got.ErrorMessage)
	}
	if got.CertDaysToExpiry == nil {
		t.Fatal("expected CertDaysToExpiry to be set for a valid cert")
	}
	// ~29.5 days out floors to 29.
	if d := *got.CertDaysToExpiry; d != 29 {
		t.Errorf("CertDaysToExpiry = %d, want 29", d)
	}
}

func TestSSL_ExpiredCertIsDown(t *testing.T) {
	now := time.Now()
	// Issued and expired in the past. NotAfter is placed 10.5 days in the
	// past — safely mid-bucket so the floor lands on -11 regardless of the
	// small clock advance between here and the executor's time.Now().
	cert := genCert(t, now.Add(-60*24*time.Hour), now.Add(-10*24*time.Hour-12*time.Hour))
	host, port := startTLSListener(t, cert)

	got := SSLCheck{}.Run(context.Background(), SSLParams{
		Host:    host,
		Port:    port,
		Timeout: 2 * time.Second,
	})
	if got.Up {
		t.Fatal("expected Down for an expired certificate")
	}
	if got.ErrorMessage == "" {
		t.Error("expected error message for an expired certificate")
	}
	if got.CertDaysToExpiry == nil {
		t.Fatal("expected CertDaysToExpiry to be set even for an expired cert")
	}
	// Expired 10.5 days ago → floor of a negative duration → -11.
	if d := *got.CertDaysToExpiry; d != -11 {
		t.Errorf("CertDaysToExpiry = %d, want -11", d)
	}
}

func TestSSL_UnreachableIsDown(t *testing.T) {
	// Port 1 is reserved/never-listening; the TLS dial fails.
	got := SSLCheck{}.Run(context.Background(), SSLParams{
		Host:    "127.0.0.1",
		Port:    1,
		Timeout: 500 * time.Millisecond,
	})
	if got.Up {
		t.Fatal("expected Down for an unreachable endpoint")
	}
	if got.ErrorMessage == "" {
		t.Error("expected error message for an unreachable endpoint")
	}
	if got.CertDaysToExpiry != nil {
		t.Errorf("CertDaysToExpiry should be nil when no cert was read, got %d", *got.CertDaysToExpiry)
	}
}

func TestDaysToExpiry(t *testing.T) {
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		notAfter time.Time
		want     int
	}{
		{"30 days minus a sliver floors to 29", now.Add(30*24*time.Hour - time.Minute), 29},
		{"exactly 12 days", now.Add(12 * 24 * time.Hour), 12},
		{"under a day floors to 0", now.Add(6 * time.Hour), 0},
		{"expired 10 days ago", now.Add(-10 * 24 * time.Hour), -10},
		{"expired 1 hour ago floors to -1", now.Add(-time.Hour), -1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := daysToExpiry(c.notAfter, now); got != c.want {
				t.Errorf("daysToExpiry = %d, want %d", got, c.want)
			}
		})
	}
}
