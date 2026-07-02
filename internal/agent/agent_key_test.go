package agent

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// TestAgentKeypair_SealOpenRoundTrip exercises the #10 contract end to end:
// the key persists stably across restarts, a DSN the "Console" seals to the
// agent's public key opens back to the same plaintext, and a garbage box
// fails cleanly instead of panicking.
func TestAgentKeypair_SealOpenRoundTrip(t *testing.T) {
	dir := t.TempDir()

	kp, err := LoadOrCreateAgentKeypair(dir)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}

	// Reload must return the same public key - the Console keeps sealing to
	// it across agent restarts.
	kp2, err := LoadOrCreateAgentKeypair(dir)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if kp.PublicKeyBase64() != kp2.PublicKeyBase64() {
		t.Fatalf("public key changed across reload: %q vs %q",
			kp.PublicKeyBase64(), kp2.PublicKeyBase64())
	}

	// Console side: anonymous-seal a DSN to the agent's public key.
	const dsn = "postgres://user:pass@10.0.0.5:5432/app?sslmode=require"
	sealed, err := box.SealAnonymous(nil, []byte(dsn), kp.Public, rand.Reader)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := kp.OpenSealedDSN(base64.StdEncoding.EncodeToString(sealed))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got != dsn {
		t.Fatalf("round-trip mismatch: got %q want %q", got, dsn)
	}

	// A malformed sealed box must error, not panic.
	if _, err := kp.OpenSealedDSN(base64.StdEncoding.EncodeToString([]byte("not a box"))); err == nil {
		t.Fatal("expected error opening a garbage sealed box, got nil")
	}
}
