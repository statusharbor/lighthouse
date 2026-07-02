package agent

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// agentKeyFile is the basename of the per-install NaCl box private key,
// joined with cfg.Agent.DataDir at runtime. The 32-byte private key is
// written at first boot and reused on every subsequent start so the Console
// keeps sealing DSNs to a stable public key - see design #10 "sealed
// per-agent DSN". The public key travels on /register (AgentPublicKey).
const agentKeyFile = "agent_box.key"

// AgentKeypair is the agent's NaCl box (X25519) keypair. The private key
// never leaves the process; the public key is base64(std)-encoded and sent
// on /register so the Console can seal per-node DSNs to it with
// box.SealAnonymous.
type AgentKeypair struct {
	Public  *[32]byte
	Private *[32]byte
}

// PublicKeyBase64 returns the standard-base64 encoding of the 32-byte public
// key - the exact shape the Console's sealing contract expects in the
// register request's agent_public_key field.
func (k *AgentKeypair) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(k.Public[:])
}

// OpenSealedDSN opens a base64(std) NaCl anonymous sealed box
// (box.SealAnonymous) that the Console sealed to this agent's public key,
// returning the plaintext DSN. The plaintext is held only in the caller's
// memory. Returns an error (never panics) on a malformed base64 payload or
// an authentication failure so a single bad node can be logged and skipped.
func (k *AgentKeypair) OpenSealedDSN(sealedB64 string) (string, error) {
	sealed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sealedB64))
	if err != nil {
		return "", fmt.Errorf("decode sealed dsn: %w", err)
	}
	plain, ok := box.OpenAnonymous(nil, sealed, k.Public, k.Private)
	if !ok {
		return "", errors.New("open sealed dsn: box authentication failed")
	}
	return string(plain), nil
}

// LoadOrCreateAgentKeypair returns the agent's stable NaCl box keypair,
// generating and persisting it on first run.
//
// Semantics mirror LoadOrCreateInstanceID:
//   - Read <DataDir>/agent_box.key (base64(std) of the 32-byte private
//     key). If present and well-formed, derive the public key and return
//     the pair. The key must NOT change on restart, otherwise the Console
//     keeps sealing DSNs the agent can no longer open.
//   - If the file is missing or malformed, generate a fresh keypair,
//     persist the private key with 0600 (so other local users can't read
//     it on shared boxes), and return it.
//   - On any persistence failure, return the error and let the caller
//     decide. A caller that proceeds without a key simply registers no
//     public key, and the Console sends plaintext DSNs as before.
//
// The data dir is created (0700) if it doesn't exist. We never panic or
// kill the agent on key errors; sealing is a hardening layer, not a
// correctness one.
func LoadOrCreateAgentKeypair(dataDir string) (*AgentKeypair, error) {
	if dataDir == "" {
		return nil, errors.New("data dir is empty")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir for agent key: %w", err)
	}

	path := filepath.Join(dataDir, agentKeyFile)

	if b, err := os.ReadFile(path); err == nil {
		trimmed := strings.TrimSpace(string(b))
		if raw, derr := base64.StdEncoding.DecodeString(trimmed); derr == nil && len(raw) == 32 {
			var priv [32]byte
			copy(priv[:], raw)
			return keypairFromPrivate(&priv), nil
		}
		// Corrupt / wrong shape - overwrite with a fresh one rather than
		// carrying a half-formed value forward. Surface it: an operator who
		// hand-edited the file should see why their value didn't stick.
		slog.Warn("agent key file present but unparseable; regenerating",
			"path", path, "bytes", len(b))
	}

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate agent key: %w", err)
	}
	// 0600 - the private key lets the agent open sealed DSNs, so keep it
	// off other local accounts. Write atomically via tmp + rename so a
	// crash mid-write doesn't leave a half-written file the next start
	// can't parse.
	enc := base64.StdEncoding.EncodeToString(priv[:])
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(enc+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write agent key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("commit agent key: %w", err)
	}
	return &AgentKeypair{Public: pub, Private: priv}, nil
}

// keypairFromPrivate derives the public key from a stored private key via
// curve25519 scalar-base multiplication - the same derivation
// box.GenerateKey performs internally - so we only need to persist the
// private half.
func keypairFromPrivate(priv *[32]byte) *AgentKeypair {
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, priv)
	return &AgentKeypair{Public: &pub, Private: priv}
}
