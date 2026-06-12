package agent

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// instanceIDFile is the basename of the per-install identity file, joined
// with cfg.Agent.DataDir at runtime. The file holds a stable UUID written
// at first boot and read on every subsequent start. It's the agent half
// of the Console's single-active-instance claim — see middleware.go in
// status-harbor for the enforcement side.
const instanceIDFile = "instance.id"

// LoadOrCreateInstanceID returns the agent's stable per-install UUID,
// creating it on first run.
//
// Semantics:
//   - Read <DataDir>/instance.id. If present and parses as a UUID,
//     return it. Operators run `systemctl restart` regularly — the
//     UUID must NOT change on restart, otherwise the Console treats
//     every restart as a token-sharing event.
//   - If the file is missing, generate a new v4 UUID, persist with
//     0600 (so other local users can't read it on shared boxes), and
//     return it.
//   - On any persistence failure, log via the returned error and the
//     caller decides whether to proceed without an ID. The agent's
//     transport treats an empty ID as "don't participate in the
//     claim" — backwards-compatible with older Consoles and a graceful
//     degradation when the data dir is read-only.
//
// The data dir is created (0700) if it doesn't exist. We never panic
// or kill the agent on identity errors; the claim is a hardening layer,
// not a correctness one.
func LoadOrCreateInstanceID(dataDir string) (string, error) {
	if dataDir == "" {
		return "", errors.New("data dir is empty")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", fmt.Errorf("create data dir for instance id: %w", err)
	}

	path := filepath.Join(dataDir, instanceIDFile)

	if b, err := os.ReadFile(path); err == nil {
		trimmed := strings.TrimSpace(string(b))
		if isLikelyUUID(trimmed) {
			return trimmed, nil
		}
		// Corrupt / wrong shape — overwrite with a fresh one rather
		// than carrying a half-formed value forward. A stale value
		// only matters if it matches another agent's; effectively
		// impossible by birthday-bound. Surface it: an operator who
		// hand-edited the file should see why their value didn't stick.
		slog.Warn("instance id file present but unparseable; regenerating",
			"path", path, "bytes", len(b))
	}

	id, err := newV4()
	if err != nil {
		return "", fmt.Errorf("generate instance id: %w", err)
	}
	// 0600 — the file is the secret that anchors the token claim, so
	// keep it off other local accounts. Write atomically via tmp +
	// rename so a crash mid-write doesn't leave a half-written file
	// that the next start can't parse.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write instance id: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", fmt.Errorf("commit instance id: %w", err)
	}
	return id, nil
}

// newV4 returns a fresh UUIDv4 string. Avoids the github.com/google/uuid
// dependency — this is the entire crypto/rand-based recipe and it's
// well-trodden enough to inline.
func newV4() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	// RFC 4122 §4.4: set version (0x40) and variant (0x80) bits.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// isLikelyUUID is a cheap shape check — 36 chars, four dashes in the
// expected positions, hex elsewhere. The Console's middleware does the
// strict validation (Postgres UUID parse on the way in); this side just
// rejects garbage so we regenerate cleanly instead of sending a
// definitely-bad value.
func isLikelyUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHexRune(c) {
				return false
			}
		}
	}
	return true
}

func isHexRune(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}
