// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

// TestVerdictKeyLoadOrGenerateRoundTrip: first call generates + persists,
// second call loads the identical key; the file is mode 0600 and no .tmp
// residue is left behind.
func TestVerdictKeyLoadOrGenerateRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "verdict-key.json")

	kid1, priv1, err := loadOrCreateVerdictKey(path)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if kid1 != verdictKeyKid {
		t.Fatalf("kid = %q, want %q", kid1, verdictKeyKid)
	}
	if len(priv1) != ed25519.PrivateKeySize {
		t.Fatalf("private key length = %d", len(priv1))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("key file mode = %o, want 0600", perm)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("tmp file left behind after atomic write")
	}

	kid2, priv2, err := loadOrCreateVerdictKey(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if kid2 != kid1 || !bytes.Equal(priv1, priv2) {
		t.Fatalf("load did not round-trip the generated key")
	}
}

// TestVerdictKeyCorruptFileFailsLoad: a corrupt key file must surface an
// error (the server then falls back to an ephemeral key) rather than
// silently regenerating over it.
func TestVerdictKeyCorruptFileFailsLoad(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "verdict-key.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := loadOrCreateVerdictKey(path); err == nil {
		t.Fatalf("corrupt key file should error")
	}
}

// TestVerdictKeyEphemeralWithoutStore: with no persistence path configured
// the server still exposes a working verdict key (in-memory only).
func TestVerdictKeyEphemeralWithoutStore(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	pub := s.VerdictPublicKey()
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("ephemeral verdict public key length = %d", len(pub))
	}
	if s.VerdictKid() != verdictKeyKid {
		t.Fatalf("kid = %q, want %q", s.VerdictKid(), verdictKeyKid)
	}
}

// TestVerdictKeyPersistsNextToStore: with persistence configured the key
// lands in verdict-key.json beside the registry snapshot and survives a
// server restart with the same public key.
func TestVerdictKeyPersistsNextToStore(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "registry.json")

	s1 := NewWithStore("", storePath)
	pub1 := append(ed25519.PublicKey(nil), s1.VerdictPublicKey()...)
	if err := s1.Close(); err != nil {
		t.Fatalf("close s1: %v", err)
	}
	if len(pub1) != ed25519.PublicKeySize {
		t.Fatalf("verdict public key length = %d", len(pub1))
	}

	keyPath := filepath.Join(dir, "verdict-key.json")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("verdict key not persisted next to store: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("key file mode = %o, want 0600", perm)
	}

	s2 := NewWithStore("", storePath)
	t.Cleanup(func() { _ = s2.Close() })
	if !bytes.Equal(pub1, s2.VerdictPublicKey()) {
		t.Fatalf("verdict key changed across restart")
	}
}
