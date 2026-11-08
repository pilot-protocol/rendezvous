// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// A snapshot node without a valid public key is never loaded: such a node
// can't sign, and some handlers once let anyone act for a keyless node
// (audit, 2026-11-08). Production held none when this was added.
func TestSnapshotSkipsNodesWithoutAValidKey(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(nil)
	good := base64.StdEncoding.EncodeToString(pub)
	short := base64.StdEncoding.EncodeToString(pub[:16])
	snap := `{"version":1,"next_node":5,"next_net":1,"nodes":{` +
		`"1":{"id":1,"public_key":"` + good + `"},` +
		`"2":{"id":2,"public_key":""},` +
		`"3":{"id":3},` +
		`"4":{"id":4,"public_key":"` + short + `"}}}`
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(path, []byte(snap), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewWithStore("", path)
	if err := s.load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	defer s.Close()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.nodes[1]; !ok {
		t.Fatal("the node with a valid key was not loaded")
	}
	for _, id := range []uint32{2, 3, 4} {
		if _, ok := s.nodes[id]; ok {
			t.Errorf("node %d without a valid key was loaded", id)
		}
	}
}
