// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/json"
	"testing"
	"time"
)

// TestApplySnapshotPreservesBadgeAndRecovery proves the persistence
// guarantee that matters most for recovery: a node's badge and — critically
// — its recovery commitment survive a snapshot load. Losing the commitment
// on restart would break recovery for that address.
func TestApplySnapshotPreservesBadgeAndRecovery(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	now := time.Now().UTC().Format(time.RFC3339)

	snap := snapshot{
		NextNode: 200,
		NextNet:  20,
		Nodes:    map[string]*snapshotNode{},
		Networks: map[string]*snapshotNet{},
	}
	snap.Nodes["42"] = &snapshotNode{
		ID:                   42,
		PublicKey:            "AAAA" + "00000000000000000000000000000042",
		Networks:             []uint16{1},
		LastSeen:             now,
		Badge:                "pilotbadge:v1:42:github:1700000000:0:bdg-v1:",
		BadgeSig:             "badgesig",
		VerificationProvider: "github",
		VerifiedAt:           now,
		RecoveryCommitment:   "COMMIT==",
		RecoveryProvider:     "github",
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if err := s.applySnapshot(data); err != nil {
		t.Fatalf("applySnapshot: %v", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	node, ok := s.nodes[42]
	if !ok {
		t.Fatal("node 42 not loaded")
	}
	if node.Badge == "" || node.BadgeSig != "badgesig" || node.VerificationProvider != "github" {
		t.Fatalf("badge fields not preserved: %+v", node)
	}
	if node.RecoveryCommitment != "COMMIT==" || node.RecoveryProvider != "github" {
		t.Fatalf("recovery enrollment not preserved (recovery would break on restart): %+v", node)
	}
}
