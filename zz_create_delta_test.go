// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/json"
	"testing"
	"time"
)

func TestApplyNetworkCreateDelta_IdempotentForExistingNetwork(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	// Pre-create network 7 directly.
	s.mu.Lock()
	s.networks[7] = &NetworkInfo{ID: 7, Name: "exists"}
	s.mu.Unlock()
	body, _ := json.Marshal(map[string]any{
		"network_id": 7,
		"name":       "different",
	})
	if err := s.applyNetworkCreateDelta(body); err != nil {
		t.Errorf("idempotent: %v", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Existing entry untouched.
	if s.networks[7].Name != "exists" {
		t.Errorf("existing name changed: %q", s.networks[7].Name)
	}
}

func TestApplyNetworkCreateDelta_WithCreatorNodeID(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	// Pre-create creator node.
	s.mu.Lock()
	s.nodes[42] = &NodeInfo{ID: 42, Networks: []uint16{0}}
	s.mu.Unlock()
	body, _ := json.Marshal(map[string]any{
		"network_id":      9,
		"name":            "created",
		"join_rule":       "open",
		"creator_node_id": 42,
		"created_at":      time.Now().Format(time.RFC3339),
	})
	if err := s.applyNetworkCreateDelta(body); err != nil {
		t.Fatalf("applyNetworkCreateDelta: %v", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	net := s.networks[9]
	if net == nil {
		t.Fatal("network not created")
	}
	if len(net.Members) != 1 || net.Members[0] != 42 {
		t.Errorf("Members = %v, want [42]", net.Members)
	}
	if net.MemberRoles[42] != RoleOwner {
		t.Errorf("creator role = %v, want owner", net.MemberRoles[42])
	}
	// Creator's Networks list should now include 9.
	found := false
	for _, n := range s.nodes[42].Networks {
		if n == 9 {
			found = true
		}
	}
	if !found {
		t.Error("creator's Networks list missing 9")
	}
}

func TestApplyNetworkCreateDelta_AlreadyInCreatorNetworks(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	// Creator already lists network 9.
	s.mu.Lock()
	s.nodes[42] = &NodeInfo{ID: 42, Networks: []uint16{0, 9}}
	s.mu.Unlock()
	body, _ := json.Marshal(map[string]any{
		"network_id":      9,
		"name":            "ok",
		"creator_node_id": 42,
	})
	if err := s.applyNetworkCreateDelta(body); err != nil {
		t.Fatalf("delta: %v", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Should not double-add.
	count := 0
	for _, n := range s.nodes[42].Networks {
		if n == 9 {
			count++
		}
	}
	if count != 1 {
		t.Errorf("network 9 appears %d times in creator.Networks, want 1", count)
	}
}

func TestApplyNetworkCreateDelta_BadCreatedAtFallsBackToNow(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	body, _ := json.Marshal(map[string]any{
		"network_id": 11,
		"name":       "bad-time",
		"created_at": "not-a-time",
	})
	if err := s.applyNetworkCreateDelta(body); err != nil {
		t.Fatalf("delta: %v", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.networks[11] == nil {
		t.Error("network not created despite bad created_at fallback")
	}
}

func TestApplyNetworkCreateDelta_NextNetAdvances(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	body, _ := json.Marshal(map[string]any{
		"network_id": 100,
		"name":       "high-id",
	})
	if err := s.applyNetworkCreateDelta(body); err != nil {
		t.Fatalf("delta: %v", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.nextNet <= 100 {
		t.Errorf("nextNet = %d, want > 100", s.nextNet)
	}
}
