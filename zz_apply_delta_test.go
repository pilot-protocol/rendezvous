// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/json"
	"testing"
)

func TestApplyDeregisterDelta_BadJSON(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if err := s.applyDeregisterDelta([]byte("not-json")); err == nil {
		t.Error("expected JSON parse error")
	}
}

func TestApplyDeregisterDelta_UnknownNodeIsIdempotent(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	body, _ := json.Marshal(map[string]any{"node_id": 9999})
	if err := s.applyDeregisterDelta(body); err != nil {
		t.Errorf("idempotent: %v", err)
	}
}

func TestApplyDeregisterDelta_RemovesNode(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	// Manually seed a node so we can deregister it.
	s.mu.Lock()
	s.nodes[42] = &NodeInfo{
		ID:        42,
		PublicKey: []byte("pubkey-32-bytes-AAAAAAAAAAAAAAAAA"),
		Owner:     "alice",
		Hostname:  "alice-host",
		Networks:  []uint16{0},
	}
	s.pubKeyIdx["pubkey-32-bytes-AAAAAAAAAAAAAAAAA-b64"] = 42
	s.ownerIdx["alice"] = 42
	s.hostnameIdx["alice-host"] = 42
	s.mu.Unlock()

	body, _ := json.Marshal(map[string]any{"node_id": 42})
	if err := s.applyDeregisterDelta(body); err != nil {
		t.Fatalf("applyDeregisterDelta: %v", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.nodes[42]; ok {
		t.Error("node should be removed")
	}
	if _, ok := s.ownerIdx["alice"]; ok {
		t.Error("ownerIdx entry not removed")
	}
	if _, ok := s.hostnameIdx["alice-host"]; ok {
		t.Error("hostnameIdx entry not removed")
	}
}

func TestApplyNetworkDeleteDelta_BadJSON(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if err := s.applyNetworkDeleteDelta([]byte("not-json")); err == nil {
		t.Error("expected JSON parse error")
	}
}

func TestApplyNetworkDeleteDelta_UnknownIsIdempotent(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	body, _ := json.Marshal(map[string]any{"network_id": 9999})
	if err := s.applyNetworkDeleteDelta(body); err != nil {
		t.Errorf("idempotent: %v", err)
	}
}

func TestApplyNetworkDeleteDelta_RemovesNetwork(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	netID, _, err := s.findOrCreateNetwork("delete-me", false, "", "", "", "ADM")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	body, _ := json.Marshal(map[string]any{"network_id": netID})
	if err := s.applyNetworkDeleteDelta(body); err != nil {
		t.Fatalf("applyNetworkDeleteDelta: %v", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.networks[netID]; ok {
		t.Error("network should be removed")
	}
}

func TestApplyNetworkMembershipDelta_BadJSON(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if err := s.applyNetworkMembershipDelta([]byte("not-json"), true); err == nil {
		t.Error("expected JSON parse error")
	}
}

func TestApplyNetworkMembershipDelta_UnknownNetworkIsNoop(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	body, _ := json.Marshal(map[string]any{"network_id": 9999, "node_id": 1})
	if err := s.applyNetworkMembershipDelta(body, true); err != nil {
		t.Errorf("unknown net: %v", err)
	}
}

func TestApplyNetworkMembershipDelta_UnknownNodeIsNoop(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	netID, _, _ := s.findOrCreateNetwork("n", false, "", "", "", "ADM")
	body, _ := json.Marshal(map[string]any{"network_id": netID, "node_id": 9999})
	if err := s.applyNetworkMembershipDelta(body, true); err != nil {
		t.Errorf("unknown node: %v", err)
	}
}

func TestUpdateGauges_FreshServerNoPanic(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.updateGauges(s.metrics) // just verify it doesn't panic on empty state
}

func TestServer_NodePubKeyAndAdminToken_UnknownNode(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	_, token, ok := s.NodePubKeyAndAdminToken(9999)
	if ok {
		t.Errorf("ok = true for unknown node")
	}
	if token != "" {
		t.Errorf("token = %q, want empty (early-return path)", token)
	}
}

func TestServer_NodePubKeyAndAdminToken_KnownNode(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	s.mu.Lock()
	s.nodes[42] = &NodeInfo{
		ID:        42,
		PublicKey: []byte("some-public-key"),
	}
	s.mu.Unlock()

	pubKey, token, ok := s.NodePubKeyAndAdminToken(42)
	if !ok {
		t.Error("ok = false for known node")
	}
	if string(pubKey) != "some-public-key" {
		t.Errorf("pubKey = %q", pubKey)
	}
	if token != "ADM" {
		t.Errorf("token = %q", token)
	}
}
