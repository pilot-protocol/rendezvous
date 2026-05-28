// SPDX-License-Identifier: AGPL-3.0-or-later

package trust_test

import (
	"strings"
	"testing"

	"github.com/pilot-protocol/rendezvous/trust"
)

func TestHandleRequestHandshake_UnknownFromNode(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret") // no node IDs
	st := trust.NewStore(nodes, noopCallbacks())
	_, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id": float64(1),
		"to_node_id":   float64(2),
	})
	if err == nil {
		t.Error("expected error for unknown from_node")
	}
}

func TestHandleRequestHandshake_UnknownToNode(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1) // only the sender
	st := trust.NewStore(nodes, noopCallbacks())
	_, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id": float64(1),
		"to_node_id":   float64(2),
	})
	if err == nil {
		t.Error("expected error for unknown to_node")
	}
}

func TestHandleRequestHandshake_TooLongJustification(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1, 2)
	st := trust.NewStore(nodes, noopCallbacks())
	_, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id":  float64(1),
		"to_node_id":    float64(2),
		"justification": strings.Repeat("x", 100000),
	})
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected too-large error, got %v", err)
	}
}

func TestHandleRequestHandshake_DuplicatePendingRejected(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1, 2)
	st := trust.NewStore(nodes, noopCallbacks())

	// First request succeeds.
	if _, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id": float64(1),
		"to_node_id":   float64(2),
	}); err != nil {
		t.Fatalf("first request: %v", err)
	}
	// Duplicate from same sender → rejected.
	_, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id": float64(1),
		"to_node_id":   float64(2),
	})
	if err == nil || !strings.Contains(err.Error(), "already pending") {
		t.Errorf("expected 'already pending' error, got %v", err)
	}
}

func TestHandleRespondHandshake_UnknownNode(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret") // no nodes
	st := trust.NewStore(nodes, noopCallbacks())
	_, err := st.HandleRespondHandshake(map[string]interface{}{
		"node_id": float64(1),
		"peer_id": float64(2),
		"accept":  true,
	})
	if err == nil {
		t.Error("expected error for unknown responder")
	}
}

func TestHandleRespondHandshake_AcceptCreatesTrustPair(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1, 2)
	st := trust.NewStore(nodes, noopCallbacks())
	// Seed an inbox entry so respond has something to clear.
	if _, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id": float64(1),
		"to_node_id":   float64(2),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	resp, err := st.HandleRespondHandshake(map[string]interface{}{
		"node_id":     float64(2),
		"peer_id":     float64(1),
		"accept":      true,
		"admin_token": "secret",
	})
	if err != nil {
		t.Fatalf("HandleRespondHandshake: %v", err)
	}
	if resp["type"] != "respond_handshake_ok" {
		t.Errorf("type = %v", resp["type"])
	}
	if !st.IsTrusted(1, 2) {
		t.Error("trust pair should exist after accept")
	}
}

func TestHandleRespondHandshake_RejectDoesNotCreatePair(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1, 2)
	st := trust.NewStore(nodes, noopCallbacks())
	if _, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id": float64(1),
		"to_node_id":   float64(2),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := st.HandleRespondHandshake(map[string]interface{}{
		"node_id":     float64(2),
		"peer_id":     float64(1),
		"accept":      false,
		"admin_token": "secret",
	}); err != nil {
		t.Fatalf("HandleRespondHandshake: %v", err)
	}
	if st.IsTrusted(1, 2) {
		t.Error("trust pair should NOT exist after reject")
	}
}

func TestHandlePollHandshakes_HappyAndUnknown(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1, 2)
	st := trust.NewStore(nodes, noopCallbacks())
	// Seed an inbox entry.
	if _, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id": float64(1),
		"to_node_id":   float64(2),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	resp, err := st.HandlePollHandshakes(map[string]interface{}{
		"node_id":     float64(2),
		"admin_token": "secret",
	})
	if err != nil {
		t.Fatalf("HandlePollHandshakes: %v", err)
	}
	if requests, _ := resp["requests"].([]map[string]interface{}); len(requests) != 1 {
		t.Errorf("requests len = %d, want 1", len(requests))
	}

	// Unknown node.
	if _, err := st.HandlePollHandshakes(map[string]interface{}{
		"node_id": float64(9999),
	}); err == nil {
		t.Error("expected error for unknown node")
	}
}

func TestInboxSnapshot_EmptyOnFreshStore(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1, 2)
	st := trust.NewStore(nodes, noopCallbacks())
	inbox, responses := st.InboxSnapshot()
	if len(inbox) != 0 {
		t.Errorf("inbox = %v, want empty", inbox)
	}
	if len(responses) != 0 {
		t.Errorf("responses = %v, want empty", responses)
	}
}

func TestInboxSnapshot_AfterRequest(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1, 2)
	st := trust.NewStore(nodes, noopCallbacks())
	if _, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id": float64(1),
		"to_node_id":   float64(2),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	inbox, _ := st.InboxSnapshot()
	if len(inbox[2]) != 1 {
		t.Errorf("inbox[2] = %v, want 1 entry", inbox[2])
	}
}
