// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import (
	"strings"
	"testing"
)

// createInviteNetwork creates an enterprise network with join_rule=invite.
// HandleCreateNetwork won't accept an "invite" join_rule on a non-enterprise
// network, so we go through open→enterprise→manual-flip-of-join_rule.
func createInviteNetwork(t *testing.T, e *testEnv, owner uint32) uint16 {
	t.Helper()
	e.addNode(owner)
	netID, err := e.createNetwork(owner, "invite-net")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := e.st.HandleSetNetworkEnterprise(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
		"enterprise":  true,
	}); err != nil {
		t.Fatalf("set enterprise: %v", err)
	}
	// Flip join_rule in-place under the env's lock.
	e.mu.Lock()
	e.networks[netID].JoinRule = "invite"
	e.mu.Unlock()
	return netID
}

func TestHandleInviteToNetwork_InviteSelfRejected(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleInviteToNetwork(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(1),
		"inviter_id":     float64(1),
		"target_node_id": float64(1),
	})
	if err == nil || !strings.Contains(err.Error(), "invite yourself") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleInviteToNetwork_UnknownInviter(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleInviteToNetwork(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(1),
		"inviter_id":     float64(9999),
		"target_node_id": float64(1),
	})
	if err == nil {
		t.Error("expected unknown-inviter error")
	}
}

func TestHandleInviteToNetwork_HappyPath(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(2)
	netID := createInviteNetwork(t, e, 1)

	resp, err := e.st.HandleInviteToNetwork(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"inviter_id":     float64(1),
		"target_node_id": float64(2),
	})
	if err != nil {
		t.Fatalf("HandleInviteToNetwork: %v", err)
	}
	if resp["type"] != "invite_to_network_ok" {
		t.Errorf("type = %v", resp["type"])
	}
}

func TestHandleInviteToNetwork_DuplicateInviteReturnsAlreadyInvited(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(2)
	netID := createInviteNetwork(t, e, 1)

	// First invite.
	if _, err := e.st.HandleInviteToNetwork(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"inviter_id":     float64(1),
		"target_node_id": float64(2),
	}); err != nil {
		t.Fatalf("first invite: %v", err)
	}
	// Second invite — should return already_invited.
	resp, err := e.st.HandleInviteToNetwork(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"inviter_id":     float64(1),
		"target_node_id": float64(2),
	})
	if err != nil {
		t.Fatalf("second invite: %v", err)
	}
	if resp["status"] != "already_invited" {
		t.Errorf("status = %v, want already_invited", resp["status"])
	}
}

func TestHandleInviteToNetwork_OpenNetworkRejected(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	e.addNode(2)
	netID, _ := e.createNetwork(1, "open-net") // join_rule=open
	// Flip enterprise on.
	if _, err := e.st.HandleSetNetworkEnterprise(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
		"enterprise":  true,
	}); err != nil {
		t.Fatalf("set enterprise: %v", err)
	}
	_, err := e.st.HandleInviteToNetwork(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"inviter_id":     float64(1),
		"target_node_id": float64(2),
	})
	if err == nil || !strings.Contains(err.Error(), "not invite-only") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleInviteToNetwork_TargetUnknown(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	netID := createInviteNetwork(t, e, 1)
	_, err := e.st.HandleInviteToNetwork(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"inviter_id":     float64(1),
		"target_node_id": float64(9999),
	})
	if err == nil {
		t.Error("expected unknown-target error")
	}
}

func TestHandleRespondInvite_HappyAccept(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(2)
	netID := createInviteNetwork(t, e, 1)
	if _, err := e.st.HandleInviteToNetwork(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"inviter_id":     float64(1),
		"target_node_id": float64(2),
	}); err != nil {
		t.Fatalf("invite: %v", err)
	}
	resp, err := e.st.HandleRespondInvite(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
		"network_id":  float64(netID),
		"accept":      true,
	})
	if err != nil {
		t.Fatalf("HandleRespondInvite: %v", err)
	}
	if resp["accepted"] != true {
		t.Errorf("accepted = %v, want true", resp["accepted"])
	}
}

func TestHandleRespondInvite_Reject(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(2)
	netID := createInviteNetwork(t, e, 1)
	if _, err := e.st.HandleInviteToNetwork(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"inviter_id":     float64(1),
		"target_node_id": float64(2),
	}); err != nil {
		t.Fatalf("invite: %v", err)
	}
	resp, err := e.st.HandleRespondInvite(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
		"network_id":  float64(netID),
		"accept":      false,
	})
	if err != nil {
		t.Fatalf("HandleRespondInvite: %v", err)
	}
	if resp["accepted"] != false {
		t.Errorf("accepted = %v, want false", resp["accepted"])
	}
}

func TestHandleRespondInvite_NoPendingInvite(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(2)
	netID := createInviteNetwork(t, e, 1)
	_, err := e.st.HandleRespondInvite(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
		"network_id":  float64(netID),
		"accept":      true,
	})
	if err == nil {
		t.Error("expected no-pending-invite error")
	}
}

func TestHandleRespondInvite_UnknownNode(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	netID := createInviteNetwork(t, e, 1)
	_, err := e.st.HandleRespondInvite(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(9999),
		"network_id":  float64(netID),
		"accept":      true,
	})
	if err == nil {
		t.Error("expected unknown-node error")
	}
}
