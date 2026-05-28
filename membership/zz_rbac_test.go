// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import (
	"strings"
	"testing"
)

// enterpriseNetworkWithMembers creates an enterprise network with the
// given members; returns the netID.
func enterpriseNetworkWithMembers(t *testing.T, e *testEnv, owner uint32, others ...uint32) uint16 {
	t.Helper()
	e.addNode(owner)
	for _, n := range others {
		e.addNode(n)
	}
	netID, err := e.createNetwork(owner, "rbac-net")
	if err != nil {
		t.Fatalf("createNetwork: %v", err)
	}
	for _, n := range others {
		if _, err := e.st.HandleJoinNetwork(map[string]interface{}{
			"admin_token": "admin",
			"network_id":  float64(netID),
			"node_id":     float64(n),
		}); err != nil {
			t.Fatalf("join %d: %v", n, err)
		}
	}
	// Flip enterprise on.
	if _, err := e.st.HandleSetNetworkEnterprise(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
		"enterprise":  true,
	}); err != nil {
		t.Fatalf("set enterprise: %v", err)
	}
	return netID
}

func TestHandlePromoteMember_HappyPath(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	netID := enterpriseNetworkWithMembers(t, e, 1, 2)

	resp, err := e.st.HandlePromoteMember(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(2),
	})
	if err != nil {
		t.Fatalf("HandlePromoteMember: %v", err)
	}
	if resp["role"] != "admin" {
		t.Errorf("role = %v, want admin", resp["role"])
	}
}

func TestHandlePromoteMember_UnknownTarget(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	netID := enterpriseNetworkWithMembers(t, e, 1)
	_, err := e.st.HandlePromoteMember(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(9999),
	})
	if err == nil {
		t.Error("expected unknown-target error")
	}
}

func TestHandlePromoteMember_CannotPromoteOwner(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	netID := enterpriseNetworkWithMembers(t, e, 1)
	_, err := e.st.HandlePromoteMember(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(1),
	})
	if err == nil || !strings.Contains(err.Error(), "owner") {
		t.Errorf("err = %v", err)
	}
}

func TestHandlePromoteMember_AlreadyAdmin(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	netID := enterpriseNetworkWithMembers(t, e, 1, 2)

	// First promote.
	if _, err := e.st.HandlePromoteMember(map[string]interface{}{
		"admin_token": "admin", "network_id": float64(netID), "target_node_id": float64(2),
	}); err != nil {
		t.Fatalf("first promote: %v", err)
	}
	// Second promote on already-admin.
	_, err := e.st.HandlePromoteMember(map[string]interface{}{
		"admin_token": "admin", "network_id": float64(netID), "target_node_id": float64(2),
	})
	if err == nil || !strings.Contains(err.Error(), "already an admin") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleDemoteMember_HappyPath(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	netID := enterpriseNetworkWithMembers(t, e, 1, 2)
	// Promote to admin first.
	if _, err := e.st.HandlePromoteMember(map[string]interface{}{
		"admin_token": "admin", "network_id": float64(netID), "target_node_id": float64(2),
	}); err != nil {
		t.Fatalf("promote: %v", err)
	}

	resp, err := e.st.HandleDemoteMember(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(2),
	})
	if err != nil {
		t.Fatalf("HandleDemoteMember: %v", err)
	}
	if resp["role"] != "member" {
		t.Errorf("role = %v, want member", resp["role"])
	}
}

func TestHandleDemoteMember_CannotDemoteOwner(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	netID := enterpriseNetworkWithMembers(t, e, 1)
	_, err := e.st.HandleDemoteMember(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(1),
	})
	if err == nil || !strings.Contains(err.Error(), "owner") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleDemoteMember_AlreadyMember(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	netID := enterpriseNetworkWithMembers(t, e, 1, 2)
	_, err := e.st.HandleDemoteMember(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(2),
	})
	if err == nil || !strings.Contains(err.Error(), "already a member") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleDemoteMember_UnknownTarget(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	netID := enterpriseNetworkWithMembers(t, e, 1)
	_, err := e.st.HandleDemoteMember(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(9999),
	})
	if err == nil {
		t.Error("expected unknown-target error")
	}
}

func TestHandleTransferOwnership_HappyPath(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	netID := enterpriseNetworkWithMembers(t, e, 1, 2)

	resp, err := e.st.HandleTransferOwnership(map[string]interface{}{
		"admin_token":  "admin",
		"network_id":   float64(netID),
		"new_owner_id": float64(2),
	})
	if err != nil {
		t.Fatalf("HandleTransferOwnership: %v", err)
	}
	if resp["type"] != "transfer_ownership_ok" {
		t.Errorf("type = %v", resp["type"])
	}
}

func TestHandleTransferOwnership_MissingNewOwnerID(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleTransferOwnership(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(1),
	})
	if err == nil {
		t.Error("expected error for missing new_owner_id")
	}
}

func TestHandleTransferOwnership_SelfTransfer(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	netID := enterpriseNetworkWithMembers(t, e, 1)
	_, err := e.st.HandleTransferOwnership(map[string]interface{}{
		"admin_token":  "admin",
		"network_id":   float64(netID),
		"new_owner_id": float64(1),
	})
	if err == nil || !strings.Contains(err.Error(), "already the owner") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleTransferOwnership_NewOwnerNotMember(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	netID := enterpriseNetworkWithMembers(t, e, 1)
	_, err := e.st.HandleTransferOwnership(map[string]interface{}{
		"admin_token":  "admin",
		"network_id":   float64(netID),
		"new_owner_id": float64(9999),
	})
	if err == nil {
		t.Error("expected not-a-member error")
	}
}
