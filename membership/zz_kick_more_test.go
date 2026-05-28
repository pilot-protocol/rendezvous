// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import (
	"strings"
	"testing"
)

func TestHandleKickMember_CannotKickOwner(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	netID := enterpriseNetworkWithMembers(t, e, 1)
	_, err := e.st.HandleKickMember(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(1),
	})
	if err == nil || !strings.Contains(err.Error(), "owner") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleKickMember_NotAMember(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	netID := enterpriseNetworkWithMembers(t, e, 1)
	_, err := e.st.HandleKickMember(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(9999),
	})
	if err == nil || !strings.Contains(err.Error(), "not a member") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleKickMember_UnknownNetwork(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleKickMember(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(9999),
		"target_node_id": float64(1),
	})
	if err == nil {
		t.Error("expected unknown-network error")
	}
}

func TestHandleDeleteNetwork_RemovesInvites(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	e.addNode(2)
	netID, _ := e.createNetwork(1, "del-with-invites")
	// Add invites for two different nodes, one for netID and one for another.
	e.mu.Lock()
	e.inviteInbox[2] = []*NetworkInvite{
		{NetworkID: netID, InviterID: 1},
		{NetworkID: 999, InviterID: 1},
	}
	e.inviteInbox[3] = []*NetworkInvite{
		{NetworkID: netID, InviterID: 1},
	}
	e.mu.Unlock()

	if _, err := e.st.HandleDeleteNetwork(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
	}); err != nil {
		t.Fatalf("HandleDeleteNetwork: %v", err)
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	// Node 3's inbox is empty for our net, so the entry is fully deleted.
	if _, ok := e.inviteInbox[3]; ok {
		t.Error("node 3 inbox should be deleted")
	}
	// Node 2's inbox keeps the netID=999 invite.
	if len(e.inviteInbox[2]) != 1 {
		t.Errorf("node 2 inbox = %v, want 1 remaining", e.inviteInbox[2])
	}
}
