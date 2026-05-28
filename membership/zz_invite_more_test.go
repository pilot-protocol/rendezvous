// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import (
	"strings"
	"testing"
	"time"
)

func TestHandleInviteToNetwork_TargetAlreadyMember(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(2)
	netID := createInviteNetwork(t, e, 1)
	// Make node 2 already a member.
	e.nodes[2] = nodeRecord{networks: []uint16{netID}}

	_, err := e.st.HandleInviteToNetwork(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"inviter_id":     float64(1),
		"target_node_id": float64(2),
	})
	if err == nil || !strings.Contains(err.Error(), "already a member") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleInviteToNetwork_InboxFull(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(2)
	netID := createInviteNetwork(t, e, 1)
	// Fill target node 2's inbox to MaxInviteInbox using different netIDs.
	e.mu.Lock()
	for i := 0; i < MaxInviteInbox; i++ {
		e.inviteInbox[2] = append(e.inviteInbox[2], &NetworkInvite{
			NetworkID: uint16(100 + i),
			InviterID: 99,
			Timestamp: time.Now(),
		})
	}
	e.mu.Unlock()

	_, err := e.st.HandleInviteToNetwork(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"inviter_id":     float64(1),
		"target_node_id": float64(2),
	})
	if err == nil || !strings.Contains(err.Error(), "inbox full") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleInviteToNetwork_UnknownNetwork(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	e.addNode(2)
	_, err := e.st.HandleInviteToNetwork(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(9999),
		"inviter_id":     float64(1),
		"target_node_id": float64(2),
	})
	if err == nil {
		t.Error("expected error for unknown network")
	}
}
