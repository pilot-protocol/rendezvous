// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import (
	"testing"
	"time"
)

func TestHandlePollInvites_UnknownNode(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandlePollInvites(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(9999),
	})
	if err == nil {
		t.Error("expected unknown-node error")
	}
}

func TestHandlePollInvites_ExpiredInvitesAreCleanedUp(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(2)
	// Seed inbox with one expired + one fresh invite.
	old := time.Now().Add(-2 * InviteTTL)
	fresh := time.Now()
	e.mu.Lock()
	e.inviteInbox[2] = []*NetworkInvite{
		{NetworkID: 5, InviterID: 1, Timestamp: old},
		{NetworkID: 7, InviterID: 1, Timestamp: fresh},
	}
	e.mu.Unlock()

	resp, err := e.st.HandlePollInvites(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
	})
	if err != nil {
		t.Fatalf("HandlePollInvites: %v", err)
	}
	invites, _ := resp["invites"].([]map[string]interface{})
	if len(invites) != 1 {
		t.Errorf("invites len = %d, want 1 (expired filtered)", len(invites))
	}
	// Verify the inbox in storage now only has the fresh one.
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.inviteInbox[2]) != 1 {
		t.Errorf("inbox len = %d, want 1", len(e.inviteInbox[2]))
	}
}

func TestHandlePollInvites_AllExpiredEmptiesInbox(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(2)
	old := time.Now().Add(-2 * InviteTTL)
	e.mu.Lock()
	e.inviteInbox[2] = []*NetworkInvite{
		{NetworkID: 5, InviterID: 1, Timestamp: old},
	}
	e.mu.Unlock()

	resp, err := e.st.HandlePollInvites(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
	})
	if err != nil {
		t.Fatalf("HandlePollInvites: %v", err)
	}
	invites, _ := resp["invites"].([]map[string]interface{})
	if len(invites) != 0 {
		t.Errorf("invites len = %d, want 0", len(invites))
	}
}
