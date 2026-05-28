// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import (
	"strings"
	"testing"
)

func TestHandleJoinNetwork_BackboneRejected(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
		"network_id":  float64(0),
	})
	if err == nil || !strings.Contains(err.Error(), "backbone") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleJoinNetwork_UnknownNode(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(9999),
		"network_id":  float64(1),
	})
	if err == nil {
		t.Error("expected unknown-node error")
	}
}

func TestHandleJoinNetwork_UnknownNetwork(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	_, err := e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
		"network_id":  float64(9999),
	})
	if err == nil {
		t.Error("expected unknown-network error")
	}
}

func TestHandleJoinNetwork_AlreadyMember(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, _ := e.createNetwork(1, "already")
	// Creator is auto-member; joining again should error.
	_, err := e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
		"network_id":  float64(netID),
	})
	if err == nil || !strings.Contains(err.Error(), "already in network") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleJoinNetwork_TokenRuleWrongToken(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	e.addNode(2)
	resp, err := e.st.HandleCreateNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
		"name":        "tok-net",
		"join_rule":   "token",
		"token":       "secret",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := resp["network_id"].(uint16)

	_, err = e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
		"network_id":  float64(netID),
		"token":       "wrong",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid token") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleJoinNetwork_TokenRuleCorrectToken(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	e.addNode(2)
	resp, err := e.st.HandleCreateNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
		"name":        "tok-ok",
		"join_rule":   "token",
		"token":       "right",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := resp["network_id"].(uint16)
	if _, err := e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
		"network_id":  float64(netID),
		"token":       "right",
	}); err != nil {
		t.Errorf("happy join: %v", err)
	}
}

func TestHandleJoinNetwork_InviteRuleRejectsDirectJoin(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	e.addNode(2)
	netID := createInviteNetwork(t, e, 1)

	_, err := e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
		"network_id":  float64(netID),
	})
	if err == nil || !strings.Contains(err.Error(), "invite") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleJoinNetwork_MembershipLimitReached(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	e.addNode(2)
	netID, _ := e.createNetwork(1, "limit-test")
	// Pre-set Policy.MaxMembers=1 — creator already a member, so node 2 hits the limit.
	e.mu.Lock()
	e.networks[netID].Policy.MaxMembers = 1
	e.mu.Unlock()

	_, err := e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
		"network_id":  float64(netID),
	})
	if err == nil || !strings.Contains(err.Error(), "limit reached") {
		t.Errorf("err = %v", err)
	}
}
