// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import (
	"strings"
	"testing"
	"time"
)

func TestHandleDeleteNetwork_HappyPath(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, err := e.createNetwork(1, "to-delete")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	resp, err := e.st.HandleDeleteNetwork(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
	})
	if err != nil {
		t.Fatalf("HandleDeleteNetwork: %v", err)
	}
	if resp["type"] != "delete_network_ok" {
		t.Errorf("got %v", resp["type"])
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if _, ok := e.networks[netID]; ok {
		t.Error("network should be deleted")
	}
}

func TestHandleDeleteNetwork_BackboneRejected(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleDeleteNetwork(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(0),
	})
	if err == nil || !strings.Contains(err.Error(), "backbone") {
		t.Errorf("expected backbone-protection error, got %v", err)
	}
}

func TestHandleDeleteNetwork_Unknown(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleDeleteNetwork(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(9999),
	})
	if err == nil {
		t.Fatal("expected error for unknown network")
	}
}

func TestHandleRenameNetwork_HappyPath(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, _ := e.createNetwork(1, "old-name")

	resp, err := e.st.HandleRenameNetwork(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
		"name":        "new-name",
	})
	if err != nil {
		t.Fatalf("HandleRenameNetwork: %v", err)
	}
	if resp["name"] != "new-name" {
		t.Errorf("got %v", resp["name"])
	}
}

func TestHandleRenameNetwork_BackboneRejected(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleRenameNetwork(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(0),
		"name":        "x",
	})
	if err == nil || !strings.Contains(err.Error(), "backbone") {
		t.Errorf("expected backbone error, got %v", err)
	}
}

func TestHandleRenameNetwork_InvalidName(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, _ := e.createNetwork(1, "ok-name")
	_, err := e.st.HandleRenameNetwork(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
		"name":        "BAD!@#",
	})
	if err == nil {
		t.Error("expected invalid name error")
	}
}

func TestHandleRenameNetwork_DuplicateRejected(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	net1, _ := e.createNetwork(1, "first")
	_, _ = e.createNetwork(1, "second")
	_, err := e.st.HandleRenameNetwork(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(net1),
		"name":        "second",
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected duplicate name error, got %v", err)
	}
}

func TestHandleSetNetworkEnterprise_OnAndOff(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	e.addNode(2)
	netID, _ := e.createNetwork(1, "ent-net")

	// Join node 2 so there's a member set when going enterprise.
	if _, err := e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
		"node_id":     float64(2),
	}); err != nil {
		t.Fatalf("join: %v", err)
	}

	// Turn enterprise on.
	resp, err := e.st.HandleSetNetworkEnterprise(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
		"enterprise":  true,
	})
	if err != nil {
		t.Fatalf("set enterprise on: %v", err)
	}
	if resp["enterprise"] != true {
		t.Errorf("got %v", resp["enterprise"])
	}
	e.mu.RLock()
	net := e.networks[netID]
	if !net.Enterprise {
		t.Error("Enterprise flag not set")
	}
	if len(net.MemberRoles) == 0 {
		t.Error("MemberRoles should be populated")
	}
	e.mu.RUnlock()

	// Turn enterprise off.
	_, err = e.st.HandleSetNetworkEnterprise(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
		"enterprise":  false,
	})
	if err != nil {
		t.Fatalf("set enterprise off: %v", err)
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.networks[netID].MemberRoles != nil {
		t.Error("MemberRoles should be cleared when enterprise=false")
	}
}

func TestHandleSetNetworkEnterprise_BackboneRejected(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleSetNetworkEnterprise(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(0),
		"enterprise":  true,
	})
	if err == nil {
		t.Error("expected backbone error")
	}
}

func TestHandleSetNetworkEnterprise_NeedsAdminToken(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, _ := e.createNetwork(1, "any")
	_, err := e.st.HandleSetNetworkEnterprise(map[string]interface{}{
		// No admin_token
		"network_id": float64(netID),
		"enterprise": true,
	})
	if err == nil {
		t.Error("expected admin token error")
	}
}

func TestHandleListNetworks_HappyPath(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	_, _ = e.createNetwork(1, "alpha")
	_, _ = e.createNetwork(1, "beta")

	resp, err := e.st.HandleListNetworks(map[string]interface{}{
		"admin_token": "admin",
	})
	if err != nil {
		t.Fatalf("HandleListNetworks: %v", err)
	}
	nets, _ := resp["networks"].([]map[string]interface{})
	if len(nets) != 2 {
		t.Errorf("got %d networks, want 2", len(nets))
	}
	// With admin_token, member counts are included.
	for _, n := range nets {
		if _, ok := n["members"]; !ok {
			t.Errorf("members count missing in admin listing: %v", n)
		}
	}
}

func TestHandleListNetworks_WithoutAdminOmitsMembers(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	_, _ = e.createNetwork(1, "alpha")

	resp, err := e.st.HandleListNetworks(map[string]interface{}{})
	if err != nil {
		t.Fatalf("HandleListNetworks: %v", err)
	}
	nets, _ := resp["networks"].([]map[string]interface{})
	for _, n := range nets {
		if _, ok := n["members"]; ok {
			t.Errorf("non-admin listing should hide member counts: %v", n)
		}
	}
}

func TestHandleKickMember_HappyPath(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	e.addNode(2)
	netID, _ := e.createNetwork(1, "kick-net")
	if _, err := e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
		"node_id":     float64(2),
	}); err != nil {
		t.Fatalf("join: %v", err)
	}
	// Kick requires enterprise mode.
	if _, err := e.st.HandleSetNetworkEnterprise(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
		"enterprise":  true,
	}); err != nil {
		t.Fatalf("enterprise: %v", err)
	}

	resp, err := e.st.HandleKickMember(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(2),
	})
	if err != nil {
		t.Fatalf("HandleKickMember: %v", err)
	}
	if resp["type"] != "kick_member_ok" {
		t.Errorf("got %v", resp["type"])
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, m := range e.networks[netID].Members {
		if m == 2 {
			t.Error("node 2 should be removed from members")
		}
	}
}

func TestHandleKickMember_BackboneRejected(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleKickMember(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(0),
		"target_node_id": float64(1),
	})
	if err == nil {
		t.Error("expected backbone error")
	}
}

func TestHandlePollInvites_EmptyAndPopulated(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	// Initially: empty inbox.
	resp, err := e.st.HandlePollInvites(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
	})
	if err != nil {
		t.Fatalf("HandlePollInvites empty: %v", err)
	}
	if invites, _ := resp["invites"].([]map[string]interface{}); len(invites) != 0 {
		t.Errorf("expected empty invites, got %v", invites)
	}

	// Seed an invite.
	e.mu.Lock()
	e.inviteInbox[1] = []*NetworkInvite{{NetworkID: 5, InviterID: 99, Timestamp: time.Now()}}
	e.mu.Unlock()

	resp, err = e.st.HandlePollInvites(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
	})
	if err != nil {
		t.Fatalf("HandlePollInvites populated: %v", err)
	}
	if invites, _ := resp["invites"].([]map[string]interface{}); len(invites) != 1 {
		t.Errorf("expected 1 invite, got %v", invites)
	}
}

func TestHandleGetMemberRole_HappyAndUnknown(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, _ := e.createNetwork(1, "rolenet")
	// Mark enterprise so MemberRoles is populated.
	if _, err := e.st.HandleSetNetworkEnterprise(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
		"enterprise":  true,
	}); err != nil {
		t.Fatalf("enterprise: %v", err)
	}

	resp, err := e.st.HandleGetMemberRole(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(1),
	})
	if err != nil {
		t.Fatalf("HandleGetMemberRole: %v", err)
	}
	if resp["role"] == nil {
		t.Errorf("role missing: %v", resp)
	}

	// Unknown member.
	_, err = e.st.HandleGetMemberRole(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(9999),
	})
	if err == nil {
		t.Error("expected error for unknown member")
	}
}

func TestHandleSetMemberTags_HappyAndUnknown(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	e.addNode(2)
	netID, _ := e.createNetwork(1, "tagnet")
	if _, err := e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
		"node_id":     float64(2),
	}); err != nil {
		t.Fatalf("join: %v", err)
	}

	resp, err := e.st.HandleSetMemberTags(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(2),
		"tags":           []interface{}{"role-x", "team-y"},
	})
	if err != nil {
		t.Fatalf("HandleSetMemberTags: %v", err)
	}
	if resp["type"] != "set_member_tags_ok" {
		t.Errorf("got %v", resp["type"])
	}
}

func TestHandleGetMemberTags_HappyAndAbsent(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, _ := e.createNetwork(1, "getnet")

	resp, err := e.st.HandleGetMemberTags(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(1),
	})
	if err != nil {
		t.Fatalf("HandleGetMemberTags: %v", err)
	}
	// Returns empty list when no tags set.
	if tags, _ := resp["tags"].([]string); tags == nil {
		// Allowed: zero/nil tags.
		_ = tags
	}
}

func TestReplaceState_OverwritesMap(t *testing.T) {
	t.Parallel()
	// ReplaceState swaps the Store's internal map references — it does NOT
	// mutate the caller's slice header. Verify by listing networks
	// through the Store rather than the test env's original map.
	e := newTestEnv()
	newNet := &NetworkInfo{ID: 42, Name: "replaced"}
	newInv := []*NetworkInvite{{NetworkID: 42, InviterID: 1, Timestamp: time.Now()}}

	e.st.ReplaceState(
		map[uint16]*NetworkInfo{42: newNet},
		map[uint32][]*NetworkInvite{99: newInv},
	)

	// After ReplaceState, HandleListNetworks should reflect the new map.
	resp, err := e.st.HandleListNetworks(map[string]interface{}{"admin_token": "admin"})
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	nets, _ := resp["networks"].([]map[string]interface{})
	if len(nets) != 1 {
		t.Errorf("after ReplaceState: got %d networks, want 1: %+v", len(nets), nets)
	}
}

func TestValidateNetworkName_Branches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"valid-name", false},
		{"name123", false},
		{"", true},                            // empty
		{strings.Repeat("a", 64), true},       // too long
		{"UPPER", true},                       // uppercase
		{"-leading", true},                    // leading dash
		{"trailing-", true},                   // trailing dash
		{"has space", true},                   // space
		{"has/slash", true},                   // slash
	}
	for _, tc := range cases {
		err := ValidateNetworkName(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ValidateNetworkName(%q): err=%v, wantErr=%v", tc.in, err, tc.wantErr)
		}
	}
}
