// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import (
	"testing"
)

func TestHandleGetMemberTags_UnknownNetwork(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleGetMemberTags(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(9999),
	})
	if err == nil {
		t.Error("expected unknown-network error")
	}
}

func TestHandleGetMemberTags_AllMembersBranch(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	e.addNode(2)
	netID, _ := e.createNetwork(1, "all-tags")
	if _, err := e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
		"node_id":     float64(2),
	}); err != nil {
		t.Fatalf("join: %v", err)
	}
	// Set tags for one member.
	if _, err := e.st.HandleSetMemberTags(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(2),
		"tags":           []interface{}{"web"},
	}); err != nil {
		t.Fatalf("set: %v", err)
	}

	// Query with target_node_id=0 → all-members branch.
	resp, err := e.st.HandleGetMemberTags(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
	})
	if err != nil {
		t.Fatalf("HandleGetMemberTags: %v", err)
	}
	all, ok := resp["members"].(map[string]interface{})
	if !ok {
		t.Fatalf("members not a map: %T", resp["members"])
	}
	// Should contain entries for both members (creator 1 + joined 2).
	if len(all) != 2 {
		t.Errorf("members len = %d, want 2", len(all))
	}
	// Node 2 has tags, node 1 should get an empty list.
	if tags1, ok := all["1"].([]string); !ok || len(tags1) != 0 {
		t.Errorf("node 1 tags = %v, want empty list", all["1"])
	}
	if tags2, ok := all["2"].([]string); !ok || len(tags2) != 1 || tags2[0] != "web" {
		t.Errorf("node 2 tags = %v, want [web]", all["2"])
	}
}

func TestHandleGetMemberTags_SpecificTargetReturnsEmpty(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, _ := e.createNetwork(1, "no-tags-set")
	// Don't set any tags.
	resp, err := e.st.HandleGetMemberTags(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(1),
	})
	if err != nil {
		t.Fatalf("HandleGetMemberTags: %v", err)
	}
	tags, _ := resp["tags"].([]string)
	if tags == nil || len(tags) != 0 {
		t.Errorf("tags = %v, want empty slice", tags)
	}
}
