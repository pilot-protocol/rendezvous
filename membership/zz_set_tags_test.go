// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import (
	"strings"
	"testing"
)

func TestHandleSetMemberTags_TooManyTags(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, _ := e.createNetwork(1, "tags-many")
	tags := []interface{}{}
	for i := 0; i < 11; i++ {
		tags = append(tags, "t"+string('a'+rune(i)))
	}
	_, err := e.st.HandleSetMemberTags(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(1),
		"tags":           tags,
	})
	if err == nil || !strings.Contains(err.Error(), "too many") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleSetMemberTags_EmptyTagRejected(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, _ := e.createNetwork(1, "empty-tag")
	_, err := e.st.HandleSetMemberTags(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(1),
		"tags":           []interface{}{""},
	})
	if err == nil || !strings.Contains(err.Error(), "empty tag") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleSetMemberTags_BadFormatRejected(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, _ := e.createNetwork(1, "bad-fmt")
	_, err := e.st.HandleSetMemberTags(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(1),
		"tags":           []interface{}{"UPPER-not-allowed"},
	})
	if err == nil || !strings.Contains(err.Error(), "lowercase") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleSetMemberTags_UnknownNetwork(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleSetMemberTags(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(9999),
		"target_node_id": float64(1),
		"tags":           []interface{}{"x"},
	})
	if err == nil {
		t.Error("expected unknown-network error")
	}
}

func TestHandleSetMemberTags_NotAMember(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, _ := e.createNetwork(1, "not-mem")
	_, err := e.st.HandleSetMemberTags(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(9999),
		"tags":           []interface{}{"x"},
	})
	if err == nil || !strings.Contains(err.Error(), "not a member") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleSetMemberTags_EmptyTagListClears(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, _ := e.createNetwork(1, "clear-tags")
	// First set some tags.
	if _, err := e.st.HandleSetMemberTags(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(1),
		"tags":           []interface{}{"web", "prod"},
	}); err != nil {
		t.Fatalf("first set: %v", err)
	}
	// Now clear with empty list.
	resp, err := e.st.HandleSetMemberTags(map[string]interface{}{
		"admin_token":    "admin",
		"network_id":     float64(netID),
		"target_node_id": float64(1),
		"tags":           []interface{}{},
	})
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if resp["type"] != "set_member_tags_ok" {
		t.Errorf("type = %v", resp["type"])
	}
	// Verify tag map no longer contains the target.
	e.mu.RLock()
	defer e.mu.RUnlock()
	if _, ok := e.networks[netID].MemberTags[1]; ok {
		t.Error("MemberTags entry should be removed")
	}
}
