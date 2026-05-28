// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"strings"
	"testing"
)

// --- handleDirectorySync -------------------------------------------------

func TestServer_HandleDirectorySync_RequiresAdmin(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleDirectorySync(map[string]interface{}{"admin_token": "wrong"})
	if err == nil {
		t.Fatal("expected admin auth error")
	}
}

func TestServer_HandleDirectorySync_MissingNetworkID(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleDirectorySync(map[string]interface{}{
		"admin_token": "admin",
	})
	if err == nil || !strings.Contains(err.Error(), "network_id") {
		t.Fatalf("%v", err)
	}
}

func TestServer_HandleDirectorySync_MissingEntries(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleDirectorySync(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(5),
	})
	if err == nil || !strings.Contains(err.Error(), "entries") {
		t.Fatalf("%v", err)
	}
}

func TestServer_HandleDirectorySync_UnknownNetwork(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleDirectorySync(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(99),
		"entries":     []interface{}{map[string]interface{}{"external_id": "u1"}},
	})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("%v", err)
	}
}

func TestServer_HandleDirectorySync_RequiresEnterprise(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	s.mu.Lock()
	s.networks[5] = &NetworkInfo{ID: 5, Name: "plain", Enterprise: false}
	s.mu.Unlock()
	_, err := s.handleDirectorySync(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(5),
		"entries":     []interface{}{map[string]interface{}{"external_id": "u1"}},
	})
	if err == nil || !strings.Contains(err.Error(), "enterprise") {
		t.Fatalf("%v", err)
	}
}

func TestServer_HandleDirectorySync_HappyPath(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	s.mu.Lock()
	s.networks[5] = &NetworkInfo{
		ID:          5,
		Name:        "ent",
		Enterprise:  true,
		Members:     []uint32{1},
		MemberRoles: map[uint32]Role{1: RoleMember},
	}
	s.nodes[1] = &NodeInfo{ID: 1, ExternalID: "user-1"}
	s.mu.Unlock()
	resp, err := s.handleDirectorySync(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(5),
		"entries": []interface{}{
			map[string]interface{}{
				"external_id":  "user-1",
				"role":         "admin",
				"display_name": "user-one",
			},
			map[string]interface{}{
				"external_id": "user-future",
				"role":        "member",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Expect: 1 mapped (user-1), 1 unmapped (user-future), 1 updated (role change), 0 disabled.
	if resp["mapped"].(int) != 1 {
		t.Errorf("mapped: %+v", resp)
	}
	if resp["unmapped"].(int) != 1 {
		t.Errorf("unmapped: %+v", resp)
	}
	if resp["updated"].(int) < 1 {
		t.Errorf("updated: %+v", resp)
	}
}

func TestServer_HandleDirectorySync_RemoveUnlisted(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	s.mu.Lock()
	s.networks[5] = &NetworkInfo{
		ID:          5,
		Name:        "ent",
		Enterprise:  true,
		Members:     []uint32{1, 2},
		MemberRoles: map[uint32]Role{1: RoleMember, 2: RoleMember},
	}
	s.nodes[1] = &NodeInfo{ID: 1, ExternalID: "user-1", Networks: []uint16{5}}
	s.nodes[2] = &NodeInfo{ID: 2, ExternalID: "user-orphan", Networks: []uint16{5}}
	s.mu.Unlock()
	resp, err := s.handleDirectorySync(map[string]interface{}{
		"admin_token":     "admin",
		"network_id":      float64(5),
		"remove_unlisted": true,
		"entries": []interface{}{
			map[string]interface{}{"external_id": "user-1"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp["disabled"].(int) < 1 {
		t.Errorf("expected at least one disabled (user-orphan removed): %+v", resp)
	}
}

// --- handleGetDirectoryStatus -------------------------------------------

func TestServer_HandleGetDirectoryStatus_RequiresAdmin(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleGetDirectoryStatus(map[string]interface{}{"admin_token": "wrong"})
	if err == nil {
		t.Fatal("expected admin error")
	}
}

func TestServer_HandleGetDirectoryStatus_MissingNetworkID(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleGetDirectoryStatus(map[string]interface{}{
		"admin_token": "admin",
	})
	if err == nil {
		t.Fatal("expected network_id error")
	}
}

func TestServer_HandleGetDirectoryStatus_HappyPath(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	s.mu.Lock()
	s.networks[5] = &NetworkInfo{ID: 5, Name: "ent", Enterprise: true, Members: []uint32{1}}
	s.nodes[1] = &NodeInfo{ID: 1, ExternalID: "u1"}
	s.mu.Unlock()
	resp, err := s.handleGetDirectoryStatus(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(5),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := resp["network_id"]; !ok {
		t.Fatalf("missing network_id: %+v", resp)
	}
}

// --- strField / boolField shims ----------------------------------------

func TestStrField_Cases(t *testing.T) {
	t.Parallel()
	if got := strField(map[string]interface{}{"k": "v"}, "k"); got != "v" {
		t.Fatalf("got %q", got)
	}
	if got := strField(map[string]interface{}{}, "missing"); got != "" {
		t.Fatalf("missing key not empty: %q", got)
	}
	if got := strField(map[string]interface{}{"k": 42}, "k"); got != "" {
		t.Fatalf("non-string not empty: %q", got)
	}
}

func TestBoolField_Cases(t *testing.T) {
	t.Parallel()
	if !boolField(map[string]interface{}{"k": true}, "k") {
		t.Fatal("true not preserved")
	}
	if boolField(map[string]interface{}{}, "k") {
		t.Fatal("missing key returned true")
	}
}
