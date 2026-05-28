// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"strings"
	"testing"
)

// registerNode is a helper that registers a fresh node and returns its ID +
// public key b64.
func registerNode(t *testing.T, st *Store, owner string) (nodeID uint32, pubKey string) {
	t.Helper()
	pk := genPubKeyB64(t)
	resp, err := st.HandleRegister(map[string]interface{}{
		"public_key": pk,
		"owner":      owner,
	}, "10.0.0.1:4000", nil, nil)
	if err != nil {
		t.Fatalf("HandleRegister: %v", err)
	}
	return resp["node_id"].(uint32), pk
}

func TestHandleSetVisibility_HappyPath(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	nodeID, _ := registerNode(t, st, "alice")

	resp, err := st.HandleSetVisibility(map[string]interface{}{
		"node_id":     float64(nodeID),
		"public":      true,
		"admin_token": "test-admin",
	})
	if err != nil {
		t.Fatalf("HandleSetVisibility: %v", err)
	}
	if resp["type"] != "set_visibility_ok" {
		t.Errorf("got %v", resp["type"])
	}
	if resp["visibility"] != "public" {
		t.Errorf("visibility = %v, want public", resp["visibility"])
	}
}

func TestHandleSetVisibility_UnknownNode(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	_, err := st.HandleSetVisibility(map[string]interface{}{
		"node_id":     float64(0x9999),
		"public":      false,
		"admin_token": "test-admin",
	})
	if err == nil {
		t.Fatal("expected error for unknown node")
	}
}

func TestHandleSetHostname_HappyPath(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	nodeID, _ := registerNode(t, st, "alice")

	resp, err := st.HandleSetHostname(map[string]interface{}{
		"node_id":     float64(nodeID),
		"hostname":    "my-host",
		"admin_token": "test-admin",
	})
	if err != nil {
		t.Fatalf("HandleSetHostname: %v", err)
	}
	if resp["hostname"] != "my-host" {
		t.Errorf("hostname = %v", resp["hostname"])
	}
}

func TestHandleSetHostname_InvalidName(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	_, err := st.HandleSetHostname(map[string]interface{}{
		"node_id":  float64(1),
		"hostname": "UPPERCASE-NOT-ALLOWED",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid hostname") {
		t.Errorf("expected invalid hostname error, got %v", err)
	}
}

func TestHandleSetHostname_DuplicateRejected(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	node1, _ := registerNode(t, st, "alice")
	node2, _ := registerNode(t, st, "bob")

	// Claim "shared" for node1.
	if _, err := st.HandleSetHostname(map[string]interface{}{
		"node_id":     float64(node1),
		"hostname":    "shared",
		"admin_token": "test-admin",
	}); err != nil {
		t.Fatalf("first set: %v", err)
	}
	// node2 tries the same name → must fail.
	_, err := st.HandleSetHostname(map[string]interface{}{
		"node_id":     float64(node2),
		"hostname":    "shared",
		"admin_token": "test-admin",
	})
	if err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Errorf("expected duplicate error, got %v", err)
	}
}

func TestHandleSetTags_HappyPath(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	nodeID, _ := registerNode(t, st, "alice")
	resp, err := st.HandleSetTags(map[string]interface{}{
		"node_id":     float64(nodeID),
		"tags":        []interface{}{"web", "api", "#prod", "prod"}, // dedup + strip-#
		"admin_token": "test-admin",
	})
	if err != nil {
		t.Fatalf("HandleSetTags: %v", err)
	}
	tags, _ := resp["tags"].([]string)
	if len(tags) != 3 {
		t.Errorf("got %d tags, want 3 (deduped): %v", len(tags), tags)
	}
}

func TestHandleSetTags_TooManyRejected(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	nodeID, _ := registerNode(t, st, "alice")
	tags := []interface{}{}
	for i := 0; i < 11; i++ {
		tags = append(tags, string('a'+rune(i)))
	}
	_, err := st.HandleSetTags(map[string]interface{}{
		"node_id":     float64(nodeID),
		"tags":        tags,
		"admin_token": "test-admin",
	})
	if err == nil || !strings.Contains(err.Error(), "too many tags") {
		t.Errorf("expected 'too many tags' error, got %v", err)
	}
}

func TestHandleSetTags_TagTooLong(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	nodeID, _ := registerNode(t, st, "alice")
	_, err := st.HandleSetTags(map[string]interface{}{
		"node_id":     float64(nodeID),
		"tags":        []interface{}{strings.Repeat("a", 33)},
		"admin_token": "test-admin",
	})
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("expected 'too long' error, got %v", err)
	}
}

func TestHandleSetTags_TagBadFormat(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	nodeID, _ := registerNode(t, st, "alice")
	_, err := st.HandleSetTags(map[string]interface{}{
		"node_id":     float64(nodeID),
		"tags":        []interface{}{"UPPER-not-allowed"},
		"admin_token": "test-admin",
	})
	if err == nil || !strings.Contains(err.Error(), "lowercase") {
		t.Errorf("expected lowercase error, got %v", err)
	}
}

func TestHandleSetTags_UnknownNode(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	_, err := st.HandleSetTags(map[string]interface{}{
		"node_id":     float64(0x9999),
		"tags":        []interface{}{"x"},
		"admin_token": "test-admin",
	})
	if err == nil {
		t.Fatal("expected error for unknown node")
	}
}

func TestHandleHeartbeat_HappyAndUnknown(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	nodeID, _ := registerNode(t, st, "alice")

	resp, err := st.HandleHeartbeat(map[string]interface{}{
		"node_id":     float64(nodeID),
		"admin_token": "test-admin",
	})
	if err != nil {
		t.Fatalf("HandleHeartbeat: %v", err)
	}
	if _, ok := resp[RawResponseKey]; !ok {
		t.Errorf("response missing raw body: %v", resp)
	}

	if _, err := st.HandleHeartbeat(map[string]interface{}{
		"node_id":     float64(0x9999),
		"admin_token": "test-admin",
	}); err == nil {
		t.Error("expected error for unknown node")
	}
}

func TestHandleDeregister_HappyPath(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	nodeID, _ := registerNode(t, st, "alice")

	resp, err := st.HandleDeregister(map[string]interface{}{
		"node_id":     float64(nodeID),
		"admin_token": "test-admin",
	})
	if err != nil {
		t.Fatalf("HandleDeregister: %v", err)
	}
	if resp["type"] != "deregister_ok" {
		t.Errorf("got %v", resp["type"])
	}
	// Subsequent lookup must miss.
	st.mu.RLock()
	_, exists := st.nodes[nodeID]
	st.mu.RUnlock()
	if exists {
		t.Error("node should be removed after deregister")
	}
}

func TestHandleLookup_HappyAndUnknown(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	nodeID, _ := registerNode(t, st, "alice")

	resp, err := st.HandleLookup(map[string]interface{}{
		"node_id": float64(nodeID),
	})
	if err != nil {
		t.Fatalf("HandleLookup: %v", err)
	}
	if resp["type"] != "lookup_ok" {
		t.Errorf("got %v", resp["type"])
	}

	if _, err := st.HandleLookup(map[string]interface{}{
		"node_id": float64(0x9999),
	}); err == nil {
		t.Error("expected error for unknown node")
	}
}

func TestHandleResolve_HappyAndUnknown(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	nodeID, _ := registerNode(t, st, "alice")
	requester, _ := registerNode(t, st, "bob")
	// Make target public so the resolve passes the privacy gate.
	if _, err := st.HandleSetVisibility(map[string]interface{}{
		"node_id":     float64(nodeID),
		"public":      true,
		"admin_token": "test-admin",
	}); err != nil {
		t.Fatalf("set visibility: %v", err)
	}

	resp, err := st.HandleResolve(map[string]interface{}{
		"node_id":      float64(nodeID),
		"requester_id": float64(requester),
	})
	if err != nil {
		t.Fatalf("HandleResolve: %v", err)
	}
	if resp["type"] != "resolve_ok" {
		t.Errorf("got %v", resp["type"])
	}

	if _, err := st.HandleResolve(map[string]interface{}{
		"node_id":      float64(0x9999),
		"requester_id": float64(requester),
	}); err == nil {
		t.Error("expected error for unknown node")
	}
}

func TestHandleResolveHostname_HappyAndMisses(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	nodeID, _ := registerNode(t, st, "alice")
	if _, err := st.HandleSetHostname(map[string]interface{}{
		"node_id":     float64(nodeID),
		"hostname":    "resolver",
		"admin_token": "test-admin",
	}); err != nil {
		t.Fatalf("set hostname: %v", err)
	}
	// Make node public so cross-requester resolve is allowed.
	if _, err := st.HandleSetVisibility(map[string]interface{}{
		"node_id":     float64(nodeID),
		"public":      true,
		"admin_token": "test-admin",
	}); err != nil {
		t.Fatalf("set visibility: %v", err)
	}

	resp, err := st.HandleResolveHostname(map[string]interface{}{"hostname": "resolver"})
	if err != nil {
		t.Fatalf("HandleResolveHostname: %v", err)
	}
	if resp["type"] != "resolve_hostname_ok" {
		t.Errorf("got %v", resp["type"])
	}

	if _, err := st.HandleResolveHostname(map[string]interface{}{"hostname": "no-such"}); err == nil {
		t.Error("expected error for unknown hostname")
	}
	// Empty hostname → error.
	if _, err := st.HandleResolveHostname(map[string]interface{}{"hostname": ""}); err == nil {
		t.Error("expected error for empty hostname")
	}
}

func TestHandleListNodes_BackboneRequiresAdmin(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	// requireAdmin returns nil → admin path → AdminListNodesCached.
	_, err := st.HandleListNodes(map[string]interface{}{}, func(map[string]interface{}) error {
		return nil
	})
	if err != nil {
		t.Errorf("admin path: %v", err)
	}
}

func TestHandleListNodes_BackboneWithoutAdminFails(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	_, err := st.HandleListNodes(map[string]interface{}{}, func(map[string]interface{}) error {
		return errSimulated{}
	})
	if err == nil {
		t.Fatal("expected error when admin check fails")
	}
}

type errSimulated struct{}

func (errSimulated) Error() string { return "no" }

func TestSanitizeListenAddr_Branches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		remote string
		client string
		want   string
	}{
		// Both empty → empty.
		{"", "", ""},
		// Only client set → returned as-is.
		{"", "1.2.3.4:9000", "1.2.3.4:9000"},
		// Remote and client → client wins.
		{"10.0.0.1:55555", "8.8.8.8:9000", "8.8.8.8:9000"},
	}
	for _, tc := range cases {
		if got := sanitizeListenAddr(tc.remote, tc.client); got != tc.want {
			t.Errorf("sanitizeListenAddr(%q, %q) = %q, want %q", tc.remote, tc.client, got, tc.want)
		}
	}
}
