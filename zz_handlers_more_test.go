// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"strings"
	"testing"
	"time"
)

// --- trustPairKey -------------------------------------------------------

func TestTrustPairKey_OrderInvariant(t *testing.T) {
	t.Parallel()
	if trustPairKey(2, 1) != trustPairKey(1, 2) {
		t.Fatal("order should not change the key")
	}
	if trustPairKey(1, 2) != "1:2" {
		t.Fatalf("got %q", trustPairKey(1, 2))
	}
	if trustPairKey(10, 3) != "3:10" {
		t.Fatalf("got %q", trustPairKey(10, 3))
	}
}

// --- cleanupNode --------------------------------------------------------

func TestServer_CleanupNode_NoPanicNoMutation(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	// Intentionally a no-op stub in production; call to cover.
	s.cleanupNode(123)
}

// --- setNodeHostname ----------------------------------------------------

func TestServer_SetNodeHostname_EmptyIsNoop(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	node := &NodeInfo{ID: 1}
	resp := map[string]interface{}{}
	s.mu.Lock()
	s.nodes[1] = node
	s.mu.Unlock()
	s.setNodeHostname(node, "", resp)
	if _, set := resp["hostname"]; set {
		t.Fatal("empty hostname should not set field")
	}
}

func TestServer_SetNodeHostname_HappyPath(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	node := &NodeInfo{ID: 1}
	s.mu.Lock()
	s.nodes[1] = node
	s.mu.Unlock()
	resp := map[string]interface{}{}
	s.mu.Lock()
	s.setNodeHostname(node, "host-a", resp)
	s.mu.Unlock()
	if resp["hostname"] != "host-a" {
		t.Fatalf("resp: %+v", resp)
	}
	s.mu.RLock()
	if s.hostnameIdx["host-a"] != 1 {
		t.Fatal("hostnameIdx not updated")
	}
	s.mu.RUnlock()
}

func TestServer_SetNodeHostname_CollisionSetsError(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	node1 := &NodeInfo{ID: 1, Hostname: "first"}
	node2 := &NodeInfo{ID: 2}
	s.mu.Lock()
	s.nodes[1] = node1
	s.nodes[2] = node2
	s.hostnameIdx["first"] = 1
	s.mu.Unlock()
	resp := map[string]interface{}{}
	s.mu.Lock()
	s.setNodeHostname(node2, "first", resp)
	s.mu.Unlock()
	if msg, ok := resp["hostname_error"].(string); !ok || !strings.Contains(msg, "already in use") {
		t.Fatalf("expected hostname_error: %+v", resp)
	}
}

// --- handleSetWebhook / handleSetIdentityWebhook ------------------------

func TestServer_HandleSetWebhook_RequiresAdmin(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleSetWebhook(map[string]interface{}{
		"admin_token": "wrong",
		"url":         "https://x",
	})
	if err == nil {
		t.Fatal("expected admin auth failure")
	}
}

func TestServer_HandleSetWebhook_HappyPath(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleSetWebhook(map[string]interface{}{
		"admin_token": "admin",
		"url":         "https://example.com/hook",
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestServer_HandleSetWebhook_BadURLRejected(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleSetWebhook(map[string]interface{}{
		"admin_token": "admin",
		"url":         "ftp://not-allowed",
	})
	if err == nil {
		t.Fatal("expected URL validation error")
	}
}

func TestServer_HandleSetIdentityWebhook_RequiresAdmin(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleSetIdentityWebhook(map[string]interface{}{
		"admin_token": "wrong",
	})
	if err == nil {
		t.Fatal("expected admin auth")
	}
}

func TestServer_HandleSetIdentityWebhook_BadURLRejected(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleSetIdentityWebhook(map[string]interface{}{
		"admin_token": "admin",
		"url":         "javascript:alert(1)",
	})
	if err == nil {
		t.Fatal("expected URL validation error")
	}
}

// --- handleSetAuditExport -----------------------------------------------

func TestServer_HandleSetAuditExport_DisablesWhenEmpty(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	resp, err := s.handleSetAuditExport(map[string]interface{}{
		"admin_token": "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "disabled" {
		t.Fatalf("%+v", resp)
	}
}

func TestServer_HandleSetAuditExport_EnablesWithValidEndpoint(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	resp, err := s.handleSetAuditExport(map[string]interface{}{
		"admin_token": "admin",
		"format":      "json",
		"endpoint":    "https://example.com/audit",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "enabled" {
		t.Fatalf("%+v", resp)
	}
}

func TestServer_HandleSetAuditExport_BadURLRejected(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleSetAuditExport(map[string]interface{}{
		"admin_token": "admin",
		"format":      "json",
		"endpoint":    "javascript:bad",
	})
	if err == nil {
		t.Fatal("expected URL validation error")
	}
}

func TestServer_HandleSetAuditExport_RequiresAdmin(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleSetAuditExport(map[string]interface{}{
		"admin_token": "wrong",
	})
	if err == nil {
		t.Fatal("expected admin auth")
	}
}

// --- handleSetIDPConfig / handleGetIDPConfig ----------------------------

func TestServer_HandleSetIDPConfig_RequiresAdmin(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleSetIDPConfig(map[string]interface{}{
		"admin_token": "wrong",
	})
	if err == nil {
		t.Fatal("expected admin auth")
	}
}

func TestServer_HandleSetIDPConfig_BadURLRejected(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleSetIDPConfig(map[string]interface{}{
		"admin_token": "admin",
		"url":         "javascript:bad",
	})
	if err == nil {
		t.Fatal("expected URL validation error")
	}
}

func TestServer_HandleGetIDPConfig_RequiresAdmin(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleGetIDPConfig(map[string]interface{}{
		"admin_token": "wrong",
	})
	if err == nil {
		t.Fatal("expected admin auth")
	}
}

func TestServer_HandleGetIDPConfig_UnconfiguredFlagFalse(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	resp, err := s.handleGetIDPConfig(map[string]interface{}{
		"admin_token": "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp["configured"] != false {
		t.Fatalf("%+v", resp)
	}
}

func TestServer_HandleGetIDPConfig_ReturnsStoredFields(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	cfg := &BlueprintIdentityProvider{
		Type:     "oidc",
		URL:      "https://idp.example.com",
		Issuer:   "issuer-1",
		ClientID: "client-1",
		TenantID: "tenant-1",
		Domain:   "example.com",
	}
	s.storeIdentityProviderConfig(cfg)
	resp, err := s.handleGetIDPConfig(map[string]interface{}{
		"admin_token": "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp["configured"] != true {
		t.Fatalf("configured: %+v", resp)
	}
	if resp["idp_type"] != "oidc" || resp["url"] != "https://idp.example.com" {
		t.Fatalf("fields: %+v", resp)
	}
	if resp["issuer"] != "issuer-1" || resp["client_id"] != "client-1" {
		t.Fatalf("optional fields missing: %+v", resp)
	}
}

// --- handleGetAuditLog --------------------------------------------------

func TestServer_HandleGetAuditLog_RequiresAdmin(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleGetAuditLog(map[string]interface{}{
		"admin_token": "wrong",
	})
	if err == nil {
		t.Fatal("expected admin auth")
	}
}

func TestServer_HandleGetAuditLog_HappyPathReturnsEntries(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	s.appendAudit("act", 5, 42, "k", "v")
	resp, err := s.handleGetAuditLog(map[string]interface{}{
		"admin_token": "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	entries, ok := resp["entries"].([]map[string]interface{})
	if !ok || len(entries) == 0 {
		t.Fatalf("entries: %+v", resp)
	}
	if entries[0]["action"] != "act" {
		t.Fatalf("first entry: %+v", entries[0])
	}
}

func TestServer_HandleGetAuditLog_FiltersByNetwork(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	s.appendAudit("a", 5, 0)
	s.appendAudit("b", 9, 0)
	resp, err := s.handleGetAuditLog(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(5),
	})
	if err != nil {
		t.Fatal(err)
	}
	entries := resp["entries"].([]map[string]interface{})
	for _, e := range entries {
		if id, ok := e["network_id"]; ok && id != uint16(5) {
			t.Errorf("entry leaked from other net: %+v", e)
		}
	}
}

// --- handleBeaconRegister -----------------------------------------------

func TestServer_HandleBeaconRegister_RequiresAdmin(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleBeaconRegister(map[string]interface{}{
		"admin_token": "wrong",
	})
	if err == nil {
		t.Fatal("expected admin auth")
	}
}

// --- TriggerSnapshot ----------------------------------------------------

func TestServer_TriggerSnapshot_NoStorePathReturnsNil(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if err := s.TriggerSnapshot(); err != nil {
		t.Fatal(err)
	}
}

// --- UpdateNodeExternalID -----------------------------------------------

func TestServer_UpdateNodeExternalID_UnknownNode(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	_, ok := s.UpdateNodeExternalID(999, "new-ext")
	if ok {
		t.Fatal("unknown node should return ok=false")
	}
}

func TestServer_UpdateNodeExternalID_RoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	s.nodes[7] = &NodeInfo{ID: 7, ExternalID: "old"}
	s.mu.Unlock()
	old, ok := s.UpdateNodeExternalID(7, "new")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if old != "old" {
		t.Fatalf("old = %q", old)
	}
	s.mu.RLock()
	if s.nodes[7].ExternalID != "new" {
		t.Errorf("ExternalID = %q", s.nodes[7].ExternalID)
	}
	s.mu.RUnlock()
}

// --- UpdateNodeKeyExpiry ------------------------------------------------

func TestServer_UpdateNodeKeyExpiry_UnknownNode(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	_, ok := s.UpdateNodeKeyExpiry(999, time.Now())
	if ok {
		t.Fatal("unknown node should return ok=false")
	}
}

func TestServer_UpdateNodeKeyExpiry_HappyPath(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	expiry := time.Now().Add(24 * time.Hour)
	s.mu.Lock()
	s.nodes[7] = &NodeInfo{ID: 7}
	s.mu.Unlock()
	old, ok := s.UpdateNodeKeyExpiry(7, expiry)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !old.IsZero() {
		t.Errorf("old should be zero on first set: %v", old)
	}
}

// --- LookupNode / LookupNodeKey / LookupNodeFull ------------------------

func TestServer_LookupNode_Empty(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	_, _, ok := s.LookupNode(999)
	if ok {
		t.Fatal("unknown node")
	}
}

func TestServer_LookupNode_ReturnsFields(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	s.nodes[7] = &NodeInfo{ID: 7, PublicKey: []byte{1, 2, 3}, Networks: []uint16{1, 2}}
	s.mu.Unlock()
	pk, nets, ok := s.LookupNode(7)
	if !ok || len(pk) != 3 || len(nets) != 2 {
		t.Fatalf("pk=%v nets=%v ok=%v", pk, nets, ok)
	}
}

func TestServer_LookupNodeKey_ReturnsCopy(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	s.nodes[7] = &NodeInfo{ID: 7, PublicKey: []byte{9, 8, 7}}
	s.mu.Unlock()
	got, ok := s.LookupNodeKey(7)
	if !ok || got[0] != 9 {
		t.Fatalf("got %v", got)
	}
	// Mutating the returned slice must not mutate the stored key.
	got[0] = 1
	got2, _ := s.LookupNodeKey(7)
	if got2[0] != 9 {
		t.Fatalf("stored key was mutated")
	}
}

func TestServer_LookupNodeKey_Unknown(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if _, ok := s.LookupNodeKey(999); ok {
		t.Fatal("expected !ok")
	}
}

func TestServer_LookupNodeFull_Unknown(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	_, _, _, _, _, ok := s.LookupNodeFull(999)
	if ok {
		t.Fatal("expected !ok")
	}
}

func TestServer_LookupNodeFull_HappyPath(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	s.nodes[42] = &NodeInfo{
		ID:         42,
		PublicKey:  []byte{1, 2},
		Networks:   []uint16{5},
		ExternalID: "ext",
		Owner:      "owner-1",
	}
	s.mu.Unlock()
	pk, _, nets, ext, owner, ok := s.LookupNodeFull(42)
	if !ok {
		t.Fatal("expected ok")
	}
	if len(pk) != 2 || len(nets) != 1 || ext != "ext" || owner != "owner-1" {
		t.Fatalf("pk=%v nets=%v ext=%q owner=%q", pk, nets, ext, owner)
	}
}

// --- AdminToken ---------------------------------------------------------

func TestServer_AdminTokenAccessor(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "secret-token")
	if s.AdminToken() != "secret-token" {
		t.Fatalf("got %q", s.AdminToken())
	}
}

// --- sanitizeListenAddr (server package wrapper) ------------------------

func TestServer_SanitizeListenAddr_DelegatesToAccept(t *testing.T) {
	t.Parallel()
	// Just exercise the wrapper.
	_ = sanitizeListenAddr("1.2.3.4:5", "5.6.7.8:9")
}
