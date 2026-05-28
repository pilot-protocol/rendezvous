// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/json"
	"strings"
	"testing"

	identpkg "github.com/pilot-protocol/rendezvous/identity"
)

func TestFindOrCreateNetwork_DisabledWithoutAdminToken(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	_, _, err := s.findOrCreateNetwork("new-net", false, "open", "", "", "")
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Errorf("err = %v, want 'disabled'", err)
	}
}

func TestFindOrCreateNetwork_HappyAndIdempotent(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	netID, created, err := s.findOrCreateNetwork("foo", true, "", "", "", "ADM")
	if err != nil {
		t.Fatalf("findOrCreateNetwork: %v", err)
	}
	if netID == 0 || !created {
		t.Errorf("netID=%d created=%v", netID, created)
	}

	// Second call with same name returns the same net, created=false.
	netID2, created2, err := s.findOrCreateNetwork("foo", true, "", "", "", "ADM")
	if err != nil {
		t.Fatalf("re-find: %v", err)
	}
	if netID2 != netID || created2 {
		t.Errorf("idempotency: netID=%d created=%v, want %d, false", netID2, created2, netID)
	}
}

func TestFindOrCreateNetwork_AdminTokenMismatch(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	if _, _, err := s.findOrCreateNetwork("foo", false, "", "", "", "wrong"); err == nil {
		t.Error("expected admin token mismatch")
	}
}

func TestFindOrCreateNetwork_InvalidName(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	if _, _, err := s.findOrCreateNetwork("BAD NAME!@#", false, "", "", "", "ADM"); err == nil {
		t.Error("expected validation error")
	}
}

func TestApplyBlueprintPolicy_HappyPath(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	netID, _, err := s.findOrCreateNetwork("p", false, "", "", "", "ADM")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	pol := &identpkg.BlueprintPolicy{
		MaxMembers:   50,
		AllowedPorts: []uint16{80, 443},
		Description:  "test desc",
	}
	if err := s.applyBlueprintPolicy(netID, pol); err != nil {
		t.Fatalf("applyBlueprintPolicy: %v", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	net := s.networks[netID]
	if net.Policy.MaxMembers != 50 {
		t.Errorf("MaxMembers = %d", net.Policy.MaxMembers)
	}
	if net.Policy.Description != "test desc" {
		t.Errorf("Description = %q", net.Policy.Description)
	}
}

func TestApplyBlueprintPolicy_UnknownNetwork(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	if err := s.applyBlueprintPolicy(9999, &identpkg.BlueprintPolicy{}); err == nil {
		t.Error("expected unknown network error")
	}
}

func TestApplyBlueprintExprPolicy_HappyPath(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	netID, _, _ := s.findOrCreateNetwork("p", false, "", "", "", "ADM")
	body := json.RawMessage(`{"version":1}`)
	if err := s.applyBlueprintExprPolicy(netID, body); err != nil {
		t.Fatalf("applyBlueprintExprPolicy: %v", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if string(s.networks[netID].ExprPolicy) != string(body) {
		t.Errorf("expr policy = %s", s.networks[netID].ExprPolicy)
	}
}

func TestApplyBlueprintExprPolicy_UnknownNetwork(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	if err := s.applyBlueprintExprPolicy(9999, json.RawMessage(`{}`)); err == nil {
		t.Error("expected unknown network error")
	}
}

func TestConfigureAuditExport_DelegatesToStore(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.configureAuditExport(&identpkg.BlueprintAuditExport{
		Format:   "splunk_hec",
		Endpoint: "https://splunk/hec",
	})
	// Verify via the audit store's accessor.
	cfg := s.auditStore.ExporterConfig()
	if cfg == nil || cfg.Format != "splunk_hec" {
		t.Errorf("audit cfg = %+v", cfg)
	}
}

func TestProvisionCallbacks_NotNil(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	cb := s.provisionCallbacks()
	if cb.FindOrCreateNetwork == nil {
		t.Error("FindOrCreateNetwork nil")
	}
	if cb.EnableEnterprise == nil {
		t.Error("EnableEnterprise nil")
	}
}
