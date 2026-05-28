// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

func makePCB() (ProvisionCallbacks, *struct {
	foundOrCreatedCalls   int
	enableEnterpriseCalls int
	applyPolicyCalls      int
	applyExprCalls        int
	setAuditWHCalls       int
	storeRBACCalls        int
	configureAuditCalls   int
	incProvisionsCalls    int
}) {
	counts := &struct {
		foundOrCreatedCalls   int
		enableEnterpriseCalls int
		applyPolicyCalls      int
		applyExprCalls        int
		setAuditWHCalls       int
		storeRBACCalls        int
		configureAuditCalls   int
		incProvisionsCalls    int
	}{}
	pcb := ProvisionCallbacks{
		FindOrCreateNetwork: func(_ string, _ bool, _, _, _, _ string) (uint16, bool, error) {
			counts.foundOrCreatedCalls++
			return 42, true, nil
		},
		EnableEnterprise:        func(uint16) { counts.enableEnterpriseCalls++ },
		ApplyNetworkPolicy:      func(uint16, *BlueprintPolicy) error { counts.applyPolicyCalls++; return nil },
		ApplyExprPolicy:         func(uint16, json.RawMessage) error { counts.applyExprCalls++; return nil },
		SetAuditWebhookURL:      func(string) { counts.setAuditWHCalls++ },
		StoreRBACPreAssignments: func(uint16, []BlueprintRole) { counts.storeRBACCalls++ },
		ConfigureAuditExport:    func(*BlueprintAuditExport) { counts.configureAuditCalls++ },
		IncProvisionsTotal:      func() { counts.incProvisionsCalls++ },
	}
	return pcb, counts
}

func TestApplyBlueprint_InvalidBlueprint(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	bp := &NetworkBlueprint{} // empty → fails ValidateBlueprint
	pcb, _ := makePCB()
	_, err := st.ApplyBlueprint(bp, "admin", pcb)
	if err == nil {
		t.Error("expected invalid-blueprint error")
	}
}

func TestApplyBlueprint_RequiresFindOrCreateCallback(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	bp := &NetworkBlueprint{Name: "valid-net"}
	pcb := ProvisionCallbacks{} // no FindOrCreateNetwork
	_, err := st.ApplyBlueprint(bp, "admin", pcb)
	if err == nil {
		t.Error("expected error for missing callback")
	}
}

func TestApplyBlueprint_FindOrCreateError(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	bp := &NetworkBlueprint{Name: "valid-net"}
	pcb := ProvisionCallbacks{
		FindOrCreateNetwork: func(_ string, _ bool, _, _, _, _ string) (uint16, bool, error) {
			return 0, false, errors.New("simulated")
		},
	}
	_, err := st.ApplyBlueprint(bp, "admin", pcb)
	if err == nil {
		t.Error("expected error propagation")
	}
}

func TestApplyBlueprint_FullHappyPath(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	bp := &NetworkBlueprint{
		Name:       "full",
		Enterprise: true,
		Policy:     &BlueprintPolicy{MaxMembers: 10},
		ExprPolicy: json.RawMessage(`{"version":1,"rules":[{"name":"r"}]}`),
		IdentityProvider: &wire.BlueprintIdentityProvider{
			Type: "oidc", URL: "https://idp/jwks",
		},
		Webhooks: &BlueprintWebhooks{
			AuditURL:    "https://audit",
			IdentityURL: "https://id",
		},
		AuditExport: &BlueprintAuditExport{Format: "splunk_hec", Endpoint: "https://splunk"},
		Roles:       []BlueprintRole{{ExternalID: "alice", Role: "owner"}},
	}
	pcb, counts := makePCB()
	res, err := st.ApplyBlueprint(bp, "admin", pcb)
	if err != nil {
		t.Fatalf("ApplyBlueprint: %v", err)
	}
	if res.NetworkID != 42 || !res.Created {
		t.Errorf("result = %+v", res)
	}
	// Every callback path should have fired at least once.
	if counts.foundOrCreatedCalls == 0 || counts.enableEnterpriseCalls == 0 ||
		counts.applyPolicyCalls == 0 || counts.applyExprCalls == 0 ||
		counts.setAuditWHCalls == 0 || counts.storeRBACCalls == 0 ||
		counts.configureAuditCalls == 0 || counts.incProvisionsCalls == 0 {
		t.Errorf("counts = %+v (some callback never fired)", counts)
	}
}

func TestApplyBlueprint_ApplyPolicyErrorPropagates(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	bp := &NetworkBlueprint{
		Name:   "policy-err",
		Policy: &BlueprintPolicy{MaxMembers: 10},
	}
	pcb, _ := makePCB()
	pcb.ApplyNetworkPolicy = func(uint16, *BlueprintPolicy) error {
		return errors.New("policy failed")
	}
	_, err := st.ApplyBlueprint(bp, "admin", pcb)
	if err == nil {
		t.Error("expected policy-apply error")
	}
}

func TestApplyBlueprint_ApplyExprPolicyErrorPropagates(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	bp := &NetworkBlueprint{
		Name:       "expr-err",
		ExprPolicy: json.RawMessage(`{"version":1,"rules":[{"name":"r"}]}`),
	}
	pcb, _ := makePCB()
	pcb.ApplyExprPolicy = func(uint16, json.RawMessage) error {
		return errors.New("expr failed")
	}
	_, err := st.ApplyBlueprint(bp, "admin", pcb)
	if err == nil {
		t.Error("expected expr-apply error")
	}
}

func TestHandleProvisionNetwork_AuthRequired(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, false)
	pcb, _ := makePCB()
	_, err := st.HandleProvisionNetwork(map[string]interface{}{
		"blueprint": map[string]interface{}{"name": "x"},
	}, "admin", pcb)
	if err == nil {
		t.Error("expected admin-required error")
	}
}

func TestHandleProvisionNetwork_MissingBlueprint(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	pcb, _ := makePCB()
	_, err := st.HandleProvisionNetwork(map[string]interface{}{}, "admin", pcb)
	if err == nil {
		t.Error("expected missing-blueprint error")
	}
}

func TestHandleProvisionNetwork_HappyPath(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	pcb, _ := makePCB()
	resp, err := st.HandleProvisionNetwork(map[string]interface{}{
		"blueprint": map[string]interface{}{
			"name": "provisioned",
		},
	}, "admin", pcb)
	if err != nil {
		t.Fatalf("HandleProvisionNetwork: %v", err)
	}
	if resp["type"] != "provision_network_ok" {
		t.Errorf("type = %v", resp["type"])
	}
}
