// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"errors"
	"testing"
)

// TestHandleProvisionNetwork_ApplyBlueprintErrorPropagates exercises the
// error-path branch when ApplyBlueprint fails (via a FindOrCreate error).
func TestHandleProvisionNetwork_ApplyBlueprintErrorPropagates(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	pcb := ProvisionCallbacks{
		FindOrCreateNetwork: func(_ string, _ bool, _, _, _, _ string) (uint16, bool, error) {
			return 0, false, errors.New("create failed")
		},
	}
	_, err := st.HandleProvisionNetwork(map[string]interface{}{
		"blueprint": map[string]interface{}{"name": "x"},
	}, "admin", pcb)
	if err == nil {
		t.Error("expected error propagation")
	}
}

// TestHandleProvisionNetwork_FallsBackToMsgAdminToken covers the
// adminToken == "" branch that pulls from msg["admin_token"].
func TestHandleProvisionNetwork_FallsBackToMsgAdminToken(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	var seenAdmin string
	pcb := ProvisionCallbacks{
		FindOrCreateNetwork: func(_ string, _ bool, _, _, _, adminToken string) (uint16, bool, error) {
			seenAdmin = adminToken
			return 1, true, nil
		},
	}
	if _, err := st.HandleProvisionNetwork(map[string]interface{}{
		"admin_token": "from-msg",
		"blueprint":   map[string]interface{}{"name": "x"},
	}, "", pcb); err != nil {
		t.Fatalf("HandleProvisionNetwork: %v", err)
	}
	if seenAdmin != "from-msg" {
		t.Errorf("FindOrCreateNetwork saw adminToken = %q, want from-msg", seenAdmin)
	}
}
