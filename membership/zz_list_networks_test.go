// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import (
	"encoding/json"
	"testing"

	"github.com/pilot-protocol/common/registry/wire"
)

func TestHandleListNetworks_EnterprisePolicyFieldsIncluded(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, _ := e.createNetwork(1, "ent-net")
	// Flip enterprise + set policy fields directly.
	e.mu.Lock()
	e.networks[netID].Enterprise = true
	e.networks[netID].Policy.MaxMembers = 100
	e.networks[netID].Policy.Description = "test desc"
	e.mu.Unlock()

	resp, err := e.st.HandleListNetworks(map[string]interface{}{
		"admin_token": "admin",
	})
	if err != nil {
		t.Fatalf("HandleListNetworks: %v", err)
	}
	nets, _ := resp["networks"].([]map[string]interface{})
	var ent map[string]interface{}
	for _, n := range nets {
		if n["id"] == netID {
			ent = n
		}
	}
	if ent == nil {
		t.Fatal("network not in response")
	}
	if ent["max_members"] != 100 {
		t.Errorf("max_members = %v, want 100", ent["max_members"])
	}
	if ent["description"] != "test desc" {
		t.Errorf("description = %v", ent["description"])
	}
}

func TestHandleListNetworks_WithRulesAndExprPolicy(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, _ := e.createNetwork(1, "rules-net")
	// Inject rules + expr policy directly.
	e.mu.Lock()
	e.networks[netID].Rules = &wire.NetworkRules{}
	e.networks[netID].ExprPolicy = json.RawMessage(`{"version":1}`)
	e.mu.Unlock()

	resp, err := e.st.HandleListNetworks(map[string]interface{}{
		"admin_token": "admin",
	})
	if err != nil {
		t.Fatalf("HandleListNetworks: %v", err)
	}
	nets, _ := resp["networks"].([]map[string]interface{})
	var ent map[string]interface{}
	for _, n := range nets {
		if n["id"] == netID {
			ent = n
		}
	}
	if ent == nil {
		t.Fatal("network not in response")
	}
	if ent["managed"] != true {
		t.Errorf("managed = %v, want true", ent["managed"])
	}
	if ent["has_expr_policy"] != true {
		t.Errorf("has_expr_policy = %v, want true", ent["has_expr_policy"])
	}
	if _, ok := ent["rules"]; !ok {
		t.Error("rules field missing")
	}
}
