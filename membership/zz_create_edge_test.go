// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import (
	"strings"
	"testing"
)

func TestHandleCreateNetwork_AdminTokenRequired(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleCreateNetwork(map[string]interface{}{
		"node_id":   float64(1),
		"name":      "n1",
		"join_rule": "open",
	})
	if err == nil {
		t.Error("expected admin-token error")
	}
}

func TestHandleCreateNetwork_DuplicateName(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	if _, err := e.createNetwork(1, "dup"); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := e.st.HandleCreateNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
		"name":        "dup",
		"join_rule":   "open",
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleCreateNetwork_NodeNotRegistered(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	// node not added to env.nodes
	_, err := e.st.HandleCreateNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(99),
		"name":        "n1",
		"join_rule":   "open",
	})
	if err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleCreateNetwork_InviteWithoutEnterprise(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	_, err := e.st.HandleCreateNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
		"name":        "n1",
		"join_rule":   "invite",
	})
	if err == nil || !strings.Contains(err.Error(), "enterprise") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleCreateNetwork_InvalidName(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	_, err := e.st.HandleCreateNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
		"name":        "BAD!NAME",
		"join_rule":   "open",
	})
	if err == nil {
		t.Error("expected invalid-name error")
	}
}

func TestHandleCreateNetwork_BadExprPolicyJSON(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	_, err := e.st.HandleCreateNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
		"name":        "n1",
		"join_rule":   "open",
		"expr_policy": "not-json",
	})
	if err == nil {
		t.Error("expected JSON error")
	}
}

func TestHandleCreateNetwork_UnsupportedExprPolicyVersion(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	_, err := e.st.HandleCreateNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
		"name":        "n1",
		"join_rule":   "open",
		"expr_policy": `{"version":99}`,
	})
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleCreateNetwork_WithExprPolicyMap(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	resp, err := e.st.HandleCreateNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
		"name":        "n1",
		"join_rule":   "open",
		"expr_policy": map[string]interface{}{"version": 1},
	})
	if err != nil {
		t.Fatalf("HandleCreateNetwork: %v", err)
	}
	if resp["network_id"] == nil {
		t.Error("network_id missing")
	}
}
