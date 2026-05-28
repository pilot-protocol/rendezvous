// SPDX-License-Identifier: AGPL-3.0-or-later

package policy_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/pilot-protocol/rendezvous/policy"
)

func newTestStore(state policy.NetworkState) *policy.Store {
	return policy.NewStore(
		func(uint16) (policy.NetworkState, error) { return state, nil },
		func(uint16, policy.NetworkPolicy, policy.ExprPolicy) error { return nil },
		func(map[string]interface{}, uint16) error { return nil },
		func(uint16) error { return nil },
		policy.Callbacks{
			Save:             func() {},
			Audit:            func(string, ...any) {},
			IncPolicyChanges: func() {},
		},
	)
}

func TestHandleSetNetworkPolicy_AuthFails(t *testing.T) {
	t.Parallel()
	st := policy.NewStore(
		func(uint16) (policy.NetworkState, error) { return policy.NetworkState{}, nil },
		func(uint16, policy.NetworkPolicy, policy.ExprPolicy) error { return nil },
		func(map[string]interface{}, uint16) error { return errors.New("denied") },
		func(uint16) error { return nil },
		policy.Callbacks{Save: func() {}, Audit: func(string, ...any) {}, IncPolicyChanges: func() {}},
	)
	if _, err := st.HandleSetNetworkPolicy(map[string]interface{}{"network_id": float64(1)}); err == nil {
		t.Error("expected auth error")
	}
}

func TestHandleSetNetworkPolicy_EnterpriseFails(t *testing.T) {
	t.Parallel()
	st := policy.NewStore(
		func(uint16) (policy.NetworkState, error) { return policy.NetworkState{}, nil },
		func(uint16, policy.NetworkPolicy, policy.ExprPolicy) error { return nil },
		func(map[string]interface{}, uint16) error { return nil },
		func(uint16) error { return errors.New("not enterprise") },
		policy.Callbacks{Save: func() {}, Audit: func(string, ...any) {}, IncPolicyChanges: func() {}},
	)
	if _, err := st.HandleSetNetworkPolicy(map[string]interface{}{"network_id": float64(1)}); err == nil {
		t.Error("expected enterprise error")
	}
}

func TestHandleSetNetworkPolicy_BadMaxMembers(t *testing.T) {
	t.Parallel()
	st := newTestStore(policy.NetworkState{})
	cases := []float64{-1, 99999, 10.5}
	for _, v := range cases {
		_, err := st.HandleSetNetworkPolicy(map[string]interface{}{
			"network_id":  float64(1),
			"max_members": v,
		})
		if err == nil {
			t.Errorf("max_members=%v: expected error", v)
		}
	}
}

func TestHandleSetNetworkPolicy_MaxMembersBelowCurrentCountFails(t *testing.T) {
	t.Parallel()
	st := newTestStore(policy.NetworkState{MemberCount: 50})
	_, err := st.HandleSetNetworkPolicy(map[string]interface{}{
		"network_id":  float64(1),
		"max_members": float64(10),
	})
	if err == nil || !strings.Contains(err.Error(), "already has") {
		t.Errorf("expected member-count error, got %v", err)
	}
}

func TestHandleSetNetworkPolicy_TooManyPorts(t *testing.T) {
	t.Parallel()
	st := newTestStore(policy.NetworkState{})
	ports := make([]interface{}, 101)
	for i := range ports {
		ports[i] = float64(i + 1)
	}
	_, err := st.HandleSetNetworkPolicy(map[string]interface{}{
		"network_id":    float64(1),
		"allowed_ports": ports,
	})
	if err == nil || !strings.Contains(err.Error(), "too many") {
		t.Errorf("expected too-many-ports error, got %v", err)
	}
}

func TestHandleSetNetworkPolicy_BadPortValues(t *testing.T) {
	t.Parallel()
	st := newTestStore(policy.NetworkState{})
	cases := [][]interface{}{
		{float64(-1)},
		{float64(70000)},
		{float64(80.5)},
		{"string"},
	}
	for _, c := range cases {
		_, err := st.HandleSetNetworkPolicy(map[string]interface{}{
			"network_id":    float64(1),
			"allowed_ports": c,
		})
		if err == nil {
			t.Errorf("ports=%v: expected error", c)
		}
	}
}

func TestHandleSetNetworkPolicy_DescriptionTooLong(t *testing.T) {
	t.Parallel()
	st := newTestStore(policy.NetworkState{})
	_, err := st.HandleSetNetworkPolicy(map[string]interface{}{
		"network_id":  float64(1),
		"description": strings.Repeat("x", 257),
	})
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("expected too-long error, got %v", err)
	}
}

func TestHandleGetNetworkPolicy_PortsRoundtrip(t *testing.T) {
	t.Parallel()
	st := newTestStore(policy.NetworkState{
		Policy: policy.NetworkPolicy{
			MaxMembers:   10,
			AllowedPorts: []uint16{80, 443},
			Description:  "test",
		},
	})
	resp, err := st.HandleGetNetworkPolicy(map[string]interface{}{"network_id": float64(1)})
	if err != nil {
		t.Fatalf("HandleGetNetworkPolicy: %v", err)
	}
	ports, _ := resp["allowed_ports"].([]interface{})
	if len(ports) != 2 {
		t.Errorf("ports len = %d, want 2", len(ports))
	}
}

func TestHandleGetNetworkPolicy_EmptyPortsReturnsEmptyList(t *testing.T) {
	t.Parallel()
	st := newTestStore(policy.NetworkState{})
	resp, err := st.HandleGetNetworkPolicy(map[string]interface{}{"network_id": float64(1)})
	if err != nil {
		t.Fatalf("HandleGetNetworkPolicy: %v", err)
	}
	ports, ok := resp["allowed_ports"].([]interface{})
	if !ok {
		t.Errorf("allowed_ports missing or wrong type: %T", resp["allowed_ports"])
	}
	if len(ports) != 0 {
		t.Errorf("ports = %v, want empty", ports)
	}
}

func TestHandleSetExprPolicy_Clear(t *testing.T) {
	t.Parallel()
	st := newTestStore(policy.NetworkState{})
	resp, err := st.HandleSetExprPolicy(map[string]interface{}{
		"network_id":  float64(1),
		"expr_policy": "",
	})
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if resp["cleared"] != true {
		t.Errorf("cleared = %v, want true", resp["cleared"])
	}
}

func TestHandleSetExprPolicy_ClearNullSentinel(t *testing.T) {
	t.Parallel()
	st := newTestStore(policy.NetworkState{})
	resp, _ := st.HandleSetExprPolicy(map[string]interface{}{
		"network_id":  float64(1),
		"expr_policy": "null",
	})
	if resp["cleared"] != true {
		t.Errorf("null sentinel: cleared = %v", resp["cleared"])
	}
}

func TestHandleSetExprPolicy_MissingField(t *testing.T) {
	t.Parallel()
	st := newTestStore(policy.NetworkState{})
	if _, err := st.HandleSetExprPolicy(map[string]interface{}{
		"network_id": float64(1),
	}); err == nil {
		t.Error("expected error for missing expr_policy")
	}
}

func TestHandleSetExprPolicy_BadJSON(t *testing.T) {
	t.Parallel()
	st := newTestStore(policy.NetworkState{})
	if _, err := st.HandleSetExprPolicy(map[string]interface{}{
		"network_id":  float64(1),
		"expr_policy": "not-json",
	}); err == nil {
		t.Error("expected JSON error")
	}
}

func TestHandleSetExprPolicy_BadVersion(t *testing.T) {
	t.Parallel()
	st := newTestStore(policy.NetworkState{})
	if _, err := st.HandleSetExprPolicy(map[string]interface{}{
		"network_id":  float64(1),
		"expr_policy": `{"version":99,"rules":[{}]}`,
	}); err == nil {
		t.Error("expected version error")
	}
}

func TestHandleSetExprPolicy_NoRules(t *testing.T) {
	t.Parallel()
	st := newTestStore(policy.NetworkState{})
	if _, err := st.HandleSetExprPolicy(map[string]interface{}{
		"network_id":  float64(1),
		"expr_policy": `{"version":1}`,
	}); err == nil {
		t.Error("expected no-rules error")
	}
}

func TestHandleSetExprPolicy_HappyMap(t *testing.T) {
	t.Parallel()
	st := newTestStore(policy.NetworkState{})
	resp, err := st.HandleSetExprPolicy(map[string]interface{}{
		"network_id": float64(1),
		"expr_policy": map[string]interface{}{
			"version": 1,
			"rules":   []interface{}{map[string]interface{}{"name": "r"}},
		},
	})
	if err != nil {
		t.Fatalf("HandleSetExprPolicy: %v", err)
	}
	if resp["type"] != "set_expr_policy_ok" {
		t.Errorf("type = %v", resp["type"])
	}
}

func TestHandleGetExprPolicy_WithAndWithoutPolicy(t *testing.T) {
	t.Parallel()
	// With policy.
	st := newTestStore(policy.NetworkState{Expr: json.RawMessage(`{"version":1}`)})
	resp, err := st.HandleGetExprPolicy(map[string]interface{}{"network_id": float64(1)})
	if err != nil {
		t.Fatalf("with: %v", err)
	}
	if _, ok := resp["expr_policy"]; !ok {
		t.Error("expr_policy should be present")
	}

	// Without policy.
	st = newTestStore(policy.NetworkState{})
	resp, _ = st.HandleGetExprPolicy(map[string]interface{}{"network_id": float64(1)})
	if _, ok := resp["expr_policy"]; ok {
		t.Error("expr_policy should be absent when Expr is empty")
	}
}
