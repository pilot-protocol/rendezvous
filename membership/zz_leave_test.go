// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import (
	"strings"
	"testing"
)

func TestHandleLeaveNetwork_BackboneRejected(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleLeaveNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
		"network_id":  float64(0),
	})
	if err == nil || !strings.Contains(err.Error(), "backbone") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleLeaveNetwork_UnknownNode(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	_, err := e.st.HandleLeaveNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(9999),
		"network_id":  float64(1),
	})
	if err == nil {
		t.Error("expected unknown-node error")
	}
}

func TestHandleLeaveNetwork_HappyPath(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	e.addNode(2)
	netID, err := e.createNetwork(1, "leave-test")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
		"node_id":     float64(2),
	}); err != nil {
		t.Fatalf("join: %v", err)
	}

	resp, err := e.st.HandleLeaveNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
		"network_id":  float64(netID),
	})
	if err != nil {
		t.Fatalf("leave: %v", err)
	}
	if resp["type"] != "leave_network_ok" {
		t.Errorf("type = %v", resp["type"])
	}
}

func TestHandleLeaveNetwork_OwnerInEnterpriseRejected(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	netID, err := e.createNetwork(1, "owner-leave")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := e.st.HandleSetNetworkEnterprise(map[string]interface{}{
		"admin_token": "admin",
		"network_id":  float64(netID),
		"enterprise":  true,
	}); err != nil {
		t.Fatalf("enterprise: %v", err)
	}
	_, err = e.st.HandleLeaveNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
		"network_id":  float64(netID),
	})
	if err == nil || !strings.Contains(err.Error(), "transfer ownership") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleLeaveNetwork_NotAMember(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	e.addNode(2)
	netID, _ := e.createNetwork(1, "not-member")
	_, err := e.st.HandleLeaveNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2), // never joined
		"network_id":  float64(netID),
	})
	if err == nil || !strings.Contains(err.Error(), "not a member") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleLeaveNetwork_UnknownNetwork(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	_, err := e.st.HandleLeaveNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
		"network_id":  float64(9999),
	})
	if err == nil {
		t.Error("expected unknown-network error")
	}
}
