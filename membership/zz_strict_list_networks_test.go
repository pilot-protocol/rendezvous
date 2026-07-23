// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import "testing"

func findNetEntry(nets []map[string]interface{}, id uint16) map[string]interface{} {
	for _, n := range nets {
		if n["id"] == id {
			return n
		}
	}
	return nil
}

func TestHandleListNetworks_StrictOff_AllNetworksVisible(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)
	e.addNode(2)
	openID, _ := e.createNetwork(1, "open-net")
	privID, _ := e.createNetwork(1, "priv-net")
	e.mu.Lock()
	e.networks[privID].JoinRule = "token"
	e.mu.Unlock()

	resp, err := e.st.HandleListNetworks(map[string]interface{}{
		"requester_id": float64(2),
	})
	if err != nil {
		t.Fatalf("HandleListNetworks: %v", err)
	}
	nets, _ := resp["networks"].([]map[string]interface{})
	if findNetEntry(nets, openID) == nil {
		t.Fatal("expected open network visible")
	}
	if findNetEntry(nets, privID) == nil {
		t.Fatal("flag-off behavior must not filter private networks")
	}
}

func TestHandleListNetworks_StrictOn_NonMemberOnlySeesOpenNetworks(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.st.cb.StrictDirectoryAuth = func() bool { return true }
	e.addNode(1)
	e.addNode(2)
	openID, _ := e.createNetwork(1, "open-net")
	privID, _ := e.createNetwork(1, "priv-net")
	e.mu.Lock()
	e.networks[privID].JoinRule = "token"
	e.mu.Unlock()

	resp, err := e.st.HandleListNetworks(map[string]interface{}{
		"requester_id": float64(2),
	})
	if err != nil {
		t.Fatalf("HandleListNetworks: %v", err)
	}
	nets, _ := resp["networks"].([]map[string]interface{})
	if findNetEntry(nets, openID) == nil {
		t.Fatal("expected open network to remain visible to any caller")
	}
	if findNetEntry(nets, privID) != nil {
		t.Fatal("expected private (non-open) network to be hidden from a non-member under strict mode")
	}
}

func TestHandleListNetworks_StrictOn_MemberSeesOwnPrivateNetwork(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.st.cb.StrictDirectoryAuth = func() bool { return true }
	e.addNode(1)
	privID, _ := e.createNetwork(1, "priv-net")
	e.mu.Lock()
	e.networks[privID].JoinRule = "token"
	e.mu.Unlock()

	resp, err := e.st.HandleListNetworks(map[string]interface{}{
		"requester_id": float64(1),
	})
	if err != nil {
		t.Fatalf("HandleListNetworks: %v", err)
	}
	nets, _ := resp["networks"].([]map[string]interface{})
	if findNetEntry(nets, privID) == nil {
		t.Fatal("expected the creator/member to still see their own private network")
	}
}

func TestHandleListNetworks_StrictOn_AdminSeesEverything(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.st.cb.StrictDirectoryAuth = func() bool { return true }
	e.addNode(1)
	privID, _ := e.createNetwork(1, "priv-net")
	e.mu.Lock()
	e.networks[privID].JoinRule = "token"
	e.mu.Unlock()

	resp, err := e.st.HandleListNetworks(map[string]interface{}{
		"admin_token": "admin",
	})
	if err != nil {
		t.Fatalf("HandleListNetworks: %v", err)
	}
	nets, _ := resp["networks"].([]map[string]interface{})
	if findNetEntry(nets, privID) == nil {
		t.Fatal("expected the global admin to still see private networks")
	}
}
