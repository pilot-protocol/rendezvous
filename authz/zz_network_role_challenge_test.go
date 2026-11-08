// SPDX-License-Identifier: AGPL-3.0-or-later

package authz_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pilot-protocol/rendezvous/authz"
)

// roleChallengeVectors pins the challenge for each role-gated request. The
// same table (request JSON -> challenge) is pinned in
// common/registry/client, which is what keeps the client's signing and the
// server's verification from drifting apart. Change one, change both.
var roleChallengeVectors = []struct {
	request string
	want    string
}{
	{`{"type":"delete_network","node_id":5,"network_id":7}`,
		"delete_network:5:7"},
	{`{"type":"rename_network","node_id":5,"network_id":7,"name":"lab-net"}`,
		"rename_network:5:7:lab-net"},
	{`{"type":"kick_member","node_id":5,"network_id":7,"target_node_id":9}`,
		"kick_member:5:7:9"},
	{`{"type":"promote_member","node_id":5,"network_id":7,"target_node_id":9}`,
		"promote_member:5:7:9"},
	{`{"type":"demote_member","node_id":5,"network_id":7,"target_node_id":9}`,
		"demote_member:5:7:9"},
	{`{"type":"transfer_ownership","node_id":5,"network_id":7,"new_owner_id":9}`,
		"transfer_ownership:5:7:9"},
	{`{"type":"set_member_tags","node_id":5,"network_id":7,"target_node_id":9,"tags":["gpu","eu-west"]}`,
		"set_member_tags:5:7:9:6181819da0f863b3ef845fbd74e290e98bf779d2c18a2c1a3afcf5fdc63eb66c"},
	{`{"type":"set_member_tags","node_id":5,"network_id":7,"target_node_id":9,"tags":[]}`,
		"set_member_tags:5:7:9:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{`{"type":"set_network_policy","node_id":5,"network_id":7,"max_members":50,"allowed_ports":[80,443],"description":"prod"}`,
		"set_network_policy:5:7:23afbff65fece371606dd2bf351e0656fe72604d2dd4bc2a2dab5f114762d2da"},
	{`{"type":"set_network_policy","node_id":5,"network_id":7,"max_members":50}`,
		"set_network_policy:5:7:216c888a3e02e0063d6d91ec4e8e502bb9e2dfe984e5d4a59482d464c197bc71"},
	{`{"type":"set_network_policy","node_id":5,"network_id":7,"description":""}`,
		"set_network_policy:5:7:622ba1eb91d05acfb62b09f19bf4573d07f6842860c2eb444900c1600997ea4b"},
	{`{"type":"set_expr_policy","node_id":5,"network_id":7,"expr_policy":"{\"version\":1,\"rules\":[]}"}`,
		"set_expr_policy:5:7:6be6bac38f2d35217ca3cd98e36322f9e8fb6638564f5a87ff660589f6302103"},
	{`{"type":"set_expr_policy","node_id":5,"network_id":7,"expr_policy":""}`,
		"set_expr_policy:5:7:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
}

func TestNetworkRoleChallengeVectors(t *testing.T) {
	t.Parallel()
	for _, v := range roleChallengeVectors {
		var msg map[string]interface{}
		if err := json.Unmarshal([]byte(v.request), &msg); err != nil {
			t.Fatalf("%s: %v", v.request, err)
		}
		if got := authz.NetworkRoleChallenge(msg, 5, 7); got != v.want {
			t.Errorf("%s\n got  %s\n want %s", v.request, got, v.want)
		}
	}
}

func TestNetworkPolicyDigestInput(t *testing.T) {
	t.Parallel()
	var msg map[string]interface{}
	_ = json.Unmarshal([]byte(`{"max_members":50,"allowed_ports":[80,443],"description":"prod"}`), &msg)
	if got, want := authz.NetworkPolicyDigestInput(msg), "max_members=50\nallowed_ports=80,443\ndescription=prod"; got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if got, want := authz.NetworkPolicyDigestInput(map[string]interface{}{}), "max_members-\nallowed_ports-\ndescription-"; got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

// keylessReader is a NetworkReader that is not a NodeKeyReader.
type keylessReader struct{ *stubNetworkReader }

func (keylessReader) GetNodePublicKey() {}

// A reader with no keys to offer cannot authenticate anyone: the RBAC path
// fails closed rather than falling back to the bare node_id.
func TestRequireNetworkRole_NoKeyReaderFailsClosed(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("globaladmin", "")
	nr := newStubNetworkReader()
	nr.addNetwork(2, "", false, map[uint32]authz.Role{7: authz.RoleOwner})
	msg := nr.signedClaim(t, 7, 2)

	err := c.RequireNetworkRole(msg, 2, keylessReader{nr}, authz.RoleOwner)
	if err == nil || !strings.Contains(err.Error(), "admin token required") {
		t.Fatalf("want fail-closed refusal, got %v", err)
	}
}

func TestRequireNetworkRole_UnsignedRefused(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("globaladmin", "")
	nr := newStubNetworkReader()
	nr.addNetwork(2, "", false, map[uint32]authz.Role{7: authz.RoleOwner})
	msg := nr.signedClaim(t, 7, 2)
	delete(msg, "signature")

	err := c.RequireNetworkRole(msg, 2, nr, authz.RoleOwner)
	if err == nil || !strings.Contains(err.Error(), "signature required") {
		t.Fatalf("want signature-required refusal, got %v", err)
	}

	c.SetAllowUnsignedNetworkRole(true)
	if !c.AllowUnsignedNetworkRole() {
		t.Fatal("escape hatch did not turn on")
	}
	if err := c.RequireNetworkRole(msg, 2, nr, authz.RoleOwner); err != nil {
		t.Fatalf("escape hatch: unsigned claim: %v", err)
	}
}
