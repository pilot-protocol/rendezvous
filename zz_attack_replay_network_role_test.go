// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
	authzpkg "github.com/pilot-protocol/rendezvous/authz"
)

// Regression tests for role-based network administration: a node_id in a
// request is a claim, and the role it names may only be exercised with a
// signature from that node's registered key over authz.NetworkRoleChallenge.

// seedRoleNetwork builds a server (global admin token "admin") holding one
// enterprise network, 7, whose owner (node 1), admin (node 2) and member
// (node 3) all have registered keys. Node 9 is registered with a key but is
// not a member: it plays the attacker.
func seedRoleNetwork(t *testing.T) (s *Server, owner, admin, attacker *crypto.Identity) {
	t.Helper()
	s = newTestServer(t, "admin")
	owner = seedVerifyNode(t, s, 1, "", []uint16{7})
	admin = seedVerifyNode(t, s, 2, "", []uint16{7})
	seedVerifyNode(t, s, 3, "", []uint16{7})
	attacker = seedVerifyNode(t, s, 9, "", nil)
	s.mu.Lock()
	s.networks[7] = &NetworkInfo{
		ID:         7,
		Name:       "role-net",
		JoinRule:   "open",
		Enterprise: true,
		Members:    []uint32{1, 2, 3},
		MemberRoles: map[uint32]Role{
			1: RoleOwner,
			2: RoleAdmin,
			3: RoleMember,
		},
		MemberTags: make(map[uint32][]string),
		Created:    time.Now(),
	}
	s.mu.Unlock()
	return s, owner, admin, attacker
}

func roleSig(id *crypto.Identity, challenge string) string {
	return base64.StdEncoding.EncodeToString(id.Sign([]byte(challenge)))
}

// roleOps is every operation gated by requireNetworkRole, phrased as the
// owner (node 1) of network 7 would send it.
func roleOps() []map[string]interface{} {
	ops := []map[string]interface{}{
		{"type": "rename_network", "name": "taken-over"},
		{"type": "set_member_tags", "target_node_id": float64(3), "tags": []interface{}{"pwned"}},
		{"type": "set_network_policy", "max_members": float64(50)},
		{"type": "set_expr_policy", "expr_policy": `{"version":1,"rules":[]}`},
		{"type": "promote_member", "target_node_id": float64(3)},
		{"type": "demote_member", "target_node_id": float64(2)},
		{"type": "kick_member", "target_node_id": float64(3)},
		{"type": "transfer_ownership", "new_owner_id": float64(2)},
		{"type": "delete_network"},
	}
	for _, op := range ops {
		op["network_id"] = float64(7)
		op["node_id"] = float64(1)
	}
	return ops
}

// signRole signs msg as nodeID with the challenge the server derives for it.
func signRole(id *crypto.Identity, msg map[string]interface{}, nodeID uint32, netID uint16) {
	msg["signature"] = roleSig(id, authzpkg.NetworkRoleChallenge(msg, nodeID, netID))
}

// TestNetworkRoleUnsignedOwnerClaimRefused is the attack: a caller holding no
// admin token and no key for node 1 writes node 1's id into node_id. Nothing
// on the accept/dispatch path binds a connection to a node, so before the fix
// every one of these was authorized on the claimed owner's role.
func TestNetworkRoleUnsignedOwnerClaimRefused(t *testing.T) {
	for _, op := range roleOps() {
		op := op
		t.Run(op["type"].(string), func(t *testing.T) {
			s, _, _, _ := seedRoleNetwork(t)
			_, err := s.handleMessage(op, "203.0.113.9:4000")
			if err == nil {
				t.Fatalf("unsigned %s claiming owner node 1 was accepted", op["type"])
			}
			if !strings.Contains(err.Error(), "signature required") {
				t.Fatalf("unsigned %s: refused for the wrong reason: %v", op["type"], err)
			}
		})
	}

	// End state of the two headline cases: the network survives and its
	// owner is unchanged.
	s, _, _, _ := seedRoleNetwork(t)
	_, _ = s.handleMessage(map[string]interface{}{
		"type": "transfer_ownership", "network_id": float64(7), "node_id": float64(1), "new_owner_id": float64(2),
	}, "203.0.113.9:4000")
	_, _ = s.handleMessage(map[string]interface{}{
		"type": "delete_network", "network_id": float64(7), "node_id": float64(1),
	}, "203.0.113.9:4000")
	s.mu.RLock()
	defer s.mu.RUnlock()
	net, ok := s.networks[7]
	if !ok {
		t.Fatal("network 7 was deleted by an unauthenticated caller")
	}
	if net.MemberRoles[1] != RoleOwner {
		t.Fatalf("ownership moved to an unauthenticated caller's choice: roles=%v", net.MemberRoles)
	}
}

// TestNetworkRoleForgedSignatureRefused: a signature is only as good as the
// key behind it. The attacker signs the right challenge with its own key.
func TestNetworkRoleForgedSignatureRefused(t *testing.T) {
	s, _, _, attacker := seedRoleNetwork(t)
	_, err := s.handleMessage(map[string]interface{}{
		"type": "delete_network", "network_id": float64(7), "node_id": float64(1),
		"signature": roleSig(attacker, "delete_network:1:7"),
	}, "")
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("delete_network claiming owner node 1, signed with a non-member's key: err=%v", err)
	}
}

// TestNetworkRoleSignedOwnerAccepted: every role-gated operation succeeds
// when the owner signs the challenge for exactly that request.
func TestNetworkRoleSignedOwnerAccepted(t *testing.T) {
	for _, op := range roleOps() {
		op := op
		t.Run(op["type"].(string), func(t *testing.T) {
			s, owner, _, _ := seedRoleNetwork(t)
			signRole(owner, op, 1, 7)
			if _, err := s.handleMessage(op, ""); err != nil {
				t.Fatalf("signed %s by the owner: %v", op["type"], err)
			}
		})
	}
}

// TestNetworkRoleSignatureBoundToOperation: a signature captured from one
// operation does not authorize another, nor the same one with a different
// target or network.
func TestNetworkRoleSignatureBoundToOperation(t *testing.T) {
	s, owner, _, _ := seedRoleNetwork(t)
	cases := []map[string]interface{}{
		// rename signature replayed as a delete
		{"type": "delete_network", "signature": roleSig(owner, "rename_network:1:7:x")},
		// promote of node 3 replayed as a kick of node 3
		{"type": "kick_member", "target_node_id": float64(3), "signature": roleSig(owner, "promote_member:1:7:3")},
		// kick of node 3 replayed against node 2
		{"type": "kick_member", "target_node_id": float64(2), "signature": roleSig(owner, "kick_member:1:7:3")},
		// transfer to node 2 replayed with another beneficiary
		{"type": "transfer_ownership", "new_owner_id": float64(3), "signature": roleSig(owner, "transfer_ownership:1:7:2")},
		// delete of another network replayed against this one
		{"type": "delete_network", "signature": roleSig(owner, "delete_network:1:8")},
		// rename to one name replayed with another
		{"type": "rename_network", "name": "evil", "signature": roleSig(owner, "rename_network:1:7:good")},
	}
	for _, msg := range cases {
		msg["network_id"] = float64(7)
		msg["node_id"] = float64(1)
		_, err := s.handleMessage(msg, "")
		if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
			t.Fatalf("replayed signature for %v: err=%v", msg, err)
		}
	}

	// Hashed arguments: sign one tag set / policy, send another.
	swaps := []struct {
		signed, sent map[string]interface{}
	}{
		{
			map[string]interface{}{"type": "set_member_tags", "target_node_id": float64(3), "tags": []interface{}{"guest"}},
			map[string]interface{}{"type": "set_member_tags", "target_node_id": float64(3), "tags": []interface{}{"root"}},
		},
		{
			map[string]interface{}{"type": "set_network_policy", "max_members": float64(50)},
			map[string]interface{}{"type": "set_network_policy", "max_members": float64(50), "description": "added"},
		},
		{
			map[string]interface{}{"type": "set_expr_policy", "expr_policy": `{"version":1,"rules":[]}`},
			map[string]interface{}{"type": "set_expr_policy", "expr_policy": ""},
		},
	}
	for _, sw := range swaps {
		sw.sent["network_id"] = float64(7)
		sw.sent["node_id"] = float64(1)
		sw.sent["signature"] = roleSig(owner, authzpkg.NetworkRoleChallenge(sw.signed, 1, 7))
		_, err := s.handleMessage(sw.sent, "")
		if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
			t.Fatalf("signature for %v accepted on %v: err=%v", sw.signed, sw.sent, err)
		}
	}
}

// TestNetworkRoleSignedRoleStillChecked: a valid signature proves who is
// asking, not that they may. A member signing as itself is still refused an
// owner-only operation, and an admin still cannot delete.
func TestNetworkRoleSignedRoleStillChecked(t *testing.T) {
	s, _, admin, attacker := seedRoleNetwork(t)
	_, err := s.handleMessage(map[string]interface{}{
		"type": "delete_network", "network_id": float64(7), "node_id": float64(2),
		"signature": roleSig(admin, "delete_network:2:7"),
	}, "")
	if err == nil || !strings.Contains(err.Error(), "rbac") {
		t.Fatalf("admin deleting: err=%v", err)
	}
	_, err = s.handleMessage(map[string]interface{}{
		"type": "delete_network", "network_id": float64(7), "node_id": float64(9),
		"signature": roleSig(attacker, "delete_network:9:7"),
	}, "")
	if err == nil || !strings.Contains(err.Error(), "rbac") {
		t.Fatalf("non-member deleting: err=%v", err)
	}
}

// TestNetworkRoleAdminTokensUnaffected: the two token paths authorize on
// their own, with no node_id and no signature, exactly as before.
func TestNetworkRoleAdminTokensUnaffected(t *testing.T) {
	s, _, _, _ := seedRoleNetwork(t)
	s.mu.Lock()
	s.networks[7].AdminToken = "net-secret"
	s.mu.Unlock()
	if _, err := s.handleMessage(map[string]interface{}{
		"type": "rename_network", "network_id": float64(7), "name": "by-net-token", "admin_token": "net-secret",
	}, ""); err != nil {
		t.Fatalf("per-network admin token: %v", err)
	}
	if _, err := s.handleMessage(map[string]interface{}{
		"type": "delete_network", "network_id": float64(7), "admin_token": "admin",
	}, ""); err != nil {
		t.Fatalf("global admin token: %v", err)
	}
}

// TestNetworkRoleKeylessNodeRefused: a node registered without a public key
// cannot prove anything, so its role cannot be exercised by claim alone.
func TestNetworkRoleKeylessNodeRefused(t *testing.T) {
	s, _, _, _ := seedRoleNetwork(t)
	s.mu.Lock()
	s.nodes[1].PublicKey = nil
	s.mu.Unlock()
	_, err := s.handleMessage(map[string]interface{}{
		"type": "delete_network", "network_id": float64(7), "node_id": float64(1),
	}, "")
	if err == nil || !strings.Contains(err.Error(), "admin token required") {
		t.Fatalf("keyless owner claim without an admin token: err=%v", err)
	}
}

// TestNetworkRoleEscapeHatch covers -allow-unsigned-network-role-auth: an
// unsigned claim is honored for a node that has never signed a role
// operation (old role-path clients keep working, and so does the attack),
// a signature that is present is still verified, and the first valid
// signature from a node ratchets that node to signed-only.
func TestNetworkRoleEscapeHatch(t *testing.T) {
	s, owner, _, attacker := seedRoleNetwork(t)
	s.SetAllowUnsignedNetworkRoleAuth(true)

	if _, err := s.handleMessage(map[string]interface{}{
		"type": "rename_network", "network_id": float64(7), "node_id": float64(1), "name": "old-client",
	}, ""); err != nil {
		t.Fatalf("unsigned claim from a never-signed node: %v", err)
	}

	_, err := s.handleMessage(map[string]interface{}{
		"type": "delete_network", "network_id": float64(7), "node_id": float64(1),
		"signature": roleSig(attacker, "delete_network:1:7"),
	}, "")
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("forged signature under the escape hatch: err=%v", err)
	}

	signed := map[string]interface{}{
		"type": "rename_network", "network_id": float64(7), "node_id": float64(1), "name": "new-client",
	}
	signRole(owner, signed, 1, 7)
	if _, err := s.handleMessage(signed, ""); err != nil {
		t.Fatalf("signed claim: %v", err)
	}

	_, err = s.handleMessage(map[string]interface{}{
		"type": "delete_network", "network_id": float64(7), "node_id": float64(1),
	}, "")
	if err == nil || !strings.Contains(err.Error(), "signature required") {
		t.Fatalf("unsigned claim after the node signed: err=%v", err)
	}
}
