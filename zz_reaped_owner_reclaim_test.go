// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
)

// Reaping deletes the node record but keeps what is keyed on its id —
// network roles, trust pairs, the owner and public-key indices — so the node
// can resume. These tests pin who may resume it.

// seedReapedOwner registers a node as owner "n1@lab.test", makes it the
// owner of network 7, and reaps it. It returns the node's identity and id.
func seedReapedOwner(t *testing.T, s *Server) (*crypto.Identity, uint32) {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	resp := reapRegister(t, s, id, "n1@lab.test", "")
	nodeID := resp["node_id"].(uint32)

	s.mu.Lock()
	s.networks[7] = &NetworkInfo{
		ID: 7, Name: "victim-net", JoinRule: "open",
		Members:     []uint32{nodeID},
		MemberRoles: map[uint32]Role{nodeID: RoleOwner},
		MemberTags:  make(map[uint32][]string),
		Created:     time.Now(),
	}
	s.nodes[nodeID].Networks = append(s.nodes[nodeID].Networks, 7)
	s.nodes[nodeID].SetLastSeen(time.Now().Add(-31 * time.Minute))
	s.mu.Unlock()
	s.Reap()

	s.mu.RLock()
	_, alive := s.nodes[nodeID]
	s.mu.RUnlock()
	if alive {
		t.Fatal("node was not reaped")
	}
	return id, nodeID
}

func reapRegisterMsg(id *crypto.Identity, owner, adminToken string) map[string]interface{} {
	msg := map[string]interface{}{
		"type":        "register",
		"listen_addr": "198.51.100.7:4000",
		"public_key":  crypto.EncodePublicKey(id.PublicKey),
		"owner":       owner,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return msg
}

func reapRegister(t *testing.T, s *Server, id *crypto.Identity, owner, adminToken string) map[string]interface{} {
	t.Helper()
	resp, err := s.handleMessage(reapRegisterMsg(id, owner, adminToken), "198.51.100.7:4000")
	if err != nil {
		t.Fatalf("register(owner=%q): %v", owner, err)
	}
	return resp
}

// The takeover: a key the registry has never seen presents the reaped
// node's owner string. Before the fix it was handed the node_id, and with
// it the owner role of network 7.
func TestReapedOwnerIDNotReclaimableByOwnerStringAlone(t *testing.T) {
	s := newTestServer(t, "admin")
	_, victimID := seedReapedOwner(t, s)

	stranger, _ := crypto.GenerateIdentity()
	for _, tok := range []string{"", "wrong-token"} {
		_, err := s.handleMessage(reapRegisterMsg(stranger, "n1@lab.test", tok), "203.0.113.9:4000")
		if err == nil || !strings.Contains(err.Error(), "already bound to node") {
			t.Fatalf("admin_token=%q: want owner-binding refusal, got %v", tok, err)
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.nodes[victimID]; ok {
		t.Fatal("refused registration still recreated the reaped node")
	}
	if _, ok := s.pubKeyIdx[crypto.EncodePublicKey(stranger.PublicKey)]; ok {
		t.Fatal("refused registration still indexed the stranger's key")
	}
	if got := s.networks[7].MemberRoles[victimID]; got != RoleOwner {
		t.Fatalf("network role disturbed: %q", got)
	}
}

// The original key resumes the same id, and its network memberships, exactly
// as before — with or without the owner string, before or after a refused
// takeover attempt.
func TestReapedNodeSameKeyReclaimsID(t *testing.T) {
	for _, owner := range []string{"n1@lab.test", ""} {
		s := newTestServer(t, "admin")
		id, nodeID := seedReapedOwner(t, s)

		stranger, _ := crypto.GenerateIdentity()
		_, _ = s.handleMessage(reapRegisterMsg(stranger, "n1@lab.test", ""), "203.0.113.9:4000")

		resp := reapRegister(t, s, id, owner, "")
		if got := resp["node_id"].(uint32); got != nodeID {
			t.Fatalf("owner=%q: same-key reclaim got node %d, want %d", owner, got, nodeID)
		}
		s.mu.RLock()
		nets := append([]uint16(nil), s.nodes[nodeID].Networks...)
		s.mu.RUnlock()
		found := false
		for _, n := range nets {
			if n == 7 {
				found = true
			}
		}
		if !found {
			t.Fatalf("owner=%q: network 7 membership not restored: %v", owner, nets)
		}
	}
}

// The operator can reassign a reaped node's id to a new key by putting the
// global admin token on the registration. The old key then no longer maps
// to the id.
func TestReapedOwnerAdminTokenReclaim(t *testing.T) {
	s := newTestServer(t, "admin")
	oldID, nodeID := seedReapedOwner(t, s)

	fresh, _ := crypto.GenerateIdentity()
	resp := reapRegister(t, s, fresh, "n1@lab.test", "admin")
	if got := resp["node_id"].(uint32); got != nodeID {
		t.Fatalf("admin reclaim got node %d, want %d", got, nodeID)
	}

	s.mu.RLock()
	gotKey := crypto.EncodePublicKey(s.nodes[nodeID].PublicKey)
	_, oldIndexed := s.pubKeyIdx[crypto.EncodePublicKey(oldID.PublicKey)]
	s.mu.RUnlock()
	if gotKey != crypto.EncodePublicKey(fresh.PublicKey) {
		t.Fatal("node is not bound to the new key")
	}
	if oldIndexed {
		t.Fatal("previous key is still indexed to the reassigned node")
	}

	// The previous key is now a stranger: with the owner string it meets the
	// live-node guard; without, it is a new node.
	if _, err := s.handleMessage(reapRegisterMsg(oldID, "n1@lab.test", ""), ""); err == nil {
		t.Fatal("previous key re-took the owner binding")
	}
	if got := reapRegister(t, s, oldID, "", "")["node_id"].(uint32); got == nodeID {
		t.Fatal("previous key was given the reassigned node id")
	}
}

// What a node that lost its key can do without the operator: register under
// a different owner string (or none) and get a brand-new id.
func TestReapedOwnerLostKeyNewOwnerGetsNewID(t *testing.T) {
	s := newTestServer(t, "admin")
	_, nodeID := seedReapedOwner(t, s)

	fresh, _ := crypto.GenerateIdentity()
	resp := reapRegister(t, s, fresh, "n1-new@lab.test", "")
	if got := resp["node_id"].(uint32); got == nodeID {
		t.Fatalf("new owner string was given the reaped node id %d", got)
	}
}
