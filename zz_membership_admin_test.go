// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
	dashpkg "github.com/pilot-protocol/rendezvous/dashboard"
	dirpkg "github.com/pilot-protocol/rendezvous/directory"
)

// seedAdminMembershipServer builds a server with a single non-backbone
// network containing an owner, an admin, and two members so the admin-
// path methods have something to mutate. Uses NewWithStore so the
// internal wiring (membership, directory, audit, walStore=nil because no
// storePath) matches the production constructor.
func seedAdminMembershipServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "registry.json")
	s := NewWithStore("", storePath)
	now := time.Now()

	// Register four nodes directly into the maps. The membership-admin
	// methods only read s.nodes for hostname/last-seen enrichment so we
	// don't need a full register/handshake flow.
	for _, nid := range []uint32{1, 2, 3, 4} {
		s.nodes[nid] = &dirpkg.NodeInfo{
			ID:       nid,
			LastSeen: now,
			Networks: []uint16{7},
		}
		s.nodes[nid].SetLastSeen(now)
	}

	s.networks[7] = &NetworkInfo{
		ID:      7,
		Name:    "test-net",
		Members: []uint32{1, 2, 3, 4},
		MemberRoles: map[uint32]Role{
			1: RoleOwner,
			2: RoleAdmin,
			3: RoleMember,
			4: RoleMember,
		},
		Created: now,
	}
	return s
}

// AdminKickMember on a plain member removes them from Members AND
// MemberRoles, and emits a "network.admin_kick" audit entry.
func TestAdminKickMember_RemovesMember(t *testing.T) {
	t.Parallel()
	s := seedAdminMembershipServer(t)

	if err := s.AdminKickMember(7, 3, "spam"); err != nil {
		t.Fatalf("AdminKickMember: %v", err)
	}

	s.mu.RLock()
	net := s.networks[7]
	for _, m := range net.Members {
		if m == 3 {
			s.mu.RUnlock()
			t.Fatalf("node 3 still in Members slice")
		}
	}
	if _, has := net.MemberRoles[3]; has {
		s.mu.RUnlock()
		t.Fatalf("node 3 still in MemberRoles map")
	}
	s.mu.RUnlock()

	// Audit entry written. server.audit() routes through appendAudit
	// with positional (netID, nodeID) = (0, 0); the network/node ids
	// land in the attrs map instead, so we only assert the action name.
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	found := false
	for _, e := range s.auditLog {
		if e.Action == "network.admin_kick" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("network.admin_kick audit entry not found; log=%+v", s.auditLog)
	}
}

// AdminKickMember on the owner errors and leaves state unchanged.
func TestAdminKickMember_OwnerProtected(t *testing.T) {
	t.Parallel()
	s := seedAdminMembershipServer(t)

	err := s.AdminKickMember(7, 1, "rogue")
	if err == nil {
		t.Fatalf("expected error when kicking owner, got nil")
	}

	s.mu.RLock()
	net := s.networks[7]
	if len(net.Members) != 4 {
		s.mu.RUnlock()
		t.Fatalf("expected 4 members, got %d", len(net.Members))
	}
	if net.MemberRoles[1] != RoleOwner {
		s.mu.RUnlock()
		t.Fatalf("owner role lost: %v", net.MemberRoles[1])
	}
	s.mu.RUnlock()
}

// AdminSetMemberRole flips the admin back and forth between admin and
// member without affecting other roles.
func TestAdminSetMemberRole_AdminToMemberAndBack(t *testing.T) {
	t.Parallel()
	s := seedAdminMembershipServer(t)

	if err := s.AdminSetMemberRole(7, 2, "member", "deescalate"); err != nil {
		t.Fatalf("demote: %v", err)
	}
	s.mu.RLock()
	if got := s.networks[7].MemberRoles[2]; got != RoleMember {
		s.mu.RUnlock()
		t.Fatalf("expected RoleMember, got %v", got)
	}
	s.mu.RUnlock()

	if err := s.AdminSetMemberRole(7, 2, "admin", "reinstate"); err != nil {
		t.Fatalf("promote: %v", err)
	}
	s.mu.RLock()
	if got := s.networks[7].MemberRoles[2]; got != RoleAdmin {
		s.mu.RUnlock()
		t.Fatalf("expected RoleAdmin, got %v", got)
	}
	s.mu.RUnlock()
}

// AdminSetMemberRole on the owner errors.
func TestAdminSetMemberRole_OwnerProtected(t *testing.T) {
	t.Parallel()
	s := seedAdminMembershipServer(t)

	if err := s.AdminSetMemberRole(7, 1, "member", "coup"); err == nil {
		t.Fatalf("expected error when demoting owner, got nil")
	}
	if err := s.AdminSetMemberRole(7, 1, "admin", "coup"); err == nil {
		t.Fatalf("expected error when re-roling owner, got nil")
	}

	s.mu.RLock()
	if got := s.networks[7].MemberRoles[1]; got != RoleOwner {
		s.mu.RUnlock()
		t.Fatalf("owner role lost: %v", got)
	}
	s.mu.RUnlock()
}

// AdminSetMemberRole rejects bogus role strings before touching state.
func TestAdminSetMemberRole_BadRole(t *testing.T) {
	t.Parallel()
	s := seedAdminMembershipServer(t)

	for _, role := range []string{"owner", "junk", ""} {
		if err := s.AdminSetMemberRole(7, 3, role, ""); err == nil {
			t.Fatalf("expected error for role %q", role)
		}
	}
}

// AdminListMembers returns a snapshot covering every member with their
// role. Hostname/LastSeenUnix are populated from the seed setup.
func TestAdminListMembers_ReturnsAll(t *testing.T) {
	t.Parallel()
	s := seedAdminMembershipServer(t)

	out, err := s.AdminListMembers(7)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out) != 4 {
		t.Fatalf("expected 4 members, got %d", len(out))
	}

	roles := make(map[uint32]string)
	for _, m := range out {
		roles[m.NodeID] = m.Role
	}
	if roles[1] != "owner" || roles[2] != "admin" ||
		roles[3] != "member" || roles[4] != "member" {
		t.Fatalf("roles mismatch: %+v", roles)
	}
}

// AdminListMembers on an unknown network returns protocol.ErrNetworkNotFound
// so the dashboard handler can surface it as 404.
func TestAdminListMembers_UnknownNetwork(t *testing.T) {
	t.Parallel()
	s := seedAdminMembershipServer(t)

	_, err := s.AdminListMembers(999)
	if err == nil {
		t.Fatalf("expected error for unknown network")
	}
	if !errors.Is(err, protocol.ErrNetworkNotFound) {
		t.Fatalf("expected ErrNetworkNotFound, got %v", err)
	}
}

// AdminListNetworks surfaces every network with its numeric ID, name,
// and per-role counts. Sorting is not guaranteed — assert by content.
func TestAdminListNetworks_ReturnsRollup(t *testing.T) {
	t.Parallel()
	s := seedAdminMembershipServer(t)

	out := s.AdminListNetworks()
	// Find the one we seeded (ID 7); the backbone (ID 0) is created
	// implicitly by the server and may or may not be present depending
	// on test setup.
	var n *NetworkSnapshotAlias
	for i := range out {
		if out[i].ID == 7 {
			n = (*NetworkSnapshotAlias)(&out[i])
			break
		}
	}
	if n == nil {
		t.Fatalf("network 7 not in list: %+v", out)
	}
	if n.MembersCount != 4 {
		t.Fatalf("MembersCount = %d, want 4", n.MembersCount)
	}
	if n.OwnersCount != 1 {
		t.Fatalf("OwnersCount = %d, want 1", n.OwnersCount)
	}
	if n.AdminsCount != 1 {
		t.Fatalf("AdminsCount = %d, want 1", n.AdminsCount)
	}
}

// Local alias so the test reads naturally without importing dashpkg here.
type NetworkSnapshotAlias = dashpkg.NetworkSnapshot
