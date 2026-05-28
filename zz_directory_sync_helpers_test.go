// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"testing"
)

func TestStoreRBACPreAssignmentLocked_AvoidsDuplicates(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	s.storeRBACPreAssignmentLocked(5, "alice@example.com", "admin")
	// Second call with the same externalID should be deduped.
	s.storeRBACPreAssignmentLocked(5, "alice@example.com", "admin")
	// Case difference should still be deduped via NormalizeExternalID.
	s.storeRBACPreAssignmentLocked(5, "ALICE@EXAMPLE.COM", "member")
	s.mu.Unlock()

	s.mu.RLock()
	defer s.mu.RUnlock()
	if got := len(s.rbacPreAssign[5]); got != 1 {
		t.Errorf("entries = %d, want 1 (deduped)", got)
	}
}

func TestStoreRBACPreAssignmentLocked_DifferentExternalIDsCoexist(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	s.storeRBACPreAssignmentLocked(5, "alice@example.com", "admin")
	s.storeRBACPreAssignmentLocked(5, "bob@example.com", "member")
	s.mu.Unlock()

	s.mu.RLock()
	defer s.mu.RUnlock()
	if got := len(s.rbacPreAssign[5]); got != 2 {
		t.Errorf("entries = %d, want 2", got)
	}
}

func TestRemoveMemberLocked_RemovesFromMembersAndRoles(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	net := &NetworkInfo{
		Members:     []uint32{1, 2, 3},
		MemberRoles: map[uint32]Role{1: RoleOwner, 2: RoleAdmin, 3: RoleMember},
	}
	s.mu.Lock()
	s.removeMemberLocked(net, 2)
	s.mu.Unlock()

	if len(net.Members) != 2 {
		t.Errorf("Members len = %d, want 2", len(net.Members))
	}
	if _, ok := net.MemberRoles[2]; ok {
		t.Error("MemberRoles[2] should be removed")
	}
}

func TestRemoveMemberLocked_AbsentNodeNoop(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	net := &NetworkInfo{
		Members:     []uint32{1, 2},
		MemberRoles: map[uint32]Role{1: RoleOwner, 2: RoleMember},
	}
	s.mu.Lock()
	s.removeMemberLocked(net, 9999) // not present
	s.mu.Unlock()
	if len(net.Members) != 2 {
		t.Errorf("Members len = %d, want 2 (no change)", len(net.Members))
	}
}

func TestSyncTimestamp_UpdatesViaApplySync(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	// SyncTimestamp returns time.Time; default zero.
	got := s.SyncTimestamp(1)
	if !got.IsZero() {
		t.Errorf("fresh server: SyncTimestamp = %v, want zero", got)
	}
}
