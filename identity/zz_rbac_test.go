// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"testing"
)

func TestApplyRBACPreAssignment_NilGetRolesIsNoop(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	// Should not panic.
	st.ApplyRBACPreAssignment(1, 1, RBACPreAssignCallbacks{})
}

func TestApplyRBACPreAssignment_NotFoundIsNoop(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	committed := false
	rcb := RBACPreAssignCallbacks{
		GetRoles: func(uint16, uint32) ([]BlueprintRole, string, bool) {
			return nil, "", false
		},
		CommitRole: func(uint16, uint32, string) { committed = true },
	}
	st.ApplyRBACPreAssignment(1, 1, rcb)
	if committed {
		t.Error("CommitRole should not fire when not found")
	}
}

func TestApplyRBACPreAssignment_EmptyExternalIDIsNoop(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	rcb := RBACPreAssignCallbacks{
		GetRoles: func(uint16, uint32) ([]BlueprintRole, string, bool) {
			return []BlueprintRole{{ExternalID: "alice", Role: "admin"}}, "", true
		},
	}
	// No panic + nothing commits.
	st.ApplyRBACPreAssignment(1, 1, rcb)
}

func TestApplyRBACPreAssignment_NoMatchingExternalID(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	committed := false
	rcb := RBACPreAssignCallbacks{
		GetRoles: func(uint16, uint32) ([]BlueprintRole, string, bool) {
			return []BlueprintRole{{ExternalID: "alice", Role: "admin"}}, "bob", true
		},
		CommitRole: func(uint16, uint32, string) { committed = true },
	}
	st.ApplyRBACPreAssignment(1, 1, rcb)
	if committed {
		t.Error("CommitRole should not fire for unmatched external_id")
	}
}

func TestApplyRBACPreAssignment_MatchCommitsAndCounts(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	var gotNet uint16
	var gotNode uint32
	var gotRole string
	counts := 0
	rcb := RBACPreAssignCallbacks{
		GetRoles: func(uint16, uint32) ([]BlueprintRole, string, bool) {
			return []BlueprintRole{
				{ExternalID: "other", Role: "member"},
				{ExternalID: "alice", Role: "admin"},
			}, "Alice", true // case-insensitive match
		},
		CommitRole: func(netID uint16, nodeID uint32, role string) {
			gotNet = netID
			gotNode = nodeID
			gotRole = role
		},
		IncCounter: func() { counts++ },
	}
	st.ApplyRBACPreAssignment(5, 42, rcb)
	if gotNet != 5 || gotNode != 42 || gotRole != "admin" {
		t.Errorf("commit got (%d, %d, %q); want (5, 42, admin)", gotNet, gotNode, gotRole)
	}
	if counts != 1 {
		t.Errorf("counts = %d, want 1", counts)
	}
}

func TestApplyRBACPreAssignment_NilCommitRoleSafe(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	// GetRoles returns a match but CommitRole is nil — must not panic.
	rcb := RBACPreAssignCallbacks{
		GetRoles: func(uint16, uint32) ([]BlueprintRole, string, bool) {
			return []BlueprintRole{{ExternalID: "alice", Role: "admin"}}, "alice", true
		},
		IncCounter: nil,
	}
	st.ApplyRBACPreAssignment(1, 1, rcb)
}
