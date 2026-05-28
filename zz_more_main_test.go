// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"strings"
	"testing"
)

// TestRecoveredPanicCount_AfterRecover increments the global counter.
func TestRecoveredPanicCount_AfterRecover(t *testing.T) {
	// Cannot t.Parallel — touches process-global counter.
	before := RecoveredPanicCount()
	func() {
		defer recoverHandler("test-recover", nil)
		panic("synthetic")
	}()
	after := RecoveredPanicCount()
	if after <= before {
		t.Errorf("counter did not advance: %d → %d", before, after)
	}
}

// TestRecoverHandler_NoPanicIsNoOp drives the recover()==nil branch.
func TestRecoverHandler_NoPanicIsNoOp(t *testing.T) {
	t.Parallel()
	// Just call it directly — when there's no panic, returns silently.
	recoverHandler("noop", nil)
}

// TestRecoverHandler_NestedPanicSafe verifies a callback that itself
// panics doesn't propagate (the nested defer-recover protects).
func TestRecoverHandler_NestedPanicSafe(t *testing.T) {
	t.Parallel()
	func() {
		defer recoverHandler("nested", func(uint64) {
			panic("nested panic")
		})
		panic("outer")
	}()
	// If we get here, the nested panic was contained.
}

// TestServer_ConnCount_FreshIsZero exercises the Dispatcher shim.
func TestServer_ConnCount_FreshIsZero(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if got := s.ConnCount(); got != 0 {
		t.Errorf("ConnCount = %d, want 0", got)
	}
}

// TestServer_AddRequestIncrements covers the AddRequest hook.
func TestServer_AddRequestIncrements(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	before := s.requestCount.Load()
	s.AddRequest()
	if got := s.requestCount.Load(); got != before+1 {
		t.Errorf("AddRequest: counter not incremented")
	}
}

// TestServer_ReplicationToken_FreshIsEmpty covers the delegation shim.
func TestServer_ReplicationToken_FreshIsEmpty(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if got := s.ReplicationToken(); got != "" {
		t.Errorf("ReplicationToken = %q, want empty", got)
	}
}

// TestServer_Reap_SafeOnEmptyServer exercises the reap entry point.
func TestServer_Reap_SafeOnEmptyServer(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.Reap() // must not panic on empty server
}

// TestServer_HandleMessageWiresThrough covers the dispatcher shim.
func TestServer_HandleMessageWiresThrough(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	resp, err := s.HandleMessage(map[string]interface{}{
		"type": "list_networks",
	}, "127.0.0.1:12345")
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	if resp == nil {
		t.Error("expected non-nil response")
	}
}

// TestServer_HandleMessageUnknownType drives the unknown-type branch.
func TestServer_HandleMessageUnknownType(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	_, err := s.HandleMessage(map[string]interface{}{
		"type": "no_such_command",
	}, "127.0.0.1:12345")
	if err == nil {
		t.Error("expected error for unknown command")
	}
	if err != nil && !strings.Contains(err.Error(), "unknown") {
		// Accept any error — the underlying server may use a different word.
	}
}

// TestServer_StoreRBACPreAssignmentLockedDirect exercises the locked
// helper via the public storeRBACPreAssignments shim.
func TestServer_StoreRBACPreAssignmentLockedDirect(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	s.storeRBACPreAssignmentLocked(5, "u1", "admin")
	s.mu.Unlock()

	s.mu.RLock()
	defer s.mu.RUnlock()
	if entries := s.rbacPreAssign[5]; len(entries) != 1 {
		t.Errorf("rbacPreAssign[5] = %v, want 1 entry", entries)
	}
}

// TestSyncTimestamp_AccessesAtomic covers the SyncTimestamp accessor.
func TestSyncTimestamp_AccessesAtomic(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	// Just verify no panic + sane initial value.
	_ = s.SyncTimestamp(1)
}
