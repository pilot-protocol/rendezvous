// SPDX-License-Identifier: AGPL-3.0-or-later

package wal_test

import (
	"path/filepath"
	"testing"

	"github.com/pilot-protocol/rendezvous/wal"
)

func newTestStore(t *testing.T) *wal.Store {
	t.Helper()
	dir := t.TempDir()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	store, err := wal.NewStore(filepath.Join(dir, "wal.log"), done, wal.StoreCallbacks{
		FlushSave:       func() error { return nil },
		SnapshotJSON:    func() []byte { return []byte(`{}`) },
		Push:            func([]byte) {},
		IncSaveFailures: func() {},
		HasReplicaSubs:  func() bool { return false },
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestStore_AccessorsAfterConstruction(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	if st.WAL() == nil {
		t.Error("WAL() returned nil for configured store")
	}
	if st.SaveCh() == nil {
		t.Error("SaveCh() returned nil")
	}
	if st.ReplicaPushCh() == nil {
		t.Error("ReplicaPushCh() returned nil")
	}
}

func TestStore_TriggerSnapshot_HappyPath(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	if err := st.TriggerSnapshot(); err != nil {
		t.Errorf("TriggerSnapshot: %v", err)
	}
}

func TestStore_TriggerSnapshot_NoWALReturnsNil(t *testing.T) {
	t.Parallel()
	// NewStore with empty path → wal field is nil → TriggerSnapshot
	// short-circuits.
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	store, err := wal.NewStore("", done, wal.StoreCallbacks{
		FlushSave:       func() error { return nil },
		IncSaveFailures: func() {},
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.TriggerSnapshot(); err != nil {
		t.Errorf("TriggerSnapshot with nil WAL: %v", err)
	}
}

func TestStore_CloseHappyPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	done := make(chan struct{})
	defer close(done)

	store, err := wal.NewStore(filepath.Join(dir, "wal.log"), done, wal.StoreCallbacks{
		FlushSave:       func() error { return nil },
		IncSaveFailures: func() {},
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestStore_StandbyAndReplToken(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	if st.IsStandby() {
		t.Error("fresh store: IsStandby = true, want false")
	}
	st.SetStandby(true)
	if !st.IsStandby() {
		t.Error("after SetStandby(true): want true")
	}
	st.SetStandby(false)
	if st.IsStandby() {
		t.Error("after SetStandby(false): want false")
	}

	if got := st.ReplicationToken(); got != "" {
		t.Errorf("fresh ReplicationToken = %q, want empty", got)
	}
	st.SetReplicationToken("secret-token")
	if got := st.ReplicationToken(); got != "secret-token" {
		t.Errorf("after Set: %q", got)
	}
}

func TestStore_TriggerSave_NonBlocking(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	// Call twice — second must be a no-op due to buffered channel.
	st.TriggerSave()
	st.TriggerSave()
}
