// SPDX-License-Identifier: AGPL-3.0-or-later

package wal_test

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/rendezvous/wal"
)

var _ = filepath.Separator // keep filepath import alive if unused
var _ time.Duration         // keep time alive



// TestStore_ReplicaPushLoop_HasReplicaSubsTruePushesSnapshot drives the
// happy branch where HasReplicaSubs=true → SnapshotJSON + Push fire.
func TestStore_ReplicaPushLoop_HasReplicaSubsTruePushesSnapshot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	done := make(chan struct{})
	defer close(done)

	var pushCount atomic.Int64
	var snapshotCount atomic.Int64
	st, err := wal.NewStore(filepath.Join(dir, "wal.log"), done, wal.StoreCallbacks{
		FlushSave:       func() error { return nil },
		IncSaveFailures: func() {},
		HasReplicaSubs:  func() bool { return true },
		Push:            func([]byte) { pushCount.Add(1) },
		SnapshotJSON: func() []byte {
			snapshotCount.Add(1)
			return []byte(`{}`)
		},
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	st.Start()

	// Trigger push and wait for the ticker (default 1s).
	st.TriggerSave()
	time.Sleep(1300 * time.Millisecond)

	if pushCount.Load() == 0 {
		t.Error("pushCount = 0, want >= 1")
	}
	if snapshotCount.Load() == 0 {
		t.Error("snapshotCount = 0, want >= 1")
	}
}

// TestStore_SaveLoop_DoneChannelFinalFlush drives the saveLoop
// shutdown path: signal done while a pending save is buffered, observe
// the final FlushSave invocation.
func TestStore_SaveLoop_DoneChannelFinalFlush(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	done := make(chan struct{})

	var flushCount atomic.Int64
	st, err := wal.NewStore(filepath.Join(dir, "wal.log"), done, wal.StoreCallbacks{
		FlushSave:       func() error { flushCount.Add(1); return nil },
		IncSaveFailures: func() {},
		HasReplicaSubs:  func() bool { return false },
		Push:            func([]byte) {},
		SnapshotJSON:    func() []byte { return []byte(`{}`) },
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st.Start()

	// Trigger save, then immediately close done — saveLoop's done branch
	// drains saveCh and runs the final FlushSave.
	st.TriggerSave()
	time.Sleep(10 * time.Millisecond)
	close(done)
	<-st.SaveDone()

	if got := flushCount.Load(); got == 0 {
		t.Errorf("flushCount = %d, want >= 1 (final flush)", got)
	}
}

// errFlushFailSentinel is used for the failure-path test.
type errFlushFailSentinel struct{}

func (errFlushFailSentinel) Error() string { return "simulated flush failure" }

// TestStore_SaveLoop_DoneChannelFlushFailure drives the failure branch
// of the final FlushSave during done-channel cleanup.
func TestStore_SaveLoop_DoneChannelFlushFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	done := make(chan struct{})

	var saveFailureCount atomic.Int64
	st, err := wal.NewStore(filepath.Join(dir, "wal.log"), done, wal.StoreCallbacks{
		FlushSave:       func() error { return errFlushFailSentinel{} },
		IncSaveFailures: func() { saveFailureCount.Add(1) },
		HasReplicaSubs:  func() bool { return false },
		Push:            func([]byte) {},
		SnapshotJSON:    func() []byte { return []byte(`{}`) },
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st.Start()

	st.TriggerSave()
	time.Sleep(10 * time.Millisecond)
	close(done)
	<-st.SaveDone()

	if got := saveFailureCount.Load(); got == 0 {
		t.Errorf("saveFailureCount = %d, want >= 1", got)
	}
}

// TestStore_ReplicaPushLoop_DoneChannelFinalPush drives the
// shutdown-with-pending-push branch in replicaPushLoop.
func TestStore_ReplicaPushLoop_DoneChannelFinalPush(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	done := make(chan struct{})

	var pushCount atomic.Int64
	st, err := wal.NewStore(filepath.Join(dir, "wal.log"), done, wal.StoreCallbacks{
		FlushSave:       func() error { return nil },
		IncSaveFailures: func() {},
		HasReplicaSubs:  func() bool { return true },
		Push:            func([]byte) { pushCount.Add(1) },
		SnapshotJSON:    func() []byte { return []byte(`{"snap":1}`) },
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st.Start()

	// Trigger a pending replica push, then close done — the shutdown
	// branch drains replicaPushCh and runs one final Push.
	st.TriggerSave()
	time.Sleep(10 * time.Millisecond)
	close(done)
	<-st.ReplicaPushDone()

	if got := pushCount.Load(); got == 0 {
		t.Errorf("pushCount = %d, want >= 1 (final push at shutdown)", got)
	}
}

// TestStore_ReplicaPushLoop_HasReplicaSubsFalseSkipsPush exercises the
// HasReplicaSubs guard.
func TestStore_ReplicaPushLoop_HasReplicaSubsFalseSkipsPush(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	done := make(chan struct{})
	defer close(done)

	var pushCount atomic.Int64
	st, err := wal.NewStore(filepath.Join(dir, "wal.log"), done, wal.StoreCallbacks{
		FlushSave:       func() error { return nil },
		IncSaveFailures: func() {},
		HasReplicaSubs:  func() bool { return false },
		Push:            func([]byte) { pushCount.Add(1) },
		SnapshotJSON:    func() []byte { return []byte(`{}`) },
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	st.Start()

	// Trigger replica push; HasReplicaSubs=false means Push should not fire.
	st.TriggerSave() // also signals replicaPushCh
	time.Sleep(50 * time.Millisecond)

	if got := pushCount.Load(); got != 0 {
		t.Errorf("pushCount = %d, want 0 (HasReplicaSubs=false)", got)
	}
}
