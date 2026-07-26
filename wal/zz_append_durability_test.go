// SPDX-License-Identifier: AGPL-3.0-or-later

package wal_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pilot-protocol/rendezvous/wal"
)

// TestAppendIsVisibleImmediatelyAfterReturn pins the half of the
// durability contract Append does guarantee: the write(2) is synchronous,
// so the bytes are in the file and readable by anyone who opens it as
// soon as Append returns — no flush, no Close, no waiting for the
// batching timer.
//
// The other half is the part the doc comment used to overstate: the
// fsync behind that write is batched, so this says nothing about
// surviving host power loss. That distinction is what the comment on
// Append and the walSyncInterval / walSyncBatch constants now spell out.
func TestAppendIsVisibleImmediatelyAfterReturn(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "visible.wal")

	w, err := wal.NewWAL(path)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	defer w.Close()

	// A single append: far below walSyncBatch and returning long before
	// walSyncInterval elapses, so no fsync has run yet.
	if err := w.Append(wal.DeltaEntry{SeqNo: 1, Type: wal.DeltaRegister, NodeID: 7}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("the file is still empty after Append returned; the write is supposed to be synchronous")
	}
	if got := w.Size(); got != info.Size() {
		t.Errorf("WAL.Size() = %d; the file on disk is %d", got, info.Size())
	}
}

// TestCloseFlushesPendingAppends pins the shutdown guarantee the Append
// comment now states: an orderly Close flushes whatever the batching
// thresholds have not yet synced, so a clean restart replays everything.
func TestCloseFlushesPendingAppends(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "close.wal")

	w, err := wal.NewWAL(path)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}

	// Fewer than walSyncBatch entries, appended and closed well inside
	// walSyncInterval, so the flush can only come from Close.
	const n = 5
	for i := 0; i < n; i++ {
		if err := w.Append(wal.DeltaEntry{SeqNo: uint64(i + 1), Type: wal.DeltaHeartbeat, NodeID: uint32(i + 1)}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := wal.NewWAL(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	var replayed []wal.DeltaEntry
	count, err := reopened.Replay(func(e wal.DeltaEntry) error {
		replayed = append(replayed, e)
		return nil
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if count != n {
		t.Fatalf("replayed %d entries after Close; want %d", count, n)
	}
	for i, e := range replayed {
		if e.SeqNo != uint64(i+1) || e.NodeID != uint32(i+1) {
			t.Errorf("entry %d = %+v; want SeqNo/NodeID %d", i, e, i+1)
		}
	}
}
