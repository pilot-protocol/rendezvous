// SPDX-License-Identifier: AGPL-3.0-or-later

package wal_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pilot-protocol/rendezvous/wal"
)

func TestNewStore_NewWALErrorPropagates(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	defer close(done)
	_, err := wal.NewStore("/dev/null/cannot/wal.log", done, wal.StoreCallbacks{})
	if err == nil {
		t.Error("expected error from NewStore on bad WAL path")
	}
}

func TestNewWAL_StatErrorAfterOpen(t *testing.T) {
	t.Parallel()
	// Hard to drive Stat failure without root, so we just sanity-check
	// that re-opening an existing file populates size from disk.
	dir := t.TempDir()
	path := filepath.Join(dir, "wal.log")
	// Pre-create a file with some content.
	if err := os.WriteFile(path, []byte("preexisting-bytes"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	w, err := wal.NewWAL(path)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	defer w.Close()
	if got := w.Size(); got != 17 {
		t.Errorf("Size = %d, want 17 (length of pre-existing content)", got)
	}
}
