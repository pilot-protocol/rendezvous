// SPDX-License-Identifier: AGPL-3.0-or-later

package wal_test

import (
	"path/filepath"
	"testing"

	"github.com/pilot-protocol/rendezvous/wal"
)

func TestWAL_NilReceiverIsSafe(t *testing.T) {
	t.Parallel()
	var w *wal.WAL
	if err := w.Truncate(); err != nil {
		t.Errorf("nil.Truncate: %v", err)
	}
	if got := w.Size(); got != 0 {
		t.Errorf("nil.Size = %d, want 0", got)
	}
	if got := w.Path(); got != "" {
		t.Errorf("nil.Path = %q, want empty", got)
	}
	w.SetSize(100) // must not panic
	if err := w.Close(); err != nil {
		t.Errorf("nil.Close: %v", err)
	}
}

func TestWAL_PathAccessor(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wal.log")
	w, err := wal.NewWAL(path)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	if got := w.Path(); got != path {
		t.Errorf("Path = %q, want %q", got, path)
	}
}

func TestWAL_SetSizeAndAppendOverCapErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	w, err := wal.NewWAL(filepath.Join(dir, "wal.log"))
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	// Force size near the cap so the next Append exceeds it.
	w.SetSize(wal.MaxWALSize)

	err = w.Append(wal.DeltaEntry{SeqNo: 1, Type: wal.DeltaRegister})
	if err == nil {
		t.Error("expected size-cap error on Append over MaxWALSize")
	}
}

func TestWAL_TruncateAfterAppend(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	w, err := wal.NewWAL(filepath.Join(dir, "wal.log"))
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	if err := w.Append(wal.DeltaEntry{SeqNo: 1, Type: wal.DeltaRegister}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if w.Size() == 0 {
		t.Error("Size should be non-zero after Append")
	}

	if err := w.Truncate(); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if got := w.Size(); got != 0 {
		t.Errorf("Size after Truncate = %d, want 0", got)
	}
}

func TestWAL_EmptyPathReturnsNilWAL(t *testing.T) {
	t.Parallel()
	w, err := wal.NewWAL("")
	if err != nil {
		t.Fatalf("NewWAL(\"\"): %v", err)
	}
	if w != nil {
		t.Errorf("empty path: WAL = %v, want nil", w)
	}
}

func TestWAL_BadPathErrors(t *testing.T) {
	t.Parallel()
	// /dev/null is a file — can't open it as a WAL file with write perms.
	_, err := wal.NewWAL("/dev/null/cannot-create-here")
	if err == nil {
		t.Error("expected open error for bad path")
	}
}
