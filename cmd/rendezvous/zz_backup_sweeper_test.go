// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// touchFile creates a file at path with the given modification time.
func touchFile(t *testing.T, path string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte("snapshot"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// retainBy applies the sweeper logic once via an immediate stop channel,
// then verifies the remaining file set matches expected.
func runOnceAndCheck(t *testing.T, dir string, maxAge time.Duration, maxCount int, wantRemaining []string) {
	t.Helper()
	stop := make(chan struct{})
	close(stop) // immediate exit after first apply()
	watchBackupsRetention(dir, maxAge, maxCount, 1*time.Hour, stop)

	got := listDir(t, dir)
	gotSet := map[string]bool{}
	for _, n := range got {
		gotSet[n] = true
	}
	wantSet := map[string]bool{}
	for _, n := range wantRemaining {
		wantSet[n] = true
	}
	for n := range gotSet {
		if !wantSet[n] {
			t.Errorf("unexpected file kept: %s", n)
		}
	}
	for n := range wantSet {
		if !gotSet[n] {
			t.Errorf("expected file missing: %s", n)
		}
	}
}

// maxCount keeps the N most recent auto-snapshot files; older ones
// are deleted.
func TestBackupSweeper_MaxCountKeepsNewest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Now()
	touchFile(t, filepath.Join(dir, "registry-20260606-120000.json"), now.Add(-3*time.Hour))
	touchFile(t, filepath.Join(dir, "registry-20260607-120000.json"), now.Add(-2*time.Hour))
	touchFile(t, filepath.Join(dir, "registry-20260608-120000.json"), now.Add(-1*time.Hour))

	runOnceAndCheck(t, dir, 0 /* no age cap */, 1, []string{"registry-20260608-120000.json"})
}

// maxAge deletes files older than the threshold; recent files survive.
func TestBackupSweeper_MaxAgeDeletesStale(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Now()
	touchFile(t, filepath.Join(dir, "registry-20260601-000000.json"), now.Add(-48*time.Hour))
	touchFile(t, filepath.Join(dir, "registry-20260608-000000.json"), now.Add(-1*time.Hour))

	runOnceAndCheck(t, dir, 24*time.Hour, 0 /* no count cap */, []string{"registry-20260608-000000.json"})
}

// Files that don't match the auto-snapshot regex are NEVER touched.
// Pins the conservative-match rule: PRISTINE, RECOVERY, operator notes,
// and any filename without a trailing YYYYMMDD-HHMMSS / YYYYMMDDTHHMMSSZ
// timestamp survive even when very old.
func TestBackupSweeper_LeavesHandCuratedFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	veryOld := time.Now().Add(-365 * 24 * time.Hour)
	// Should be deleted (matches auto-snapshot shape):
	touchFile(t, filepath.Join(dir, "registry-pre-deploy-20260601T120000Z.json"), veryOld)
	// Should ALL survive (operator-curated):
	touchFile(t, filepath.Join(dir, "registry-PRISTINE-20260607-132156.json"), veryOld)
	touchFile(t, filepath.Join(dir, "RECOVERY-README.md"), veryOld)
	touchFile(t, filepath.Join(dir, "operator-notes.txt"), veryOld)
	touchFile(t, filepath.Join(dir, "registry.json.bak.20260518T192030Z"), veryOld) // legacy .bak shape

	runOnceAndCheck(t, dir, 30*24*time.Hour, 10, []string{
		"registry-PRISTINE-20260607-132156.json",
		"RECOVERY-README.md",
		"operator-notes.txt",
		"registry.json.bak.20260518T192030Z",
	})
}

// maxCount=0 disables the count cap; only maxAge applies. maxAge=0
// disables the age cap; only count applies. Both zero is effectively
// a no-op.
func TestBackupSweeper_BothBoundsZeroIsNoOp(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Now()
	touchFile(t, filepath.Join(dir, "registry-20260608-000000.json"), now.Add(-24*time.Hour))
	touchFile(t, filepath.Join(dir, "registry-20260608-120000.json"), now.Add(-12*time.Hour))

	runOnceAndCheck(t, dir, 0, 0, []string{"registry-20260608-000000.json", "registry-20260608-120000.json"})
}

// Missing directory is fine — no panic, no error.
func TestBackupSweeper_MissingDirIsNoOp(t *testing.T) {
	t.Parallel()
	stop := make(chan struct{})
	close(stop)
	watchBackupsRetention("/tmp/does-not-exist-"+t.Name(), 1*time.Hour, 1, 1*time.Hour, stop)
	// nothing to assert — completing without panic is success
}
