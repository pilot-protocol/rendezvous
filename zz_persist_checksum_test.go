// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"path/filepath"
	"testing"
)

// TestSnapshotChecksumRoundTripWithHTMLEscapableChars is a regression test
// for the load/save asymmetry that rejected a freshly-saved registry as
// "corrupt" whenever the data contained any of '<', '>', or '&'.
//
// flushSave uses json.Encoder with SetEscapeHTML(false), which keeps those
// bytes raw. The load path's verification re-marshalled with json.Marshal,
// which is equivalent to SetEscapeHTML(true) — every '&' becomes '&'
// in the recomputed buffer, the SHA-256 differs, and the file is rejected.
//
// Production hit this on 2026-06-09: a hostname containing '&' was persisted
// and the next restart refused to load the 149 MB registry, dropping the
// network back to 323 freshly-registering nodes. Recovery required restoring
// from a pre-deploy backup AND fixing the load path.
//
// The fix: load uses the same Encoder(SetEscapeHTML=false) configuration as
// save. This test seeds an audit detail containing all three HTML-escape
// characters and asserts that a save/load round-trip succeeds (i.e. the
// checksum verifies cleanly with no "corrupt data" error).
func TestSnapshotChecksumRoundTripWithHTMLEscapableChars(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "registry.json")

	// Seed the audit ring with an entry whose Details field exercises every
	// HTML-escape byte (<, >, &). Audit details are the most common carrier
	// of these bytes in production (URL fragments, JSON snippets, etc.).
	s := NewWithStore("", storePath)
	s.appendAudit("test.html_escape", 0, 0,
		"details", "a<b & c>d url=http://example.com/?x=1&y=2",
	)
	if err := s.flushSave(); err != nil {
		t.Fatalf("flushSave: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Re-open against the same store path. Before the fix this returned
	// "snapshot checksum mismatch — refusing to load corrupt data".
	s2 := NewWithStore("", storePath)
	if err := s2.load(); err != nil {
		t.Fatalf("load after save round-trip should succeed, got: %v", err)
	}
	defer s2.Close()

	// Sanity: the audit entry survived the round-trip with its raw bytes.
	s2.auditMu.Lock()
	defer s2.auditMu.Unlock()
	found := false
	for _, e := range s2.auditLog {
		if e.Action == "test.html_escape" && e.Details ==
			"details=a<b & c>d url=http://example.com/?x=1&y=2" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("audit entry with HTML-escape chars not preserved across round-trip; ring=%+v", s2.auditLog)
	}
}
