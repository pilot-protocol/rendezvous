// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"strings"
	"testing"
)

func TestBuildEntry_ExtractsNodeIDFromAttrs(t *testing.T) {
	t.Parallel()
	e := BuildEntry("act", 0, 0, "node_id", uint32(42))
	if e.NodeID != 42 {
		t.Errorf("NodeID = %d, want 42", e.NodeID)
	}
}

func TestBuildEntry_ExtractsNodeIDFromInt(t *testing.T) {
	t.Parallel()
	e := BuildEntry("act", 0, 0, "node_id", 42)
	if e.NodeID != 42 {
		t.Errorf("NodeID = %d, want 42 (int variant)", e.NodeID)
	}
}

func TestBuildEntry_ExtractsNodeIDFromFloat64(t *testing.T) {
	t.Parallel()
	e := BuildEntry("act", 0, 0, "node_id", float64(42))
	if e.NodeID != 42 {
		t.Errorf("NodeID = %d, want 42 (float64 variant)", e.NodeID)
	}
}

func TestBuildEntry_ExtractsNetworkIDFromAttrs(t *testing.T) {
	t.Parallel()
	e := BuildEntry("act", 0, 0, "network_id", uint16(7))
	if e.NetworkID != 7 {
		t.Errorf("NetworkID = %d, want 7", e.NetworkID)
	}
}

func TestBuildEntry_ExtractsNetworkIDFromInt(t *testing.T) {
	t.Parallel()
	e := BuildEntry("act", 0, 0, "network_id", 7)
	if e.NetworkID != 7 {
		t.Errorf("NetworkID = %d, want 7 (int variant)", e.NetworkID)
	}
}

func TestBuildEntry_ExtractsNetworkIDFromFloat64(t *testing.T) {
	t.Parallel()
	e := BuildEntry("act", 0, 0, "network_id", float64(7))
	if e.NetworkID != 7 {
		t.Errorf("NetworkID = %d, want 7 (float64 variant)", e.NetworkID)
	}
}

func TestBuildEntry_ExplicitArgsBeatAttrs(t *testing.T) {
	t.Parallel()
	// Explicit netID/nodeID args win — the loop only sets them when args are 0.
	e := BuildEntry("act", 99, 42, "network_id", 1, "node_id", 2)
	if e.NetworkID != 99 || e.NodeID != 42 {
		t.Errorf("got (%d, %d), want (99, 42)", e.NetworkID, e.NodeID)
	}
}

func TestBuildEntry_PutsExtraAttrsInDetails(t *testing.T) {
	t.Parallel()
	e := BuildEntry("act", 1, 2, "reason", "test", "count", 5)
	if !strings.Contains(e.Details, "reason=test") {
		t.Errorf("Details = %q, missing 'reason=test'", e.Details)
	}
	if !strings.Contains(e.Details, "count=5") {
		t.Errorf("Details = %q, missing 'count=5'", e.Details)
	}
}

func TestBuildEntry_SkipsNonStringKey(t *testing.T) {
	t.Parallel()
	// An attribute with a non-string key is silently dropped.
	e := BuildEntry("act", 0, 0, 42, "value")
	if e.Action != "act" {
		t.Errorf("Action = %q", e.Action)
	}
}

func TestBuildEntry_TimestampIsRFC3339(t *testing.T) {
	t.Parallel()
	e := BuildEntry("act", 0, 0)
	if e.Timestamp == "" {
		t.Error("Timestamp empty")
	}
	// RFC3339 contains a 'T' separator.
	if !strings.Contains(e.Timestamp, "T") {
		t.Errorf("Timestamp = %q, want RFC3339", e.Timestamp)
	}
}

// TestStore_Append covers the bounded ring-buffer trim path.
func TestStore_Append_BoundedRingBuffer(t *testing.T) {
	t.Parallel()
	st := NewStore()
	// Append more than maxEntries to trigger the trim.
	for i := 0; i < maxEntries+10; i++ {
		st.Append(Entry{Action: "x"})
	}
	st.mu.Lock()
	got := len(st.log)
	st.mu.Unlock()
	if got != maxEntries {
		t.Errorf("log len = %d, want %d (bounded)", got, maxEntries)
	}
}
