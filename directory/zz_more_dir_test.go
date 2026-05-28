// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"testing"
	"time"
)

func TestReapStaleNodes_EmptyMap(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.ReapStaleNodes(time.Now())
	if got := len(st.nodes); got != 0 {
		t.Errorf("nodes len = %d, want 0", got)
	}
}

func TestReapStaleNodes_RemovesStale(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	// Register a node directly with a stale LastSeen.
	st.mu.Lock()
	n := &NodeInfo{ID: 1, Hostname: "stale-host"}
	n.SetLastSeen(time.Now().Add(-time.Hour))
	st.nodes[1] = n
	st.hostnameIdx["stale-host"] = 1
	st.mu.Unlock()

	st.ReapStaleNodes(time.Now().Add(-time.Minute))
	st.mu.RLock()
	defer st.mu.RUnlock()
	if _, ok := st.nodes[1]; ok {
		t.Error("stale node should be reaped")
	}
	if _, ok := st.hostnameIdx["stale-host"]; ok {
		t.Error("hostname index entry should be removed")
	}
}

func TestReapStaleNodes_KeepsFreshNodes(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.mu.Lock()
	n := &NodeInfo{ID: 1}
	n.SetLastSeen(time.Now())
	st.nodes[1] = n
	st.mu.Unlock()

	st.ReapStaleNodes(time.Now().Add(-time.Hour))
	st.mu.RLock()
	defer st.mu.RUnlock()
	if _, ok := st.nodes[1]; !ok {
		t.Error("fresh node should remain")
	}
}

func TestReplaceState_SwapsPointers(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	newNodes := map[uint32]*NodeInfo{42: {ID: 42}}
	newPubIdx := map[string]uint32{"pk": 42}
	newOwnerIdx := map[string]uint32{"alice": 42}
	newHostIdx := map[string]uint32{"alice-host": 42}

	st.mu.Lock()
	st.ReplaceState(newNodes, newPubIdx, newOwnerIdx, newHostIdx)
	st.mu.Unlock()

	st.mu.RLock()
	defer st.mu.RUnlock()
	if _, ok := st.nodes[42]; !ok {
		t.Error("nodes map not swapped")
	}
	if st.pubKeyIdx["pk"] != 42 {
		t.Error("pubKeyIdx not swapped")
	}
}
