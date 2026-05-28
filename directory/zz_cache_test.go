// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"testing"
	"time"
)

// TestAdminListNodesCached_RebuildAndHitTTL drives the rebuild + cache-hit
// branches of AdminListNodesCached.
func TestAdminListNodesCached_RebuildAndHitTTL(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	// Pre-populate a couple of nodes so the rebuild path runs end-to-end.
	st.mu.Lock()
	n1 := &NodeInfo{ID: 1, Hostname: "alice", Public: true, RealAddr: "10.0.0.1:4000",
		Tags: []string{"web"}, ExternalID: "ext-1", Version: "1.2.3"}
	n1.SetLastSeen(time.Now())
	st.nodes[1] = n1
	n2 := &NodeInfo{ID: 2, TaskExec: true}
	n2.SetLastSeen(time.Now())
	st.nodes[2] = n2
	st.mu.Unlock()

	// First call → rebuild.
	body1, err := st.AdminListNodesCached()
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if len(body1) == 0 {
		t.Error("empty body from rebuild")
	}

	// Second call within TTL → cache hit. Verify CacheHits incremented.
	if _, err := st.AdminListNodesCached(); err != nil {
		t.Fatalf("second call: %v", err)
	}
	st.listNodesCache.Mu.Lock()
	hits := st.listNodesCache.CacheHits
	st.listNodesCache.Mu.Unlock()
	if hits == 0 {
		t.Error("CacheHits should be > 0 after second call within TTL")
	}
}

// TestAdminListNodesCached_ExpiredTTLRebuilds drives the
// "Time.Since(BuiltAt) >= TTL" branch.
func TestAdminListNodesCached_ExpiredTTLRebuilds(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	// Pre-fill cache with a stale BuiltAt.
	st.listNodesCache.Mu.Lock()
	st.listNodesCache.FullBody = []byte("stale")
	st.listNodesCache.BuiltAt = time.Now().Add(-2 * AdminListNodesTTL)
	st.listNodesCache.Mu.Unlock()

	body, err := st.AdminListNodesCached()
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if string(body) == "stale" {
		t.Error("stale body should have been replaced")
	}
}

// TestPerNetworkListNodesCached_FreshNetworkBuildsCache drives the
// non-Building, non-cached path of PerNetworkListNodesCached when the
// network view returns members.
func TestPerNetworkListNodesCached_FreshNetworkBuildsCache(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	// Wire the getNetworkView callback via direct struct mutation since
	// newTestStore returns a (zero, false) callback.
	st.getNetworkView = func(netID uint16) (NetworkMemberView, bool) {
		if netID != 7 {
			return NetworkMemberView{}, false
		}
		return NetworkMemberView{
			Members:     []uint32{1, 2},
			MemberRoles: map[uint32]string{1: "owner", 2: "admin"},
			MemberTags:  map[uint32][]string{1: {"prod"}, 2: {"dev"}},
		}, true
	}

	// Populate node 1 in the directory; node 2 absent → offline branch.
	st.mu.Lock()
	n := &NodeInfo{ID: 1, Public: true, RealAddr: "10.0.0.1:4000"}
	n.SetLastSeen(time.Now())
	st.nodes[1] = n
	st.mu.Unlock()

	body, err := st.PerNetworkListNodesCached(7)
	if err != nil {
		t.Fatalf("PerNetworkListNodesCached: %v", err)
	}
	if len(body) == 0 {
		t.Error("empty body")
	}

	// Second call within TTL → cache hit.
	if _, err := st.PerNetworkListNodesCached(7); err != nil {
		t.Fatalf("second call: %v", err)
	}
}
