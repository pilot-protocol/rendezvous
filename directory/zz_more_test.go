// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestNodeInfo_GetLastSeen_PrefersAtomic exercises both branches:
// when LastSeenNano > 0, the atomic value wins; else fall back to LastSeen.
func TestNodeInfo_GetLastSeen_PrefersAtomic(t *testing.T) {
	t.Parallel()
	n := &NodeInfo{}
	// Atomic == 0 → fall through to LastSeen.
	fallback := time.Now().Add(-time.Minute)
	n.LastSeen = fallback
	if got := n.GetLastSeen(); !got.Equal(fallback) {
		t.Errorf("atomic=0: got %v, want fallback %v", got, fallback)
	}

	// SetLastSeen primes the atomic, so GetLastSeen returns that.
	t2 := time.Now()
	n.SetLastSeen(t2)
	if got := n.GetLastSeen(); got.UnixNano() != t2.UnixNano() {
		t.Errorf("atomic: got %v, want %v", got.UnixNano(), t2.UnixNano())
	}
}

// TestValidateHostname_Cases covers every branch.
func TestValidateHostname_Cases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"empty_allowed", "", false},
		{"valid_simple", "alice", false},
		{"valid_with_dash", "alice-bob", false},
		{"valid_with_digits", "a1b2", false},
		{"too_long", strings.Repeat("a", 64), true},
		{"uppercase_rejected", "Alice", true},
		{"leading_dash", "-alice", true},
		{"trailing_dash", "alice-", true},
		{"reserved_localhost", "localhost", true},
		{"reserved_backbone", "backbone", true},
		{"reserved_broadcast", "broadcast", true},
		{"contains_dot", "a.b", true},
	}
	for _, tc := range cases {
		err := ValidateHostname(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: ValidateHostname(%q) = %v, wantErr=%v", tc.name, tc.in, err, tc.wantErr)
		}
	}
}

// TestJsonUint16_Cases drives every branch of jsonUint16.
func TestJsonUint16_Cases(t *testing.T) {
	t.Parallel()
	if got := jsonUint16(map[string]interface{}{"k": float64(42)}, "k"); got != 42 {
		t.Errorf("happy: got %d", got)
	}
	if got := jsonUint16(map[string]interface{}{"k": float64(-1)}, "k"); got != 0 {
		t.Errorf("negative clamps to 0: got %d", got)
	}
	if got := jsonUint16(map[string]interface{}{"k": float64(100000)}, "k"); got != 0 {
		t.Errorf("overflow clamps to 0: got %d", got)
	}
	if got := jsonUint16(map[string]interface{}{"k": "string"}, "k"); got != 0 {
		t.Errorf("non-float type: got %d", got)
	}
	if got := jsonUint16(map[string]interface{}{}, "missing"); got != 0 {
		t.Errorf("missing key: got %d", got)
	}
}

// TestJsonUint32_OutOfRange drives the negative and overflow branches
// in the existing helper.
func TestJsonUint32_OutOfRange(t *testing.T) {
	t.Parallel()
	if got := jsonUint32(map[string]interface{}{"k": float64(-1)}, "k"); got != 0 {
		t.Errorf("negative: got %d", got)
	}
	if got := jsonUint32(map[string]interface{}{"k": float64(1e20)}, "k"); got != 0 {
		t.Errorf("overflow: got %d", got)
	}
}

// TestWrapListNodesBody covers the helper.
func TestWrapListNodesBody(t *testing.T) {
	t.Parallel()
	got := wrapListNodesBody([]byte(`[{"a":1}]`))
	want := []byte(`{"type":"list_nodes_ok","nodes":[{"a":1}]}`)
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestCleanupNode_NoOp drives the (empty) cleanupNode path.
func TestCleanupNode_NoOp(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	// Just verify it doesn't panic.
	st.cleanupNode(0xCAFE)
}

// TestInvalidateAdminListNodesCache resets the BuiltAt timestamp.
func TestInvalidateAdminListNodesCache(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	// Prime the cache so BuiltAt is non-zero.
	st.listNodesCache.Mu.Lock()
	st.listNodesCache.BuiltAt = time.Now()
	st.listNodesCache.FullBody = []byte("primed")
	st.listNodesCache.Mu.Unlock()

	st.InvalidateAdminListNodesCache()

	st.listNodesCache.Mu.Lock()
	defer st.listNodesCache.Mu.Unlock()
	if !st.listNodesCache.BuiltAt.IsZero() {
		t.Errorf("BuiltAt should be zero after Invalidate, got %v", st.listNodesCache.BuiltAt)
	}
}

// TestInvalidateListNodesCacheForNetwork drops the network entry.
func TestInvalidateListNodesCacheForNetwork(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	// Seed the per-network map.
	st.listNodesPerNetMu.Lock()
	(*st.listNodesPerNet)[42] = &ListNodesCacheState{}
	st.listNodesPerNetMu.Unlock()

	st.InvalidateListNodesCacheForNetwork(42)

	st.listNodesPerNetMu.Lock()
	defer st.listNodesPerNetMu.Unlock()
	if _, ok := (*st.listNodesPerNet)[42]; ok {
		t.Error("network 42 should be deleted from cache")
	}
}

// TestPerNetworkListNodesCached_UnknownNetworkReturnsError exercises
// the network-not-found early-return branch.
func TestPerNetworkListNodesCached_UnknownNetworkReturnsError(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	// The test store's getNetworkView always returns (zero, false).
	_, err := st.PerNetworkListNodesCached(99)
	if err == nil {
		t.Fatal("expected error for unknown network")
	}
	if !strings.Contains(err.Error(), "99") {
		t.Errorf("error should mention network 99: %v", err)
	}
}

// TestPerNetworkListNodesCached_RaceUsesCondVar verifies the
// singleflight contract: when one goroutine is Building, a concurrent
// caller waits on the cond var and then returns the rebuild error.
func TestPerNetworkListNodesCached_BuildingPathReturnsError(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	// Pre-seed a cache entry marked Building with a known error.
	c := &ListNodesCacheState{}
	c.Cond = sync.NewCond(&c.Mu)
	st.listNodesPerNetMu.Lock()
	(*st.listNodesPerNet)[7] = c
	st.listNodesPerNetMu.Unlock()

	c.Mu.Lock()
	c.Building = true
	c.LastBuildErr = errors.New("simulated build failure")
	c.Mu.Unlock()

	// Kick a goroutine to clear Building shortly so the waiter unblocks.
	go func() {
		time.Sleep(10 * time.Millisecond)
		c.Mu.Lock()
		c.Building = false
		c.Cond.Broadcast()
		c.Mu.Unlock()
	}()

	_, err := st.PerNetworkListNodesCached(7)
	if err == nil || !strings.Contains(err.Error(), "simulated") {
		t.Errorf("expected simulated build failure, got %v", err)
	}
}

