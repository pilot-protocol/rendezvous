// SPDX-License-Identifier: AGPL-3.0-or-later

package dashboard

import (
	"testing"
)

func TestNewNetHistoryRing_CapacityMatches(t *testing.T) {
	t.Parallel()
	r := NewNetHistoryRing(5)
	if r.Size != 5 || len(r.Samples) != 5 {
		t.Errorf("size=%d len=%d, want 5/5", r.Size, len(r.Samples))
	}
}

func TestNetHistoryRing_WriteAndRead(t *testing.T) {
	t.Parallel()
	r := NewNetHistoryRing(3)
	r.Write(NetworkSampleEntry{Timestamp: 100})
	r.Write(NetworkSampleEntry{Timestamp: 200})
	r.Write(NetworkSampleEntry{Timestamp: 300})

	out := r.Read()
	if len(out) != 3 {
		t.Fatalf("len = %d, want 3", len(out))
	}
	if out[0].Timestamp != 100 || out[1].Timestamp != 200 || out[2].Timestamp != 300 {
		t.Errorf("order = %v", out)
	}
}

func TestNetHistoryRing_WraparoundOverwritesOldest(t *testing.T) {
	t.Parallel()
	r := NewNetHistoryRing(3)
	for i := 1; i <= 5; i++ {
		r.Write(NetworkSampleEntry{Timestamp: int64(i)})
	}
	out := r.Read()
	if len(out) != 3 {
		t.Fatalf("len = %d, want 3", len(out))
	}
	// After 5 writes into a 3-slot ring, the visible samples are 3,4,5.
	if out[0].Timestamp != 3 || out[2].Timestamp != 5 {
		t.Errorf("got %v, want [3,4,5]", out)
	}
}

func TestNetHistoryRing_WriteBucketed_OverwritesSameBucket(t *testing.T) {
	t.Parallel()
	r := NewNetHistoryRing(5)
	// bucketSecs=10 → both samples in the same bucket.
	r.WriteBucketed(NetworkSampleEntry{Timestamp: 100, Members: 1}, 10)
	r.WriteBucketed(NetworkSampleEntry{Timestamp: 105, Members: 2}, 10)
	out := r.Read()
	if len(out) != 1 {
		t.Errorf("len = %d, want 1 (same bucket → overwrite)", len(out))
	}
	if out[0].Members != 2 {
		t.Errorf("members = %d, want 2 (overwritten)", out[0].Members)
	}
}

func TestNetHistoryRing_WriteBucketed_NewBucketAppends(t *testing.T) {
	t.Parallel()
	r := NewNetHistoryRing(5)
	r.WriteBucketed(NetworkSampleEntry{Timestamp: 100}, 10)
	r.WriteBucketed(NetworkSampleEntry{Timestamp: 200}, 10) // different bucket
	if got := r.Read(); len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
}

func TestNetHistoryRing_WriteBucketed_ZeroBucketFallback(t *testing.T) {
	t.Parallel()
	r := NewNetHistoryRing(3)
	r.WriteBucketed(NetworkSampleEntry{Timestamp: 1}, 0) // bucket==0 → plain Write
	r.WriteBucketed(NetworkSampleEntry{Timestamp: 2}, 0)
	if got := r.Read(); len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
}

func TestNetHistoryRing_Read_SkipsZeroEntries(t *testing.T) {
	t.Parallel()
	r := NewNetHistoryRing(5)
	r.Write(NetworkSampleEntry{Timestamp: 1})
	// 4 slots remain zero-valued → Read returns only the 1 written entry.
	if got := r.Read(); len(got) != 1 {
		t.Errorf("len = %d, want 1", len(got))
	}
}
