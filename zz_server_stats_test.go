// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"testing"

	dashpkg "github.com/pilot-protocol/rendezvous/dashboard"
)

// --- deduplicateSamples --------------------------------------------------

func TestDeduplicateSamples_KeepsLatestPerBucket(t *testing.T) {
	t.Parallel()
	in := []StatsSample{
		{Timestamp: 100, TotalRequests: 1},
		{Timestamp: 150, TotalRequests: 2}, // same bucket as 100 (bucket=100s)
		{Timestamp: 250, TotalRequests: 3}, // new bucket
	}
	out := deduplicateSamples(in, 100, 10)
	if len(out) != 2 {
		t.Fatalf("expected 2 unique buckets, got %d: %+v", len(out), out)
	}
	if out[0].TotalRequests != 2 {
		t.Errorf("first bucket should keep later sample: %+v", out[0])
	}
	if out[1].TotalRequests != 3 {
		t.Errorf("second bucket: %+v", out[1])
	}
}

func TestDeduplicateSamples_SkipsZeroTimestamps(t *testing.T) {
	t.Parallel()
	in := []StatsSample{
		{Timestamp: 0, TotalRequests: 99},
		{Timestamp: 100, TotalRequests: 1},
	}
	out := deduplicateSamples(in, 100, 10)
	if len(out) != 1 || out[0].TotalRequests != 1 {
		t.Fatalf("zero-Ts samples must be skipped: %+v", out)
	}
}

func TestDeduplicateSamples_CapsMaxOut(t *testing.T) {
	t.Parallel()
	in := []StatsSample{
		{Timestamp: 100}, {Timestamp: 200}, {Timestamp: 300},
		{Timestamp: 400}, {Timestamp: 500},
	}
	out := deduplicateSamples(in, 100, 3)
	if len(out) != 3 {
		t.Fatalf("expected 3, got %d", len(out))
	}
	// Latest 3 retained.
	if out[0].Timestamp != 300 || out[2].Timestamp != 500 {
		t.Fatalf("tail not kept: %+v", out)
	}
}

func TestDeduplicateSamples_EmptyInputEmptyOutput(t *testing.T) {
	t.Parallel()
	if got := deduplicateSamples(nil, 100, 10); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

// --- deduplicateNetSamples ----------------------------------------------

func TestDeduplicateNetSamples_RoundtripAndCap(t *testing.T) {
	t.Parallel()
	in := []NetworkSampleEntry{
		{Timestamp: 100, ID: 1, Members: 1},
		{Timestamp: 150, ID: 1, Members: 2}, // same bucket
		{Timestamp: 250, ID: 1, Members: 3},
		{Timestamp: 0, ID: 1, Members: 999}, // zero Ts dropped
	}
	out := deduplicateNetSamples(in, 100, 10)
	if len(out) != 2 {
		t.Fatalf("len=%d %+v", len(out), out)
	}
	if out[0].Members != 2 {
		t.Errorf("first bucket should hold later sample: %+v", out[0])
	}

	// Cap.
	out = deduplicateNetSamples(in, 100, 1)
	if len(out) != 1 || out[0].Members != 3 {
		t.Fatalf("cap should keep latest: %+v", out)
	}
}

// --- recordSample --------------------------------------------------------

func TestServer_RecordSample_WritesHourlyAndDaily(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	res := dashpkg.StatsSampleResult{
		Global: StatsSample{Timestamp: 1_700_000_000, TotalNodes: 10, TotalRequests: 100},
		Networks: map[uint16]NetworkSampleEntry{
			1: {Timestamp: 1_700_000_000, ID: 1, Members: 5},
		},
	}
	s.recordSample(res, true)

	s.mu.RLock()
	defer s.mu.RUnlock()
	// Hourly ring should now have one non-zero sample.
	found := false
	for _, h := range s.hourlyHistory {
		if h.Timestamp != 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected hourly entry after recordSample")
	}
	// Daily ring should have one entry (daily=true).
	found = false
	for _, d := range s.dailyHistory {
		if d.Timestamp != 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected daily entry after recordSample(true)")
	}
	// Per-network rings should be initialised for net 1.
	if s.netHourly[1] == nil {
		t.Fatal("netHourly[1] not initialised")
	}
	if s.netDaily[1] == nil {
		t.Fatal("netDaily[1] not initialised (daily=true)")
	}
}

func TestServer_RecordSample_HourlyOnly(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	res := dashpkg.StatsSampleResult{
		Global: StatsSample{Timestamp: 1_700_000_000, TotalNodes: 1},
	}
	s.recordSample(res, false)
	s.mu.RLock()
	defer s.mu.RUnlock()
	hasDaily := false
	for _, d := range s.dailyHistory {
		if d.Timestamp != 0 {
			hasDaily = true
			break
		}
	}
	if hasDaily {
		t.Fatal("daily=false should not write to daily ring")
	}
}

// --- sampleStats --------------------------------------------------------

func TestServer_SampleStats_BasicShape(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	n := &NodeInfo{ID: 1}
	n.SetLastSeen(s.now())
	s.nodes[1] = n
	s.networks[5] = &NetworkInfo{ID: 5, Name: "five", Members: []uint32{1}}
	s.nextNode = 2
	s.mu.Unlock()

	res := s.sampleStats()
	if res.Global.TotalNodes != 1 {
		t.Errorf("TotalNodes = %d", res.Global.TotalNodes)
	}
	if res.Global.OnlineNodes != 1 {
		t.Errorf("OnlineNodes = %d", res.Global.OnlineNodes)
	}
	entry, ok := res.Networks[5]
	if !ok {
		t.Fatal("missing entry for network 5")
	}
	if entry.Members != 1 || entry.Online != 1 || entry.Name != "five" {
		t.Errorf("network entry: %+v", entry)
	}
}

// --- SetBeaconStats ------------------------------------------------------

type fakeBeaconStats struct{ fwd, drop, nf uint64 }

func (f *fakeBeaconStats) RelayForwarded() uint64 { return f.fwd }
func (f *fakeBeaconStats) RelayDropped() uint64   { return f.drop }
func (f *fakeBeaconStats) RelayNotFound() uint64  { return f.nf }

func TestServer_SetBeaconStats_SurfacedInDashboardStats(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	bs := &fakeBeaconStats{fwd: 5, drop: 2, nf: 1}
	s.SetBeaconStats(bs)
	stats := s.GetDashboardStats()
	if stats.RelayForwarded != 5 || stats.RelayDropped != 2 || stats.RelayNotFound != 1 {
		t.Fatalf("relay counters: %+v", stats)
	}
}

// --- readHistory / computeDeltas ----------------------------------------

func TestServer_ReadHistory_OrdersOldestFirst(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	s.hourlyHistory[0] = StatsSample{Timestamp: 100, TotalRequests: 1}
	s.hourlyHistory[1] = StatsSample{Timestamp: 200, TotalRequests: 2}
	s.hourlyIdx = 2
	s.mu.Unlock()
	s.mu.RLock()
	hourly, _ := s.readHistory()
	s.mu.RUnlock()
	if len(hourly) != 2 || hourly[0].Timestamp != 100 || hourly[1].Timestamp != 200 {
		t.Fatalf("hourly: %+v", hourly)
	}
}

func TestServer_ComputeDeltas_DailyPreferred(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	s.dailyHistory[0] = StatsSample{Timestamp: 86400, TotalRequests: 100}
	s.dailyHistory[1] = StatsSample{Timestamp: 172800, TotalRequests: 350}
	s.dailyIdx = 2
	s.mu.Unlock()
	s.mu.RLock()
	d := s.computeDeltas()
	s.mu.RUnlock()
	if d != 250 {
		t.Fatalf("reqPerDay = %d, want 250", d)
	}
}

func TestServer_ComputeDeltas_HourlyFallback(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	s.hourlyHistory[0] = StatsSample{Timestamp: 3600, TotalRequests: 10}
	s.hourlyHistory[1] = StatsSample{Timestamp: 7200, TotalRequests: 30}
	s.hourlyIdx = 2
	s.mu.Unlock()
	s.mu.RLock()
	d := s.computeDeltas()
	s.mu.RUnlock()
	// (30-10) * 24 = 480
	if d != 480 {
		t.Fatalf("reqPerDay = %d, want 480", d)
	}
}

func TestServer_ComputeDeltas_NoHistoryReturnsZero(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.RLock()
	d := s.computeDeltas()
	s.mu.RUnlock()
	if d != 0 {
		t.Fatalf("empty rings should yield 0, got %d", d)
	}
}

// --- GetDashboardStatsWithHistory + GetDashboardStatsExtended -----------

func TestServer_GetDashboardStatsWithHistory_StripsTrustLinks(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	s.hourlyHistory[0] = StatsSample{Timestamp: 100, TrustLinks: 99}
	s.hourlyIdx = 1
	s.dailyHistory[0] = StatsSample{Timestamp: 200, TrustLinks: 99}
	s.dailyIdx = 1
	s.mu.Unlock()
	stats := s.GetDashboardStatsWithHistory()
	if stats.TotalTrustLinks != 0 {
		t.Errorf("TotalTrustLinks should be zero in public history view: %d", stats.TotalTrustLinks)
	}
	for _, h := range stats.Hourly {
		if h.TrustLinks != 0 {
			t.Errorf("Hourly TrustLinks not stripped: %+v", h)
		}
	}
	for _, d := range stats.Daily {
		if d.TrustLinks != 0 {
			t.Errorf("Daily TrustLinks not stripped: %+v", d)
		}
	}
}

func TestServer_GetDashboardStatsExtended_IncludesNetworks(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	n := &NodeInfo{ID: 1}
	n.SetLastSeen(s.now())
	s.nodes[1] = n
	s.networks[7] = &NetworkInfo{ID: 7, Name: "seven", Members: []uint32{1}}
	s.mu.Unlock()
	stats := s.GetDashboardStatsExtended()
	found := false
	for _, ns := range stats.Networks {
		if ns.ID == 7 {
			found = true
			if ns.Name != "seven" || ns.Members != 1 || ns.Online != 1 {
				t.Errorf("network entry: %+v", ns)
			}
		}
	}
	if !found {
		t.Fatal("network 7 missing from extended stats")
	}
}
