// SPDX-License-Identifier: AGPL-3.0-or-later

package wal

import (
	"bytes"
	"encoding/json"
	"testing"

	wire "github.com/pilot-protocol/common/registry/wire"
	auditpkg "github.com/pilot-protocol/rendezvous/audit"
	dashpkg "github.com/pilot-protocol/rendezvous/dashboard"
	membpkg "github.com/pilot-protocol/rendezvous/membership"
	trustpkg "github.com/pilot-protocol/rendezvous/trust"
)

func richSnapshot() *Snapshot {
	return &Snapshot{
		Version:  1,
		NextNode: 42,
		NextNet:  3,
		Nodes: SnapshotNodes{
			"1": {ID: 1, Owner: "o1", PublicKey: "k1", RealAddr: "10.0.0.1:1", Networks: []uint16{0, 3}, LastSeen: "2026-10-01T12:00:00Z", Hostname: "h1", Tags: []string{"a"}, Version: "v1"},
			"2": {ID: 2, PublicKey: `q"b\c`, Networks: []uint16{}, Badge: "b", KeyRotCount: 2, RelayOnly: true},
		},
		Networks: map[string]*SnapshotNet{
			"0": {ID: 0, Name: "n0", JoinRule: "open", Members: []uint32{1, 2},
				MemberRoles: map[string]string{"1": "owner"}, MemberTags: map[string][]string{"1": {"x"}},
				Policy: &membpkg.NetworkPolicy{MaxMembers: 5, AllowedPorts: []uint16{80}}, Rules: &wire.NetworkRules{},
				ExprPolicy: json.RawMessage(`{"a":1}`), Created: "2026-01-01T00:00:00Z"},
		},
		TrustPairs: json.RawMessage(`["1:2","3:4"]`),
		PubKeyIdx:  map[string]uint32{"k1": 1, "k2": 2},
		HandshakeInbox: map[string][]*trustpkg.HandshakeRelayMsg{
			"1": {{}},
		},
		HandshakeResponses: map[string][]*trustpkg.HandshakeResponseMsg{
			"1": {{}},
		},
		InviteInbox: map[string][]*membpkg.NetworkInvite{
			"1": {{}},
		},
		TotalRequests:     99,
		TotalNodes:        2,
		OnlineNodes:       1,
		TrustLinks:        2,
		UniqueTags:        1,
		TaskExecutors:     1,
		StartTime:         "2026-01-01T00:00:00Z",
		RestartEvents:     []int64{1, 2},
		DowntimeIntervals: [][2]int64{{1, 2}},
		LastHeartbeat:     123,
		ProbeStates:       map[string]*dashpkg.ProbeState{"p": {}},
		HourlyHistory:     []dashpkg.StatsSample{{}},
		DailyHistory:      []dashpkg.StatsSample{{}},
		NetHourlyHistory:  map[string][]dashpkg.NetworkSampleEntry{"0": {{}}},
		NetDailyHistory:   map[string][]dashpkg.NetworkSampleEntry{"0": {{}}},
		AuditLog:          []auditpkg.Entry{{}},
		IDPConfig:         &wire.BlueprintIdentityProvider{},
		AuditExportCfg:    &wire.BlueprintAuditExport{},
		RBACPreAssign:     map[string][]wire.BlueprintRole{"0": {{}}},
		Term:              7,
	}
}

func stdEncodeSnapshot(t testing.TB, s *Snapshot) []byte {
	t.Helper()
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(s); err != nil {
		t.Fatalf("encode: %v", err)
	}
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return b
}

func TestAppendSnapshot_ByteIdenticalFull(t *testing.T) {
	for _, s := range []*Snapshot{richSnapshot(), {}} {
		got := AppendSnapshot(nil, s)
		want := stdEncodeSnapshot(t, s)
		if !bytes.Equal(got, want) {
			n := min(len(got), len(want))
			i := 0
			for i < n && got[i] == want[i] {
				i++
			}
			lo := max(0, i-40)
			t.Fatalf("mismatch at %d:\n got=%q\nwant=%q", i, got[lo:min(i+40, len(got))], want[lo:min(i+40, len(want))])
		}
	}
}

func BenchmarkAppendSnapshot_Std(b *testing.B) {
	s := &Snapshot{Version: 1, NextNode: 200000, NextNet: 1,
		Nodes: sampleNodes(200_000), Networks: map[string]*SnapshotNet{},
		TrustPairs: json.RawMessage(`["1:2"]`),
		PubKeyIdx:  map[string]uint32{"a": 1}, TotalNodes: 200000}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = stdEncodeSnapshot(b, s)
	}
}

func BenchmarkAppendSnapshot_Fast(b *testing.B) {
	s := &Snapshot{Version: 1, NextNode: 200000, NextNet: 1,
		Nodes: sampleNodes(200_000), Networks: map[string]*SnapshotNet{},
		TrustPairs: json.RawMessage(`["1:2"]`),
		PubKeyIdx:  map[string]uint32{"a": 1}, TotalNodes: 200000}
	buf := make([]byte, 0, 32<<20)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = AppendSnapshot(buf[:0], s)
	}
}
