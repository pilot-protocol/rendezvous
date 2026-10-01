// SPDX-License-Identifier: AGPL-3.0-or-later

package wal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
)

func benchEncodePairs(n int) []string {
	p := make([]string, 0, n)
	for i := 0; i < n; i++ {
		p = append(p, strconv.Itoa(i)+":"+strconv.Itoa(i*3))
	}
	return p
}

func benchRawPairs(p []string) json.RawMessage {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	_ = e.Encode(p)
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return append(json.RawMessage(nil), b...)
}

func benchSnapshot(nodes int) *Snapshot {
	m := make(map[string]*SnapshotNode, nodes)
	for i := 0; i < nodes; i++ {
		m[strconv.Itoa(i)] = &SnapshotNode{
			ID:        uint32(i),
			PublicKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
			RealAddr:  "10.0.0.1:1234",
			Networks:  []uint16{0, 3},
			LastSeen:  "2026-10-01T12:00:00Z",
			Hostname:  fmt.Sprintf("host-%d", i),
			Version:   "v1.2.3",
		}
	}
	return &Snapshot{Version: 1, NextNode: uint32(nodes), NextNet: 1,
		Nodes: m, Networks: map[string]*SnapshotNet{}}
}

func benchEncodeSnap(s *Snapshot) error {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	return e.Encode(s)
}

// Re-encodes the trust list every save (old behaviour).
func BenchmarkSnapshotEncode_TrustReEncode(b *testing.B) {
	pairs := benchEncodePairs(5_000_000)
	snap := benchSnapshot(200_000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		snap.TrustPairs = benchRawPairs(pairs)
		if err := benchEncodeSnap(snap); err != nil {
			b.Fatal(err)
		}
	}
}

// Reuses the cached trust-list bytes (new behaviour).
func BenchmarkSnapshotEncode_TrustCached(b *testing.B) {
	pairs := benchEncodePairs(5_000_000)
	snap := benchSnapshot(200_000)
	snap.TrustPairs = benchRawPairs(pairs)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := benchEncodeSnap(snap); err != nil {
			b.Fatal(err)
		}
	}
}
