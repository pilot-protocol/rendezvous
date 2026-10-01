// SPDX-License-Identifier: AGPL-3.0-or-later

package wal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
)

type wrapFast struct {
	N SnapshotNodes `json:"n"`
}
type wrapStd struct {
	N map[string]*SnapshotNode `json:"n"`
}

func encRaw(t testing.TB, v interface{}) []byte {
	t.Helper()
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		t.Fatalf("encode: %v", err)
	}
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return b
}

func sampleNodes(n int) SnapshotNodes {
	m := make(SnapshotNodes, n)
	for i := 0; i < n; i++ {
		m[strconv.Itoa(i)] = &SnapshotNode{
			ID:        uint32(i),
			Owner:     fmt.Sprintf("owner-%d", i),
			PublicKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
			RealAddr:  "10.0.0.1:1234",
			Networks:  []uint16{0, 3},
			LastSeen:  "2026-10-01T12:00:00Z",
			Hostname:  fmt.Sprintf("host-%d", i),
			Version:   "v1.2.3",
		}
	}
	return m
}

// The hand-written encoder must be byte-identical to encoding/json — load()
// re-encodes the struct to verify the snapshot checksum.
func TestSnapshotNodes_MarshalByteIdentical(t *testing.T) {
	m := sampleNodes(8000)
	m["zz"] = &SnapshotNode{ID: 1, PublicKey: `q"b\c`, Hostname: "a<b>&c", LastSeen: "x\u2028y", Tags: []string{"t\t1", "unicode-雪", ""}}
	m["nilnode"] = nil
	m["empty"] = &SnapshotNode{ID: 2, PublicKey: "", Networks: []uint16{}}

	got := encRaw(t, wrapFast{N: m})
	want := encRaw(t, wrapStd{N: map[string]*SnapshotNode(m)})
	if !bytes.Equal(got, want) {
		n := min(len(got), len(want))
		i := 0
		for i < n && got[i] == want[i] {
			i++
		}
		lo := max(0, i-30)
		t.Fatalf("mismatch at byte %d:\n got=%q\nwant=%q", i, got[lo:min(i+30, len(got))], want[lo:min(i+30, len(want))])
	}
}

func TestSnapshotNodes_NilAndEmpty(t *testing.T) {
	if got := encRaw(t, wrapFast{N: nil}); string(got) != `{"n":null}` {
		t.Fatalf("nil = %s, want {\"n\":null}", got)
	}
	if got := encRaw(t, wrapFast{N: SnapshotNodes{}}); string(got) != `{"n":{}}` {
		t.Fatalf("empty = %s, want {\"n\":{}}", got)
	}
}

func BenchmarkSnapshotNodes_Std(b *testing.B) {
	m := map[string]*SnapshotNode(sampleNodes(200_000))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = encRaw(b, m)
	}
}

func BenchmarkSnapshotNodes_Fast(b *testing.B) {
	m := sampleNodes(200_000)
	buf := make([]byte, 0, 32<<20)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = m.appendTo(buf[:0])
	}
}
