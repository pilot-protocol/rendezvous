// SPDX-License-Identifier: AGPL-3.0-or-later

package wal

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Native fuzz targets asserting byte-parity with encoding/json(SetEscapeHTML=false).
// Run: go test ./wal/ -run '^$' -fuzz=FuzzAppendJSONString -fuzztime=60s (etc.)

func FuzzAppendJSONString(f *testing.F) {
	for _, s := range []string{
		"", "hello", `q"b`, `back\slash`, "a<b>&c", "x\u2028y\u2029z",
		"unicode-雪", "\x00\x01\x1f", "tab\tnewline\n", "\x7f", "\xff\xfe-invalid",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := appendJSONString(nil, s)
		var buf bytes.Buffer
		e := json.NewEncoder(&buf)
		e.SetEscapeHTML(false)
		if err := e.Encode(s); err != nil {
			t.Fatalf("std encode: %v", err)
		}
		want := buf.Bytes()
		if len(want) > 0 && want[len(want)-1] == '\n' {
			want = want[:len(want)-1]
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("escaping mismatch for %q:\n got=%q\nwant=%q", s, got, want)
		}
		if !json.Valid(got) {
			t.Fatalf("invalid JSON for %q: %q", s, got)
		}
	})
}

func FuzzSnapshotNodes_MarshalParity(f *testing.F) {
	f.Add("1", "own", "pub", "10.0.0.1:1", "host", "a,b", "/lan", "v1", "badge", uint32(1), 2, true, true, true)
	// funky hostname / strings seeds
	f.Add(`a"b`, "own", "pub", "10.0.0.1:1", `a\b`, "a,b", "/lan", "v1", "b", uint32(2), 0, false, false, false)
	f.Add("x\u2028y", "own", "pub", "10.0.0.1:1", "héllo.😀", "a,b", "/lan", "v1", "b", uint32(3), 0, false, false, false)
	f.Add("<h>&'", "own", "pub", "10.0.0.1:1", "\x00\x1f\x7f", "a,b", "/lan", "v1", "b", uint32(4), 0, false, false, false)
	f.Add("日本.рф", "own", "pub", "10.0.0.1:1", "USER@Host:/x?y", "a,b", "/lan", "v1", "b", uint32(5), 0, false, false, false)
	f.Fuzz(func(t *testing.T, key, owner, pub, addr, host, tags, lan, version, badge string, id uint32, rot int, public, relay, task bool) {
		var tagList, lanList []string
		if tags != "" {
			tagList = strings.Split(tags, ",")
		}
		if lan != "" {
			lanList = strings.Split(lan, ",")
		}
		m := SnapshotNodes{
			key: {ID: id, Owner: owner, PublicKey: pub, RealAddr: addr, Hostname: host,
				Tags: tagList, LANAddrs: lanList, Version: version, Badge: badge,
				KeyRotCount: rot, Public: public, RelayOnly: relay, TaskExec: task},
		}
		if key2 := key + "2"; key2 != key {
			m[key2] = &SnapshotNode{}
		}
		got := m.appendTo(nil)
		want := encRaw(t, map[string]*SnapshotNode(m))
		if !bytes.Equal(got, want) {
			n := min(len(got), len(want))
			i := 0
			for i < n && got[i] == want[i] {
				i++
			}
			lo := max(0, i-30)
			t.Fatalf("mismatch at %d for key=%q:\n got=%q\nwant=%q", i, key, got[lo:min(i+30, len(got))], want[lo:min(i+30, len(want))])
		}
	})
}

func FuzzAppendSnapshot_MarshalParity(f *testing.F) {
	f.Add("own", "pub", "host", "2026-01-01T00:00:00Z", "start", uint32(1), int64(5), uint64(2), true)
	f.Add(`a"b`, "pub", `h\st`, "x\u2028y", "héllo.😀", uint32(2), int64(0), uint64(0), false)
	f.Add("\x00\x1f", "pub", "日本.рф", "t\tb", "<h>&'", uint32(3), int64(-1), uint64(7), false)
	f.Fuzz(func(t *testing.T, owner, pub, host, lastseen, start string, id uint32, hb int64, term uint64, omit bool) {
		s := &Snapshot{
			Version:    1,
			NextNode:   id,
			NextNet:    2,
			Nodes:      SnapshotNodes{"1": {ID: id, Owner: owner, PublicKey: pub, Hostname: host, LastSeen: lastseen, Networks: []uint16{0}, Tags: []string{owner, pub}}},
			Networks:   map[string]*SnapshotNet{},
			TrustPairs: json.RawMessage(`["1:2"]`),
			PubKeyIdx:  map[string]uint32{pub: id},
			StartTime:  start, LastHeartbeat: hb, Term: term,
			TotalNodes: 1, OnlineNodes: 1, TrustLinks: 2,
		}
		if omit {
			s.TrustPairs = nil
			s.PubKeyIdx = nil
			s.StartTime = ""
			s.Term = 0
			s.TotalNodes, s.OnlineNodes, s.TrustLinks = 0, 0, 0
		}
		got := AppendSnapshot(nil, s)
		want := stdEncodeSnapshot(t, s)
		if !bytes.Equal(got, want) {
			n := min(len(got), len(want))
			i := 0
			for i < n && got[i] == want[i] {
				i++
			}
			lo := max(0, i-30)
			t.Fatalf("mismatch at %d:\n got=%q\nwant=%q", i, got[lo:min(i+30, len(got))], want[lo:min(i+30, len(want))])
		}
		if !json.Valid(got) {
			t.Fatalf("invalid JSON: %q", got)
		}
	})
}
