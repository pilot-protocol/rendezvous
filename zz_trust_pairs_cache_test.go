// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func stdEncodeStrings(t *testing.T, s []string) []byte {
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

// The cached bytes must be byte-identical to encoding the slice directly —
// load() re-encodes to verify the checksum.
func TestTrustPairsCache_ByteIdentical(t *testing.T) {
	var c trustPairsEncodeCache
	pairs := []string{`1:2`, `x"y`, `a<b>&c`, "unicode-雪", `back\slash`, ""}
	for i := 0; i < 50000; i++ {
		pairs = append(pairs, fmt.Sprintf("%d:%d", i, i*3))
	}
	got, err := c.encode(1, func() []string { return pairs }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	want := stdEncodeStrings(t, pairs)
	if !bytes.Equal(got, want) {
		t.Fatalf("cache encode differs from standard encoding")
	}
}

func TestTrustPairsCache_ReuseAndInvalidate(t *testing.T) {
	var c trustPairsEncodeCache
	var calls atomic.Int64
	pairs := []string{"1:2", "3:4"}
	fn := func() []string { calls.Add(1); return pairs }

	b1, _ := c.encode(7, fn, time.Minute)
	if calls.Load() != 1 {
		t.Fatalf("first call should encode, calls=%d", calls.Load())
	}
	b2, _ := c.encode(7, fn, time.Minute)
	if calls.Load() != 1 {
		t.Fatalf("same revision must reuse cache, calls=%d", calls.Load())
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("cached bytes changed on reuse")
	}

	// Revision change forces a re-encode, and the result is identical for
	// identical data.
	b3, _ := c.encode(8, fn, time.Minute)
	if calls.Load() != 2 {
		t.Fatalf("revision change must re-encode, calls=%d", calls.Load())
	}
	if !bytes.Equal(b1, b3) {
		t.Fatalf("same data encoded differently across revisions")
	}

	// TTL expiry forces a re-encode even with an unchanged revision.
	if _, err := c.encode(9, fn, time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	_, _ = c.encode(9, fn, time.Nanosecond)
	if calls.Load() != 4 {
		t.Fatalf("TTL expiry must re-encode, calls=%d", calls.Load())
	}
}

func TestTrustPairsCache_EmptyReturnsNil(t *testing.T) {
	var c trustPairsEncodeCache
	b, err := c.encode(1, func() []string { return nil }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if b != nil {
		t.Fatalf("empty pairs must return nil (omitempty), got %q", b)
	}
	// And a subsequent non-empty set must not be masked by the nil cache.
	b2, _ := c.encode(2, func() []string { return []string{"1:2"} }, time.Minute)
	if string(b2) != `["1:2"]` {
		t.Fatalf("got %q, want [\"1:2\"]", b2)
	}
}
