// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"testing"
)

// The snapshot encode path streams JSON straight to disk (no pooled buffer).
// trimTrailingNewlineWriter withholds the encoder's trailing '\n' so the
// checksum covers `{...}` exactly as load() recomputes it.

func TestTrimTrailingNewlineWriterDropsFinalByte(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := &trimTrailingNewlineWriter{w: &buf}
	if _, err := w.Write([]byte(`{"a":1}` + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, want := buf.String(), `{"a":1}`; got != want {
		t.Fatalf("body = %q, want %q (trailing newline must be withheld)", got, want)
	}
}

func TestTrimTrailingNewlineWriterAcrossChunks(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := &trimTrailingNewlineWriter{w: &buf}
	for _, chunk := range []string{`{"a"`, `:1}`, "\n"} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatalf("write %q: %v", chunk, err)
		}
	}
	if got, want := buf.String(), `{"a":1}`; got != want {
		t.Fatalf("body = %q, want %q (streaming across chunks)", got, want)
	}
}

func TestTrimTrailingNewlineWriterEmptyWrite(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := &trimTrailingNewlineWriter{w: &buf}
	if n, err := w.Write(nil); n != 0 || err != nil {
		t.Fatalf("empty write = (%d, %v), want (0, nil)", n, err)
	}
	if buf.Len() != 0 {
		t.Fatalf("buffer = %q, want empty", buf.String())
	}
}

func TestShouldScavengeGate(t *testing.T) {
	lastScavengeMs.Store(0)

	if shouldScavenge(scavengeMinSnapshot-1, scavengeIntervalMs*10) {
		t.Fatal("scavenge fired for a small snapshot")
	}

	base := int64(scavengeIntervalMs * 10)
	if !shouldScavenge(scavengeMinSnapshot, base) {
		t.Fatal("scavenge did not fire for a large snapshot after the interval")
	}
	if shouldScavenge(scavengeMinSnapshot, base+1) {
		t.Fatal("scavenge fired again inside the rate-limit window")
	}
	if !shouldScavenge(scavengeMinSnapshot, base+scavengeIntervalMs) {
		t.Fatal("scavenge did not fire again after the interval elapsed")
	}
}
