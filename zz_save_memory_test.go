// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import "testing"

func TestPutSaveBufDropsOversized(t *testing.T) {
	big := make([]byte, 0, maxPooledSaveBuf+1)
	putSaveBuf(&big)
	got := flushSaveBufPool.Get().(*[]byte)
	if cap(*got) > maxPooledSaveBuf {
		t.Fatalf("pool retained an oversized buffer: cap=%d", cap(*got))
	}
}

func TestPutSaveBufKeepsNormal(t *testing.T) {
	buf := make([]byte, 0, 1<<20)
	putSaveBuf(&buf)
	got := flushSaveBufPool.Get().(*[]byte)
	if cap(*got) < 1<<20 {
		t.Fatalf("normal-sized buffer was not pooled: cap=%d", cap(*got))
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
