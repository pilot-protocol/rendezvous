// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"crypto/ed25519"
	"testing"
)

func TestVerifyCached(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("heartbeat:42")
	sig := ed25519.Sign(priv, msg)

	if !VerifyCached(pub, msg, sig) {
		t.Fatal("first verify of valid signature failed")
	}
	if !VerifyCached(pub, msg, sig) {
		t.Fatal("cached verify of valid signature failed")
	}

	bad := make([]byte, len(sig))
	copy(bad, sig)
	bad[0] ^= 0xFF
	if VerifyCached(pub, msg, bad) {
		t.Fatal("tampered signature verified")
	}
	if VerifyCached(pub, msg, bad) {
		t.Fatal("tampered signature verified on repeat (failure must not be cached)")
	}

	pub2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyCached(pub2, msg, sig) {
		t.Fatal("signature verified under wrong public key despite cached success for right key")
	}

	msg2 := []byte("heartbeat:43")
	if VerifyCached(pub, msg2, sig) {
		t.Fatal("signature verified for different message despite cached success")
	}
}

func TestVerifyCachedShardReset(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("resolve:1:2")
	sig := ed25519.Sign(priv, msg)
	if !VerifyCached(pub, msg, sig) {
		t.Fatal("valid signature failed")
	}
	for i := range sigCacheShards {
		sh := &sigCacheShards[i]
		sh.mu.Lock()
		for k := range sh.m {
			sh.m[k] = struct{}{}
		}
		if sh.m != nil && len(sh.m) > sigCacheShardCap {
			t.Fatalf("shard %d exceeded cap: %d", i, len(sh.m))
		}
		sh.mu.Unlock()
	}
	if !VerifyCached(pub, msg, sig) {
		t.Fatal("re-verify after shard inspection failed")
	}
}
