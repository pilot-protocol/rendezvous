// SPDX-License-Identifier: AGPL-3.0-or-later

package accept

import (
	"testing"
	"time"
)

// TestWhitelistElevatesRateForMatchedCIDR pins the core contract: an IP
// inside a whitelist CIDR gets the elevated rate; a non-matched IP gets
// the default rate.
func TestWhitelistElevatesRateForMatchedCIDR(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(2, time.Second, 100)
	clock := time.Unix(1_700_000_000, 0)
	rl.SetClock(func() time.Time { return clock })

	if err := rl.SetWhitelist([]WhitelistEntry{
		{CIDR: "10.0.0.0/24", Rate: 10},
	}); err != nil {
		t.Fatalf("SetWhitelist: %v", err)
	}

	// Whitelisted IP must allow up to 10 requests before denial.
	for i := 0; i < 10; i++ {
		if !rl.Allow("10.0.0.5") {
			t.Fatalf("whitelisted IP denied at request %d (want 10)", i+1)
		}
	}
	if rl.Allow("10.0.0.5") {
		t.Fatal("whitelisted IP allowed past elevated rate (10)")
	}

	// Non-whitelisted IP keeps the default rate of 2.
	if !rl.Allow("203.0.113.1") || !rl.Allow("203.0.113.1") {
		t.Fatal("default IP denied within default rate")
	}
	if rl.Allow("203.0.113.1") {
		t.Fatal("default IP allowed past default rate (2)")
	}
}

// TestWhitelistSetRejectsBadInput guards the fail-closed contract.
func TestWhitelistSetRejectsBadInput(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(5, time.Second, 100)
	if err := rl.SetWhitelist([]WhitelistEntry{
		{CIDR: "10.0.0.0/24", Rate: 100},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	originalSize := rl.WhitelistSize()

	cases := []struct {
		name    string
		entries []WhitelistEntry
	}{
		{"non-positive rate", []WhitelistEntry{{CIDR: "10.0.0.0/24", Rate: 0}}},
		{"empty CIDR", []WhitelistEntry{{CIDR: "", Rate: 100}}},
		{"malformed CIDR", []WhitelistEntry{{CIDR: "not-a-cidr", Rate: 100}}},
		{"missing slash on garbage", []WhitelistEntry{{CIDR: "300.300.300.300", Rate: 100}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := rl.SetWhitelist(tc.entries); err == nil {
				t.Fatal("want error, got nil")
			}
			if got := rl.WhitelistSize(); got != originalSize {
				t.Fatalf("whitelist mutated after failed SetWhitelist: size = %d, want %d (fail-closed contract)", got, originalSize)
			}
		})
	}
}

// TestWhitelistBypassesMaxBucketsCap pins the second contract:
// whitelisted IPs always get a bucket slot even when the map is at
// maxBuckets. Operator-set trust signal — TCP source IPs cannot be
// spoofed.
func TestWhitelistBypassesMaxBucketsCap(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(5, time.Second, 2) // cap = 2 IPs
	clock := time.Unix(1_700_000_000, 0)
	rl.SetClock(func() time.Time { return clock })

	if err := rl.SetWhitelist([]WhitelistEntry{
		{CIDR: "10.0.0.5/32", Rate: 50},
	}); err != nil {
		t.Fatalf("SetWhitelist: %v", err)
	}

	// Fill the cap with non-whitelisted IPs.
	if !rl.Allow("203.0.113.1") || !rl.Allow("203.0.113.2") {
		t.Fatal("seed: non-whitelisted IPs denied")
	}
	if got := rl.BucketCount(); got != 2 {
		t.Fatalf("post-seed: bucket count = %d, want 2", got)
	}

	// Another non-whitelisted IP must be denied (cap full, all fresh).
	if rl.Allow("203.0.113.3") {
		t.Fatal("non-whitelisted IP admitted past maxBuckets cap")
	}

	// Whitelisted IP must still get through even though map is full.
	if !rl.Allow("10.0.0.5") {
		t.Fatal("whitelisted IP denied at maxBuckets cap — bypass contract broken")
	}
}

// TestWhitelistAcceptorWiring exercises the public API surface that
// operators would call — Acceptor.SetRateLimitWhitelist forwards to
// the internal RateLimiter.
func TestWhitelistAcceptorWiring(t *testing.T) {
	t.Parallel()

	a := NewAcceptor(100, nil)
	if got := a.RateLimitWhitelistSize(); got != 0 {
		t.Fatalf("default whitelist size = %d, want 0", got)
	}
	if err := a.SetRateLimitWhitelist([]WhitelistEntry{
		{CIDR: "10.0.0.0/8", Rate: 1000},
		{CIDR: "192.168.1.5", Rate: 500}, // bare IP auto-promoted to /32
	}); err != nil {
		t.Fatalf("SetRateLimitWhitelist: %v", err)
	}
	if got := a.RateLimitWhitelistSize(); got != 2 {
		t.Fatalf("size after set = %d, want 2", got)
	}
}
