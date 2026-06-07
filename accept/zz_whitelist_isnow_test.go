// SPDX-License-Identifier: AGPL-3.0-or-later

package accept

import (
	"testing"
	"time"
)

// TestIsWhitelistedMatchesCIDR pins the IsWhitelisted method behavior
// added to support per-connection rate-limit bypass in
// handleBinaryConn / handleTextConn. The whitelist is queried from the
// hot request path; correctness matters more than micro-optimisation,
// but the call must be free of allocations on the hot path and safe
// under concurrent reads.
func TestIsWhitelistedMatchesCIDR(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(100, time.Second, 1000)
	if err := rl.SetWhitelist([]WhitelistEntry{
		{CIDR: "10.128.0.0/9", Rate: 100000},
		{CIDR: "35.238.109.166/32", Rate: 5000},
	}); err != nil {
		t.Fatalf("SetWhitelist: %v", err)
	}

	cases := []struct {
		ip   string
		want bool
		note string
	}{
		{"10.128.0.89", true, "internal VPC, in 10.128.0.0/9"},
		{"10.255.255.255", true, "still inside 10.128.0.0/9 (upper edge)"},
		{"35.238.109.166", true, "exact /32 match"},
		{"35.238.109.167", false, "off-by-one — not in /32"},
		{"8.8.8.8", false, "public DNS, not whitelisted"},
		{"127.0.0.1", false, "loopback not whitelisted"},
		{"not-an-ip", false, "garbage input returns false, no panic"},
		{"", false, "empty input returns false, no panic"},
	}
	for _, c := range cases {
		if got := rl.IsWhitelisted(c.ip); got != c.want {
			t.Errorf("IsWhitelisted(%q) = %v, want %v (%s)", c.ip, got, c.want, c.note)
		}
	}
}

// TestIsWhitelistedEmptyWhitelistAlwaysFalse pins the no-config baseline:
// a freshly constructed RateLimiter with no whitelist entries reports
// every IP as not-whitelisted. This is the operational default —
// startup before the watcher's first apply, OR with a missing/empty
// whitelist file — and matters because false here means "subject to
// every rate-limit gate," which is the safe behaviour.
func TestIsWhitelistedEmptyWhitelistAlwaysFalse(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(100, time.Second, 1000)
	for _, ip := range []string{"10.128.0.89", "35.238.109.166", "8.8.8.8", "127.0.0.1"} {
		if rl.IsWhitelisted(ip) {
			t.Errorf("IsWhitelisted(%q) = true on empty whitelist, want false", ip)
		}
	}
}

// TestIsWhitelistedHotReloadReflectsNewEntries pins the dynamic-reload
// semantics needed by the cmd/rendezvous file watcher. The watcher
// calls SetWhitelist on every file change; IsWhitelisted must observe
// the new state immediately on the next call.
func TestIsWhitelistedHotReloadReflectsNewEntries(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(100, time.Second, 1000)

	// Initial state: nothing whitelisted.
	if rl.IsWhitelisted("10.128.0.89") {
		t.Fatalf("baseline: 10.128.0.89 should not be whitelisted yet")
	}

	// Operator writes a whitelist file; watcher applies it.
	if err := rl.SetWhitelist([]WhitelistEntry{
		{CIDR: "10.128.0.0/9", Rate: 100000},
	}); err != nil {
		t.Fatalf("SetWhitelist: %v", err)
	}
	if !rl.IsWhitelisted("10.128.0.89") {
		t.Fatalf("after add: 10.128.0.89 should be whitelisted")
	}

	// Operator removes the file; watcher clears the whitelist.
	if err := rl.SetWhitelist(nil); err != nil {
		t.Fatalf("SetWhitelist(nil): %v", err)
	}
	if rl.IsWhitelisted("10.128.0.89") {
		t.Fatalf("after clear: 10.128.0.89 should no longer be whitelisted")
	}
}
