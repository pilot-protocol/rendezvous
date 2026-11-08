// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"sync"
	"sync/atomic"
	"time"
)

// A trust pair is symmetric (pairKey), so it needs both nodes' consent.
// report_trust is signed by one node only: on its own it is a claim, "I
// trust that node", and the pair is written only once the other node has
// claimed the same pair too. Before this, one node's signed report_trust
// wrote the pair by itself, and a private daemon then admitted the
// reporter's streams and the registry handed it the other node's endpoint
// (security report, 2026-11-08).
//
// Claims are kept in memory only. Every daemon reports all of its trusted
// peers again on each full re-registration (pkg/daemon restoreRegistryState),
// which follows any registry restart or failover, so a claim lost with a
// restart is claimed again by the protocol itself; the pairs themselves are
// persisted as before.

const (
	// claimTTL is how long a claim waits for the other node's. A direct
	// handshake can be approved by hand and its accept reach the requester
	// days later.
	claimTTL = 30 * 24 * time.Hour

	// maxClaimsPerNode bounds the claims one node may have waiting. A
	// node's honest claims are matched within seconds of a handshake; only
	// a registry that lost its pairs sees many wait at once, and a refused
	// claim is made again on the claimer's next full re-registration.
	maxClaimsPerNode = 10000

	// claimSweepEvery is how often expired claims are swept out, so an
	// untouched one doesn't count against its node's cap for ever.
	claimSweepEvery = time.Hour
)

// claimNow is the clock claims are stamped and expired with; tests set it.
var claimNow = time.Now

// claimEntry is a pair's waiting claims: lo and hi are the pair's node IDs
// (lo < hi, as in pairKey), and fromLo/fromHi when each one claimed it
// (zero: not claimed).
type claimEntry struct {
	lo, hi         uint32
	fromLo, fromHi time.Time
}

// claimSet holds the claims waiting for the other side, sharded like the
// pair set and keyed by the pair, so both directions of one pair meet under
// one shard lock. perNode counts each node's waiting claims for the cap.
//
// Lock order: a claim shard, then perNodeMu. Never the other way.
type claimSet struct {
	shards [trustPairShards]struct {
		mu sync.Mutex
		m  map[string]*claimEntry
	}
	perNodeMu sync.Mutex
	perNode   map[uint32]int
	lastSweep atomic.Int64 // UnixNano of the last sweep
}

func newClaimSet() *claimSet {
	c := &claimSet{perNode: make(map[uint32]int)}
	for i := range c.shards {
		c.shards[i].m = make(map[string]*claimEntry)
	}
	return c
}

// claimResult is what one claim did.
type claimResult int

const (
	claimWaiting claimResult = iota // recorded; the other node hasn't claimed the pair
	claimMatched                    // the other node had claimed it: write the pair
	claimRefused                    // the claimer has maxClaimsPerNode waiting
)

// claim records that from trusts to (from != to). When to's claim on the
// pair is waiting and fresh, both are consumed and the pair is to be
// written (claimMatched).
func (c *claimSet) claim(from, to uint32) claimResult {
	key := pairKey(from, to)
	now := claimNow()
	c.maybeSweep(now)
	sh := &c.shards[trustShardIdx(key)]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	e := sh.m[key]
	if e == nil {
		e = &claimEntry{lo: min(from, to), hi: max(from, to)}
	}
	c.expireLocked(e, now)
	mine, theirs := e.sides(from)
	if !theirs.IsZero() {
		// The other node consented already: consume both claims.
		if !mine.IsZero() {
			c.count(from, -1)
		}
		c.count(to, -1)
		delete(sh.m, key)
		return claimMatched
	}
	if mine.IsZero() && !c.count(from, +1) {
		if e.empty() {
			delete(sh.m, key)
		}
		return claimRefused
	}
	*mine = now // a claim made again is renewed
	sh.m[key] = e
	return claimWaiting
}

// sides answers node's claim time on the pair and the other node's.
func (e *claimEntry) sides(node uint32) (mine, theirs *time.Time) {
	if node == e.lo {
		return &e.fromLo, &e.fromHi
	}
	return &e.fromHi, &e.fromLo
}

func (e *claimEntry) empty() bool { return e.fromLo.IsZero() && e.fromHi.IsZero() }

// withdraw drops from's waiting claim on the pair, if any, and answers
// whether there was one.
func (c *claimSet) withdraw(from, to uint32) bool {
	key := pairKey(from, to)
	sh := &c.shards[trustShardIdx(key)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := sh.m[key]
	if e == nil {
		return false
	}
	c.expireLocked(e, claimNow())
	mine, _ := e.sides(from)
	had := !mine.IsZero()
	if had {
		*mine = time.Time{}
		c.count(from, -1)
	}
	if e.empty() {
		delete(sh.m, key)
	}
	return had
}

// waiting answers whether from has a fresh claim waiting on the pair.
func (c *claimSet) waiting(from, to uint32) bool {
	key := pairKey(from, to)
	sh := &c.shards[trustShardIdx(key)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := sh.m[key]
	if e == nil {
		return false
	}
	c.expireLocked(e, claimNow())
	if e.empty() {
		delete(sh.m, key)
		return false
	}
	mine, _ := e.sides(from)
	return !mine.IsZero()
}

// size is how many claims are waiting, for metrics and tests.
func (c *claimSet) size() int {
	n := 0
	for i := range c.shards {
		sh := &c.shards[i]
		sh.mu.Lock()
		for _, e := range sh.m {
			if !e.fromLo.IsZero() {
				n++
			}
			if !e.fromHi.IsZero() {
				n++
			}
		}
		sh.mu.Unlock()
	}
	return n
}

// expireLocked clears e's claims older than claimTTL. Its shard lock held.
func (c *claimSet) expireLocked(e *claimEntry, now time.Time) {
	if !e.fromLo.IsZero() && now.Sub(e.fromLo) > claimTTL {
		e.fromLo = time.Time{}
		c.count(e.lo, -1)
	}
	if !e.fromHi.IsZero() && now.Sub(e.fromHi) > claimTTL {
		e.fromHi = time.Time{}
		c.count(e.hi, -1)
	}
}

// maybeSweep starts a sweep when the last one is claimSweepEvery old.
func (c *claimSet) maybeSweep(now time.Time) {
	last := c.lastSweep.Load()
	if now.UnixNano()-last < int64(claimSweepEvery) || !c.lastSweep.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	go c.sweep(now)
}

// sweep drops every claim older than claimTTL.
func (c *claimSet) sweep(now time.Time) {
	for i := range c.shards {
		sh := &c.shards[i]
		sh.mu.Lock()
		for key, e := range sh.m {
			c.expireLocked(e, now)
			if e.empty() {
				delete(sh.m, key)
			}
		}
		sh.mu.Unlock()
	}
}

// count moves node's waiting-claim count by d; an increase past
// maxClaimsPerNode is refused (false). A claim shard lock may be held.
func (c *claimSet) count(node uint32, d int) bool {
	c.perNodeMu.Lock()
	defer c.perNodeMu.Unlock()
	n := c.perNode[node] + d
	if d > 0 && n > maxClaimsPerNode {
		return false
	}
	if n <= 0 {
		delete(c.perNode, node)
	} else {
		c.perNode[node] = n
	}
	return true
}
