// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import "sync"

// trustPairShards is the shard count for the trust-pair set. A power of two
// so the index is a mask. Sized well above the registry's request
// concurrency so report_trust writes for different pairs proceed in
// parallel instead of serialising on one lock — the report_trust flood
// during a fleet reconverge was starving IsTrusted / check_trust readers.
const trustPairShards = 256

func trustShardIdx(key string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return h & (trustPairShards - 1)
}

// trustPairSet is a sharded set of canonical "min:max" trust-pair keys.
// Each shard carries its own RWMutex.
type trustPairSet struct {
	shards [trustPairShards]struct {
		mu sync.RWMutex
		m  map[string]bool
	}
}

func newTrustPairSet() *trustPairSet {
	s := &trustPairSet{}
	for i := range s.shards {
		s.shards[i].m = make(map[string]bool)
	}
	return s
}

func (s *trustPairSet) has(key string) bool {
	sh := &s.shards[trustShardIdx(key)]
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	return sh.m[key]
}

func (s *trustPairSet) add(key string) {
	sh := &s.shards[trustShardIdx(key)]
	sh.mu.Lock()
	sh.m[key] = true
	sh.mu.Unlock()
}

// remove deletes key, returning true if it was present.
func (s *trustPairSet) remove(key string) bool {
	sh := &s.shards[trustShardIdx(key)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if !sh.m[key] {
		return false
	}
	delete(sh.m, key)
	return true
}

func (s *trustPairSet) count() int {
	n := 0
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.RLock()
		n += len(sh.m)
		sh.mu.RUnlock()
	}
	return n
}

func (s *trustPairSet) keys() []string {
	out := make([]string, 0)
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.RLock()
		for k := range sh.m {
			out = append(out, k)
		}
		sh.mu.RUnlock()
	}
	return out
}

// addUnlocked inserts without locking — for startup restore before serving.
func (s *trustPairSet) addUnlocked(key string) {
	s.shards[trustShardIdx(key)].m[key] = true
}
