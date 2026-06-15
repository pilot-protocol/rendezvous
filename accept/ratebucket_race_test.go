package accept

import (
	"sync"
	"testing"
	"time"
)

// TestGlobalRateBucket_ConcurrentAllow is a race regression test: many
// goroutines calling allow() concurrently must not race on the bucket's
// token/lastFill state. Run with -race. Before the mutex was added this
// failed reliably under the race detector (read-modify-write on tokens).
func TestGlobalRateBucket_ConcurrentAllow(t *testing.T) {
	t.Parallel()
	gb := newGlobalRateBucket(1000)
	var wg sync.WaitGroup
	base := time.Now()
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				gb.allow(base.Add(time.Duration(j) * time.Microsecond))
			}
		}()
	}
	wg.Wait()
}
