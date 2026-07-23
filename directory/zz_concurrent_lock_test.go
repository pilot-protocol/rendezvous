// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"sync"
	"testing"
	"time"
)

func TestConcurrentReadHandlersNoRaceOnNodeFields(t *testing.T) {
	st := newTestStore(t)
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, Public: true, Hostname: "h42", RealAddr: "1.2.3.4:5000", Networks: []uint16{0}}
	st.hostnameIdx["h42"] = 42
	st.mu.Unlock()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		pub := true
		addr := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			st.mu.Lock()
			sh := st.nodeShard(42)
			sh.Lock()
			pub = !pub
			addr++
			n := st.nodes[42]
			n.Public = pub
			n.RealAddr = "9.9.9." + string(rune('0'+addr%10)) + ":6000"
			sh.Unlock()
			st.mu.Unlock()
		}
	}()

	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = st.HandleResolveHostname(map[string]interface{}{"hostname": "h42"})
				_, _ = st.HandleLookup(map[string]interface{}{"node_id": float64(42)})
			}
		}()
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}
