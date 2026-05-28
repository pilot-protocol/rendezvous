// SPDX-License-Identifier: AGPL-3.0-or-later

package replication_test

import (
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/rendezvous/replication"
	walpkg "github.com/pilot-protocol/rendezvous/wal"
)

func TestManager_PushDelta_NoSubscribersIsNoop(t *testing.T) {
	t.Parallel()
	m := replication.NewManager()
	// No panic, no error — just returns immediately.
	m.PushDelta([]walpkg.DeltaEntry{{SeqNo: 1}}, 1)
}

func TestManager_PushDelta_ReachesSubscriber(t *testing.T) {
	t.Parallel()
	m := replication.NewManager()
	primary, standby := pipeConn(t)
	m.AddSub(primary)

	go m.PushDelta([]walpkg.DeltaEntry{
		{SeqNo: 7},
	}, 7)

	msg := readFramed(t, standby)
	if msg["type"] != "replication_delta" {
		t.Errorf("type = %v, want replication_delta", msg["type"])
	}
	if got := msg["seq_no"].(float64); int(got) != 7 {
		t.Errorf("seq_no = %v, want 7", got)
	}
}

func TestManager_PushDelta_RemovesFailedSubscriber(t *testing.T) {
	t.Parallel()
	m := replication.NewManager()
	// Use a closed conn — write fails → sub removed.
	a, b := net.Pipe()
	_ = b.Close()
	m.AddSub(a)
	if got := m.SubCount(); got != 1 {
		t.Fatalf("pre: SubCount = %d", got)
	}

	// Push must finish quickly (write returns error immediately on closed pipe).
	done := make(chan struct{})
	go func() {
		m.PushDelta([]walpkg.DeltaEntry{{SeqNo: 1}}, 1)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PushDelta blocked")
	}

	if got := m.SubCount(); got != 0 {
		t.Errorf("post: SubCount = %d, want 0 (failed sub removed)", got)
	}
	_ = a.Close()
}

func TestManager_StartHeartbeat_NoSubscribersTicksOnly(t *testing.T) {
	t.Parallel()
	// StartHeartbeat blocks; we exit via the done channel.
	m := replication.NewManager()
	done := make(chan struct{})
	go m.StartHeartbeat(done)

	// Give the goroutine a moment to enter the loop, then signal exit.
	time.Sleep(50 * time.Millisecond)
	close(done)

	// Give it a beat to return; if it deadlocks the test deadline will fire.
	time.Sleep(50 * time.Millisecond)
}

func TestManager_RemoveSubBeforePush(t *testing.T) {
	t.Parallel()
	m := replication.NewManager()
	primary, _ := pipeConn(t)
	m.AddSub(primary)
	m.RemoveSub(primary)
	// Push with zero subs is a no-op.
	m.Push([]byte(`{}`))
	if got := m.SubCount(); got != 0 {
		t.Errorf("SubCount = %d, want 0", got)
	}
}
