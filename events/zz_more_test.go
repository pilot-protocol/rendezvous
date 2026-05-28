// SPDX-License-Identifier: AGPL-3.0-or-later

package events_test

import (
	"testing"
	"time"

	"github.com/pilot-protocol/rendezvous/events"
)

func TestBus_PublishDropsWhenSubscriberFull(t *testing.T) {
	t.Parallel()
	b := events.NewInProcessBus(1) // 1-slot buffer
	ch, cancel := b.Subscribe("flood")
	defer cancel()

	// Fill buffer + try to flood more — the publisher must not block.
	for i := 0; i < 100; i++ {
		b.Publish(events.Event{Type: "flood"})
	}
	// We should get at least one event (filled the buffer).
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("subscriber received nothing")
	}
}

func TestBus_UnsubscribeIdempotent(t *testing.T) {
	t.Parallel()
	b := events.NewInProcessBus(4)
	_, cancel := b.Subscribe("topic")
	cancel()
	cancel() // second cancel is a no-op (sync.Once protected)
}

func TestBus_MultipleSubscribersIndependent(t *testing.T) {
	t.Parallel()
	b := events.NewInProcessBus(4)
	ch1, c1 := b.Subscribe("a.*")
	ch2, c2 := b.Subscribe("b.*")
	defer c1()
	defer c2()

	b.Publish(events.Event{Type: "a.x"})
	b.Publish(events.Event{Type: "b.y"})

	select {
	case got := <-ch1:
		if got.Type != "a.x" {
			t.Errorf("ch1 got %s", got.Type)
		}
	case <-time.After(time.Second):
		t.Error("ch1 timeout")
	}
	select {
	case got := <-ch2:
		if got.Type != "b.y" {
			t.Errorf("ch2 got %s", got.Type)
		}
	case <-time.After(time.Second):
		t.Error("ch2 timeout")
	}
}

func TestBus_PatternMismatchDropsEvent(t *testing.T) {
	t.Parallel()
	b := events.NewInProcessBus(4)
	ch, cancel := b.Subscribe("foo.*")
	defer cancel()

	b.Publish(events.Event{Type: "bar.x"}) // doesn't match

	select {
	case got := <-ch:
		t.Errorf("unexpected delivery: %s", got.Type)
	case <-time.After(50 * time.Millisecond):
		// Good — pattern mismatch dropped the event.
	}
}
