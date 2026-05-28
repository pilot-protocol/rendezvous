// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"testing"
	"time"

	dashpkg "github.com/pilot-protocol/rendezvous/dashboard"
)

func TestReleasePoller_NoBannerYieldsNil(t *testing.T) {
	t.Parallel()
	p := newReleasePoller("owner/repo")
	if got := p.current(); got != nil {
		t.Errorf("fresh poller: current = %v, want nil", got)
	}
}

func TestReleasePoller_FreshBannerReturned(t *testing.T) {
	t.Parallel()
	p := newReleasePoller("owner/repo")
	p.latest.Store(&dashpkg.ReleaseBanner{
		Version:     "v1.2.3",
		PublishedAt: time.Now().Unix(),
	})
	got := p.current()
	if got == nil {
		t.Fatal("fresh banner: current = nil")
	}
	if got.Version != "v1.2.3" {
		t.Errorf("Version = %q", got.Version)
	}
}

func TestReleasePoller_OldBannerReturnsNil(t *testing.T) {
	t.Parallel()
	p := newReleasePoller("owner/repo")
	// Set PublishedAt to 48 hours ago — past the 36h window.
	p.latest.Store(&dashpkg.ReleaseBanner{
		Version:     "v0.0.1",
		PublishedAt: time.Now().Add(-48 * time.Hour).Unix(),
	})
	if got := p.current(); got != nil {
		t.Errorf("stale banner: current = %v, want nil", got)
	}
}
