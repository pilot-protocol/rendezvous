// SPDX-License-Identifier: AGPL-3.0-or-later

package breakers

import (
	"encoding/json"
	"log/slog"
	"os"
	"time"
)

// fileEntry is the on-disk JSON shape for a single breaker row.
// Operator-edited; structured-object form was chosen over a flat
// "name": "state" map so reasons can be supplied without ambiguity
// and additional metadata (UpdatedAt etc.) can ride along later
// without a format break.
type fileEntry struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// Watch polls path for mtime+size changes every interval and
// atomically reloads breakers into the Manager when the file
// changes.
//
// Operational contract — pinned by tests; identical in spirit to
// the rate-limit whitelist watcher:
//
//   - Never blocks startup, the registry, the beacon, or any request
//     path. Runs in its own goroutine; the only state it mutates is
//     the Manager, via Replace.
//   - Fail-open: missing file is fine (no breakers installed; every
//     name returns Allow=closed via Manager's default-allow). Parse,
//     stat, or apply errors are logged at WARN and leave whatever
//     map is currently installed in place.
//   - Idempotent: same file content (unchanged mtime + size) is a
//     no-op.
//   - File removal reverts the Manager to an empty map on the next
//     tick (logged INFO).
//
// File format — JSON object, name → {state, reason?}:
//
//	{
//	  "registry.register":       {"state": "closed"},
//	  "beacon.punch":            {"state": "open",     "reason": "maintenance"},
//	  "dashboard.public_stats":  {"state": "half_open","reason": "soaking pre-lockdown"}
//	}
//
// state must be one of "closed", "half_open", "open" (case-insensitive,
// with the same aliases ParseState accepts). reason is operator-facing
// free text surfaced in error messages when a breaker is open.
func Watch(
	m *Manager,
	path string,
	interval time.Duration,
	stop <-chan struct{},
) {
	var lastMtime time.Time
	var lastSize int64

	apply := func() {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				if !lastMtime.IsZero() || lastSize != 0 {
					slog.Info("breakers file removed; reverting to empty map", "path", path)
					m.Replace(nil)
					lastMtime = time.Time{}
					lastSize = 0
				}
				return
			}
			slog.Warn("breakers stat failed; leaving previous map in place",
				"path", path, "err", err)
			return
		}
		if info.ModTime().Equal(lastMtime) && info.Size() == lastSize {
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("breakers read failed; leaving previous map in place",
				"path", path, "err", err)
			return
		}
		var entries map[string]fileEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			slog.Warn("breakers parse failed; leaving previous map in place",
				"path", path, "err", err)
			return
		}
		next := make(map[string]*Breaker, len(entries))
		for name, e := range entries {
			st, perr := ParseState(e.State)
			if perr != nil {
				slog.Warn("breakers entry has unrecognised state; skipping",
					"path", path, "name", name, "raw_state", e.State, "err", perr)
				continue
			}
			next[name] = &Breaker{
				Name:        name,
				State:       st,
				StateString: st.String(),
				Reason:      e.Reason,
				UpdatedAt:   info.ModTime(),
			}
		}
		m.Replace(next)
		lastMtime = info.ModTime()
		lastSize = info.Size()
		slog.Info("breakers reloaded",
			"path", path, "count", len(next), "mtime", lastMtime.UTC())
	}

	apply() // initial load
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			apply()
		}
	}
}
