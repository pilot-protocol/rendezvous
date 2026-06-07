// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"github.com/pilot-protocol/rendezvous/accept"
)

// whitelistFileEntry is the on-disk shape of one rate-limit whitelist
// row. Matches accept.WhitelistEntry but lives here so the operator-
// facing JSON format is decoupled from the internal type.
type whitelistFileEntry struct {
	CIDR string `json:"cidr"`
	Rate int    `json:"rate"`
}

// watchRateLimitWhitelist polls path for mtime/size changes every
// interval and atomically reloads the whitelist via set() when the
// file changes.
//
// Operational contract:
//   - Never blocks any other part of the process. Runs in its own
//     goroutine and the only state it touches is the rate-limiter,
//     via the set callback.
//   - Fail-open: missing file is fine (no whitelist installed; baseline
//     rate limits apply to every IP).
//   - Fail-soft on any error (stat, read, parse, apply): logs at WARN
//     and leaves whatever whitelist is currently installed in place.
//     The watcher never crashes, never panics, never blocks startup.
//   - Hot reload: any change to the file (mtime OR size) triggers a
//     reparse + atomic apply on the next tick.
//   - Idempotent: same file content (unchanged mtime + size) is a no-op.
//
// File format — JSON array of {cidr, rate} objects:
//
//	[
//	  {"cidr": "10.128.0.0/9",     "rate": 100000},
//	  {"cidr": "35.238.109.166/32","rate": 10000}
//	]
//
// rate is the per-window allowance for the per-IP token bucket on the
// rate limiter. Whitelisted CIDRs also bypass the per-connection
// abusive-rate close (>500 req/s/conn) AND the process-wide global
// rate cap unconditionally, regardless of rate.
func watchRateLimitWhitelist(
	path string,
	interval time.Duration,
	set func([]accept.WhitelistEntry) error,
	stop <-chan struct{},
) {
	var lastMtime time.Time
	var lastSize int64
	apply := func() {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				// File is optional. Reset state so a later create-then-
				// modify cycle is correctly detected.
				if !lastMtime.IsZero() || lastSize != 0 {
					slog.Info("rate-limit-whitelist removed; reverting to empty whitelist", "path", path)
					if err := set(nil); err != nil {
						slog.Warn("rate-limit-whitelist clear failed; leaving previous in place",
							"path", path, "err", err)
					} else {
						lastMtime = time.Time{}
						lastSize = 0
					}
				}
				return
			}
			slog.Warn("rate-limit-whitelist stat failed; leaving previous in place",
				"path", path, "err", err)
			return
		}
		if info.ModTime().Equal(lastMtime) && info.Size() == lastSize {
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("rate-limit-whitelist read failed; leaving previous in place",
				"path", path, "err", err)
			return
		}
		var entries []whitelistFileEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			slog.Warn("rate-limit-whitelist parse failed; leaving previous in place",
				"path", path, "err", err)
			return
		}
		out := make([]accept.WhitelistEntry, 0, len(entries))
		for _, e := range entries {
			out = append(out, accept.WhitelistEntry{CIDR: e.CIDR, Rate: e.Rate})
		}
		if err := set(out); err != nil {
			slog.Warn("rate-limit-whitelist apply failed; leaving previous in place",
				"path", path, "err", err)
			return
		}
		lastMtime = info.ModTime()
		lastSize = info.Size()
		slog.Info("rate-limit-whitelist reloaded",
			"path", path, "entries", len(out), "mtime", lastMtime.UTC())
	}
	apply() // initial load (before tick — gives ~immediate first apply)
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
