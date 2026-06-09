// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

// autoSnapshotName matches ONLY filenames produced by the deploy/restore
// scripts and the registry itself — never operator-curated backups.
//
// Accepted shapes (all start with "registry-" and end with ".json"):
//   - registry-YYYYMMDD-HHMMSS.json                     (legacy date dash time)
//   - registry-YYYYMMDDTHHMMSSZ.json                    (RFC3339 compact)
//   - registry-<lowercase-tag>-YYYYMMDD[-T]HHMMSS[Z].json
//     where <tag> is operator-defined but the trailing timestamp marks
//     it as machine-generated (e.g. "pre-deploy", "pre-admin-knobs")
//
// Anything with an upper-case PRISTINE/RECOVERY/-bak* token, or any
// name without a trailing timestamp, falls through and survives.
var autoSnapshotName = regexp.MustCompile(`^registry-([a-z0-9_-]+-)?[0-9]{8}[T-][0-9]{6}Z?\.json$`)

// watchBackupsRetention polls the backups directory every interval and
// deletes files older than maxAge OR keeps only the most recent maxCount
// snapshot backups. Either bound can be zero to disable that side.
//
// Operational contract — same shape as watchRateLimitWhitelist:
//   - Own goroutine. Never blocks startup, the registry, the beacon, or
//     the dashboard.
//   - Fail-soft on every error. A failed stat / open / unlink is logged
//     at WARN and the next tick retries.
//   - Idempotent. A tick with nothing to delete is silent.
//   - Files NOT matching the registry-snapshot prefix are left alone
//     (RECOVERY-README.md, hand-curated PRISTINE snapshots, anything
//     the operator dropped in). The sweeper only touches files whose
//     name begins with "registry-" AND ends with ".json".
//
// The sweeper exists because /var/lib/pilot/backups/ accumulates one
// file per deploy (we snapshot pre-deploy), and the rendezvous binary
// itself never deletes. Left unmanaged, ~150 MB × deploy frequency
// fills the 49 GB root disk within a few months.
func watchBackupsRetention(dir string, maxAge time.Duration, maxCount int, interval time.Duration, stop <-chan struct{}) {
	apply := func() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				return // backups dir not created yet
			}
			slog.Warn("backup retention: read dir failed; leaving as-is",
				"path", dir, "err", err)
			return
		}

		type file struct {
			name string
			mod  time.Time
			size int64
		}
		candidates := make([]file, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			// Strict match against the auto-generated timestamp shape so
			// hand-curated files (PRISTINE-*, RECOVERY-*, names without
			// a trailing timestamp) are never deleted.
			if !autoSnapshotName.MatchString(name) {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			candidates = append(candidates, file{name: name, mod: info.ModTime(), size: info.Size()})
		}

		// Newest first — keeps the most recent maxCount and ages out the rest.
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].mod.After(candidates[j].mod) })

		var deleted, freed int64
		now := time.Now()
		for i, f := range candidates {
			keep := true
			if maxCount > 0 && i >= maxCount {
				keep = false
			}
			if keep && maxAge > 0 && now.Sub(f.mod) > maxAge {
				keep = false
			}
			if keep {
				continue
			}
			full := filepath.Join(dir, f.name)
			if err := os.Remove(full); err != nil {
				slog.Warn("backup retention: delete failed; leaving as-is",
					"path", full, "err", err)
				continue
			}
			deleted++
			freed += f.size
		}
		if deleted > 0 {
			slog.Info("backup retention swept",
				"path", dir, "deleted", deleted, "freed_bytes", freed,
				"kept", len(candidates)-int(deleted),
				"max_age", maxAge, "max_count", maxCount)
		}
	}
	apply() // initial pass at boot — releases space immediately if behind

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
