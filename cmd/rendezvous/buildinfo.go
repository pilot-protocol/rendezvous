// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"runtime"
)

// Build-time identity. Populated via -ldflags="-X main.version=...
// -X main.gitCommit=... -X main.buildTime=...". When set with a
// reproducible-build invocation (-trimpath, pinned go toolchain), the
// resulting binarySHA256 can be reproduced from the same git_commit by
// any third party — see scripts/verify-build.sh for the recipe we
// publish alongside the public-stats endpoint.
var (
	gitCommit = ""
	buildTime = ""
)

// collectBuildInfo bundles the build-time identity into a flat map for
// publishing on /api/public-stats. binary_sha256 is computed lazily on
// first call from /proc/self/exe so an attacker who replaces the
// on-disk binary post-start can't fake the value at startup (the
// running process always hashes its own backing image at the time of
// the call).
func collectBuildInfo() map[string]string {
	info := map[string]string{
		"version":    version,
		"go_version": runtime.Version(),
	}
	if gitCommit != "" {
		info["git_commit"] = gitCommit
	}
	if buildTime != "" {
		info["build_time"] = buildTime
	}
	if sum, err := selfSHA256(); err == nil {
		info["binary_sha256"] = sum
	}
	return info
}

// selfSHA256 returns the hex-encoded SHA256 of the running binary by
// streaming /proc/self/exe (Linux). Returns an error on platforms
// without that symlink so the public-stats payload omits the field
// rather than ship a misleading value.
func selfSHA256() (string, error) {
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
