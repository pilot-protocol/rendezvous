#!/usr/bin/env bash
#
# verify-build.sh — reproduce the production rendezvous binary from
# source so anyone can independently confirm what code is running
# behind https://polo.pilotprotocol.network.
#
# How it works:
#   1. Query the live registry for its claimed build identity.
#   2. Check out the matching git commit.
#   3. Build with the same -ldflags + -trimpath the deploy uses.
#   4. SHA256 the resulting binary and compare to build_info.binary_sha256
#      returned by the running server.
#
# Reproducibility requires the same Go toolchain version that built the
# production binary (printed as build_info.go_version). The script
# warns when the local Go version differs.
#
# Usage:
#   scripts/verify-build.sh                # verify live polo
#   scripts/verify-build.sh http://1.2.3.4:3000   # verify any rendezvous

set -euo pipefail

ENDPOINT="${1:-https://polo.pilotprotocol.network}"

need() {
    command -v "$1" >/dev/null 2>&1 || { echo "Missing required tool: $1"; exit 1; }
}
need curl
need jq
need go
need sha256sum
need git

echo "=== Fetching build identity from $ENDPOINT ==="
PAYLOAD=$(curl -fsS --max-time 10 "$ENDPOINT/api/public-stats")
echo "$PAYLOAD" | jq -e '.build_info' >/dev/null 2>&1 || {
    echo "ERROR: server did not return build_info. Either it's a pre-verification build, or build info wasn't compiled in."
    exit 1
}

VERSION=$(echo "$PAYLOAD" | jq -r '.build_info.version // empty')
COMMIT=$(echo "$PAYLOAD" | jq -r '.build_info.git_commit // empty')
BUILD_TIME=$(echo "$PAYLOAD" | jq -r '.build_info.build_time // empty')
WANT_SHA=$(echo "$PAYLOAD" | jq -r '.build_info.binary_sha256 // empty')
WANT_GO=$(echo "$PAYLOAD" | jq -r '.build_info.go_version // empty')

echo "  version:       $VERSION"
echo "  git_commit:    $COMMIT"
echo "  build_time:    $BUILD_TIME"
echo "  go_version:    $WANT_GO"
echo "  binary_sha256: $WANT_SHA"

[ -n "$COMMIT" ] || { echo "ERROR: no git_commit in build_info — server isn't running a tagged build"; exit 1; }
[ -n "$WANT_SHA" ] || { echo "ERROR: no binary_sha256 in build_info — server is not on Linux or /proc/self/exe was unreadable"; exit 1; }

GOT_GO=$(go version | awk '{print $3}')
if [ "$GOT_GO" != "$WANT_GO" ]; then
    echo "WARN: local go=$GOT_GO ; production go=$WANT_GO ; SHA mismatch is expected unless you switch toolchains"
fi

echo ""
echo "=== Checking out commit $COMMIT ==="
git fetch --quiet
git checkout --quiet "$COMMIT"

echo ""
echo "=== Building with -trimpath + matching ldflags ==="
OUT=$(mktemp -d)/pilot-rendezvous
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=$VERSION -X main.gitCommit=$COMMIT -X main.buildTime=$BUILD_TIME" \
    -o "$OUT" \
    ./cmd/rendezvous

GOT_SHA=$(sha256sum "$OUT" | awk '{print $1}')

echo ""
echo "=== Result ==="
echo "  want sha256: $WANT_SHA"
echo "  got  sha256: $GOT_SHA"

if [ "$GOT_SHA" = "$WANT_SHA" ]; then
    echo "  STATUS:      MATCH — production runs commit $COMMIT verbatim"
    exit 0
else
    echo "  STATUS:      MISMATCH — production binary diverges from the source at $COMMIT"
    echo ""
    echo "  Possible causes:"
    echo "    - Go toolchain mismatch (got=$GOT_GO want=$WANT_GO)"
    echo "    - Build flags changed (--trimpath, ldflags)"
    echo "    - Cross-compile environment differs"
    exit 1
fi
