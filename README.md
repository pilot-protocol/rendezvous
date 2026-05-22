# rendezvous

[![ci](https://github.com/pilot-protocol/rendezvous/actions/workflows/ci.yml/badge.svg)](https://github.com/pilot-protocol/rendezvous/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/pilot-protocol/rendezvous/branch/main/graph/badge.svg)](https://codecov.io/gh/pilot-protocol/rendezvous)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

The Pilot Protocol rendezvous server. Tracks node registrations, network memberships, trust links, and routing state for the overlay. Supports hot-standby replication, WAL-backed durability, an admin REST API, and a live operational dashboard.

> **This repository is published for source-code transparency and auditability.** It is **not** a self-hosting guide. The canonical Pilot Protocol rendezvous is operated by Vulture Labs at `34.71.57.205:9000` (with the companion beacon at `34.71.57.205:9001`); production daemons connect there by default. If you want to read the code that produced the binary your daemon is talking to, you're in the right place.

## Architecture

The rendezvous is the control plane for the overlay. Daemons register here on startup, look up peers, fetch network membership, and stream live events. It is intentionally a small, durable service: registrations + memberships + trust links live in a JSON-encoded store, all state mutations go through a WAL, and a leader/follower pair can run hot-standby behind a virtual IP.

The server speaks a length-prefixed JSON RPC over TCP on port 9000 (registry) and exposes an admin REST API and live HTML+JSON dashboard on port 3000. Beacon coordination runs alongside on the companion beacon process (see the `beacon` repo).

## Layout

| Path | What it does |
|---|---|
| `*.go` (root) | `Server` struct + lifecycle, top-level wiring. |
| `accept/` | Pending-registration accept queue. |
| `api/` | HTTP/JSON admin API handlers. |
| `audit/` | Audit-log emitter + export. |
| `authz/` | Admin-token bearer auth. |
| `dashboard/` | Live HTML+JSON dashboard. |
| `directory/` | Node-info directory + caches. |
| `events/` | Pub/sub event bus for clients. |
| `identity/` | Ed25519 identity verification. |
| `membership/` | Per-network membership state. |
| `metrics/` | Prometheus + per-call timing. |
| `policy/` | Network policy enforcement at the server. |
| `replication/` | Leader/follower WAL streaming. |
| `routing/` | Beacon/relay assignment. |
| `trust/` | Trust-link replication + validation. |
| `wal/` | Write-ahead log for durable persistence. |
| `webhook/` | Outbound webhook dispatcher. |
| `cmd/rendezvous/` | Production binary entrypoint. |
| `cmd/registry/` | Minimal variant used by test fixtures. |

## Build locally

If you want to compile the source locally — for example to read the exact binary that produced your daemon's traffic, or to step through it under a debugger:

```bash
go build ./cmd/rendezvous
```

The build is hermetic Go with no cgo; any Go toolchain at the version pinned in `go.mod` will reproduce the binary.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
