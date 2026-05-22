# rendezvous

Pilot Protocol rendezvous server. Tracks node registrations, network
memberships, trust links, and routing state for the overlay; supports
hot-standby replication, WAL-backed durability, an admin REST API,
and a live operational dashboard.

This is a **standalone binary**, not a daemon plugin. Operators run
one (or a hot-standby pair) at the network edge; daemons connect to
it via `pkg/registry/client` in the protocol repo.

## Layout

| Path | What it does |
|---|---|
| `*.go` (root) | `Server` struct + lifecycle, top-level wiring. |
| `accept/` | Pending-registration accept queue. |
| `api/` | HTTP/JSON admin API handlers. |
| `audit/` | Audit-log emitter + export. |
| `authz/` | Admin-token bearer auth. |
| `dashboard/` | Live HTML+JSON dashboard (R5.1). |
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
| `cmd/rendezvous/` | Production binary (`pilot-rendezvous`). |
| `cmd/registry/` | Minimal variant used by some test fixtures. |

## Build + run

```bash
go build -o pilot-rendezvous ./cmd/rendezvous
./pilot-rendezvous -beacon :9001 -listen :9000 -store /var/lib/pilot/registry.json
```

## Import paths

Daemon-side consumers in the protocol repo still get the client +
wire format from `pkg/registry/{client,wire}`. The server-side
package is imported only by test fixtures:

```go
import "github.com/pilot-protocol/rendezvous"

s := rendezvous.NewWithStore(beaconAddr, "")
go s.ListenAndServe(":0")
```

(Note the package name is still `server` inside the module — the
external module path is `rendezvous`. We'll rename the package on a
future tag if it bothers anyone.)

## Releasing

Tag a SemVer version (e.g. `v0.1.0`); web4's test fixtures consume
this via `require github.com/pilot-protocol/rendezvous v0.1.0`.
During co-development consumers use `replace ../rendezvous`.
