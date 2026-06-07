# Live circuit breakers

The rendezvous process ships with named, hot-reloadable on/off switches that
let an operator cut off entire surfaces without a restart. The wiring is
default-allow: a missing breaker entry means "closed" (normal operation).

## How to flip one

Edit `<store-dir>/breakers.json` (sibling to `registry.json`). A file
watcher polls every 2 s; changes take effect within that window.

**File format — flat map of breaker name → entry:**

```json
{
  "registry.register": {
    "state": "open",
    "reason": "incident #2061 — pause registrations while we rotate the audit log"
  },
  "beacon.relay": {
    "state": "half_open",
    "reason": "load shed test — log only, do not deny"
  }
}
```

Three states:

| state       | semantic                                       |
|-------------|------------------------------------------------|
| `closed`    | normal operation (default if absent)           |
| `half_open` | allow + log warning at debug level             |
| `open`      | deny; caller receives error with the reason    |

To re-enable: change `"state"` back to `"closed"`, delete the entry,
or delete the file entirely (reverts to empty map = full default-allow).

### Flipping via API (no SSH needed)

Same in-memory effect as editing `breakers.json`, but accessible from
anywhere with the admin token. The API also persists the change to the
file so it survives restart, and emits an audit-log entry.

```bash
# List every gate + its live counters
curl -H "X-Admin-Token: $TOKEN" https://polo.pilotprotocol.network/api/breakers

# Open one
curl -X PUT -H "X-Admin-Token: $TOKEN" -H "Content-Type: application/json" \
     -d '{"state":"open","reason":"incident #2061 — pause registrations"}' \
     https://polo.pilotprotocol.network/api/breakers/registry.register

# Revert
curl -X DELETE -H "X-Admin-Token: $TOKEN" \
     https://polo.pilotprotocol.network/api/breakers/registry.register
```

PUT and DELETE **require** the `X-Admin-Token` header (no query-param
fallback) — dodges CSRF via referer leaks. GET also accepts
`?admin_token=…` for convenience.

The list payload shape:

```json
{
  "breakers": [
    {
      "name": "registry.register",
      "state": "closed",
      "allowed_total": 1234567,
      "denied_total": 0
    },
    {
      "name": "registry.heartbeat",
      "state": "open",
      "reason": "incident #2061",
      "updated_at": "2026-06-08T09:12:33Z",
      "allowed_total": 4521,
      "denied_total": 17,
      "last_denied_at": "2026-06-08T09:12:34Z"
    }
  ]
}
```

Counters are monotonic since process start and survive `DELETE` — post-
incident review keeps seeing exactly how much traffic flowed through
the gate. Names that appear in `counters` but never had a registered
breaker are real traffic on ungated paths; useful for picking which
surface to gate next.

### Process health (`/api/runtime`)

Admin-only sibling endpoint surfacing Go runtime data that Prometheus
scrapers don't expose by default:

```bash
curl -H "X-Admin-Token: $TOKEN" https://polo.pilotprotocol.network/api/runtime
```

Returns goroutine count, heap stats, GC cycle count + pause percentiles
(p50/p99/max in seconds), scheduler latency percentiles, cumulative
mutex wait time, and (on Linux) open file-descriptor count. Useful for
spotting:

- **Goroutine leaks**: monotonic climb over hours.
- **Lock contention**: `mutex_wait_seconds` rate climbing without a
  matching workload increase.
- **Scheduler congestion**: `sched_latency_p99_seconds` climbing even
  with idle CPU — too many ready goroutines for `GOMAXPROCS`.
- **GC pressure**: `gc_pause_p99_seconds` > 10 ms on a registry doing
  20k rps queues thousands of in-flight requests behind one STW.

### Verifying a flip took effect

The wire-level error returned to the caller is sanitised to a generic
`"request failed"` by the accept layer (avoids leaking internal state
to arbitrary callers). To see the breaker name + reason as the gate
fires, watch the registry logs:

```bash
sudo journalctl -u pilot-rendezvous -f | grep -i breaker
```

A successful flip looks like:

```
INFO  msg="breakers reloaded" path=/var/lib/pilot/breakers.json count=1
WARN  msg="registry handle error" remote=… type=heartbeat err="service unavailable: breaker \"registry.heartbeat\" is open (live-flip test)"
```

## Available breakers

### Registry-side (JSON-RPC dispatch)

Gated at `Server.handleMessage` via the `breakerForType` map in
[`dispatch.go`](../dispatch.go). Open returns
`service unavailable: breaker "<name>" is open (<reason>)` to the client.

| breaker name               | covers msgTypes                                                            |
|----------------------------|----------------------------------------------------------------------------|
| `registry.register`        | `register`                                                                 |
| `registry.heartbeat`       | `heartbeat`                                                                |
| `registry.resolve`         | `lookup`, `resolve`, `resolve_hostname`, `list_networks`, `list_nodes`     |
| `registry.punch`           | `punch` (JSON-RPC level, NOT the UDP beacon punch)                         |
| `registry.deregister`      | `deregister`                                                               |
| `registry.trust`           | `report_trust`, `revoke_trust`, `check_trust`                              |
| `registry.handshake`       | `request_handshake`, `poll_handshakes`, `respond_handshake`                |
| `registry.invite`          | `invite_to_network`, `poll_invites`, `respond_invite`                      |
| `registry.network_admin`   | `create_network`, `delete_network`, `join_network`, `leave_network`, `rename_network` |
| `registry.beacon_register` | `beacon_register`, `beacon_list`                                           |

### Beacon-side (UDP)

Gated inside the in-process `beacon.Server`. UDP has no reply path for
errors — open simply drops the inbound message. Senders retry / fall
back per the normal client-side logic.

| breaker name       | covers                                                                |
|--------------------|-----------------------------------------------------------------------|
| `beacon.discover`  | STUN-style discover probes (new nodes / endpoint moves only)          |
| `beacon.punch`     | NAT hole-punch coordination (existing tunnels unaffected)             |
| `beacon.relay`     | relayed packet forwarding (counted in `relay_dropped` metric)         |

### Persistence

Gated inside `Server.flushSave`. Open makes the periodic snapshot a
no-op so an emergency state-corruption never reaches disk. Useful
during post-crash recovery when the in-memory state is suspect.

| breaker name      | covers                                                  |
|-------------------|---------------------------------------------------------|
| `snapshot.write`  | the periodic snapshot save loop                         |

### Dashboard

Gated inside the `/api/public-stats` handler. Open returns
`503 Service Unavailable` so even the public headline numbers can be
hidden during an incident.

| breaker name              | covers                            |
|---------------------------|-----------------------------------|
| `dashboard.public_stats`  | the public stats endpoint         |

## Operational notes

- Names are case-sensitive. A typo never gates anything (default-allow), so a
  typo can't cause an outage but also can't cut off the path you wanted to
  cut off. Verify after each edit:
  `curl http://localhost:3000/api/breakers` (admin-gated).
- Half-open logs at `debug` level — usually filtered in production. Bump
  `-log-level=debug` temporarily to actually see the lines.
- The breaker check runs BEFORE handler-side validation. A registration
  with a malformed payload still gets the breaker-open error when the
  switch is open — useful when you want a clean "no, not now" signal
  without paying the cost of validation.
- Open does NOT abort in-flight requests. A handler that started before
  the watcher noticed the file change finishes normally; only the next
  request hits the open breaker.
