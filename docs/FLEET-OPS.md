# Fleet operations runbook

The production VMs are hand-managed (no startup-script / IaC). The manual
system-level state below is **not** captured anywhere else — re-apply it after
any VM reprovision. Each item caused, or was applied in response to, a
2026-07-24 outage.

## pilot-rendezvous-new — registry + embedded beacon

GCP `vulture-vision-cloud` / `us-central1-a`, static IP `pilot-registry-ip`
(`34.71.57.205`), `n2-standard-16` (63 GB / 16 vCPU). systemd unit
`pilot-rendezvous.service`, binary `/usr/local/bin/pilot-rendezvous`.

### GOMEMLIMIT

Drop-in `/etc/systemd/system/pilot-rendezvous.service.d/gomemlimit.conf`:

```ini
[Service]
Environment=GOMEMLIMIT=48GiB
```

63 GB box; `24GiB` (the earlier value) GC-thrashes under the ~150-207K
connection baseline and starves the embedded beacon → fleet-wide
"resolves but no reply". Raise to `~75%` of box RAM. See also the RSS-growth
fix (bound the pooled save buffer + periodic `debug.FreeOSMemory`) — without
it, RSS ratchets to the ceiling and re-wedges regardless of the limit.

### Registry ports

Registry `:9000` (TCP), beacon `:9001` (UDP), WSS bridge `127.0.0.1:18443`,
dashboard/metrics `:3000` (`curl 127.0.0.1:3000/metrics`,
`/debug/pprof/{heap,goroutine,profile}`). The standalone MIG beacons
(`beacon-18p1`, `beacon-tl3n`) are unused — the beacon that serves the fleet
is embedded in this process.

## pilot-service-agents — ~430 service agents

GCP `us-central1-a`, `n2-standard-64`, 397 GB `pd-balanced` (`34.69.26.204`).
Hosts essentially the whole `list-agents` catalogue.

### Log rotation (CRITICAL — prevents disk-full outage)

Per-agent logs under `/var/log/pilot-*/` have **no rotation** by default and
grew to 284 GB, filling the root FS to 100% → `jbd2` journal hang → all 430
daemons frozen in disk-wait → fleet outage. Re-apply:

`/etc/logrotate.d/pilot-agents`:

```
/var/log/pilot-*/*.log /var/log/pilot-*/*.out /var/log/pilot-*/*.err {
    daily
    rotate 2
    maxsize 50M
    missingok
    notifempty
    compress
    copytruncate
}
```

`/etc/cron.d/pilot-agents-logrotate` (default daily is too slow for 430 agents):

```
0 * * * * root /usr/sbin/logrotate /etc/logrotate.d/pilot-agents
```

Also cap journald: `journalctl --vacuum-size=500M` (it had reached 3.9 GB).

If the disk is already full and SSH hangs: drive `fsck -y /dev/sda1` via the
GCP serial console (`gcloud compute connect-to-serial-port`), then truncate
`/var/log/pilot-*/*` before rebooting.

## MOM planner box (Lambda `192.222.58.112`)

Overlay responder is the compiled C++ `pilot-mom-responder.service`
(concurrent, thread-per-message) fronting the `server.py` `/api/plan` (`:8080`,
`pilot-mom.service`) + vLLM (`:8000`). The Python `pilot-mom-planner.service`
(`responder.py --serve`, serial) is **disabled** — it raced the C++ responder
on the shared inbox/seen-file.

`sync_and_reload.sh` (daily 04:30) must restart `pilot-mom-responder`, not the
disabled `pilot-mom-planner`. Inbox files accumulate (responders track a
seen-file, never unlink) — prune `~/.pilot/inbox/` periodically.
