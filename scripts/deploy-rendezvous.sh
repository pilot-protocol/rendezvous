#!/usr/bin/env bash
#
# deploy-rendezvous.sh — deploy, health-check, and auto-rollback for the rendezvous server.
# Runs on the VM. Called by the GitHub Actions workflow.
#
set -euo pipefail

BINARY_NAME="pilot-rendezvous"
INSTALL_DIR="/usr/local/bin"
CURRENT="$INSTALL_DIR/$BINARY_NAME"
PREV="$INSTALL_DIR/$BINARY_NAME.prev"
STAGED="$HOME/$BINARY_NAME-staged"
SERVICE_NAME="pilot-rendezvous"
REGISTRY_JSON="/var/lib/pilot/registry.json"
BACKUP_DIR="/var/lib/pilot/backups"
HEALTH_LIVENESS_URL="http://127.0.0.1:3000/healthz"
# /api/public-stats (anonymous, curated payload) added by PR #50 as
# part of the polo public-stats lockdown. Use it for the data-loaded
# gate — /api/stats is now admin-gated and the deploy script has no
# admin token to present. /api/public-stats carries total_nodes
# unchanged, which is the only field the gate reads.
HEALTH_STATS_URL="http://127.0.0.1:3000/api/public-stats"
HEALTH_TIMEOUT=30
HEALTH_INTERVAL=2
# Production registry holds ~242k nodes (2026-06-07). A successful
# load should reach the bulk of that quickly. Tuned conservatively so
# a partial-load freshly-started binary doesn't sneak past the gate.
MIN_NODES=100000

log() { echo "[deploy] $(date '+%H:%M:%S') $*"; }

preflight() {
    if [ ! -f "$STAGED" ]; then
        log "ERROR: staged binary not found at $STAGED"
        exit 1
    fi
    if ! file "$STAGED" | grep -q "ELF"; then
        log "ERROR: staged file is not a valid ELF binary"
        exit 1
    fi
    chmod +x "$STAGED"
    log "Preflight OK — staged binary is valid ELF"
}

backup() {
    # Backup current binary
    if [ -f "$CURRENT" ]; then
        sudo cp "$CURRENT" "$PREV"
        log "Backed up current binary to $PREV"
    fi

    # Backup registry JSON
    if [ -f "$REGISTRY_JSON" ]; then
        sudo mkdir -p "$BACKUP_DIR"
        TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
        sudo cp "$REGISTRY_JSON" "$BACKUP_DIR/registry-$TIMESTAMP.json"
        log "Backed up registry.json to registry-$TIMESTAMP.json"

        # Rotate: keep last 5 backups
        BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/registry-*.json 2>/dev/null | wc -l)
        if [ "$BACKUP_COUNT" -gt 5 ]; then
            ls -1t "$BACKUP_DIR"/registry-*.json | tail -n +"6" | xargs sudo rm -f
            log "Rotated backups — kept last 5"
        fi
    fi
}

prepare_snapshot() {
    # PILOT-78 (#6): HEAD's snapshot loader returns an error on stored
    # checksum mismatch instead of silently zeroing the directory.
    # Schema drift between the binary that wrote registry.json and the
    # binary about to load it produces a re-marshal mismatch, so the
    # new binary would refuse the file and start fresh with zero nodes
    # — then overwrite the on-disk snapshot with that empty state
    # before the deploy script could rollback.
    #
    # Strip the trailing `,"checksum":"<hex>"` from the snapshot so the
    # new binary loads on bare data and writes a fresh checksum on the
    # first snapshot save. Idempotent: if no checksum field is present
    # (already migrated), sed does nothing.
    #
    # MUST run AFTER stop_service. The first deploy attempt ran this
    # before stop_service while the old binary was still active; the
    # old binary's shutdown-sync re-persisted the snapshot with a fresh
    # checksum between sed completing (09:59:42) and the service
    # actually stopping (09:59:54), undoing the strip. New binary saw
    # the re-checksummed file, refused it, started fresh with ~60 nodes
    # (rapidly growing via live re-registrations). Auto-rollback fired
    # correctly on the >=100000 gate — but the deploy didn't land.
    if [ ! -f "$REGISTRY_JSON" ]; then
        log "No snapshot at $REGISTRY_JSON — skipping prepare_snapshot"
        return 0
    fi
    # Defensive sanity: refuse to proceed if the service is still active
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "ERROR: prepare_snapshot called while $SERVICE_NAME is still active — refusing to race the writer"
        exit 1
    fi
    log "Stripping stored snapshot checksum (migration safety)..."
    sudo sed -i 's/,"checksum":"[a-f0-9]*"}/}/' "$REGISTRY_JSON"
    # Verify the strip actually took effect — if the file still ends
    # with a checksum field, abort cleanly rather than start the new
    # binary against an unmigrated snapshot.
    if sudo tail -c 2048 "$REGISTRY_JSON" | grep -q '"checksum":"[a-f0-9]'; then
        log "ERROR: snapshot still contains a checksum field after strip — aborting deploy"
        exit 1
    fi
    log "Snapshot prepared"
}

stop_service() {
    log "Stopping $SERVICE_NAME..."
    sudo systemctl stop "$SERVICE_NAME"
    sleep 1
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "ERROR: service still active after stop"
        exit 1
    fi
    log "Service stopped"
}

swap_binary() {
    sudo cp "$STAGED" "$CURRENT"
    log "Swapped binary"
}

start_service() {
    log "Starting $SERVICE_NAME..."
    sudo systemctl start "$SERVICE_NAME"
    log "Service started"
}

health_check() {
    log "Running health checks (${HEALTH_TIMEOUT}s timeout, every ${HEALTH_INTERVAL}s)..."
    ELAPSED=0
    while [ "$ELAPSED" -lt "$HEALTH_TIMEOUT" ]; do
        sleep "$HEALTH_INTERVAL"
        ELAPSED=$((ELAPSED + HEALTH_INTERVAL))

        # 1. systemd unit active
        if ! systemctl is-active --quiet "$SERVICE_NAME"; then
            log "Health: service not active (${ELAPSED}s)"
            continue
        fi

        # 2. liveness probe: /healthz returns {"status":"ok",...}
        STATUS=$(curl -s -m 5 "$HEALTH_LIVENESS_URL" | jq -r '.status // "down"' 2>/dev/null || echo "down")
        if [ "$STATUS" != "ok" ]; then
            log "Health: /healthz status=$STATUS (${ELAPSED}s)"
            continue
        fi

        # 3. data-loaded probe: /api/public-stats.active_nodes >= MIN_NODES.
        # Use active_nodes (currently-online), NOT total_nodes — as of
        # the 2026-06-07 r2 payload, total_nodes is restored from the
        # snapshot's next_node counter (cumulative ever-registered) and
        # would pass this gate even on an empty load (the original
        # rollback-cascade failure mode). active_nodes is computed from
        # in-memory nodes whose last_seen > stale_threshold; only a real
        # snapshot load makes it climb quickly post-start.
        NODES=$(curl -s -m 5 "$HEALTH_STATS_URL" | jq -r '.active_nodes // 0' 2>/dev/null || echo "0")
        if [ "$NODES" -ge "$MIN_NODES" ]; then
            log "Health check PASSED — nodes=$NODES (${ELAPSED}s)"
            return 0
        fi
        log "Health: nodes=$NODES (need >=$MIN_NODES) — waiting (${ELAPSED}s)"
    done

    log "Health check FAILED after ${HEALTH_TIMEOUT}s"
    return 1
}

rollback() {
    log "ROLLING BACK to previous binary..."
    if [ ! -f "$PREV" ]; then
        log "ERROR: no previous binary at $PREV — cannot rollback"
        exit 1
    fi

    sudo systemctl stop "$SERVICE_NAME" || true
    sleep 1
    sudo cp "$PREV" "$CURRENT"

    # Restore the most recent pre-deploy snapshot. The new binary may
    # have started fresh on a checksum mismatch (mitigated by
    # prepare_snapshot but kept as defense-in-depth) and overwritten
    # the on-disk snapshot with empty state before the health check
    # failed. Loading the old binary against an empty snapshot would
    # serve correctly-formed responses for nothing — strictly worse
    # than serving nothing at all. Backup() runs immediately before
    # the swap, so the freshest backup is exactly the pre-deploy
    # state.
    LATEST_BACKUP=$(ls -1t "$BACKUP_DIR"/registry-*.json 2>/dev/null | head -1 || true)
    if [ -n "$LATEST_BACKUP" ]; then
        sudo cp "$LATEST_BACKUP" "$REGISTRY_JSON"
        log "Restored snapshot from $(basename "$LATEST_BACKUP")"
    else
        log "WARNING: no pre-deploy snapshot backup found — keeping current $REGISTRY_JSON"
    fi

    sudo systemctl start "$SERVICE_NAME"
    sleep 3

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "Rollback complete — service is active"
    else
        log "CRITICAL: rollback failed — service did not start"
        sudo journalctl -u "$SERVICE_NAME" --no-pager -n 20
        exit 1
    fi
}

deploy() {
    log "=== Starting deployment ==="
    preflight
    backup
    stop_service
    prepare_snapshot   # must run after stop_service to avoid racing
                       # the old binary's shutdown-sync re-persist
    swap_binary
    start_service

    if health_check; then
        log "=== Deployment successful ==="
        exit 0
    else
        rollback
        log "=== Deployment FAILED — rolled back ==="
        exit 1
    fi
}

case "${1:-deploy}" in
    deploy)   deploy ;;
    rollback) rollback ;;
    health)   health_check ;;
    *)        echo "Usage: $0 {deploy|rollback|health}"; exit 1 ;;
esac
