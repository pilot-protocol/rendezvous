// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/pilot-protocol/common/protocol"
	acceptpkg "github.com/pilot-protocol/rendezvous/accept"
	auditpkg "github.com/pilot-protocol/rendezvous/audit"
	authzpkg "github.com/pilot-protocol/rendezvous/authz"
	breakerspkg "github.com/pilot-protocol/rendezvous/breakers"
	dashpkg "github.com/pilot-protocol/rendezvous/dashboard"
	dirpkg "github.com/pilot-protocol/rendezvous/directory"
	"github.com/pilot-protocol/rendezvous/events"
	identpkg "github.com/pilot-protocol/rendezvous/identity"
	membpkg "github.com/pilot-protocol/rendezvous/membership"
	metrpkg "github.com/pilot-protocol/rendezvous/metrics"
	policypkg "github.com/pilot-protocol/rendezvous/policy"
	replpkg "github.com/pilot-protocol/rendezvous/replication"
	"github.com/pilot-protocol/rendezvous/routing"
	trustpkg "github.com/pilot-protocol/rendezvous/trust"
	walpkg "github.com/pilot-protocol/rendezvous/wal"
	webhookpkg "github.com/pilot-protocol/rendezvous/webhook"
)

// SetStandby puts the server into standby mode: write operations are rejected
// and state is received from the given primary.
func (s *Server) SetStandby(primary string) {
	s.walStore.SetStandby(true)
	go s.RunStandby(primary)
}

func (s *Server) IsStandby() bool {
	return s.walStore.IsStandby()
}

// SetBuildInfo records the build-time identity surfaced on
// /api/public-stats for supply-chain verification. Must be called
// before Start; the resulting map is treated as immutable. Pass a copy
// to defend against callers mutating their input.
func (s *Server) SetBuildInfo(info map[string]string) {
	if info == nil {
		return
	}
	cp := make(map[string]string, len(info))
	for k, v := range info {
		cp[k] = v
	}
	s.mu.Lock()
	s.buildInfo = cp
	s.mu.Unlock()
}

// BuildInfo returns a copy of the recorded build identity, or nil if
// none was registered. Safe to call concurrently.
func (s *Server) BuildInfo() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.buildInfo) == 0 {
		return nil
	}
	cp := make(map[string]string, len(s.buildInfo))
	for k, v := range s.buildInfo {
		cp[k] = v
	}
	return cp
}

// SetAdminToken sets the token required for network creation.
// Empty string disables network creation entirely.
func (s *Server) SetAdminToken(token string) {
	s.mu.Lock()
	s.authz.SetAdminToken(token)
	s.mu.Unlock()
}

// LookupPublicKey returns the Ed25519 pubkey registered for nodeID,
// or (nil, false) if the node is unknown. Safe to call concurrently.
//
// Used by the in-process beacon's compat-mode WSS bridge to
// authenticate daemons during the post-upgrade challenge. The key is
// copied before release so callers can hold the result past the lock.
func (s *Server) LookupPublicKey(nodeID uint32) ([]byte, bool) {
	s.mu.RLock()
	node, ok := s.nodes[nodeID]
	if !ok || node == nil || len(node.PublicKey) == 0 {
		s.mu.RUnlock()
		return nil, false
	}
	out := make([]byte, len(node.PublicKey))
	copy(out, node.PublicKey)
	s.mu.RUnlock()
	return out, true
}

// SetMaxNodes caps the number of registered nodes. Zero means unlimited.
func (s *Server) SetMaxNodes(n int) {
	s.mu.Lock()
	s.maxNodes = n
	s.mu.Unlock()
}

// SetDashboardToken gates per-network stats on the dashboard.
// Empty string restricts the dashboard to global aggregates only.
func (s *Server) SetDashboardToken(token string) {
	s.mu.Lock()
	s.authz.SetDashboardToken(token)
	s.mu.Unlock()
}

// SetMaintenanceBanner sets a notice rendered on the dashboard. Empty string clears it.
// If SetBannerPath was called, the value is atomically written to disk so it survives restart.
func (s *Server) SetMaintenanceBanner(msg string) { s.dashboard.SetMaintenanceBanner(msg) }

func (s *Server) MaintenanceBanner() string { return s.dashboard.MaintenanceBanner() }

// SetBannerPath enables disk persistence for the maintenance banner.
// If the file exists when called, its content becomes the initial banner value.
func (s *Server) SetBannerPath(path string) { s.dashboard.SetBannerPath(path) }

func (s *Server) SetDashboardHTTPAddr(addr string) { s.dashboard.SetHTTPProbeAddr(addr) }

// SetWhitelistCallbacks plugs operator-installable callbacks into the
// dashboard handler that back GET/PUT /api/admin/whitelist. Called by
// cmd/rendezvous/main.go once the on-disk whitelist path is known.
func (s *Server) SetWhitelistCallbacks(get func() ([]byte, error), set func([]byte) error) {
	s.dashboard.SetWhitelistCallbacks(get, set)
}

// SetLogLevelCallbacks plugs operator-installable callbacks into the
// dashboard handler that back GET/PUT /api/admin/runtime/log-level.
func (s *Server) SetLogLevelCallbacks(get func() string, set func(string) error) {
	s.dashboard.SetLogLevelCallbacks(get, set)
}

// SetBackupsCallback plugs the backup-directory enumerator into the
// dashboard. The closure owns the directory path; only the cmd-level
// package knows it, so wiring happens after NewWithStore.
func (s *Server) SetBackupsCallback(fn func() ([]dashpkg.BackupEntry, error)) {
	s.dashboard.SetBackupsList(fn)
}

func (s *Server) ServeDashboard(addr string) error { return s.dashboard.Serve(addr) }

// SetClock replaces the time source. Used in tests for deterministic time.
func (s *Server) SetClock(fn func() time.Time) {
	s.mu.Lock()
	s.now = fn
	s.mu.Unlock()
	s.routing.SetClock(fn)
}

// SetRateLimitWhitelist installs (or replaces) the rate-limit whitelist
// on the underlying Acceptor. Whitelisted CIDRs bypass the per-IP token
// bucket, the per-connection abusive-rate close (>500 req/s/conn), AND
// the process-wide global rate cap (~1000 req/s default). Use for
// operator-trusted internal infrastructure that legitimately drives
// high sustained load (presence simulators, traffic generators, the
// service-agents host running specialist agents, etc.).
//
// Pass nil or empty slice to clear the whitelist. Fail-closed: returns
// an error on any malformed CIDR; the previous whitelist remains in
// place on error.
func (s *Server) SetRateLimitWhitelist(entries []acceptpkg.WhitelistEntry) error {
	return s.accept.SetRateLimitWhitelist(entries)
}

// RateLimitWhitelistSize returns the number of installed whitelist rules.
func (s *Server) RateLimitWhitelistSize() int {
	return s.accept.RateLimitWhitelistSize()
}

// BreakerManager returns the Server's named-breaker manager. Call sites
// inside the rendezvous binary consult breakers via this manager
// (e.g. s.breakers.Allow("registry.register")); cmd/rendezvous wires
// the file watcher against it so operator edits to breakers.json hot-
// reload without restart. Never returns nil for a properly-constructed
// Server.
func (s *Server) BreakerManager() *breakerspkg.Manager {
	return s.breakers
}

// BreakerAllow is a convenience adapter matching the
// func(name) (allowed, reason) shape that out-of-package call sites
// (the in-process beacon, the WSS bridge) want when consulting the
// breakers. Returning the reason here lets sites surface it in any
// log line or error response without taking a second lookup.
// Unknown names default to allow (matches Manager.Allow semantic).
func (s *Server) BreakerAllow(name string) (bool, string) {
	if s.breakers == nil {
		return true, ""
	}
	allow, _ := s.breakers.Allow(name)
	if allow {
		return true, ""
	}
	return false, s.breakers.Reason(name)
}

// HealthSnapshot returns the operator-facing process health bundle
// served by /api/health. Mostly atomic-field loads, plus a few
// subsystem queries — WAL size, the breaker snapshot, and
// replMgr.SubCount(). Those queries take their own short subsystem
// locks (the WAL mutex, the breaker mutex, the replication manager's
// sub lock), all uncontended fast paths — but the probe does NOT take
// the hot registry mutex (s.mu), so it never blocks behind a save in
// flight. Missing subsystems (no WAL, no replication) are omitted
// from the payload entirely.
func (s *Server) HealthSnapshot() map[string]any {
	out := map[string]any{
		"snapshots_total":          s.snapshotsTotal.Load(),
		"snapshots_failed":         s.snapshotsFailed.Load(),
		"max_snapshot_duration_ms": s.maxSnapshotDurMs.Load(),
		"server_time":              time.Now().Unix(),
	}
	if ms := s.lastSnapshotUnixMs.Load(); ms > 0 {
		out["last_snapshot_at"] = ms
	}
	if ms := s.lastSnapshotDurMs.Load(); ms > 0 {
		out["last_snapshot_duration_ms"] = ms
	}
	if b := s.lastSnapshotSizeB.Load(); b > 0 {
		out["last_snapshot_size_bytes"] = b
	}
	if ms := s.lastSnapshotRLockMs.Load(); ms > 0 {
		out["last_snapshot_rlock_ms"] = ms
	}
	if s.walStore != nil {
		if w := s.walStore.WAL(); w != nil {
			out["wal_size_bytes"] = w.Size()
		}
	}
	if s.breakers != nil {
		// Use ParseState round-trip to surface the canonical name.
		// We don't call Allow here because Allow increments counters
		// and a health probe shouldn't pollute the gate metrics.
		state := "closed"
		for _, b := range s.breakers.Snapshot() {
			if b.Name == "snapshot.write" {
				state = b.StateString
				break
			}
		}
		out["snapshot_write_breaker"] = state
	}
	if s.replMgr != nil {
		out["replication_subscribers"] = s.replMgr.SubCount()
	}
	return out
}

// SetBreakersPath registers the on-disk breakers.json path so the
// admin control API can persist its changes there. Setting it after
// the file watcher has started is safe: the watcher polls by mtime so
// the next tick picks up our atomic write as a no-op (we apply the
// same map in-process before writing).
func (s *Server) SetBreakersPath(path string) {
	s.mu.Lock()
	s.breakersPath = path
	s.mu.Unlock()
}

// BreakerList returns the live per-name snapshot for /api/breakers
// (state + reason + counters + last-denied timestamp). Adapter to the
// shape dashboard.Callbacks expects. Never panics; an empty manager
// returns an empty slice.
func (s *Server) BreakerList() []dashpkg.BreakerListEntry {
	if s.breakers == nil {
		return nil
	}
	rows := s.breakers.StatsSnapshot()
	out := make([]dashpkg.BreakerListEntry, len(rows))
	for i, r := range rows {
		out[i] = dashpkg.BreakerListEntry{
			Name:         r.Name,
			State:        r.State,
			Reason:       r.Reason,
			UpdatedAt:    r.UpdatedAt,
			AllowedTotal: r.AllowedTotal,
			DeniedTotal:  r.DeniedTotal,
			LastDeniedAt: r.LastDeniedAt,
		}
	}
	return out
}

// BreakerSet upserts one breaker by name + state + operator reason.
// Returns an error when state is unrecognised so the API caller gets
// a clean 400 rather than silently treating a typo as Closed. Applies
// the change in-memory immediately, then persists the full breaker
// map to breakersPath (if set) so the change survives restart.
// Emits an audit-log entry for the change.
func (s *Server) BreakerSet(name, state, reason string) error {
	if s.breakers == nil {
		return fmt.Errorf("breakers manager not configured")
	}
	st, err := breakerspkg.ParseState(state)
	if err != nil {
		return err
	}
	prev := "closed"
	if cur := s.breakers.StatsSnapshot(); cur != nil {
		for _, c := range cur {
			if c.Name == name {
				prev = c.State
				break
			}
		}
	}
	s.breakers.Set(name, st, reason)
	if err := s.persistBreakers(); err != nil {
		slog.Warn("breaker change applied in memory but failed to persist", "name", name, "err", err)
	}
	s.audit("breaker.set",
		"name", name,
		"from", prev,
		"to", st.String(),
		"reason", reason)
	slog.Info("breaker state changed",
		"name", name, "from", prev, "to", st.String(), "reason", reason)
	return nil
}

// BreakerDelete removes one breaker. Counters are preserved so
// post-incident review still shows what flowed through the gate.
// Emits an audit-log entry. Persists the new (smaller) map to disk.
func (s *Server) BreakerDelete(name string) error {
	if s.breakers == nil {
		return fmt.Errorf("breakers manager not configured")
	}
	s.breakers.Delete(name)
	if err := s.persistBreakers(); err != nil {
		slog.Warn("breaker delete applied in memory but failed to persist", "name", name, "err", err)
	}
	s.audit("breaker.delete", "name", name)
	slog.Info("breaker removed", "name", name)
	return nil
}

// persistBreakers atomically writes the current breaker map to
// s.breakersPath in the shape the file watcher expects (flat map of
// name -> {state, reason}). Returns nil when no path is configured —
// the in-memory change still took effect; only durability is
// affected. Format matches breakers/watcher.go's fileEntry struct.
func (s *Server) persistBreakers() error {
	s.mu.RLock()
	path := s.breakersPath
	s.mu.RUnlock()
	if path == "" {
		return nil
	}
	rows := s.breakers.Snapshot()
	out := make(map[string]map[string]string, len(rows))
	for _, b := range rows {
		entry := map[string]string{"state": b.StateString}
		if b.Reason != "" {
			entry["reason"] = b.Reason
		}
		out[b.Name] = entry
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SetMaxConnections overrides the default connection limit. Used in tests to prevent port exhaustion.
func (s *Server) SetMaxConnections(max int64) {
	s.accept.SetMaxConnections(max)
}

// SetReplicationToken sets the bearer token required for subscribe_replication.
// Empty string disables replication subscription entirely.
func (s *Server) SetReplicationToken(token string) {
	s.walStore.SetReplicationToken(token)
}

// SetWebhookURL sets the endpoint for audit event POSTs. Empty string disables dispatching.
func (s *Server) SetWebhookURL(url string) {
	s.webhook.SetURL(url)
}

// SetWebhookRetryBackoff sets the initial backoff for webhook retries.
// Tests set a short value to avoid waiting on retry exhaustion.
func (s *Server) SetWebhookRetryBackoff(d time.Duration) {
	s.webhook.SetInitialBackoff(d)
}

// SetTLS enables TLS. Empty certFile triggers automatic self-signed certificate generation.
func (s *Server) SetTLS(certFile, keyFile string) error {
	return s.accept.SetTLS(certFile, keyFile)
}

func (s *Server) ListenAndServe(addr string) error {
	if err := s.accept.Listen(addr); err != nil {
		return err
	}

	ln := s.accept.Listener()
	tlsStr := "plaintext"
	if s.accept.TLSConfig() != nil {
		tlsStr = "TLS"
	}
	slog.Info("registry listening", "addr", ln.Addr(), "transport", tlsStr)
	close(s.readyCh)

	go s.reapLoop()
	go s.replMgr.StartHeartbeat(s.done)

	return s.accept.Accept(s.done)
}

// reapLoop removes nodes that have not sent a heartbeat recently.
// Runs every 10s instead of 60s, processing 10K nodes per tick (chunked reap).
// Full sweep completes in ~100s at 100K nodes, within 3-min stale threshold.
func (s *Server) reapLoop() {
	defer recoverHandler("reapLoop", nil)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.reapStaleNodes()
			s.reapStaleBeacons()
			s.accept.LogSamplerCleanup()
			s.accept.RateLimiterCleanup()
		case <-s.done:
			return
		}
	}
}

// reapChunkSize is how many nodes to process per reap tick.
const reapChunkSize = 10000

func (s *Server) reapStaleNodes() {
	threshold := s.now().Add(-s.StaleNodeThreshold())
	s.mu.Lock()
	defer s.mu.Unlock()

	nodeIDs := make([]uint32, 0, len(s.nodes))
	for id := range s.nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Slice(nodeIDs, func(i, j int) bool { return nodeIDs[i] < nodeIDs[j] })

	startIdx := 0
	for startIdx < len(nodeIDs) && nodeIDs[startIdx] < s.reapCursor {
		startIdx++
	}

	processed := 0
	reaped := false
	for i := 0; i < len(nodeIDs) && processed < reapChunkSize; i++ {
		idx := (startIdx + i) % len(nodeIDs)
		id := nodeIDs[idx]
		processed++

		node := s.nodes[id]
		lastSeen := node.GetLastSeen()
		if lastSeen.Before(threshold) {
			staleDuration := time.Since(lastSeen).Round(time.Second)
			slog.Info("registry reaping stale node", "node_id", id, "last_seen_ago", staleDuration)
			s.audit("node.reaped", "node_id", id, "reason", "stale_heartbeat",
				"last_seen_ago", staleDuration.String(), "networks", len(node.Networks))
			// Backbone membership is removed. Non-backbone memberships are kept
			// so re-registration can restore the node to its prior networks.
			if net, ok := s.networks[0]; ok {
				for j, m := range net.Members {
					if m == id {
						net.Members = append(net.Members[:j], net.Members[j+1:]...)
						break
					}
				}
			}
			// pubKeyIdx and ownerIdx are intentionally preserved so re-registration
			// reclaims the same node_id rather than allocating a new one.
			if node.Hostname != "" {
				delete(s.hostnameIdx, node.Hostname)
			}
			s.cleanupNode(id)
			delete(s.nodes, id)
			s.invalidateAdminListNodesCache()
			reaped = true
		}

		s.reapCursor = id + 1
	}

	if processed >= len(nodeIDs) {
		s.reapCursor = 0
	}

	if reaped {
		s.save()
	}
}

func (s *Server) reapStaleBeacons() {
	s.routing.ReapStale()
}

func (s *Server) Ready() <-chan struct{} {
	return s.readyCh
}

// Addr returns the bound address. Valid only after Ready() fires.
func (s *Server) Addr() net.Addr {
	ln := s.accept.Listener()
	if ln == nil {
		return nil
	}
	return ln.Addr()
}

func (s *Server) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	// Bound the wait on background loops. If a flushSave or replica push
	// is stuck (slow disk, peer stuck on write), we'd otherwise hang the
	// process indefinitely on shutdown. shutdownDrainTimeout is generous
	// enough for a normal final flush (synchronous disk write of the full
	// snapshot) but bounded so a misbehaving environment cannot wedge us.
	waitOrTimeout := func(name string, ch <-chan struct{}) {
		select {
		case <-ch:
		case <-time.After(shutdownDrainTimeout):
			slog.Warn("registry shutdown: background loop did not finish in time", "loop", name, "timeout", shutdownDrainTimeout)
		}
	}
	waitOrTimeout("saveLoop", s.walStore.SaveDone())
	waitOrTimeout("replicaPushLoop", s.walStore.ReplicaPushDone())
	s.walStore.Close()
	s.webhook.Close()
	s.auditStore.Close()
	if ln := s.accept.Listener(); ln != nil {
		return ln.Close()
	}
	return nil
}

func New(beaconAddr string) *Server {
	return NewWithStore(beaconAddr, "")
}

func NewWithStore(beaconAddr, storePath string) *Server {
	s := &Server{
		nodes:           make(map[uint32]*NodeInfo),
		networks:        make(map[uint16]*NetworkInfo),
		pubKeyIdx:       make(map[string]uint32),
		ownerIdx:        make(map[string]uint32),
		hostnameIdx:     make(map[string]uint32),
		maxNodes:        1_000_000,
		nextNode:        1, // 0 is reserved
		nextNet:         1, // 0 is backbone
		beaconAddr:      beaconAddr,
		storePath:       storePath,
		startTime:       time.Now(),
		inviteInbox:     make(map[uint32][]*NetworkInvite),
		beacons:         make(map[uint32]*beaconEntry),
		replMgr:         replpkg.NewManager(),
		deltaLog:        newDeltaLog(),
		metrics:         metrpkg.NewStore(RecoveredPanicCount),
		readyCh:         make(chan struct{}),
		done:            make(chan struct{}),
		now:             time.Now,
		netHourly:       make(map[uint16]*netHistoryRing),
		netDaily:        make(map[uint16]*netHistoryRing),
		listNodesPerNet: make(map[uint16]*listNodesCacheState),
		bus:             events.NewInProcessBus(0),
	}
	// Bridge bus publishes into the Prometheus counter without having
	// events/ import metrics/. The type-assert is checked because the
	// Bus interface only requires Publish; only the in-process impl
	// supports SetOnPublish.
	if op, ok := s.bus.(interface{ SetOnPublish(func()) }); ok {
		op.SetOnPublish(func() { s.metrics.EventBusPublish.Inc() })
	}
	// Per-source-type breakdown so operators can see what's actually
	// flowing through the bus (membership.changed vs trust.created vs
	// audit.entry). Source and Type both come from the publisher.
	if op, ok := s.bus.(interface{ SetOnPublishEvent(func(events.Event)) }); ok {
		op.SetOnPublishEvent(func(evt events.Event) {
			label := evt.Source + "." + evt.Type
			s.metrics.EventBusPublishByType.WithLabel(label).Inc()
		})
	}
	// Webhook stats — polled at scrape time. Returns ok=false when no
	// URL is configured so the metrics block is omitted entirely.
	s.metrics.WebhookStatsFn = func() (delivered, failed, dropped uint64, lastUnix int64, ok bool) {
		return s.webhook.Stats()
	}
	s.staleNodeThresholdNs.Store(int64(defaultStaleNodeThreshold))
	s.accept = acceptpkg.NewAcceptor(defaultMaxConnections, s) // R3.2: accept/TLS/rate-limit layer
	s.breakers = breakerspkg.New()                             // operator-controllable on/off switches; gated paths consult via Server.Breakers().Allow()
	s.authz = authzpkg.NewChecker("", "")                      // tokens set later via SetAdminToken / SetDashboardToken
	s.listNodesCache.Cond = sync.NewCond(&s.listNodesCache.Mu)
	s.routing = routing.NewStore(s)                    // R1.4: beacon/punch routing sub-package
	s.webhook = webhookpkg.NewStore()                  // R1.3: webhook sub-package
	s.webhook.Subscribe(s.bus)                         // fan-out audit.entry events → webhook HTTP POST
	s.auditStore = auditpkg.NewStore()                 // R1.2: audit sub-package
	s.auditStore.SetStorePath(s.storePath)             // enable audit-export WAL when persistence is configured
	s.auditStore.Subscribe(s.bus)                      // async ring-buffer + exporter fan-out
	s.trust = trustpkg.NewStore(s, trustpkg.Callbacks{ // R2.1: trust sub-package
		Save:                 s.save,
		Audit:                s.audit,
		IncTrustReports:      s.metrics.TrustReports.Inc,
		IncTrustRevocations:  s.metrics.TrustRevocations.Inc,
		IncHandshakeRequests: s.metrics.HandshakeRequests.Inc,
	})
	s.identity = identpkg.NewStore(s, identpkg.Callbacks{ // R2.3: identity sub-package
		Save:                s.save,
		Audit:               s.audit,
		IncKeyRotations:     s.metrics.KeyRotations.Inc,
		IncIDPVerifications: s.metrics.IdpVerifications.Inc,
		RecordWAL: func(nodeID uint32, newPubKeyB64, rotatedAt string, clearBadge bool) {
			s.recordWAL(DeltaKeyRotation, nodeID, keyRotationDelta{
				NodeID:       nodeID,
				NewPublicKey: newPubKeyB64,
				RotatedAt:    rotatedAt,
				ClearBadge:   clearBadge,
			})
		},
		OnKeyRotated: func(nodeID uint32, oldPubKeyB64, newPubKeyB64 string) {
			s.mu.Lock()
			delete(s.pubKeyIdx, oldPubKeyB64)
			s.pubKeyIdx[newPubKeyB64] = nodeID
			s.mu.Unlock()
		},
		Bus: s.bus,
	})
	s.policy = policypkg.NewStore( // R2.4: policy sub-package
		func(netID uint16) (policypkg.NetworkState, error) {
			s.mu.RLock()
			network, ok := s.networks[netID]
			if !ok {
				s.mu.RUnlock()
				return policypkg.NetworkState{}, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
			}
			state := policypkg.NetworkState{
				Policy: policypkg.NetworkPolicy{
					MaxMembers:   network.Policy.MaxMembers,
					AllowedPorts: append([]uint16(nil), network.Policy.AllowedPorts...),
					Description:  network.Policy.Description,
				},
				Expr:        append([]byte(nil), network.ExprPolicy...),
				MemberCount: len(network.Members),
			}
			s.mu.RUnlock()
			return state, nil
		},
		func(netID uint16, p policypkg.NetworkPolicy, expr policypkg.ExprPolicy) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			network, ok := s.networks[netID]
			if !ok {
				return fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
			}
			network.Policy = NetworkPolicy{
				MaxMembers:   p.MaxMembers,
				AllowedPorts: p.AllowedPorts,
				Description:  p.Description,
			}
			network.ExprPolicy = expr
			return nil
		},
		func(msg map[string]interface{}, netID uint16) error {
			return s.requireNetworkRole(msg, netID, RoleOwner, RoleAdmin)
		},
		s.requireEnterprise,
		policypkg.Callbacks{
			Save:             s.save,
			Audit:            s.audit,
			IncPolicyChanges: s.metrics.PolicyChanges.Inc,
		},
	)

	s.membership = membpkg.NewStore( // R4.1: membership sub-package
		&s.mu,
		s.networks,
		s.inviteInbox,
		&s.nextNet,
		membpkg.Callbacks{
			Save:  s.save,
			Audit: s.audit,
			RecordWALNetworkCreate: func(netID uint16, name, joinRule, token, adminToken string, enterprise bool, creatorNodeID uint32, createdAt string) {
				s.recordWAL(DeltaNetworkCreate, 0, networkCreateDelta{
					NetworkID:     netID,
					Name:          name,
					JoinRule:      joinRule,
					Token:         token,
					AdminToken:    adminToken,
					Enterprise:    enterprise,
					CreatorNodeID: creatorNodeID,
					CreatedAt:     createdAt,
				})
			},
			RecordWALNetworkJoin: func(nodeID uint32, netID uint16) {
				s.recordWAL(DeltaNetworkJoin, nodeID, networkMembershipDelta{
					NodeID:    nodeID,
					NetworkID: netID,
				})
			},
			RecordWALNetworkLeave: func(nodeID uint32, netID uint16) {
				s.recordWAL(DeltaNetworkLeave, nodeID, networkMembershipDelta{
					NodeID:    nodeID,
					NetworkID: netID,
				})
			},
			RecordWALNetworkDelete: func(netID uint16) {
				s.recordWAL(DeltaNetworkDelete, 0, networkDeleteDelta{NetworkID: netID})
			},
			InvalidateListNodesCache: s.invalidateListNodesCacheForNetwork,
			PublishMembershipChanged: s.publishMembershipChanged,
			ApplyRBACPreAssignment:   s.applyRBACPreAssignmentLocked,
			RequireAdminToken:        s.requireAdminToken,
			RequireNetworkRole: func(msg map[string]interface{}, netID uint16, roles ...membpkg.Role) error {
				srv := make([]Role, len(roles))
				for i, r := range roles {
					srv[i] = Role(r)
				}
				return s.requireNetworkRole(msg, netID, srv...)
			},
			RequireEnterprise: s.requireEnterprise,
			VerifyNodeSignature: func(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error {
				return authzpkg.VerifyNodeSignature(pubKey, adminToken, msg, challenge)
			},
			AdminToken: func() string {
				return s.authz.AdminToken()
			},
			NodeExists: func(nodeID uint32) bool {
				_, ok := s.nodes[nodeID]
				return ok
			},
			GetNode: func(nodeID uint32) (pubKey []byte, networks []uint16, externalID string, ok bool) {
				node, ok := s.nodes[nodeID]
				if !ok {
					return nil, nil, "", false
				}
				return node.PublicKey, node.Networks, node.ExternalID, true
			},
			NodeNetworks: func(nodeID uint32) ([]uint16, bool) {
				node, ok := s.nodes[nodeID]
				if !ok {
					return nil, false
				}
				return node.Networks, true
			},
			AppendNodeNetwork: func(nodeID uint32, netID uint16) {
				node, ok := s.nodes[nodeID]
				if !ok {
					return
				}
				sh := s.nodeShard(nodeID)
				sh.Lock()
				node.Networks = append(node.Networks, netID)
				sh.Unlock()
			},
			RemoveNodeNetwork: func(nodeID uint32, netID uint16) bool {
				node, ok := s.nodes[nodeID]
				if !ok {
					return false
				}
				sh := s.nodeShard(nodeID)
				sh.Lock()
				found := false
				for i, n := range node.Networks {
					if n == netID {
						node.Networks = append(node.Networks[:i], node.Networks[i+1:]...)
						found = true
						break
					}
				}
				sh.Unlock()
				return found
			},
			IncInvitesSent:     s.metrics.InvitesSent.Inc,
			IncInvitesAccepted: s.metrics.InvitesAccepted.Inc,
			IncInvitesRejected: s.metrics.InvitesRejected.Inc,
			IncRbacOps:         func(op string) { s.metrics.RbacOps.WithLabel(op).Inc() },
		},
		func() time.Time { return s.now() },
	)

	s.directory = dirpkg.NewStore( // R4.2: directory sub-package
		&s.mu,
		(*dirpkg.NodeShards)(&s.nodeShards),
		s.nodes,
		s.pubKeyIdx,
		s.ownerIdx,
		s.hostnameIdx,
		&s.nextNode,
		&s.maxNodes,
		&s.reapCursor,
		&s.listNodesCache,
		&s.listNodesPerNetMu,
		&s.listNodesPerNet,
		func(netID uint16) (dirpkg.NetworkMemberView, bool) {
			// Caller holds mu.RLock.
			network, ok := s.networks[netID]
			if !ok {
				return dirpkg.NetworkMemberView{}, false
			}
			members := make([]uint32, len(network.Members))
			copy(members, network.Members)
			roles := make(map[uint32]string, len(network.MemberRoles))
			for k, v := range network.MemberRoles {
				roles[k] = string(v)
			}
			tags := make(map[uint32][]string, len(network.MemberTags))
			for k, v := range network.MemberTags {
				tags[k] = append([]string(nil), v...)
			}
			return dirpkg.NetworkMemberView{Members: members, MemberRoles: roles, MemberTags: tags}, true
		},
		dirpkg.Callbacks{
			Save:  s.save,
			Audit: s.audit,
			RecordWALRegister: func(nodeID uint32, owner, pubKeyB64, realAddr, hostname string, lanAddrs []string, version, createdAt string) {
				s.recordWAL(DeltaRegister, nodeID, registerDelta{
					NodeID:    nodeID,
					Owner:     owner,
					PublicKey: pubKeyB64,
					RealAddr:  realAddr,
					Hostname:  hostname,
					LANAddrs:  lanAddrs,
					Version:   version,
					CreatedAt: createdAt,
				})
			},
			RecordWALDeregister: func(nodeID uint32) {
				s.recordWAL(DeltaDeregister, nodeID, deregisterDelta{NodeID: nodeID})
			},
			InvalidateListNodesCache:      s.invalidateListNodesCacheForNetwork,
			InvalidateAdminListNodesCache: s.invalidateAdminListNodesCache,
			PublishMembershipChanged:      s.publishMembershipChanged,
			RemoveFromNetworks: func(nodeID uint32, networks []uint16) []uint16 {
				var lostOwnerNets []uint16
				for _, netID := range networks {
					if net, ok := s.networks[netID]; ok {
						if net.MemberRoles[nodeID] == RoleOwner && len(net.Members) > 1 {
							lostOwnerNets = append(lostOwnerNets, netID)
						}
						for i, m := range net.Members {
							if m == nodeID {
								net.Members = append(net.Members[:i], net.Members[i+1:]...)
								break
							}
						}
						delete(net.MemberRoles, nodeID)
					}
				}
				return lostOwnerNets
			},
			ClearInviteInbox: func(nodeID uint32) {
				delete(s.inviteInbox, nodeID)
				for targetID, invites := range s.inviteInbox {
					remaining := make([]*NetworkInvite, 0, len(invites))
					for _, inv := range invites {
						if inv.InviterID != nodeID {
							remaining = append(remaining, inv)
						}
					}
					if len(remaining) == 0 {
						delete(s.inviteInbox, targetID)
					} else if len(remaining) < len(invites) {
						s.inviteInbox[targetID] = remaining
					}
				}
			},
			RequireAdminToken:       s.requireAdminToken,
			RequireAdminTokenLocked: s.requireAdminTokenLocked,
			AdminToken:              func() string { return s.authz.AdminToken() },
			VerifyNodeSignature:     s.verifyHeartbeatSignature,
			IsTrusted:               s.trust.IsTrusted,
			BeaconAddr:              func() string { return s.beaconAddr },
			IncRegistrations:        s.metrics.Registrations.Inc,
			IncDeregistrations:      s.metrics.Deregistrations.Inc,
			IncRequestsTotal:        func(label string) { s.metrics.RequestsTotal.WithLabel(label).Inc() },
			IncErrorsTotal:          func(label string) { s.metrics.ErrorsTotal.WithLabel(label).Inc() },
			ObserveRequestDuration:  func(label string, sec float64) { s.metrics.RequestDuration.WithLabel(label).Observe(sec) },
			Now:                     func() time.Time { return s.now() },
			AddNodeToBackbone: func(nodeID uint32) {
				// Caller holds mu.Lock. Only add if not already a member.
				backbone := s.networks[0]
				for _, m := range backbone.Members {
					if m == nodeID {
						return
					}
				}
				backbone.Members = append(backbone.Members, nodeID)
			},
			ScanNetworkMemberships: func(nodeID uint32) []uint16 {
				// Caller holds mu.Lock. Returns non-backbone networks that list nodeID.
				var nets []uint16
				for netID, net := range s.networks {
					if netID == 0 {
						continue
					}
					for _, m := range net.Members {
						if m == nodeID {
							nets = append(nets, netID)
							break
						}
					}
				}
				return nets
			},
		},
	)

	// Wire the event bus subscriber that invalidates the list_nodes cache
	// whenever any handler publishes "membership.changed". This is the
	// authoritative invalidation path for handlers that call s.publishMembershipChanged;
	// direct calls to invalidateListNodesCacheForNetwork in handlers ensure
	// synchronous correctness for existing code paths as well.
	{
		ch, unsubscribe := s.bus.Subscribe("membership.changed")
		go func() {
			defer unsubscribe()
			for {
				select {
				case evt, ok := <-ch:
					if !ok {
						return
					}
					if netID, ok := evt.Payload["net_id"].(uint16); ok {
						s.invalidateListNodesCacheForNetwork(netID)
					}
				case <-s.done:
					return
				}
			}
		}()
	}

	// Initialize WAL Store (R6.1): owns WAL file, save/replica-push goroutines,
	// standby flag, and replication token. The walPath is empty when no
	// persistence is configured, which causes NewStore to return a Store with
	// a nil WAL (all WAL operations become no-ops).
	{
		walPath := ""
		if storePath != "" {
			walPath = storePath + ".wal"
		}
		walCbs := walpkg.StoreCallbacks{
			FlushSave:       s.flushSave,
			SnapshotJSON:    s.snapshotJSON,
			Push:            s.replMgr.Push,
			IncSaveFailures: s.metrics.SaveFailures.Inc,
			HasReplicaSubs:  func() bool { return s.replMgr.SubCount() > 0 },
		}
		ws, err := walpkg.NewStore(walPath, s.done, walCbs)
		if err != nil {
			slog.Error("failed to initialize WAL store; falling back to no persistence", "err", err)
			var fbErr error
			ws, fbErr = walpkg.NewStore("", s.done, walCbs)
			if fbErr != nil {
				// NewStore("") only fails if its own goroutine startup fails,
				// which should never happen. Treat it as unrecoverable.
				panic(fmt.Sprintf("failed to initialize in-memory WAL store: %v", fbErr))
			}
		}
		s.walStore = ws
		ws.Start()
	}

	// Wire the package-level hooks that turn signature-verify outcomes
	// and rate-limit deny events into Prometheus counter increments.
	// The hooks are set once at boot; authz/ and accept/ stay free of
	// any metrics-package import.
	authzpkg.SetOnSignatureVerify(func(ok bool) {
		if ok {
			s.metrics.SignatureVerify.WithLabel("ok").Inc()
		} else {
			s.metrics.SignatureVerify.WithLabel("fail").Inc()
		}
	})
	acceptpkg.SetOnDeny(func(kind string) {
		s.metrics.RateLimitDenied.WithLabel(kind).Inc()
	})

	// Hook registry internals into /metrics so pilot_pubkeys_total,
	// pilot_wal_size_bytes, pilot_replication_term and
	// pilot_replication_is_standby render on each scrape. The closure
	// captures s; reads are under s.mu.RLock to stay consistent with the
	// rest of the API surface.
	s.metrics.RegistryInternalsFn = func() (uint64, uint64, uint64, bool, bool) {
		s.mu.RLock()
		pk := uint64(len(s.pubKeyIdx))
		term := s.term
		s.mu.RUnlock()
		var walSize uint64
		if s.walStore != nil && s.walStore.WAL() != nil {
			walSize = uint64(s.walStore.WAL().Size())
		}
		standby := s.walStore != nil && s.walStore.IsStandby()
		return pk, walSize, term, standby, true
	}
	// Mirror the same state on the admin endpoint so the dashboard's
	// replication panel doesn't have to grep the /metrics scrape.
	replSnap := func() dashpkg.ReplicationSnapshot {
		s.mu.RLock()
		term := s.term
		s.mu.RUnlock()
		subs := 0
		if s.replMgr != nil {
			subs = s.replMgr.SubCount()
		}
		standby := s.walStore != nil && s.walStore.IsStandby()
		return dashpkg.ReplicationSnapshot{
			Term:        term,
			IsStandby:   standby,
			Subscribers: subs,
		}
	}

	// Initialize dashboard Handler (R5.1): owns probe state, pulse ring,
	// maintenance banner, and the HTTP mux. Wired via Callbacks to avoid
	// circular imports between the server and dashboard packages.
	s.dashboard = dashpkg.NewHandler(dashpkg.Callbacks{
		GetDashboardToken: func() string { return s.authz.DashboardToken() },
		GetAdminToken:     func() string { return s.authz.AdminToken() },
		BuildStatsPayload: s.buildDashboardStatsPayload,
		GetNodes: func() []dashpkg.NodeSnapshot {
			s.mu.RLock()
			out := make([]dashpkg.NodeSnapshot, 0, len(s.nodes))
			for _, node := range s.nodes {
				out = append(out, dashpkg.NodeSnapshot{
					ID:       node.ID,
					Hostname: node.Hostname,
					LastSeen: node.GetLastSeen(),
				})
			}
			s.mu.RUnlock()
			return out
		},
		RequestCount: s.requestCount.Load,
		StartTime:    func() time.Time { return s.startTime },
		NodeCount:    func() int { s.mu.RLock(); n := len(s.nodes); s.mu.RUnlock(); return n },
		OnlineCount:  s.onlineCount,
		TotalEverRegistered: func() int64 {
			s.mu.RLock()
			defer s.mu.RUnlock()
			if s.nextNode == 0 {
				return 0
			}
			return int64(s.nextNode - 1)
		},
		BuildInfo:       s.BuildInfo,
		StaleThreshold:  s.StaleNodeThreshold,
		TriggerSnapshot: s.TriggerSnapshot,
		UpdateGauges:    func() { s.updateGauges(s.metrics) },
		WriteMetrics:    func(w io.Writer) { s.metrics.WriteTo(w) }, //nolint:errcheck
		ListenerAddr: func() string {
			if ln := s.accept.Listener(); ln != nil {
				return ln.Addr().String()
			}
			return ""
		},
		BeaconAddr: func() string { return s.beaconAddr },
		ReadyCh:    func() <-chan struct{} { return s.readyCh },
		Done:       func() <-chan struct{} { return s.done },
		Save:       s.save,
		BreakerAllow: func(name string) (bool, string) {
			if s.breakers == nil {
				return true, ""
			}
			allow, _ := s.breakers.Allow(name)
			return allow, s.breakers.Reason(name)
		},
		BreakerList:       s.BreakerList,
		BreakerSet:        s.BreakerSet,
		BreakerDelete:     s.BreakerDelete,
		HealthSnapshot:    s.HealthSnapshot,
		VerifyRequest: func(canonical, sigB64 string) interface{} {
			return s.VerifyRequest(canonical, sigB64)
		},
		VerifyKeys: func() []map[string]string {
			pub := s.VerdictPublicKey()
			if len(pub) == 0 {
				return nil
			}
			return []map[string]string{{
				"kid":        s.VerdictKid(),
				"algo":       "ed25519",
				"public_key": base64.StdEncoding.EncodeToString(pub),
			}}
		},
		ReplicationStatus: replSnap,
		NetworksList:      s.AdminListNetworks,
		MembersList:       s.AdminListMembers,
		MemberKick:        s.AdminKickMember,
		MemberRole:        s.AdminSetMemberRole,
		AuditRecent: func(n int) []dashpkg.AuditEntrySnapshot {
			s.auditMu.Lock()
			ring := make([]AuditEntry, len(s.auditLog))
			copy(ring, s.auditLog)
			s.auditMu.Unlock()
			if n > len(ring) {
				n = len(ring)
			}
			out := make([]dashpkg.AuditEntrySnapshot, 0, n)
			// Most recent first.
			for i := len(ring) - 1; i >= 0 && len(out) < n; i-- {
				e := ring[i]
				out = append(out, dashpkg.AuditEntrySnapshot{
					Timestamp: e.Timestamp,
					Action:    e.Action,
					NetworkID: e.NetworkID,
					NodeID:    e.NodeID,
					Details:   e.Details,
					Hash:      e.Hash,
				})
			}
			return out
		},
	})

	s.releasePoller = newReleasePoller("TeoSlayer/pilotprotocol")
	go s.dashboard.StatsCollectorLoop(s.readyCh, s.done, s.sampleStats, s.recordSample)
	go s.dashboard.PulseLoop()
	go s.heartbeatLoop()
	go s.dashboard.ProbeLoop()
	go s.releasePoller.run(s.done)

	// Try loading from disk
	if storePath != "" {
		loaded := false
		if err := s.load(); err != nil {
			slog.Info("registry starting fresh", "reason", err)
		} else {
			slog.Info("registry loaded state from disk",
				"nodes", len(s.nodes),
				"networks", len(s.networks),
				"next_node", s.nextNode,
				"next_net", s.nextNet,
			)
			loaded = true
		}
		// Replay WAL in both cases: entries after the last snapshot when one
		// exists, and entries written before the first-ever snapshot when the
		// server crashed before the first flush. Without this, a node registered
		// then lost before the first flush is silently dropped on restart.
		s.replayWAL()
		if loaded {
			return s
		}
		// Fall through to backbone creation for the fresh-start case.
	}

	// Create the backbone network (ID 0)
	s.networks[0] = &NetworkInfo{
		ID:       0,
		Name:     "backbone",
		JoinRule: "open",
		Members:  []uint32{},
		Created:  time.Now(),
	}

	return s
}
