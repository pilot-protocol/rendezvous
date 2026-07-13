// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dashboard implements the HTTP dashboard server, probe loop, and
// pulse-sample ring for the Pilot Protocol registry.
//
// Thread safety: all exported Handler methods are safe for concurrent use.
package dashboard

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/rendezvous/locks"
)

// --------------------------------------------------------------------------
// Probe state
// --------------------------------------------------------------------------

// ProbeState holds the health history for a single named probe.
type ProbeState struct {
	LastSuccess       int64      `json:"last_success,omitempty"`       // millis
	DowntimeIntervals [][2]int64 `json:"downtime_intervals,omitempty"` // pruned to 30d
	CurrentDownStart  int64      `json:"current_down_start,omitempty"` // 0 when up
}

// ProbeRetention is the maximum age of probe downtime intervals kept in memory
// and persisted to snapshots.
const ProbeRetention = 30 * 24 * time.Hour

const probeRetention = ProbeRetention

// PulseSample is one entry in the server-side 1/sec request-count ring.
type PulseSample struct {
	Ts    int64 `json:"ts"`
	Total int64 `json:"total"`
}

// --------------------------------------------------------------------------
// Callbacks
// --------------------------------------------------------------------------

// Callbacks bundles the side-effect functions Handler calls on the parent server.
// All functions must be safe for concurrent use.
type Callbacks struct {
	// GetDashboardToken returns the current dashboard token.
	GetDashboardToken func() string
	// GetAdminToken returns the current admin token.
	GetAdminToken func() string
	// BuildStatsPayload assembles the core /api/stats JSON payload (without
	// probe state and maintenance banner, which are owned by Handler).
	// The returned map is JSON-safe; callers must not mutate it.
	BuildStatsPayload func(authenticated bool) map[string]interface{}
	// GetNodes returns a snapshot of registered nodes for /api/nodes.
	GetNodes func() []NodeSnapshot
	// RequestCount returns the current total request count.
	RequestCount func() int64
	// StartTime returns when the server started.
	StartTime func() time.Time
	// NodeCount returns the number of registered nodes currently in the
	// in-memory map. Decays toward OnlineCount as the reaper deletes
	// stale entries (see server_lifecycle.reapStaleNodes).
	NodeCount func() int
	// OnlineCount returns the number of nodes online at or after threshold.
	OnlineCount func(threshold time.Time) int
	// TotalEverRegistered returns the cumulative count of node IDs ever
	// allocated by this registry (monotonic across reaps, persisted
	// across restarts via the snapshot's next_node counter). Surfaced on
	// /api/public-stats as total_nodes so it stays distinct from
	// active_nodes (which post-reap is identical to NodeCount).
	TotalEverRegistered func() int64
	// BuildInfo returns the build-time identity of the running binary
	// (version, git_commit, build_time, binary_sha256, go_version) so
	// /api/public-stats can publish a verifiable record of what code is
	// actually running. Returns nil when build info wasn't registered;
	// the handler then omits the build_info field entirely.
	BuildInfo func() map[string]string
	// StaleThreshold returns the configured stale-node threshold.
	StaleThreshold func() time.Duration
	// TriggerSnapshot triggers a snapshot save.
	TriggerSnapshot func() error
	// UpdateGauges updates Prometheus gauges before /metrics scrape.
	UpdateGauges func()
	// WriteMetrics writes Prometheus metrics to w.
	WriteMetrics func(w io.Writer)
	// ListenerAddr returns the registry TCP listener address for probeRegistry.
	// Returns "" when no listener is bound.
	ListenerAddr func() string
	// BeaconAddr returns the beacon UDP address for probeBeacon. "" = disabled.
	BeaconAddr func() string
	// ReadyCh returns the channel closed when the server is ready.
	ReadyCh func() <-chan struct{}
	// Done returns the channel closed on server shutdown.
	Done func() <-chan struct{}
	// Save triggers a debounced snapshot after probe state changes.
	Save func()
	// BreakerAllow consults the Server's breaker manager for the named
	// switch. Returns (allow, reason). Allowed=true means the gated path
	// should proceed; allowed=false means it should return 503 to the
	// caller with reason surfaced. Optional — when nil, every name is
	// implicitly allowed (default-Closed semantics, same as a missing
	// breakers.json).
	BreakerAllow func(name string) (allowed bool, reason string)
	// VerifyRequest verifies an external request-signature envelope
	// (reqsig canonical form) plus its base64 signature and returns the
	// JSON-serializable verification response (server.VerifyResponse).
	// nil disables POST /api/v1/verify.
	VerifyRequest func(canonical, sigB64 string) interface{}
	// VerifyKeys returns the verdict-issuer public keys published on
	// GET /api/v1/verify/keys. Each entry carries kid, algo, public_key.
	VerifyKeys func() []map[string]string
	// BreakerList returns the live snapshot for /api/breakers — one
	// entry per known name with state, reason, counters, last-denied
	// timestamp. Required for the read endpoint; nil disables it.
	BreakerList func() []BreakerListEntry
	// BreakerSet upserts one breaker by name, returning an error when
	// the state value is malformed. Reason is operator free-text. Used
	// by PUT /api/breakers/<name>. Writes to breakers.json on disk so
	// the change survives restart; the file watcher's next poll is a
	// no-op due to the matching mtime.
	BreakerSet func(name, state, reason string) error
	// BreakerDelete removes one breaker by name. Counters are
	// preserved so post-incident review still shows traffic that
	// flowed through the gate. Persists the change to breakers.json.
	BreakerDelete func(name string) error
	// HealthSnapshot returns a flat map of operator-facing health
	// signals: snapshot save telemetry, WAL size, snapshot.write
	// breaker state, replica subscriber count. Backs /api/health.
	// Optional — when nil, /api/health 503s.
	HealthSnapshot func() map[string]any
	// AuditRecent returns the most recent N audit-log entries from the
	// in-memory ring buffer (caller-supplied bound, server-clamped to a
	// safe maximum). Optional — when nil, /api/admin/audit/recent
	// returns an empty list.
	AuditRecent func(n int) []AuditEntrySnapshot

	// WhitelistGet returns the on-disk rate-limit whitelist as raw JSON
	// bytes (the exact contents of /var/lib/pilot/rate-limit-whitelist.json).
	// Optional — when nil, GET /api/admin/whitelist returns 404. When the
	// file does not exist on disk, the callback should return ([]byte("[]"),
	// nil) so the editor sees an empty list rather than an error.
	WhitelistGet func() ([]byte, error)
	// WhitelistSet atomically replaces the whitelist file with the given
	// JSON bytes. The on-disk watcher (cmd/rendezvous/whitelist_watcher.go)
	// picks the change up on its next 2 s poll, so the limiter is updated
	// without a restart. Optional — when nil, PUT /api/admin/whitelist
	// returns 405.
	WhitelistSet func(data []byte) error

	// GetLogLevel returns the current slog level ("debug", "info", "warn",
	// "error"). Optional — when nil, GET /api/admin/runtime/log-level
	// returns the static string "unknown".
	GetLogLevel func() string
	// SetLogLevel re-installs the default slog handler at the requested
	// level. The level string must be one of debug/info/warn/error
	// (case-insensitive); anything else returns an error and the previous
	// handler is left in place. Optional — when nil, PUT
	// /api/admin/runtime/log-level returns 405.
	SetLogLevel func(level string) error

	// ReplicationStatus returns a snapshot of the registry's replication
	// state — current term, standby flag, replica subscriber count, and
	// last replica push timestamp. Optional — when nil,
	// GET /api/admin/replication-status returns 404.
	ReplicationStatus func() ReplicationSnapshot
	// BackupsList returns metadata for snapshot backup files. Used to power
	// the dashboard's backup browser. Optional — when nil,
	// GET /api/admin/backups returns 404.
	BackupsList func() ([]BackupEntry, error)

	// MembersList returns a snapshot of the membership for the given
	// network — one entry per node with role, hostname (if registered),
	// and last-seen unix timestamp. Backs the GET
	// /api/admin/networks/{id}/members endpoint, which the dashboard's
	// operator-facing member browser consumes. Optional — when nil, the
	// endpoint returns 404 so a registry running without membership
	// admin wiring still serves the rest of the dashboard cleanly.
	// Errors are returned to the client as 500; protocol.ErrNetworkNotFound
	// surfaces as 404.
	MembersList func(netID uint16) ([]MemberSnapshot, error)
	// NetworksList returns a snapshot of every known network with both
	// the numeric ID and the human-readable name, plus per-role counts
	// and the enterprise / policy-set flags. Powers the dashboard's
	// network picker — without this the per-metric rollup (keyed by
	// label = name) doesn't know which numeric ID the management
	// endpoints (kick / set-role) need.
	// Backs GET /api/admin/networks. Optional; nil → endpoint 404.
	NetworksList func() []NetworkSnapshot
	// MemberKick removes the given node from the network's member list
	// and role map. The reason string is the operator's audit note (why
	// the action was taken) and is required — endpoints reject empty
	// reasons with 400 so post-incident review always has a paper trail.
	// Backs DELETE /api/admin/networks/{id}/members/{nodeID}?reason=...
	// Optional — when nil, the endpoint returns 404. Errors surface as
	// 400 (cannot kick owner, unknown member) or 500 (generic failures);
	// protocol.ErrNetworkNotFound surfaces as 404.
	MemberKick func(netID uint16, nodeID uint32, reason string) error
	// MemberRole updates the per-network role for the given node. Role
	// must be "admin" or "member" (case-insensitive); anything else
	// returns 400. Cannot demote the network owner — returns an error
	// the handler surfaces as 400. Reason is the operator's audit note.
	// Backs PUT /api/admin/networks/{id}/members/{nodeID}/role.
	// Optional — when nil, the endpoint returns 404. The role-validation
	// step is split between the dashboard handler (string accept set)
	// and the server callback (owner-demotion check) so the wire format
	// is policed at the edge.
	MemberRole func(netID uint16, nodeID uint32, role, reason string) error
}

// ReplicationSnapshot is the wire shape returned by /api/admin/replication-status.
type ReplicationSnapshot struct {
	Term            uint64 `json:"term"`
	IsStandby       bool   `json:"is_standby"`
	Subscribers     int    `json:"subscribers"`
	LastPushUnix    int64  `json:"last_push_unix,omitempty"`
	LastPushAgeSecs int64  `json:"last_push_age_secs,omitempty"`
}

// BackupEntry is the wire shape returned per file by /api/admin/backups.
type BackupEntry struct {
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
	ModUnix   int64  `json:"mod_unix"`
}

// AuditEntrySnapshot is the JSON-friendly shape returned by /api/admin/audit/recent.
// Lifted out of the server package so the dashboard doesn't import it directly.
// Fields mirror audit.Entry so the wire format is stable across releases.
type AuditEntrySnapshot struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	NetworkID uint16 `json:"network_id,omitempty"`
	NodeID    uint32 `json:"node_id,omitempty"`
	Details   string `json:"details,omitempty"`
	Hash      string `json:"hash,omitempty"`
}

// NodeSnapshot is a minimal node record for the /api/nodes endpoint.
type NodeSnapshot struct {
	ID       uint32
	Hostname string
	LastSeen time.Time
}

// MemberSnapshot is one row in the GET /api/admin/networks/{id}/members
// response. Hostname and LastSeenUnix are omitted when zero so the wire
// payload stays compact for members that have never registered a
// hostname or whose last_seen is unknown.
type MemberSnapshot struct {
	NodeID       uint32 `json:"node_id"`
	Role         string `json:"role"`
	Hostname     string `json:"hostname,omitempty"`
	LastSeenUnix int64  `json:"last_seen_unix,omitempty"`
}

// NetworkSnapshot is one row in the GET /api/admin/networks response.
// Powers the dashboard's network picker: the labeled /metrics rollup is
// keyed by network NAME but the management endpoints (kick / set role)
// take numeric IDs, so this endpoint surfaces both alongside the
// per-network role counts and the enterprise / policy-set flags.
type NetworkSnapshot struct {
	ID           uint16 `json:"id"`
	Name         string `json:"name"`
	MembersCount int    `json:"members_count"`
	AdminsCount  int    `json:"admins_count"`
	OwnersCount  int    `json:"owners_count"`
	Enterprise   bool   `json:"enterprise"`
	PolicySet    bool   `json:"policy_set"`
}

// BreakerListEntry is one row in the /api/breakers response. Marshalled
// as-is to JSON, so field tags pin the public wire format. Counters are
// monotonic since process start; LastDeniedAt is nil when DeniedTotal
// is 0.
type BreakerListEntry struct {
	Name         string     `json:"name"`
	State        string     `json:"state"`
	Reason       string     `json:"reason,omitempty"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
	AllowedTotal int64      `json:"allowed_total"`
	DeniedTotal  int64      `json:"denied_total"`
	LastDeniedAt *time.Time `json:"last_denied_at,omitempty"`
}

// --------------------------------------------------------------------------
// Handler
// --------------------------------------------------------------------------

// Handler owns the dashboard HTTP mux, probe state, pulse ring, and the
// maintenance banner. It is wired into the parent server via Callbacks.
type Handler struct {
	cb Callbacks

	// Maintenance banner (operator notice rendered on dashboard).
	bannerMu          sync.RWMutex
	maintenanceBanner string
	bannerPath        string

	// Per-IP rate limiter for public badge endpoints.
	badgeLimiter *ipRateLimiter

	// Per-IP rate limiters for the public verification endpoints.
	// Deliberately separate buckets from badgeLimiter (and from each
	// other) so verify traffic can't starve badge fetches or vice versa.
	verifyLimiter     *ipRateLimiter
	verifyKeysLimiter *ipRateLimiter

	// Probe state — per-probe health history ring.
	probeMu       sync.Mutex
	probeStates   map[string]*ProbeState
	httpProbeAddr string // injected via SetHTTPProbeAddr

	// Pulse ring — 2-minute 1/sec request-count sample ring.
	pulseMu      sync.Mutex
	pulseSamples [120]PulseSample
	pulseIdx     int
	pulseFilled  bool
}

// NewHandler creates a ready-to-use dashboard Handler backed by cb.
func NewHandler(cb Callbacks) *Handler {
	return &Handler{
		cb:                cb,
		badgeLimiter:      newIPRateLimiter(),
		verifyLimiter:     newIPRateLimiter(),
		verifyKeysLimiter: newIPRateLimiter(),
	}
}

// SetWhitelistCallbacks wires the GET/PUT /api/admin/whitelist endpoints
// after construction. The Handler is created early in NewWithStore (before
// main.go knows the whitelist path), so the cmd-level package installs the
// callbacks once both pieces exist. Either argument may be nil to leave
// that direction disabled.
func (h *Handler) SetWhitelistCallbacks(get func() ([]byte, error), set func([]byte) error) {
	h.cb.WhitelistGet = get
	h.cb.WhitelistSet = set
}

// SetLogLevelCallbacks wires the GET/PUT /api/admin/runtime/log-level
// endpoints after construction. The level lives in cmd/rendezvous/main.go
// (alongside logging.Setup) so cannot be set inside NewWithStore.
func (h *Handler) SetLogLevelCallbacks(get func() string, set func(string) error) {
	h.cb.GetLogLevel = get
	h.cb.SetLogLevel = set
}

// SetReplicationStatus wires the GET /api/admin/replication-status endpoint.
func (h *Handler) SetReplicationStatus(fn func() ReplicationSnapshot) {
	h.cb.ReplicationStatus = fn
}

// SetBackupsList wires the GET /api/admin/backups endpoint. The closure
// owns the directory path; the dashboard package only enumerates what it
// returns.
func (h *Handler) SetBackupsList(fn func() ([]BackupEntry, error)) {
	h.cb.BackupsList = fn
}

// --------------------------------------------------------------------------
// Maintenance banner
// --------------------------------------------------------------------------

// SetMaintenanceBanner sets a free-form notice rendered on the dashboard.
// Empty string clears it. If a bannerPath has been configured, the new
// value is atomically written to disk.
func (h *Handler) SetMaintenanceBanner(msg string) {
	h.bannerMu.Lock()
	h.maintenanceBanner = msg
	bp := h.bannerPath
	h.bannerMu.Unlock()
	if bp != "" {
		tmp := bp + ".tmp"
		if err := os.WriteFile(tmp, []byte(msg), 0644); err != nil {
			slog.Warn("banner persist write failed", "path", bp, "err", err)
			return
		}
		if err := os.Rename(tmp, bp); err != nil {
			slog.Warn("banner persist rename failed", "path", bp, "err", err)
		}
	}
}

// MaintenanceBanner returns the currently-set maintenance notice (or "").
func (h *Handler) MaintenanceBanner() string {
	h.bannerMu.RLock()
	defer h.bannerMu.RUnlock()
	return h.maintenanceBanner
}

// SetBannerPath wires a disk-persistence path for the maintenance banner.
// If the file already exists, its contents become the in-memory banner.
func (h *Handler) SetBannerPath(path string) {
	h.bannerMu.Lock()
	h.bannerPath = path
	h.bannerMu.Unlock()
	if data, err := os.ReadFile(path); err == nil {
		msg := strings.TrimRight(string(data), "\r\n")
		h.bannerMu.Lock()
		h.maintenanceBanner = msg
		h.bannerMu.Unlock()
	}
}

// --------------------------------------------------------------------------
// HTTP probe address
// --------------------------------------------------------------------------

// SetHTTPProbeAddr records the dashboard HTTP listen address so the probe
// loop knows where to dial for the dashboard + metrics probes.
func (h *Handler) SetHTTPProbeAddr(addr string) {
	h.probeMu.Lock()
	h.httpProbeAddr = addr
	h.probeMu.Unlock()
}

// --------------------------------------------------------------------------
// Probe state management
// --------------------------------------------------------------------------

var probeNames = []string{"registry", "beacon", "dashboard", "metrics"} //nolint:unused

func (h *Handler) runProbe(name string, ok bool) {
	now := time.Now().UnixMilli()
	cutoff := time.Now().Add(-probeRetention).UnixMilli()
	h.probeMu.Lock()
	defer h.probeMu.Unlock()
	if h.probeStates == nil {
		h.probeStates = map[string]*ProbeState{}
	}
	p := h.probeStates[name]
	if p == nil {
		p = &ProbeState{}
		h.probeStates[name] = p
	}
	// Prune intervals older than the retention window.
	if len(p.DowntimeIntervals) > 0 {
		kept := p.DowntimeIntervals[:0]
		for _, iv := range p.DowntimeIntervals {
			if iv[1] >= cutoff {
				kept = append(kept, iv)
			}
		}
		p.DowntimeIntervals = kept
	}
	if ok {
		p.LastSuccess = now
		if p.CurrentDownStart > 0 {
			p.DowntimeIntervals = append(p.DowntimeIntervals, [2]int64{p.CurrentDownStart, now})
			p.CurrentDownStart = 0
		}
	} else {
		if p.CurrentDownStart == 0 {
			p.CurrentDownStart = now
		}
	}
}

// GetProbeStates returns a deep-copy snapshot of all probe states.
func (h *Handler) GetProbeStates() map[string]*ProbeState {
	h.probeMu.Lock()
	defer h.probeMu.Unlock()
	if len(h.probeStates) == 0 {
		return nil
	}
	out := make(map[string]*ProbeState, len(h.probeStates))
	for k, v := range h.probeStates {
		cp := *v
		if len(v.DowntimeIntervals) > 0 {
			cp.DowntimeIntervals = append([][2]int64(nil), v.DowntimeIntervals...)
		}
		out[k] = &cp
	}
	return out
}

// SetProbeStates replaces the probe state map (used during snapshot restore).
func (h *Handler) SetProbeStates(states map[string]*ProbeState) {
	h.probeMu.Lock()
	h.probeStates = states
	h.probeMu.Unlock()
}

// --------------------------------------------------------------------------
// Individual probes
// --------------------------------------------------------------------------

func (h *Handler) probeRegistry() bool {
	addr := h.cb.ListenerAddr()
	if addr == "" {
		return false
	}
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func (h *Handler) probeBeacon() bool {
	beaconAddr := h.cb.BeaconAddr()
	if beaconAddr == "" {
		return false
	}
	target, err := net.ResolveUDPAddr("udp", beaconAddr)
	if err != nil {
		return false
	}
	c, err := net.DialUDP("udp", nil, target)
	if err != nil {
		return false
	}
	defer c.Close()
	// Reserved probe nodeID — kept high so it doesn't collide with real nodes.
	msg := make([]byte, 5)
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:], 0xFFFFFFFE)
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(msg); err != nil {
		return false
	}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil || n < 1 || buf[0] != protocol.BeaconMsgDiscoverReply {
		return false
	}
	return true
}

func (h *Handler) probeHTTP(path string) bool {
	h.probeMu.Lock()
	addr := h.httpProbeAddr
	h.probeMu.Unlock()
	if addr == "" {
		return false
	}
	if addr[0] == ':' {
		addr = "127.0.0.1" + addr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+addr+path, nil)
	if err != nil {
		return false
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

// ProbeLoop runs the 4 component probes at a steady cadence. Must be called
// in a separate goroutine (typically by the parent server).
func (h *Handler) ProbeLoop() {
	<-h.cb.ReadyCh()
	// Give listeners a moment to bind before first probe.
	time.Sleep(500 * time.Millisecond)
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	tick := func() {
		h.runProbe("registry", h.probeRegistry())
		h.runProbe("beacon", h.probeBeacon())
		h.runProbe("dashboard", h.probeHTTP("/healthz"))
		h.runProbe("metrics", h.probeHTTP("/metrics"))
		if h.cb.Save != nil {
			h.cb.Save()
		}
	}
	tick()
	for {
		select {
		case <-t.C:
			tick()
		case <-h.cb.Done():
			return
		}
	}
}

// --------------------------------------------------------------------------
// Pulse ring
// --------------------------------------------------------------------------

// RecentThroughput returns smoothed requests-per-second over the last
// `window` pulse samples (1 sample/sec). Returns 0 when there aren't yet
// two samples to differentiate or the span is zero.
func (h *Handler) RecentThroughput(window int) float64 {
	if window < 2 {
		window = 2
	}
	samples := h.GetPulseSamples()
	if len(samples) < 2 {
		return 0
	}
	if len(samples) < window {
		window = len(samples)
	}
	first := samples[len(samples)-window]
	last := samples[len(samples)-1]
	dtMs := last.Ts - first.Ts
	if dtMs <= 0 {
		return 0
	}
	dr := last.Total - first.Total
	if dr < 0 {
		return 0
	}
	return float64(dr) * 1000.0 / float64(dtMs)
}

// GetPulseSamples returns the ordered pulse samples from the ring buffer.
func (h *Handler) GetPulseSamples() []PulseSample {
	h.pulseMu.Lock()
	defer h.pulseMu.Unlock()
	n := len(h.pulseSamples)
	if !h.pulseFilled {
		out := make([]PulseSample, h.pulseIdx)
		copy(out, h.pulseSamples[:h.pulseIdx])
		return out
	}
	out := make([]PulseSample, 0, n)
	out = append(out, h.pulseSamples[h.pulseIdx:]...)
	out = append(out, h.pulseSamples[:h.pulseIdx]...)
	return out
}

// PulseLoop records one request-count sample per second into the ring.
// Must be called in a separate goroutine.
func (h *Handler) PulseLoop() {
	<-h.cb.ReadyCh()
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			sample := PulseSample{Ts: time.Now().UnixMilli(), Total: h.cb.RequestCount()}
			h.pulseMu.Lock()
			h.pulseSamples[h.pulseIdx] = sample
			h.pulseIdx++
			if h.pulseIdx >= len(h.pulseSamples) {
				h.pulseIdx = 0
				h.pulseFilled = true
			}
			h.pulseMu.Unlock()
		case <-h.cb.Done():
			return
		}
	}
}

// --------------------------------------------------------------------------
// HTTP helpers
// --------------------------------------------------------------------------

// readSmallBody reads up to maxBytes of the request body and trims trailing
// whitespace. Used by admin write endpoints.
func readSmallBody(r *http.Request, maxBytes int64) (string, error) {
	if r.Body == nil {
		return "", nil
	}
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > maxBytes {
		return "", fmt.Errorf("body too large (max %d bytes)", maxBytes)
	}
	return strings.TrimRight(string(data), "\r\n\t "), nil
}

// --------------------------------------------------------------------------
// Per-IP rate limiter for public endpoints (e.g. badge SVGs)
// --------------------------------------------------------------------------

// ipRateLimiter is a per-IP sliding-window rate limiter. Safe for concurrent use.
type ipRateLimiter struct {
	mu  sync.Mutex
	ips map[string]*ipBucket
}

type ipBucket struct {
	count   int
	resetAt time.Time
}

func newIPRateLimiter() *ipRateLimiter {
	return &ipRateLimiter{ips: make(map[string]*ipBucket)}
}

// extractClientIP returns the client IP, respecting X-Real-IP when the
// direct connection is from localhost.
func extractClientIP(r *http.Request) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remoteIP == "127.0.0.1" || remoteIP == "::1" || remoteIP == "localhost" {
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			return realIP
		}
	}
	return remoteIP
}

// middleware returns an http.HandlerFunc that rate-limits by client IP.
// maxReqs is the burst size; window is reset after it elapses.
func (l *ipRateLimiter) middleware(maxReqs int, window time.Duration, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := extractClientIP(r)

		l.mu.Lock()
		b, ok := l.ips[ip]
		now := time.Now()
		if !ok || now.After(b.resetAt) {
			l.ips[ip] = &ipBucket{count: 1, resetAt: now.Add(window)}
			l.mu.Unlock()
			next(w, r)
			return
		}
		if b.count >= maxReqs {
			l.mu.Unlock()
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		b.count++
		// Periodic sweep: every 1000th increment, purge expired entries.
		if b.count%1000 == 0 {
			for k, v := range l.ips {
				if now.After(v.resetAt) {
					delete(l.ips, k)
				}
			}
		}
		l.mu.Unlock()
		next(w, r)
	}
}

// localhostOnly rejects requests not originating from loopback.
// requireAdminToken wraps next so it returns 401 Unauthorized to anyone
// that doesn't present the operator-configured admin token. The token
// may be supplied via X-Admin-Token header (preferred for write paths)
// or admin_token=... query parameter (GET only — read-only convenience;
// mutations require the header to prevent CSRF from leaked URLs).
// When no admin token is configured on the server the wrapped path is
// locked shut entirely — operators must set -admin-token to enable access.
//
// Used to lock down the previously-public stats / pulse / badge /
// snapshot endpoints so polo.pilotprotocol.network can expose only the
// curated /api/public-stats payload to anonymous visitors while
// operators retain access to the full picture via the dashboard token.
func (h *Handler) requireAdminToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Admin-Token")
		// Query-param fallback only for GET (read-only, no CSRF risk).
		// POST/PUT/DELETE require the header so a leaked URL cannot
		// be used for cross-site mutation attacks.
		if token == "" && r.Method == http.MethodGet {
			token = r.URL.Query().Get("admin_token")
		}
		adminToken := h.cb.GetAdminToken()
		if adminToken == "" {
			http.Error(w, "admin token not configured", http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func localhostOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if remoteIP != "127.0.0.1" && remoteIP != "::1" && remoteIP != "localhost" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// --------------------------------------------------------------------------
// External request verification — /api/v1/verify
// --------------------------------------------------------------------------

// maxVerifyBodyBytes caps the POST /api/v1/verify request body. A canonical
// envelope plus base64 signature fits comfortably under 1 KB; 8 KB leaves
// headroom without letting anonymous callers stream junk.
const maxVerifyBodyBytes = 8 << 10

// registerVerifyRoutes registers the public verification endpoints on mux.
// Called from Serve; split out so tests can mount the routes on a bare mux
// without spinning up the full Serve lifecycle.
func (h *Handler) registerVerifyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/verify", h.verifyLimiter.middleware(60, time.Minute, h.handleVerify))
	mux.HandleFunc("/api/v1/verify/keys", h.verifyKeysLimiter.middleware(120, time.Minute, h.handleVerifyKeys))
}

// verifyBreakerDenied writes the 503 breaker payload (same shape as
// /api/public-stats) and reports whether the request was denied. Both
// verification endpoints share the single "dashboard.verify" switch.
func (h *Handler) verifyBreakerDenied(w http.ResponseWriter) bool {
	if h.cb.BreakerAllow == nil {
		return false
	}
	ok, reason := h.cb.BreakerAllow("dashboard.verify")
	if ok {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	body := map[string]string{"status": "unavailable"}
	if reason != "" {
		body["reason"] = reason
	}
	_ = json.NewEncoder(w).Encode(body)
	return true
}

// handleVerify serves POST /api/v1/verify — public (no admin token),
// breaker-gated, per-IP rate-limited. Body: {"envelope":"...","signature":"..."}.
// The response is the server's VerifyResponse; failures inside verification
// still return 200 with valid:false (uniform shape, no existence oracle).
func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.verifyBreakerDenied(w) {
		return
	}
	if h.cb.VerifyRequest == nil {
		http.Error(w, "verification not available", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxVerifyBodyBytes)
	defer r.Body.Close()
	var req struct {
		Envelope  string `json:"envelope"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// MaxBytesReader turns an oversized body into a read error, so
		// malformed JSON and oversized bodies both land here.
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Envelope == "" || req.Signature == "" {
		http.Error(w, "envelope and signature are required", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(h.cb.VerifyRequest(req.Envelope, req.Signature))
}

// handleVerifyKeys serves GET /api/v1/verify/keys — the verdict-issuer public
// keys, so consumers can pin them and check verdicts offline.
func (h *Handler) handleVerifyKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.verifyBreakerDenied(w) {
		return
	}
	keys := []map[string]string{}
	if h.cb.VerifyKeys != nil {
		if k := h.cb.VerifyKeys(); k != nil {
			keys = k
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": keys})
}

// --------------------------------------------------------------------------
// Serve
// --------------------------------------------------------------------------

// Serve starts an HTTP server serving the dashboard UI and stats API.
func (h *Handler) Serve(addr string) error {
	mux := h.buildMux()
	slog.Info("dashboard listening", "addr", addr)
	return http.ListenAndServe(addr, mux)
}

// buildMux constructs the dashboard's route table. Factored out of
// Serve so tests can exercise the real routes (e.g. the /api/stats
// auth path) against an httptest server without re-implementing
// registration and drifting from production wiring.
func (h *Handler) buildMux() *http.ServeMux {
	mux := http.NewServeMux()

	// /api/v1/verify + /api/v1/verify/keys — public external
	// request-signature verification (no admin token, breaker-gated,
	// per-IP rate-limited).
	h.registerVerifyRoutes(mux)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	})

	// /api/public-stats — anonymous, deliberately minimal payload for the
	// public website (polo.pilotprotocol.network). Curated to leak nothing
	// beyond aggregate node counts + uptime + per-component health. No
	// history, no per-IP, no badge counters, no traffic rate, no trust
	// links. Operator can hide the endpoint entirely by flipping the
	// `dashboard.public_stats` breaker open — useful during incidents
	// when even the headline numbers shouldn't go out publicly.
	mux.HandleFunc("/api/public-stats", func(w http.ResponseWriter, r *http.Request) {
		if h.cb.BreakerAllow != nil {
			if ok, reason := h.cb.BreakerAllow("dashboard.public_stats"); !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				body := map[string]string{"status": "unavailable"}
				if reason != "" {
					body["reason"] = reason
				}
				_ = json.NewEncoder(w).Encode(body)
				return
			}
		}
		now := time.Now()
		startTime := h.cb.StartTime()
		threshold := now.Add(-h.cb.StaleThreshold())

		probes := h.GetProbeStates()
		componentStatus := func(name string) string {
			p := probes[name]
			if p == nil {
				return "unknown"
			}
			if p.CurrentDownStart != 0 {
				return "down"
			}
			return "up"
		}

		// total_nodes deliberately uses the cumulative ever-registered
		// counter (TotalEverRegistered, == next_node-1), not NodeCount.
		// The reaper deletes stale entries from the in-memory map, so
		// NodeCount converges to OnlineCount within the stale-threshold
		// window — exposing both would mean reporting the same number
		// under two names.
		var totalNodes int64
		if h.cb.TotalEverRegistered != nil {
			totalNodes = h.cb.TotalEverRegistered()
		} else {
			totalNodes = int64(h.cb.NodeCount())
		}
		var totalRequests int64
		if h.cb.RequestCount != nil {
			totalRequests = h.cb.RequestCount()
		}
		// 10-sample (~10s) smoothed throughput. Two-sample noise is too
		// jumpy for a public dashboard; one minute is too slow to feel
		// "live."
		throughput := h.RecentThroughput(10)

		payload := map[string]interface{}{
			"server_time":      now.Unix(),
			"uptime_seconds":   int64(now.Sub(startTime).Seconds()),
			"active_nodes":     h.cb.OnlineCount(threshold),
			"total_nodes":      totalNodes,
			"total_requests":   totalRequests,
			"requests_per_sec": throughput,
			"components": map[string]string{
				"registry":  componentStatus("registry"),
				"beacon":    componentStatus("beacon"),
				"dashboard": componentStatus("dashboard"),
			},
		}
		if h.cb.BuildInfo != nil {
			if bi := h.cb.BuildInfo(); len(bi) > 0 {
				payload["build_info"] = bi
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_ = json.NewEncoder(w).Encode(payload)
	})

	// /api/stats — full rich payload (history, per-IP, etc.). Moved
	// behind admin auth so polo's public view only consumes
	// /api/public-stats. The dashboard-token branch is preserved so
	// authenticated operator views (network-tagged stats etc.) still
	// work via that token alongside the admin gate.
	mux.HandleFunc("/api/stats", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		// requireAdminToken (PR #50) already verified a valid admin
		// token reached this handler — so the caller is an authenticated
		// operator and gets the elevated per-network payload. The old
		// inner ?token= dashboard-token check became dead once the
		// endpoint moved behind the admin gate (the gate 401s anything
		// without the admin token first), and the dashboard frontend
		// sent ?token= which the gate ignored, so operator stats silently
		// 401'd. The frontend now sends admin_token=; this matches it.
		_ = json.NewEncoder(w).Encode(h.buildStatsResponse(true))
	}))

	mux.HandleFunc("/api/nodes", func(w http.ResponseWriter, r *http.Request) {
		remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if remoteIP != "127.0.0.1" && remoteIP != "::1" && remoteIP != "localhost" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		nodes := h.cb.GetNodes()
		items := make([]map[string]interface{}, 0, len(nodes))
		for _, node := range nodes {
			entry := map[string]interface{}{
				"node_id": node.ID,
				"address": protocol.Addr{Network: 0, Node: node.ID}.String(),
			}
			if node.Hostname != "" {
				entry["hostname"] = node.Hostname
			}
			entry["last_seen"] = node.LastSeen.Format(time.RFC3339)
			items = append(items, entry)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"nodes": items,
			"count": len(items),
		})
	})

	// /api/banner — admin-only management endpoint for the dashboard notice.
	// GET accepts the admin token via header X-Admin-Token or query admin_token=.
	// POST/PUT require X-Admin-Token header (no query fallback — CSRF protection).
	mux.HandleFunc("/api/banner", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Admin-Token")
		// Query-param fallback only for GET (read-only, no CSRF risk).
		if token == "" && r.Method == http.MethodGet {
			token = r.URL.Query().Get("admin_token")
		}
		adminToken := h.cb.GetAdminToken()
		if adminToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"banner": h.MaintenanceBanner(),
			})
		case http.MethodPut, http.MethodPost:
			body, err := readSmallBody(r, 8192)
			if err != nil {
				http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
				return
			}
			h.SetMaintenanceBanner(body)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":     true,
				"banner": body,
			})
		default:
			w.Header().Set("Allow", "GET, PUT, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// /api/breakers (admin) — list + control circuit breakers live.
	//
	// GET /api/breakers
	//   -> 200 {"breakers": [BreakerListEntry, ...]}
	//   Each entry has state/reason/updated_at + allowed_total /
	//   denied_total / last_denied_at since process start.
	//
	// PUT /api/breakers/<name>
	//   body: {"state": "closed|half_open|open", "reason": "..."}
	//   -> 200 {"ok": true, "breaker": BreakerListEntry}
	//   Persists to breakers.json so the change survives restart; the
	//   file watcher's next poll is a no-op via matching mtime.
	//
	// DELETE /api/breakers/<name>
	//   -> 200 {"ok": true}
	//   Removes the override; the gate reverts to default-closed
	//   (allow). Counters are preserved.
	//
	// Auth: requireAdminToken — same surface as /api/banner. PUT/DELETE
	// require X-Admin-Token header (no query-param fallback) so a leaked
	// referer can't flip a switch.
	mux.HandleFunc("/api/breakers", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if h.cb.BreakerList == nil {
			http.Error(w, "breaker manager not wired", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"breakers": h.cb.BreakerList(),
		})
	}))
	mux.HandleFunc("/api/breakers/", func(w http.ResponseWriter, r *http.Request) {
		// requireAdminToken's behaviour: GET accepts header OR
		// admin_token query param; PUT/DELETE force header to dodge
		// CSRF + referer leaks. Replicate that policy here directly
		// rather than over-wrap so the rule lives next to the code.
		token := r.Header.Get("X-Admin-Token")
		if token == "" && r.Method == http.MethodGet {
			token = r.URL.Query().Get("admin_token")
		}
		adminToken := h.cb.GetAdminToken()
		if adminToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/api/breakers/")
		if name == "" || strings.Contains(name, "/") {
			http.Error(w, "missing or invalid breaker name", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			if h.cb.BreakerSet == nil {
				http.Error(w, "breaker manager not wired", http.StatusServiceUnavailable)
				return
			}
			body, err := readSmallBody(r, 8192)
			if err != nil {
				http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
				return
			}
			var payload struct {
				State  string `json:"state"`
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal([]byte(body), &payload); err != nil {
				http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
				return
			}
			if err := h.cb.BreakerSet(name, payload.State, payload.Reason); err != nil {
				http.Error(w, "breaker set: "+err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"name": name,
			})
		case http.MethodDelete:
			if h.cb.BreakerDelete == nil {
				http.Error(w, "breaker manager not wired", http.StatusServiceUnavailable)
				return
			}
			if err := h.cb.BreakerDelete(name); err != nil {
				http.Error(w, "breaker delete: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"name": name,
			})
		default:
			w.Header().Set("Allow", "PUT, POST, DELETE")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// /api/runtime (admin) — process-level health + lock contention.
	// Reads Go's runtime/metrics package which is zero-overhead (sampled
	// by the runtime itself, no instrumentation needed). Surfaces the
	// signals operators actually care about:
	//   - goroutines: current count + GOMAXPROCS
	//   - memory:     heap_alloc, heap_objects, gc_cycles_total
	//   - locks:      mutex_wait_total (cumulative blocked time), sched
	//                 latency p50/p99 (goroutine scheduling delay; a
	//                 climbing p99 means the runtime is congested even
	//                 when CPU looks idle)
	//   - gc_pause:   p50/p99/max of stop-the-world pauses (last cycle)
	//   - fd_count:   from /proc/self/fd (Linux only; omitted elsewhere)
	mux.HandleFunc("/api/runtime", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(collectRuntimeMetrics())
	}))

	// /api/health (admin) — single curl-able operator health snapshot.
	// Aggregates the persistence + WAL + replication signals that today
	// require scraping the rich /api/stats or reading journald. Output
	// is a flat map so future fields can be added without versioning
	// the response shape.
	//
	// Fields surfaced (typical values, all optional — present only when
	// the Server has the corresponding subsystem):
	//
	//   snapshots_total              monotonic count of successful saves
	//   snapshots_failed             monotonic count of failed saves
	//   last_snapshot_at             unix-ms of last successful save
	//   last_snapshot_duration_ms    duration of last successful save
	//   last_snapshot_size_bytes     bytes written by last save
	//   last_snapshot_rlock_ms       s.mu.RLock hold time in phase 1
	//   max_snapshot_duration_ms     worst-ever save (process lifetime)
	//   wal_size_bytes               current WAL size (0 if not in use)
	//   wal_size_cap_bytes           configured WAL cap
	//   snapshot_write_breaker       "closed" | "half_open" | "open"
	//   replication_subscribers      live standby count
	mux.HandleFunc("/api/health", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if h.cb.HealthSnapshot == nil {
			http.Error(w, "health snapshot not wired", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(h.cb.HealthSnapshot())
	}))

	// /api/pulse — live request-count ring. Moved behind admin auth as
	// part of the polo public-stats lockdown; polo's public website
	// renders only /api/public-stats, which does not expose request
	// rate or any other operationally-revealing telemetry.
	mux.HandleFunc("/api/pulse", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ts":             time.Now().UnixMilli(),
			"total_requests": h.cb.RequestCount(),
			"samples":        h.GetPulseSamples(),
		})
	}))

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		nodeCount := h.cb.NodeCount()
		startTime := h.cb.StartTime()
		now := time.Now()
		onlineThreshold := now.Add(-h.cb.StaleThreshold())
		online := h.cb.OnlineCount(onlineThreshold)

		// Registry is healthy as long as it is running.
		healthy := nodeCount >= 0
		status := http.StatusOK
		statusStr := "ok"
		if !healthy {
			status = http.StatusServiceUnavailable
			statusStr = "unhealthy"
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":         statusStr,
			"version":        "1.0",
			"uptime_seconds": int64(now.Sub(startTime).Seconds()),
			"nodes_online":   online,
		})
	})

	serveBadge := func(w http.ResponseWriter, label, value, color string) {
		lw := int(float64(len(label))*6.5) + 10
		vw := int(float64(len(value))*6.5) + 10
		tw := lw + vw
		svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">`+
			`<title>%s: %s</title>`+
			`<linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>`+
			`<clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>`+
			`<g clip-path="url(#r)">`+
			`<rect width="%d" height="20" fill="#555"/>`+
			`<rect x="%d" width="%d" height="20" fill="%s"/>`+
			`<rect width="%d" height="20" fill="url(#s)"/>`+
			`</g>`+
			`<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">`+
			`<text aria-hidden="true" x="%d" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">%s</text>`+
			`<text x="%d" y="140" transform="scale(.1)">%s</text>`+
			`<text aria-hidden="true" x="%d" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">%s</text>`+
			`<text x="%d" y="140" transform="scale(.1)">%s</text>`+
			`</g></svg>`,
			tw, label, value,
			label, value,
			tw,
			lw,
			lw, vw, color,
			tw,
			lw*5, label,
			lw*5, label,
			lw*10+vw*5, value,
			lw*10+vw*5, value,
		)
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write([]byte(svg))
	}

	fmtCount := func(n int) string {
		switch {
		case n >= 1e9:
			return fmt.Sprintf("%.1fB", float64(n)/1e9)
		case n >= 1e6:
			return fmt.Sprintf("%.1fM", float64(n)/1e6)
		case n >= 1e3:
			return fmt.Sprintf("%.1fK", float64(n)/1e3)
		default:
			return fmt.Sprintf("%d", n)
		}
	}

	// Badge endpoints — moved behind admin auth as part of the polo
	// public-stats lockdown. Anyone embedding a badge in external docs
	// must now use a URL that includes ?admin_token=... or proxy the
	// fetch through an operator-controlled cache. Per-IP rate limit
	// kept in case the admin token leaks publicly.
	mux.HandleFunc("/api/badge/nodes", h.requireAdminToken(h.badgeLimiter.middleware(30, time.Minute, func(w http.ResponseWriter, r *http.Request) {
		payload := h.cb.BuildStatsPayload(false)
		activeNodes, _ := payload["active_nodes"].(int)
		c := "#4c1"
		if activeNodes == 0 {
			c = "#9f9f9f"
		}
		serveBadge(w, "online nodes", fmtCount(activeNodes), c)
	})))

	mux.HandleFunc("/api/badge/requests", h.requireAdminToken(h.badgeLimiter.middleware(30, time.Minute, func(w http.ResponseWriter, r *http.Request) {
		payload := h.cb.BuildStatsPayload(false)
		totalReqs, _ := payload["total_requests"].(int64)
		serveBadge(w, "requests", fmtCount(int(totalReqs)), "#a855f7")
	})))

	// Snapshot trigger endpoint (POST only, localhost only).
	mux.HandleFunc("/api/snapshot", func(w http.ResponseWriter, r *http.Request) {
		remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if remoteIP != "127.0.0.1" && remoteIP != "::1" && remoteIP != "localhost" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := h.cb.TriggerSnapshot(); err != nil {
			http.Error(w, fmt.Sprintf("snapshot failed: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"message": "snapshot saved successfully",
		})
	})

	// Prometheus metrics endpoint (localhost only — scraped by Alloy on the same host).
	mux.HandleFunc("/metrics", localhostOnly(func(w http.ResponseWriter, r *http.Request) {
		h.cb.UpdateGauges()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		h.cb.WriteMetrics(w)
	}))

	// pprof endpoints for live profiling (localhost only).
	mux.HandleFunc("/debug/pprof/", localhostOnly(pprof.Index))
	mux.HandleFunc("/debug/pprof/cmdline", localhostOnly(pprof.Cmdline))
	mux.HandleFunc("/debug/pprof/profile", localhostOnly(pprof.Profile))
	mux.HandleFunc("/debug/pprof/symbol", localhostOnly(pprof.Symbol))
	mux.HandleFunc("/debug/pprof/trace", localhostOnly(pprof.Trace))

	// /debug/locks: JSON snapshot of mutex/block contention, live lock waiters,
	// and runtime state. Pure stdlib, no instrumentation overhead — reads
	// what the runtime's existing sampling already collects. Useful for
	// alerting (cumulative mutex_wait_total_seconds, sched_latency_p99) and
	// for incident response (live_lock_waiters by call site).
	mux.HandleFunc("/debug/locks", localhostOnly(locks.Handler().ServeHTTP))

	// /api/admin/audit/recent: return the last N audit events from the in-memory
	// ring. Default N=100, max 1000.
	//   GET /api/admin/audit/recent?n=200
	//   -> {"count":N, "events":[{timestamp, action, network_id, node_id, details, hash}, ...]}
	// Admin token required (X-Admin-Token header or admin_token=… query for GET).
	mux.HandleFunc("/api/admin/audit/recent", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		n := 100
		if raw := r.URL.Query().Get("n"); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil && v > 0 {
				n = v
			}
		}
		if n > 1000 {
			n = 1000
		}
		var events []AuditEntrySnapshot
		if h.cb.AuditRecent != nil {
			events = h.cb.AuditRecent(n)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"count":  len(events),
			"events": events,
		})
	}))

	// /api/admin/runtime/gc: force a synchronous garbage-collection cycle.
	//   POST /api/admin/runtime/gc
	//   -> {"ok": true, "duration_ms": N}
	// Useful during incidents to confirm whether heap pressure is from
	// retention vs. allocation rate. Synchronous (blocks the request) so
	// the operator sees the wall time it took.
	mux.HandleFunc("/api/admin/runtime/gc", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		start := time.Now()
		runtime.GC()
		dur := time.Since(start)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":          true,
			"duration_ms": dur.Milliseconds(),
		})
	}))

	// /api/admin/runtime/profile-rates: tune mutex / block sampling at runtime.
	//   PUT /api/admin/runtime/profile-rates
	//     body: {"mutex_fraction": 100, "block_rate_ns": 1000}
	//   -> {"ok": true, "mutex_fraction": 100, "block_rate_ns": 1000}
	// mutex_fraction=0 disables mutex sampling; block_rate_ns=0 disables
	// block sampling. Default at boot is mutex_fraction=1000, block_rate_ns=10000.
	mux.HandleFunc("/api/admin/runtime/profile-rates", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			w.Header().Set("Allow", "PUT, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			MutexFraction *int   `json:"mutex_fraction"`
			BlockRateNs   *int64 `json:"block_rate_ns"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		// runtime.SetMutexProfileFraction(-1) reads current; runtime.SetBlockProfileRate has no read.
		mf := runtime.SetMutexProfileFraction(-1)
		if body.MutexFraction != nil {
			mf = runtime.SetMutexProfileFraction(*body.MutexFraction)
			mf = *body.MutexFraction
		}
		if body.BlockRateNs != nil {
			runtime.SetBlockProfileRate(int(*body.BlockRateNs))
		}
		w.Header().Set("Content-Type", "application/json")
		out := map[string]interface{}{"ok": true, "mutex_fraction": mf}
		if body.BlockRateNs != nil {
			out["block_rate_ns"] = *body.BlockRateNs
		}
		_ = json.NewEncoder(w).Encode(out)
	}))

	// /api/admin/runtime/log-level: get / set the slog level on the fly.
	//   GET  /api/admin/runtime/log-level -> {"level":"info"}
	//   PUT  /api/admin/runtime/log-level body {"level":"debug"} -> {"ok":true,"level":"debug"}
	// Set is gated on Callbacks.SetLogLevel (nil → 405); get falls back to
	// "unknown" if GetLogLevel is nil so the UI can still render without
	// requiring both callbacks.
	mux.HandleFunc("/api/admin/runtime/log-level", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			lvl := "unknown"
			if h.cb.GetLogLevel != nil {
				lvl = h.cb.GetLogLevel()
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"level": lvl})
		case http.MethodPut, http.MethodPost:
			if h.cb.SetLogLevel == nil {
				http.Error(w, "log-level setter not configured", http.StatusMethodNotAllowed)
				return
			}
			var body struct {
				Level string `json:"level"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 256)).Decode(&body); err != nil {
				http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
				return
			}
			if err := h.cb.SetLogLevel(body.Level); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "level": body.Level})
		default:
			w.Header().Set("Allow", "GET, PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	// /api/admin/whitelist: read / replace the rate-limit whitelist file.
	//   GET /api/admin/whitelist
	//     -> raw JSON contents of /var/lib/pilot/rate-limit-whitelist.json
	//        (the file watcher's on-disk schema: [{"cidr":...,"rate":...}]).
	//        If the file does not exist, the callback returns []. Either
	//        way the body is structured as {"entries":[…]} for client
	//        ergonomics.
	//   PUT /api/admin/whitelist body {"entries":[…]} or [{"cidr":…,"rate":…}]
	//     -> {"ok":true,"count":N}
	//        The body is written atomically (tmp + rename); the existing
	//        2 s watcher poll picks up the new state without restart.
	mux.HandleFunc("/api/admin/whitelist", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if h.cb.WhitelistGet == nil {
				http.Error(w, "whitelist getter not configured", http.StatusNotFound)
				return
			}
			data, err := h.cb.WhitelistGet()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// Pass-through the array as `entries`. If decode fails (e.g. file
			// is malformed) return raw with empty entries so the editor can
			// still recover; the parse error is visible in the body.
			var entries []map[string]any
			parseErr := ""
			if err := json.Unmarshal(data, &entries); err != nil {
				parseErr = err.Error()
				entries = []map[string]any{}
			}
			w.Header().Set("Content-Type", "application/json")
			out := map[string]interface{}{"entries": entries, "count": len(entries)}
			if parseErr != "" {
				out["parse_error"] = parseErr
				out["raw"] = string(data)
			}
			_ = json.NewEncoder(w).Encode(out)
		case http.MethodPut, http.MethodPost:
			if h.cb.WhitelistSet == nil {
				http.Error(w, "whitelist setter not configured", http.StatusMethodNotAllowed)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
				return
			}
			// Accept either {"entries":[…]} or a bare array. Re-serialise
			// to the file watcher's canonical shape (an array of objects)
			// so the on-disk format is consistent regardless of input shape.
			var asObj struct {
				Entries []map[string]any `json:"entries"`
			}
			var arr []map[string]any
			if err := json.Unmarshal(body, &asObj); err == nil && asObj.Entries != nil {
				arr = asObj.Entries
			} else if err := json.Unmarshal(body, &arr); err != nil {
				http.Error(w, "bad request: body must be {entries:[…]} or [{cidr,rate}…]: "+err.Error(), http.StatusBadRequest)
				return
			}
			canonical, err := json.MarshalIndent(arr, "", "  ")
			if err != nil {
				http.Error(w, "marshal: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if err := h.cb.WhitelistSet(canonical); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "count": len(arr)})
		default:
			w.Header().Set("Allow", "GET, PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	// /api/admin/replication-status: term, role (primary/standby), subscriber
	// count, last replica push timestamp. Read-only — primary/standby
	// transitions happen through the existing /api/standby/promote path.
	mux.HandleFunc("/api/admin/replication-status", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if h.cb.ReplicationStatus == nil {
			http.Error(w, "not configured", http.StatusNotFound)
			return
		}
		snap := h.cb.ReplicationStatus()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snap)
	}))

	// /api/admin/backups: list snapshot backup files (name, size, mtime).
	// Path is fixed by the operator at boot (typically /var/lib/pilot/backups/);
	// the endpoint only enumerates — never reads, downloads, or deletes.
	mux.HandleFunc("/api/admin/backups", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if h.cb.BackupsList == nil {
			http.Error(w, "not configured", http.StatusNotFound)
			return
		}
		entries, err := h.cb.BackupsList()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var total int64
		for _, e := range entries {
			total += e.SizeBytes
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"count":            len(entries),
			"total_size_bytes": total,
			"entries":          entries,
		})
	}))

	// /api/admin/networks (no trailing slash) — list all networks with
	// numeric ID + name + role counts. Powers the dashboard's network
	// picker so the per-network management endpoints (which take numeric
	// IDs) have a discoverable source.
	mux.HandleFunc("/api/admin/networks", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if h.cb.NetworksList == nil {
			http.Error(w, "not configured", http.StatusNotFound)
			return
		}
		list := h.cb.NetworksList()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"count":    len(list),
			"networks": list,
		})
	}))

	// /api/admin/networks/{id}/members[/<nodeID>[/role]]
	//
	// Three operator-only endpoints that bypass the protocol's network-role
	// RBAC: the admin token holder IS the registry operator, so they are
	// implicitly the highest authority over every network. This is the
	// path we route to when the network's own owner is unreachable or has
	// to be force-replaced.
	//
	//   GET    /api/admin/networks/{id}/members
	//   DELETE /api/admin/networks/{id}/members/{nodeID}?reason=...
	//   PUT    /api/admin/networks/{id}/members/{nodeID}/role  body {"role":"admin|member"}
	//
	// Path parsing is done inline (strings.Split on the trimmed tail)
	// because adding a router dependency for three routes isn't worth it.
	mux.HandleFunc("/api/admin/networks/", h.requireAdminToken(h.serveMembershipAdmin))

	return mux
}

// serveMembershipAdmin dispatches the three /api/admin/networks/{id}/members*
// endpoints. Path parsing is intentionally tolerant — trailing slashes are
// trimmed, the trailing "role" segment is recognised only for PUT — so a
// stray slash from a curl invocation doesn't 404.
func (h *Handler) serveMembershipAdmin(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/api/admin/networks/")
	tail = strings.TrimSuffix(tail, "/")
	parts := strings.Split(tail, "/")
	// Expected shapes:
	//   {id}/members                          → GET list
	//   {id}/members/{nodeID}                 → DELETE kick
	//   {id}/members/{nodeID}/role            → PUT set-role
	if len(parts) < 2 || parts[1] != "members" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	netID64, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		http.Error(w, "bad request: network id must be uint16", http.StatusBadRequest)
		return
	}
	netID := uint16(netID64)

	switch len(parts) {
	case 2:
		// GET /api/admin/networks/{id}/members[?limit=N&offset=N&q=substring]
		// Pagination + name search added because the backbone network can
		// be 200k+ members on a production registry; returning the whole
		// list would be ~30 MB JSON.
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if h.cb.MembersList == nil {
			http.Error(w, "not configured", http.StatusNotFound)
			return
		}
		members, err := h.cb.MembersList(netID)
		if err != nil {
			if errors.Is(err, protocol.ErrNetworkNotFound) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		total := len(members)

		// Optional substring filter against hostname OR stringified node ID.
		// Case-insensitive; an empty q is a no-op so the cheap path stays cheap.
		if q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q"))); q != "" {
			filtered := make([]MemberSnapshot, 0, len(members))
			for _, m := range members {
				if strings.Contains(strings.ToLower(m.Hostname), q) ||
					strings.Contains(strconv.FormatUint(uint64(m.NodeID), 10), q) {
					filtered = append(filtered, m)
				}
			}
			members = filtered
		}
		filtered := len(members)

		// Limit defaults to 200 (small enough to render fast, large enough
		// to be useful). Hard-cap at 5000 so a single bad request can't
		// pull 30 MB.
		limit := 200
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if v, perr := strconv.Atoi(raw); perr == nil && v > 0 {
				limit = v
			}
		}
		if limit > 5000 {
			limit = 5000
		}
		offset := 0
		if raw := r.URL.Query().Get("offset"); raw != "" {
			if v, perr := strconv.Atoi(raw); perr == nil && v >= 0 {
				offset = v
			}
		}
		if offset > len(members) {
			offset = len(members)
		}
		end := offset + limit
		if end > len(members) {
			end = len(members)
		}
		page := members[offset:end]

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"network_id":     netID,
			"count":          len(page),
			"total":          total,
			"filtered_total": filtered,
			"offset":         offset,
			"limit":          limit,
			"members":        page,
		})

	case 3:
		// DELETE /api/admin/networks/{id}/members/{nodeID}
		if r.Method != http.MethodDelete {
			w.Header().Set("Allow", "DELETE")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if h.cb.MemberKick == nil {
			http.Error(w, "not configured", http.StatusNotFound)
			return
		}
		nodeID64, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			http.Error(w, "bad request: node id must be uint32", http.StatusBadRequest)
			return
		}
		reason := strings.TrimSpace(r.URL.Query().Get("reason"))
		if reason == "" {
			http.Error(w, "bad request: reason is required", http.StatusBadRequest)
			return
		}
		if err := h.cb.MemberKick(netID, uint32(nodeID64), reason); err != nil {
			if errors.Is(err, protocol.ErrNetworkNotFound) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":         true,
			"network_id": netID,
			"node_id":    uint32(nodeID64),
		})

	case 4:
		// PUT /api/admin/networks/{id}/members/{nodeID}/role
		if parts[3] != "role" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			w.Header().Set("Allow", "PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if h.cb.MemberRole == nil {
			http.Error(w, "not configured", http.StatusNotFound)
			return
		}
		nodeID64, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			http.Error(w, "bad request: node id must be uint32", http.StatusBadRequest)
			return
		}
		var body struct {
			Role   string `json:"role"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		role := strings.ToLower(strings.TrimSpace(body.Role))
		if role != "admin" && role != "member" {
			http.Error(w, "bad request: role must be \"admin\" or \"member\"", http.StatusBadRequest)
			return
		}
		if err := h.cb.MemberRole(netID, uint32(nodeID64), role, body.Reason); err != nil {
			if errors.Is(err, protocol.ErrNetworkNotFound) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":         true,
			"network_id": netID,
			"node_id":    uint32(nodeID64),
			"role":       role,
		})

	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// --------------------------------------------------------------------------
// Stats response assembly
// --------------------------------------------------------------------------

// buildStatsResponse assembles the /api/stats JSON payload by merging the
// core stats from BuildStatsPayload with the probe state and maintenance
// banner owned by Handler.
func (h *Handler) buildStatsResponse(authenticated bool) map[string]interface{} {
	payload := h.cb.BuildStatsPayload(authenticated)
	// Overlay maintenance_banner from Handler (operator notice managed here).
	payload["maintenance_banner"] = h.MaintenanceBanner()
	// Overlay probe state from Handler (moved off Server in R5.1).
	if probes := h.GetProbeStates(); len(probes) > 0 {
		payload["probes"] = probes
	}
	return payload
}

// --------------------------------------------------------------------------
// Dashboard HTML
// --------------------------------------------------------------------------

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pilot Protocol — Network Status</title>
<style>
:root{
  --bg:#0a0e17; --panel:#161b22; --panel2:#0d1117;
  --border:#21262d; --border2:#30363d;
  --text:#c9d1d9; --text2:#e6edf3;
  --muted:#8b949e; --muted2:#484f58;
  --accent:#58a6ff; --good:#3fb950;
  --grid:#21262d;
}
html[data-theme="light"]{
  --bg:#ffffff; --panel:#f6f8fa; --panel2:#ffffff;
  --border:#d0d7de; --border2:#afb8c1;
  --text:#1f2328; --text2:#0d1117;
  --muted:#656d76; --muted2:#8c959f;
  --accent:#0969da; --good:#1a7f37;
  --grid:#d8dee4;
}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'SF Mono','Fira Code','Cascadia Code',monospace;font-size:14px;line-height:1.6;transition:background 0.2s,color 0.2s}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}

.container{max-width:960px;margin:0 auto;padding:24px 16px}

header{padding:16px 0;border-bottom:1px solid var(--border);margin-bottom:32px;display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
header h1{font-size:20px;font-weight:600;color:var(--text2)}
.uptime{font-size:12px;color:var(--muted);margin-top:4px}
.svc-bar-wrap{position:relative;display:inline-block}
.svc-bar-tip{position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:var(--panel);border:1px solid var(--border2);border-radius:4px;padding:6px 9px;font-size:11px;color:var(--text);white-space:nowrap;z-index:50;box-shadow:0 4px 12px rgba(0,0,0,0.3);pointer-events:none;display:none}
.svc-bar-wrap:hover .svc-bar-tip{display:block}
.svc-bar-tip .v{color:var(--text2);font-variant-numeric:tabular-nums}
.svc-bar.partial{background:#f59e0b;opacity:0.85}
.svc-bar.down{background:#ef4444;opacity:0.9}
.svc-bar.inactive{background:var(--border);opacity:0.4}
.banner-stack{display:flex;flex-direction:column;gap:8px;margin-bottom:16px}
.release-banner{background:linear-gradient(90deg,rgba(88,166,255,0.12),rgba(88,166,255,0.04));border:1px solid rgba(88,166,255,0.4);border-left:3px solid var(--accent);border-radius:6px;padding:10px 14px;font-size:13px;color:var(--text);display:flex;align-items:center;gap:10px}
.release-banner.maintenance{background:linear-gradient(90deg,rgba(245,158,11,0.14),rgba(245,158,11,0.04));border:1px solid rgba(245,158,11,0.45);border-left:3px solid #f59e0b}
.release-banner .rb-dot{width:8px;height:8px;border-radius:50%;background:var(--accent);box-shadow:0 0 8px var(--accent);flex-shrink:0;animation:rbPulse 2s ease-in-out infinite}
.release-banner.maintenance .rb-dot{background:#f59e0b;box-shadow:0 0 8px #f59e0b}
.release-banner .rb-ver{color:var(--text2);font-weight:600}
.release-banner .rb-label{font-weight:600;margin-right:4px}
@keyframes rbPulse{0%,100%{opacity:1}50%{opacity:0.45}}
.theme-toggle{background:var(--panel);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:6px 10px;font-family:inherit;font-size:12px;cursor:pointer;line-height:1}
.theme-toggle:hover{border-color:var(--accent);color:var(--accent)}

.stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:32px}
.stat-card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px;text-align:center}
.stat-card .value{font-size:32px;font-weight:700;color:var(--text2);display:block}
.stat-card .label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin-top:4px}

.token-bar{display:flex;align-items:center;gap:8px;margin-top:8px}
.token-bar input{background:var(--panel2);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:4px 8px;font-family:inherit;font-size:12px;width:180px}
.token-bar input::placeholder{color:var(--muted2)}
.token-bar button{background:var(--panel);border:1px solid var(--border2);border-radius:4px;color:var(--text);padding:4px 10px;font-family:inherit;font-size:12px;cursor:pointer}
.token-bar button:hover{border-color:var(--accent);color:var(--accent)}
.token-bar .status{font-size:11px;color:var(--muted2)}
.token-bar .status.ok{color:var(--good)}

.networks{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:32px;display:none}
.networks h2{font-size:14px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px}
.networks table{width:100%;border-collapse:collapse}
.networks th{text-align:left;font-size:11px;color:var(--muted2);text-transform:uppercase;letter-spacing:0.5px;padding:6px 8px;border-bottom:1px solid var(--border)}
.networks td{font-size:13px;color:var(--text);padding:6px 8px;border-bottom:1px solid var(--panel)}
.networks tr:hover td{background:var(--panel2)}
.net-id{color:var(--muted);font-size:11px}

.system-row{display:grid;grid-template-columns:3fr 2fr;gap:16px;margin-bottom:32px}
.system-card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px}
.system-card h2{font-size:14px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px}

.svc-row{display:grid;grid-template-columns:140px 1fr auto;gap:12px;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)}
.svc-row:last-child{border-bottom:none}
.svc-name{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text)}
.svc-dot{width:8px;height:8px;border-radius:50%;background:var(--good);box-shadow:0 0 6px var(--good)}
.svc-dot.degraded{background:#f59e0b;box-shadow:0 0 6px #f59e0b}
.svc-dot.down{background:#ef4444;box-shadow:0 0 6px #ef4444}
.svc-bars{display:flex;gap:1px;height:28px}
.svc-bar-wrap{flex:1;position:relative;display:block;height:100%}
.svc-bar{display:block;width:100%;height:100%;background:var(--good);border-radius:1px;opacity:0.85;transition:opacity 0.2s}
.svc-bar-wrap:hover .svc-bar{opacity:1}
.svc-bar.unknown{background:var(--border2);opacity:0.4}
.svc-bar.degraded{background:#f59e0b}
.svc-bar.blip{background:#f59e0b;opacity:1;box-shadow:0 0 5px rgba(245,158,11,0.7)}
.svc-uptime{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums;min-width:60px;text-align:right}

.pulse-wrap{display:flex;align-items:baseline;gap:6px;margin-bottom:8px}
.pulse-val{font-size:28px;font-weight:700;color:var(--text2);font-variant-numeric:tabular-nums}
.pulse-unit{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px}
.pulse-strip{display:flex;align-items:flex-end;gap:1px;height:48px;background:var(--panel2);border:1px solid var(--border);border-radius:4px;padding:4px}
.pulse-bar{flex:1;background:var(--accent);border-radius:1px 1px 0 0;min-height:1px;opacity:0.7}
.pulse-bar.live{opacity:1;filter:drop-shadow(0 0 4px var(--accent));animation:pulseGlow 1.2s ease-in-out infinite alternate}
@keyframes pulseGlow{from{opacity:0.7;filter:drop-shadow(0 0 2px var(--accent))}to{opacity:1;filter:drop-shadow(0 0 6px var(--accent))}}
.pulse-meta{font-size:11px;color:var(--muted2);margin-top:6px;display:flex;justify-content:space-between}

@media(max-width:640px){
  .system-row{grid-template-columns:1fr}
}


.charts-row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:32px}
.chart-card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px}
.chart-card.full{grid-column:1/-1}
.chart-card h2{font-size:14px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px}
.chart-card .disclaimer{font-size:11px;color:var(--muted2);margin-bottom:8px}
.chart-card svg{width:100%;display:block}
.chart-tooltip{position:absolute;background:var(--border);border:1px solid var(--border2);border-radius:4px;padding:4px 8px;font-size:11px;color:var(--text2);pointer-events:none;white-space:nowrap;display:none;z-index:10}

@media(max-width:900px){
  .charts-row{grid-template-columns:1fr}
}

footer{text-align:center;padding:24px 0;border-top:1px solid var(--border);margin-top:32px;font-size:12px;color:var(--muted2)}
.build-info{margin-top:10px;font-family:ui-monospace,Menlo,Monaco,monospace;font-size:10.5px;line-height:1.5;color:var(--muted2);word-break:break-all}
.build-info .bi-row{display:inline-block;margin:0 8px}
.build-info .bi-label{color:var(--muted2);opacity:0.7}
.build-info .bi-val{color:var(--ink)}
.build-info a{color:var(--ink);text-decoration:none;border-bottom:1px dotted var(--muted2)}
footer a{color:var(--muted2)}
footer a:hover{color:var(--accent)}

@media(max-width:640px){
  .stats-row{grid-template-columns:repeat(2,1fr)}
  .networks table{font-size:12px}
  header{flex-direction:column}
}
</style>
</head>
<body>
<div class="container">

<div class="banner-stack" id="banner-stack" style="display:none"></div>

<header>
  <div>
    <h1>Pilot Protocol</h1>
    <div class="uptime">Uptime: <span id="uptime">—</span></div>
    <div class="token-bar">
      <input type="password" id="token-input" placeholder="Dashboard token" autocomplete="off">
      <button id="token-btn" onclick="toggleToken()">Unlock</button>
      <span class="status" id="token-status"></span>
    </div>
  </div>
  <button class="theme-toggle" id="theme-toggle" onclick="toggleTheme()" aria-label="Toggle theme" title="Toggle theme">◐</button>
</header>

<div class="stats-row">
  <div class="stat-card">
    <span class="value" id="total-requests">—</span>
    <span class="label">Total Requests</span>
  </div>
  <div class="stat-card">
    <span class="value" id="total-nodes">—</span>
    <span class="label">Total Nodes</span>
  </div>
  <div class="stat-card">
    <span class="value" id="active-nodes">—</span>
    <span class="label">Online Nodes</span>
  </div>
</div>

<div class="system-row">
  <div class="system-card">
    <h2>System Status</h2>
    <div id="services"></div>
  </div>
  <div class="system-card">
    <h2>Live Throughput</h2>
    <div class="pulse-wrap">
      <span class="pulse-val" id="pulse-now">—</span>
      <span class="pulse-unit">req/s</span>
    </div>
    <div class="pulse-strip" id="pulse-strip"></div>
    <div class="pulse-meta"><span>60s window</span><span>peak <span id="pulse-peak">—</span> req/s</span></div>
  </div>
</div>

<div class="charts-row" id="charts-row" style="display:none">
  <div class="chart-card">
    <h2>Online Nodes — Last 24 Hours</h2>
    <div class="disclaimer">Since last registry restart</div>
    <div style="position:relative">
      <svg id="chart-hourly" viewBox="0 0 400 180" preserveAspectRatio="xMidYMid meet"></svg>
      <div class="chart-tooltip" id="tip-hourly"></div>
    </div>
  </div>
  <div class="chart-card">
    <h2>Online Nodes — Last 7 Days</h2>
    <div class="disclaimer">Since last registry restart</div>
    <div style="position:relative">
      <svg id="chart-weekly" viewBox="0 0 400 180" preserveAspectRatio="xMidYMid meet"></svg>
      <div class="chart-tooltip" id="tip-weekly"></div>
    </div>
  </div>
</div>


<div class="networks" id="networks">
  <h2>Networks</h2>
  <table>
    <thead><tr><th>Network</th><th>Members</th><th>Online</th><th>Requests</th></tr></thead>
    <tbody id="net-tbody"></tbody>
  </table>
</div>

<footer>
  Pilot Protocol &middot;
  <a href="https://pilotprotocol.network">pilotprotocol.network</a> &middot;
  <a href="https://github.com/pilot-protocol/pilotprotocol">GitHub</a>
  <div id="build-info" class="build-info" style="display:none"></div>
</footer>

</div>
<script>
function fmt(n){if(n>=1e9)return(n/1e9).toFixed(1)+'B';if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return n.toString()}
function uptimeStr(s){var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);var p=[];if(d)p.push(d+'d');if(h)p.push(h+'h');p.push(m+'m');return p.join(' ')}
function fmtDateTime(ms){var d=new Date(ms);var M=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];var pad=function(n){return n<10?'0'+n:''+n};return M[d.getMonth()]+' '+d.getDate()+', '+d.getFullYear()+' '+pad(d.getHours())+':'+pad(d.getMinutes())}
function escapeHtml(s){return String(s||'').replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function renderBanner(b,maint){
  var stack=document.getElementById('banner-stack');
  if(!stack)return;
  var html='';
  if(maint){
    html+='<div class="release-banner maintenance"><span class="rb-dot"></span><span>'+escapeHtml(maint)+'</span></div>';
  }
  if(b&&b.version){
    html+='<div class="release-banner"><span class="rb-dot"></span><span>Update <span class="rb-ver">'+escapeHtml(b.version)+'</span> propagating across network, peers may be unreachable.</span></div>';
  }
  if(!html){stack.style.display='none';stack.innerHTML='';return}
  stack.innerHTML=html;
  stack.style.display='flex';
}
function renderBuildInfo(bi){
  var el=document.getElementById('build-info');
  if(!el||!bi){if(el){el.style.display='none';el.innerHTML=''}return}
  var commit=bi.git_commit||'';
  var commitHTML=commit?('<a href="https://github.com/pilot-protocol/rendezvous/commit/'+encodeURIComponent(commit)+'" title="View commit on GitHub" target="_blank" rel="noopener">'+escapeHtml(commit)+'</a>'):'(unset)';
  var sha=bi.binary_sha256||'';
  var shaShort=sha?sha.substring(0,12)+'…':'(unset)';
  var shaTitle=sha?('Full SHA256: '+sha):'';
  var html=''+
    '<div class="bi-row"><span class="bi-label">version</span> <span class="bi-val">'+escapeHtml(bi.version||'(unset)')+'</span></div>'+
    '<div class="bi-row"><span class="bi-label">commit</span> <span class="bi-val">'+commitHTML+'</span></div>'+
    '<div class="bi-row" title="'+escapeHtml(shaTitle)+'"><span class="bi-label">sha256</span> <span class="bi-val">'+escapeHtml(shaShort)+'</span></div>';
  if(bi.go_version){
    html+='<div class="bi-row"><span class="bi-label">go</span> <span class="bi-val">'+escapeHtml(bi.go_version)+'</span></div>';
  }
  if(bi.build_time){
    html+='<div class="bi-row"><span class="bi-label">built</span> <span class="bi-val">'+escapeHtml(bi.build_time)+'</span></div>';
  }
  el.innerHTML=html;
  el.style.display='block';
}
function getToken(){return localStorage.getItem('pilot_dash_token')||''}
function setToken(t){if(t)localStorage.setItem('pilot_dash_token',t);else localStorage.removeItem('pilot_dash_token')}
function toggleToken(){
  var inp=document.getElementById('token-input');
  var btn=document.getElementById('token-btn');
  if(getToken()){setToken('');inp.value='';btn.textContent='Unlock';document.getElementById('token-status').textContent='';document.getElementById('token-status').className='status';document.getElementById('networks').style.display='none';update();return}
  var t=inp.value.trim();if(!t)return;
  setToken(t);btn.textContent='Lock';update();
}
function initToken(){
  var t=getToken();
  if(t){document.getElementById('token-input').value=t;document.getElementById('token-btn').textContent='Lock'}
}
function renderNetworks(networks){
  var wrap=document.getElementById('networks');
  var tbody=document.getElementById('net-tbody');
  if(!networks||!networks.length){wrap.style.display='none';var st=document.getElementById('token-status');if(getToken()){st.textContent='invalid token';st.className='status'}return}
  wrap.style.display='block';
  var st=document.getElementById('token-status');st.textContent='authenticated';st.className='status ok';
  var html='';
  networks.forEach(function(n){
    html+='<tr><td>'+escapeHtml(n.name)+' <span class="net-id">#'+n.id+'</span></td><td>'+fmt(n.members)+'</td><td>'+fmt(n.online)+'</td><td>'+fmt(n.requests)+'</td></tr>';
  });
  tbody.innerHTML=html;
}
function themeVar(name,fallback){
  var v=getComputedStyle(document.documentElement).getPropertyValue(name);
  return (v&&v.trim())||fallback;
}
function drawChart(svg,tip,samples,valFn,labelFn,color,unit,zoomY){
  if(!svg)return;
  var accent=themeVar('--accent','#58a6ff');
  var good=themeVar('--good','#3fb950');
  var grid=themeVar('--grid','#21262d');
  var muted2=themeVar('--muted2','#484f58');
  var bg=themeVar('--panel','#161b22');
  if(color==='accent')color=accent;
  else if(color==='good')color=good;
  color=color||accent;
  unit=unit||'online';
  if(!samples||!samples.length){svg.innerHTML='';return}
  var vb=(svg.getAttribute('viewBox')||'0 0 400 180').split(/\s+/);
  var W=parseFloat(vb[2])||400,H=parseFloat(vb[3])||180;
  var padL=40,padR=14,padT=10,padB=30;
  var cW=W-padL-padR,cH=H-padT-padB;
  var vals=samples.map(valFn);
  var maxV=Math.max.apply(null,vals);
  var minV=Math.min.apply(null,vals);
  if(maxV===0)maxV=1;
  var gridMin=0,gridMax,step;
  if(zoomY&&maxV>minV){
    var gridSpan=maxV-minV;
    step=Math.pow(10,Math.floor(Math.log10(gridSpan||1)));
    if(gridSpan/step<2)step=step/4;
    else if(gridSpan/step<5)step=step/2;
    gridMin=Math.floor(minV/step)*step;
    gridMax=Math.ceil(maxV/step)*step;
  }else{
    step=Math.pow(10,Math.floor(Math.log10(maxV||1)));
    if(maxV/step<2)step=step/4;
    else if(maxV/step<5)step=step/2;
    gridMax=Math.ceil(maxV/step)*step;
  }
  if(gridMax<=gridMin)gridMax=gridMin+1;
  var range=gridMax-gridMin;
  var html='';
  for(var g=gridMin;g<=gridMax+step*0.001;g+=step){
    var gy=padT+cH-((g-gridMin)/range)*cH;
    html+='<line x1="'+padL+'" y1="'+gy+'" x2="'+(W-padR)+'" y2="'+gy+'" stroke="'+grid+'" stroke-width="1"/>';
    html+='<text x="'+(padL-4)+'" y="'+(gy+4)+'" fill="'+muted2+'" font-size="10" text-anchor="end" font-family="monospace">'+g+'</text>';
  }
  var pts=[];
  for(var i=0;i<vals.length;i++){
    var x=padL+(vals.length>1?i/(vals.length-1):0.5)*cW;
    var y=padT+cH-((vals[i]-gridMin)/range)*cH;
    pts.push(x.toFixed(1)+','+y.toFixed(1));
  }
  var polyPts=pts.join(' ');
  var firstX=padL+(vals.length>1?0:0.5)*cW;
  var lastX=padL+(vals.length>1?1:0.5)*cW;
  var areaFill=firstX.toFixed(1)+','+(padT+cH)+' '+polyPts+' '+lastX.toFixed(1)+','+(padT+cH);
  html+='<polygon points="'+areaFill+'" fill="'+color+'" fill-opacity="0.15"/>';
  html+='<polyline points="'+polyPts+'" fill="none" stroke="'+color+'" stroke-width="2"/>';
  var lblStep=Math.max(1,Math.ceil(vals.length/7));
  for(var i=0;i<vals.length;i++){
    var x=padL+(vals.length>1?i/(vals.length-1):0.5)*cW;
    var y=padT+cH-((vals[i]-gridMin)/range)*cH;
    html+='<circle cx="'+x.toFixed(1)+'" cy="'+y.toFixed(1)+'" r="3" fill="'+color+'" stroke="'+bg+'" stroke-width="1.5"/>';
    var lbl=labelFn(samples[i]);
    var showLbl=(i%lblStep===0)||(i===vals.length-1);
    if(showLbl){
      var anchor='middle';
      if(i===0)anchor='start';
      else if(i===vals.length-1)anchor='end';
      html+='<text x="'+x.toFixed(1)+'" y="'+(padT+cH+16)+'" fill="'+muted2+'" font-size="9" text-anchor="'+anchor+'" font-family="monospace">'+escapeHtml(lbl)+'</text>';
    }
    var rw=cW/(vals.length||1);
    html+='<rect x="'+(x-rw/2).toFixed(1)+'" y="'+padT+'" width="'+rw.toFixed(1)+'" height="'+cH+'" fill="transparent" data-val="'+vals[i]+'" data-lbl="'+escapeHtml(lbl)+'" data-x="'+x.toFixed(1)+'"/>';
  }
  svg.innerHTML=html;
  if(tip){
    svg.querySelectorAll('rect[data-val]').forEach(function(r){
      r.addEventListener('mouseenter',function(){
        tip.textContent=r.getAttribute('data-lbl')+': '+r.getAttribute('data-val')+' '+unit;
        tip.style.display='block';
        var svgRect=svg.getBoundingClientRect();
        var px=parseFloat(r.getAttribute('data-x'))/W*svgRect.width;
        tip.style.left=(px+4)+'px';tip.style.top='0px';
      });
      r.addEventListener('mouseleave',function(){tip.style.display='none'});
    });
  }
}
function renderCharts(hourly,daily){
  var row=document.getElementById('charts-row');
  if((!hourly||!hourly.length)&&(!daily||!daily.length)){row.style.display='none';return}
  row.style.display='grid';
  drawChart(document.getElementById('chart-hourly'),document.getElementById('tip-hourly'),hourly||[],function(s){return s.online_nodes||0},function(s){
    var d=new Date(s.ts*1000);return ('0'+d.getHours()).slice(-2)+':00';
  },'accent','online',true);
  var d7=(daily||[]).slice(-7);
  drawChart(document.getElementById('chart-weekly'),document.getElementById('tip-weekly'),d7,function(s){return s.online_nodes||0},function(s){
    var d=new Date(s.ts*1000);return ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][d.getDay()]+' '+d.getDate();
  },'accent','online',true);
}
function update(){
  // Polo public-stats lockdown (PR #50): /api/stats moved behind admin
  // token. This embedded dashboard now drives off /api/public-stats,
  // which carries server_time, uptime_seconds, active_nodes, total_nodes,
  // and components{}. Anything the old payload supplied that isn't in
  // /api/public-stats (total_requests, hourly/daily history, networks,
  // restart_events, release_banner, dashboard-token-gated per-network
  // counts) is intentionally absent from the public view — operators
  // who need the full picture can curl /api/stats?admin_token=...
  // directly. Token-aware dashboard-token path retained for operators
  // who set one in localStorage.
  var t=getToken();
  // /api/stats is admin-gated (PR #50). The operator's stored token is
  // the admin token (same one /api/pulse uses below), so send it as
  // admin_token to clear the gate. Without this the request was sent as
  // ?token= — which the admin gate ignores — and silently 401'd.
  var url=t?('/api/stats?admin_token='+encodeURIComponent(t)):'/api/public-stats';
  fetch(url).then(function(r){
    if(!r.ok)return null;
    return r.json();
  }).then(function(d){
    if(!d)return;
    if(d.total_requests!=null)document.getElementById('total-requests').textContent=fmt(d.total_requests);
    document.getElementById('total-nodes').textContent=fmt(d.total_nodes||0);
    document.getElementById('active-nodes').textContent=fmt(d.active_nodes||0);
    document.getElementById('uptime').textContent=uptimeStr(d.uptime_seconds||d.uptime_secs||0);
    // /api/public-stats reports components{registry,beacon,dashboard}
    // with status strings; the old /api/stats path uses probes{} with
    // last_success timestamps. renderServices handles either via the
    // components mapping below.
    var probes=d.probes||{};
    if(d.components){
      Object.keys(d.components).forEach(function(name){
        probes[name]=probes[name]||{};
        // synthesise a fresh last_success so renderServices treats
        // "up" components as healthy regardless of probe ring state
        if(d.components[name]==='up')probes[name].last_success=Date.now();
      });
    }
    renderServices(d.uptime_seconds||d.uptime_secs||0,d.restart_events,probes);
    renderBanner(d.release_banner,d.maintenance_banner);
    if(d.hourly||d.daily)renderCharts(d.hourly,d.daily);
    if(d.networks)renderNetworks(d.networks);
    renderBuildInfo(d.build_info);
  }).catch(function(){})
}
function renderServices(uptimeSecs,restartEvents,probes){
  var el=document.getElementById('services');if(!el)return;
  var services=[
    {key:'registry',name:'Registry'},
    {key:'beacon',name:'Beacon Relay'},
    {key:'dashboard',name:'Dashboard API'},
    {key:'metrics',name:'Metrics'},
  ];
  var now=Date.now();
  var processStart=now-(uptimeSecs||0)*1000;
  var retention=30*86400000;
  var earliestGlobal=processStart;
  (restartEvents||[]).forEach(function(t){if(t<earliestGlobal)earliestGlobal=t});
  if(earliestGlobal<now-retention)earliestGlobal=now-retention;
  var startOfToday=new Date();startOfToday.setHours(0,0,0,0);
  var startToday=startOfToday.getTime();
  var months=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  var restartDownMs=5000;
  var restartIntervals=(restartEvents||[]).map(function(t){return [t-restartDownMs/2,t+restartDownMs/2]});
  function computeDays(ps){
    var intervals=((ps&&ps.downtime_intervals)||[]).concat(restartIntervals);
    if(ps&&ps.current_down_start>0){
      intervals=intervals.concat([[ps.current_down_start,now]]);
    }
    var earliest=earliestGlobal;
    if(ps&&ps.last_success>0&&ps.last_success<earliest)earliest=ps.last_success;
    var days=[],totalDownMs=0,totalCoverMs=0;
    for(var d=29;d>=0;d--){
      var dayStart=startToday-d*86400000;
      var dayEnd=dayStart+86400000;
      var coverStart=Math.max(dayStart,earliest);
      var coverEnd=Math.min(dayEnd,now);
      var coverMs=Math.max(0,coverEnd-coverStart);
      if(coverMs<=0){
        days.push({dayStart:dayStart,state:'inactive',upPct:null,downMs:0,coverMs:0,restarts:0});
        continue;
      }
      var downMs=0;
      intervals.forEach(function(iv){
        if(!iv||iv.length!==2)return;
        var a=Math.max(coverStart,iv[0]);
        var b=Math.min(coverEnd,iv[1]);
        if(b>a)downMs+=(b-a);
      });
      if(downMs>coverMs)downMs=coverMs;
      var upPct=(coverMs-downMs)/coverMs*100;
      var restartsOnDay=0;
      (restartEvents||[]).forEach(function(t){if(t>=dayStart&&t<dayEnd)restartsOnDay++});
      var state='ok';
      if(upPct<95)state='down';
      else if(upPct<100||restartsOnDay>0)state='partial';
      days.push({dayStart:dayStart,state:state,upPct:upPct,downMs:downMs,coverMs:coverMs,restarts:restartsOnDay});
      totalDownMs+=downMs;totalCoverMs+=coverMs;
    }
    var pct=totalCoverMs>0?((totalCoverMs-totalDownMs)/totalCoverMs*100):100;
    return {days:days,pct:pct};
  }
  var html='';
  services.forEach(function(svc){
    var ps=(probes&&probes[svc.key])||null;
    var r=computeDays(ps);
    var bars='';
    r.days.forEach(function(day){
      var cls=day.state==='ok'?'':day.state;
      var dt=new Date(day.dayStart);
      var dateStr=months[dt.getMonth()]+' '+dt.getDate();
      var tip='';
      if(day.state==='inactive'){
        tip='<div class="v">'+dateStr+'</div><div>no data</div>';
      }else{
        tip='<div class="v">'+dateStr+'</div><div>uptime: <span class="v">'+day.upPct.toFixed(2)+'%</span></div>';
        if(day.downMs>0)tip+='<div>downtime: <span class="v">'+fmtDur(day.downMs)+'</span></div>';
        if(day.restarts>0)tip+='<div>restarts: <span class="v">'+day.restarts+'</span></div>';
      }
      bars+='<span class="svc-bar-wrap"><span class="svc-bar '+cls+'"></span><span class="svc-bar-tip">'+tip+'</span></span>';
    });
    var live=ps&&ps.current_down_start>0?'down':'ok';
    html+='<div class="svc-row">'+
      '<span class="svc-name"><span class="svc-dot '+(live!=='ok'?live:'')+'"></span>'+svc.name+'</span>'+
      '<div class="svc-bars">'+bars+'</div>'+
      '<span class="svc-uptime">'+r.pct.toFixed(2)+'%</span>'+
      '</div>';
  });
  el.innerHTML=html;
}
function fmtDur(ms){
  if(ms<60000)return Math.round(ms/1000)+'s';
  if(ms<3600000)return Math.round(ms/60000)+'m';
  if(ms<86400000)return (ms/3600000).toFixed(1)+'h';
  return (ms/86400000).toFixed(1)+'d';
}
var _pulseSamples=[];
var _pulsePeak=0;
function renderPulse(){
  var strip=document.getElementById('pulse-strip');if(!strip)return;
  var N=60;
  while(_pulseSamples.length>N)_pulseSamples.shift();
  var rates=[];
  for(var i=1;i<_pulseSamples.length;i++){
    var dt=(_pulseSamples[i].ts-_pulseSamples[i-1].ts)/1000;
    var dr=_pulseSamples[i].total-_pulseSamples[i-1].total;
    if(dt>0&&dr>=0)rates.push(dr/dt);
  }
  var maxR=Math.max.apply(null,rates.concat([1]));
  if(maxR>_pulsePeak)_pulsePeak=maxR;
  var html='';
  for(var i=0;i<N;i++){
    var idx=rates.length-N+i;
    if(idx<0){html+='<div class="pulse-bar" style="height:1px"></div>';continue}
    var h=Math.max(1,(rates[idx]/maxR)*40);
    var live=(i===N-1)?' live':'';
    html+='<div class="pulse-bar'+live+'" style="height:'+h.toFixed(1)+'px"></div>';
  }
  strip.innerHTML=html;
  var now=rates.length?rates[rates.length-1]:0;
  document.getElementById('pulse-now').textContent=fmt(Math.round(now));
  document.getElementById('pulse-peak').textContent=fmt(Math.round(_pulsePeak));
}
function pulseTick(){
  // Two paths:
  //   - Operators (with a dashboard token): hit /api/pulse for the full
  //     2-min server-side ring buffer.
  //   - Anonymous viewers: /api/pulse is admin-gated, but /api/public-stats
  //     exposes total_requests + requests_per_sec. Push one sample per
  //     tick so renderPulse() can compute its own diff rate; this gives
  //     a live but lower-resolution strip without leaking history.
  var t=getToken();
  if(!t){
    fetch('/api/public-stats').then(function(r){
      if(!r.ok)return null;
      return r.json();
    }).then(function(d){
      if(!d||d.total_requests==null)return;
      _pulseSamples.push({ts:Date.now(),total:d.total_requests});
      if(d.requests_per_sec!=null){
        document.getElementById('pulse-now').textContent=fmt(Math.round(d.requests_per_sec));
        if(d.requests_per_sec>_pulsePeak)_pulsePeak=d.requests_per_sec;
        document.getElementById('pulse-peak').textContent=fmt(Math.round(_pulsePeak));
      }
      renderPulse();
    }).catch(function(){});
    return;
  }
  fetch('/api/pulse?admin_token='+encodeURIComponent(t)).then(function(r){
    if(!r.ok)return null;
    return r.json();
  }).then(function(d){
    if(!d)return;
    if(d.samples&&d.samples.length){
      _pulseSamples=d.samples.map(function(s){return {ts:s.ts,total:s.total}});
    }else{
      _pulseSamples.push({ts:d.ts,total:d.total_requests});
    }
    renderPulse();
  }).catch(function(){});
}
function applyTheme(t){
  if(t==='light')document.documentElement.setAttribute('data-theme','light');
  else document.documentElement.removeAttribute('data-theme');
  var btn=document.getElementById('theme-toggle');
  if(btn)btn.textContent=(t==='light')?'◑':'◐';
}
function currentTheme(){
  var stored=localStorage.getItem('pilot_dash_theme');
  if(stored==='light'||stored==='dark')return stored;
  return (window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark';
}
function toggleTheme(){
  var next=(currentTheme()==='light')?'dark':'light';
  localStorage.setItem('pilot_dash_theme',next);
  applyTheme(next);
  update();
}
applyTheme(currentTheme());
if(window.matchMedia){
  var mq=window.matchMedia('(prefers-color-scheme: light)');
  var sysListener=function(){if(!localStorage.getItem('pilot_dash_theme')){applyTheme(currentTheme());update();}};
  if(mq.addEventListener)mq.addEventListener('change',sysListener);
  else if(mq.addListener)mq.addListener(sysListener);
}
initToken();update();setInterval(update,30000);
pulseTick();setInterval(pulseTick,2000);
</script>
</body>
</html>`
