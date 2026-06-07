// SPDX-License-Identifier: AGPL-3.0-or-later

// Package breakers provides named, dynamically-controllable on/off
// switches for individual functional surfaces of the rendezvous
// process. Operators flip a switch by writing a JSON file
// (<store-dir>/breakers.json); a file watcher reloads the state every
// 2 s and call sites consult the breaker before serving the affected
// request type.
//
// Three states per breaker:
//
//	closed     — normal operation (default). Allow.
//	half_open  — log a warning, but allow. Use for canary testing
//	             or to observe call frequency without disrupting
//	             traffic.
//	open       — deny. The serving site returns an appropriate
//	             error to the caller (typically a 503-equivalent
//	             with the operator-supplied reason).
//
// Names are flat strings, conventionally dotted paths reflecting the
// component and action being gated (e.g. "registry.register",
// "beacon.punch", "snapshot.write"). The Manager is permissive: it
// accepts any name on the read path; a missing breaker is treated as
// "closed" (allow). Unknown names in the JSON file are kept but
// silently unused — write-time tolerance lets operators stage a name
// before its call site is wired.
package breakers

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// State enumerates the three configurable states a breaker can be in.
type State int

const (
	// Closed means normal operation: Allow returns (true, Closed).
	Closed State = iota
	// HalfOpen means warn-but-allow: Allow returns (true, HalfOpen).
	// Call sites should log a warning so operators can observe.
	HalfOpen
	// Open means deny: Allow returns (false, Open). Call sites should
	// surface the breaker's reason in any error returned to the caller.
	Open
)

// String returns the wire-format name ("closed", "half_open", "open"),
// matching the JSON file format.
func (s State) String() string {
	switch s {
	case Closed:
		return "closed"
	case HalfOpen:
		return "half_open"
	case Open:
		return "open"
	default:
		return fmt.Sprintf("state(%d)", int(s))
	}
}

// ParseState parses a wire-format state string. Accepts the canonical
// "closed" / "half_open" / "open" plus a few common aliases ("half-open",
// "halfopen") so the JSON file is forgiving. Unknown values return an
// error so a typo doesn't silently become Closed.
func ParseState(s string) (State, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "closed", "":
		return Closed, nil
	case "half_open", "half-open", "halfopen":
		return HalfOpen, nil
	case "open":
		return Open, nil
	default:
		return Closed, fmt.Errorf("unknown breaker state %q (want closed | half_open | open)", s)
	}
}

// Breaker is a snapshot of one named switch's state.
type Breaker struct {
	Name        string    `json:"name"`
	State       State     `json:"-"` // serialised via custom marshalling
	StateString string    `json:"state"`
	Reason      string    `json:"reason,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

// Manager holds the live breaker map. Safe for concurrent use.
type Manager struct {
	mu       sync.RWMutex
	breakers map[string]*Breaker
	clock    func() time.Time
}

// New returns an empty Manager. No breakers are pre-registered;
// Allow on any unknown name returns (true, Closed) — the default-
// allow semantic ensures a missing JSON file or a misspelled name
// can never cut off service.
func New() *Manager {
	return &Manager{
		breakers: make(map[string]*Breaker),
		clock:    time.Now,
	}
}

// SetClock overrides the time source (tests).
func (m *Manager) SetClock(fn func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clock = fn
}

// Allow consults the named breaker and returns:
//
//	(true, Closed)   — normal operation
//	(true, HalfOpen) — caller should log a warning, then proceed
//	(false, Open)    — caller must NOT proceed; return an error
//
// An unknown name is treated as Closed (default-allow) so a request
// path is never blocked by a typo. The state is returned alongside
// the bool so the caller can log appropriately without a second
// lookup.
func (m *Manager) Allow(name string) (bool, State) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.breakers[name]
	if !ok {
		return true, Closed
	}
	switch b.State {
	case Open:
		return false, Open
	case HalfOpen:
		return true, HalfOpen
	default:
		return true, Closed
	}
}

// Reason returns the operator-supplied reason for the named breaker's
// current state, or "" if no breaker is registered. Use in error
// messages surfaced to callers when Allow returns false.
func (m *Manager) Reason(name string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if b, ok := m.breakers[name]; ok {
		return b.Reason
	}
	return ""
}

// Set installs or replaces one breaker. Audit-logged via the Manager's
// updated-at timestamp; callers who want a separate event sink should
// wrap this method.
func (m *Manager) Set(name string, state State, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.breakers[name] = &Breaker{
		Name:        name,
		State:       state,
		StateString: state.String(),
		Reason:      reason,
		UpdatedAt:   m.clock(),
	}
}

// Replace atomically swaps the full breaker map. Used by the file
// watcher to apply a fresh JSON snapshot in one shot.
func (m *Manager) Replace(breakers map[string]*Breaker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if breakers == nil {
		m.breakers = make(map[string]*Breaker)
		return
	}
	now := m.clock()
	out := make(map[string]*Breaker, len(breakers))
	for k, v := range breakers {
		if v == nil {
			continue
		}
		cp := *v
		if cp.UpdatedAt.IsZero() {
			cp.UpdatedAt = now
		}
		// Normalise StateString so callers don't have to set both.
		cp.StateString = cp.State.String()
		out[k] = &cp
	}
	m.breakers = out
}

// Snapshot returns a copy of every registered breaker. Safe to mutate.
// Order is insertion-stable only within a single call; callers needing
// a sorted view should sort the slice themselves.
func (m *Manager) Snapshot() []Breaker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Breaker, 0, len(m.breakers))
	for _, b := range m.breakers {
		out = append(out, *b)
	}
	return out
}

// Size returns the current count of registered breakers.
func (m *Manager) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.breakers)
}
