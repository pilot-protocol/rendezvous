// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"fmt"
	"strings"

	"github.com/pilot-protocol/common/protocol"
	dashpkg "github.com/pilot-protocol/rendezvous/dashboard"
)

// AdminListMembers returns a snapshot of every member of the given network
// along with their role, hostname (if registered), and last-seen unix time.
// Bypasses the protocol's network-role RBAC: the caller has already been
// authenticated by the dashboard's requireAdminToken middleware, so the
// operator's admin token is the only authority that matters here.
//
// Returns protocol.ErrNetworkNotFound when netID is unknown.
func (s *Server) AdminListMembers(netID uint16) ([]dashpkg.MemberSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	net, ok := s.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	out := make([]dashpkg.MemberSnapshot, 0, len(net.Members))
	for _, memberID := range net.Members {
		entry := dashpkg.MemberSnapshot{
			NodeID: memberID,
		}
		if role, has := net.MemberRoles[memberID]; has {
			entry.Role = string(role)
		}
		if node, ok := s.nodes[memberID]; ok {
			entry.Hostname = node.Hostname
			if ls := node.GetLastSeen(); !ls.IsZero() {
				entry.LastSeenUnix = ls.Unix()
			}
		}
		out = append(out, entry)
	}
	return out, nil
}

// AdminKickMember removes nodeID from the network's member list and role
// map without any of the protocol's network-role gates — the operator
// (admin token holder) is the highest authority by definition. The owner
// cannot be kicked through this path; transfer ownership first.
//
// Emits a "network.admin_kick" audit entry with the operator-supplied reason,
// invalidates the list_nodes cache for the network, publishes a
// membership.changed bus event, and triggers a snapshot save.
//
// Returns protocol.ErrNetworkNotFound on unknown networks. Returns an error
// when nodeID is the owner or is not a member of the network.
func (s *Server) AdminKickMember(netID uint16, nodeID uint32, reason string) error {
	var priorRole Role
	s.mu.Lock()
	net, ok := s.networks[netID]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}
	if net.MemberRoles[nodeID] == RoleOwner {
		s.mu.Unlock()
		return fmt.Errorf("cannot kick the network owner (node %d); transfer ownership first", nodeID)
	}

	// Remove from member slice.
	found := false
	for i, m := range net.Members {
		if m == nodeID {
			net.Members = append(net.Members[:i], net.Members[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		s.mu.Unlock()
		return fmt.Errorf("node %d is not a member of network %d", nodeID, netID)
	}

	priorRole = net.MemberRoles[nodeID]
	delete(net.MemberRoles, nodeID)

	// Reflect the membership change on the node's own Networks slice so
	// lookups see the new state immediately. Same housekeeping that
	// HandleKickMember performs via st.cb.RemoveNodeNetwork.
	if node, ok := s.nodes[nodeID]; ok {
		filtered := node.Networks[:0]
		for _, nid := range node.Networks {
			if nid != netID {
				filtered = append(filtered, nid)
			}
		}
		node.Networks = filtered
	}
	s.mu.Unlock()

	// Post-mutation side effects MUST run outside the write lock — they
	// reach back into the server (flushSave RLock, audit ring lock,
	// bus publish to subscribers that may want s.mu.RLock).
	s.invalidateListNodesCacheForNetwork(netID)
	s.publishMembershipChanged(netID)
	s.audit("network.admin_kick",
		"network_id", netID,
		"target_node_id", nodeID,
		"prior_role", string(priorRole),
		"reason", reason,
	)
	if s.walStore != nil {
		// Best-effort: the snapshot is debounced, so we don't need to
		// surface a save error to the caller. The audit entry above is
		// the durable record of the operator action regardless.
		_ = s.walStore.TriggerSnapshot()
	}
	return nil
}

// AdminSetMemberRole updates the per-network role for nodeID. The role
// string must be "admin" or "member" (case-insensitive); anything else is
// rejected before the lock is taken. The owner role cannot be assigned or
// removed through this path — use the protocol's transfer_ownership flow.
//
// Emits a "network.admin_set_role" audit entry, invalidates the list_nodes
// cache, publishes a membership.changed event, and triggers a snapshot save.
//
// Returns protocol.ErrNetworkNotFound on unknown networks.
func (s *Server) AdminSetMemberRole(netID uint16, nodeID uint32, role, reason string) error {
	normalized := strings.ToLower(strings.TrimSpace(role))
	var newRole Role
	switch normalized {
	case "admin":
		newRole = RoleAdmin
	case "member":
		newRole = RoleMember
	default:
		return fmt.Errorf("invalid role %q: must be \"admin\" or \"member\"", role)
	}

	s.mu.Lock()
	net, ok := s.networks[netID]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}
	if net.MemberRoles[nodeID] == RoleOwner {
		s.mu.Unlock()
		return fmt.Errorf("cannot change role of the network owner (node %d); transfer ownership first", nodeID)
	}
	// The node must already be a member of the network; we don't add new
	// members through this path. Membership additions go through
	// HandleJoinNetwork / invite-accept.
	isMember := false
	for _, m := range net.Members {
		if m == nodeID {
			isMember = true
			break
		}
	}
	if !isMember {
		s.mu.Unlock()
		return fmt.Errorf("node %d is not a member of network %d", nodeID, netID)
	}

	if net.MemberRoles == nil {
		net.MemberRoles = make(map[uint32]Role)
	}
	oldRole := net.MemberRoles[nodeID]
	net.MemberRoles[nodeID] = newRole
	s.mu.Unlock()

	// Side effects run outside the write lock so flushSave/audit/bus
	// subscribers can reacquire s.mu freely.
	s.invalidateListNodesCacheForNetwork(netID)
	s.publishMembershipChanged(netID)
	s.audit("network.admin_set_role",
		"network_id", netID,
		"target_node_id", nodeID,
		"old_role", string(oldRole),
		"new_role", string(newRole),
		"reason", reason,
	)
	if s.walStore != nil {
		_ = s.walStore.TriggerSnapshot()
	}
	return nil
}
