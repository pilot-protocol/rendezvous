// SPDX-License-Identifier: AGPL-3.0-or-later

package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// mountMembershipAdmin re-mounts only the /api/admin/networks/* dispatcher
// so the test is focused. The dispatcher is exported via serveMembershipAdmin
// so we can wrap it with requireAdminToken exactly like Serve() does.
func mountMembershipAdmin(h *Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/networks/", h.requireAdminToken(h.serveMembershipAdmin))
	return mux
}

// membershipCallbacks returns a Callbacks bundle with an in-memory members
// table and the three new endpoints wired. The test mutates the table
// directly to verify the handler propagated state changes.
type stubNet struct {
	members map[uint32]*MemberSnapshot
}

func newStubNet() *stubNet {
	return &stubNet{members: make(map[uint32]*MemberSnapshot)}
}

func membershipCallbacks(t *testing.T) (Callbacks, map[uint16]*stubNet, *sync.Mutex) {
	t.Helper()
	state := map[uint16]*stubNet{
		7: {
			members: map[uint32]*MemberSnapshot{
				1: {NodeID: 1, Role: "owner", Hostname: "owner.example", LastSeenUnix: 1000},
				2: {NodeID: 2, Role: "admin", Hostname: "admin.example", LastSeenUnix: 1100},
				3: {NodeID: 3, Role: "member", Hostname: "m1.example", LastSeenUnix: 1200},
			},
		},
	}
	var mu sync.Mutex

	cb := minimalCallbacks()
	cb.GetAdminToken = func() string { return "OPS" }
	cb.MembersList = func(netID uint16) ([]MemberSnapshot, error) {
		mu.Lock()
		defer mu.Unlock()
		n, ok := state[netID]
		if !ok {
			return nil, fmt.Errorf("network %d not found", netID)
		}
		out := make([]MemberSnapshot, 0, len(n.members))
		for _, m := range n.members {
			out = append(out, *m)
		}
		return out, nil
	}
	cb.MemberKick = func(netID uint16, nodeID uint32, reason string) error {
		mu.Lock()
		defer mu.Unlock()
		n, ok := state[netID]
		if !ok {
			return fmt.Errorf("network %d not found", netID)
		}
		m, ok := n.members[nodeID]
		if !ok {
			return fmt.Errorf("node %d not a member", nodeID)
		}
		if m.Role == "owner" {
			return fmt.Errorf("cannot kick owner")
		}
		delete(n.members, nodeID)
		return nil
	}
	cb.MemberRole = func(netID uint16, nodeID uint32, role, reason string) error {
		mu.Lock()
		defer mu.Unlock()
		n, ok := state[netID]
		if !ok {
			return fmt.Errorf("network %d not found", netID)
		}
		m, ok := n.members[nodeID]
		if !ok {
			return fmt.Errorf("node %d not a member", nodeID)
		}
		if m.Role == "owner" {
			return fmt.Errorf("cannot change owner")
		}
		m.Role = role
		return nil
	}
	return cb, state, &mu
}

// GET /api/admin/networks/{id}/members returns the member list with the
// shape promised on the wire (network_id + count + members[]).
func TestMembersList_ReturnsMembers(t *testing.T) {
	t.Parallel()
	cb, _, _ := membershipCallbacks(t)
	srv := httptest.NewServer(mountMembershipAdmin(NewHandler(cb)))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/admin/networks/7/members", nil)
	req.Header.Set("X-Admin-Token", "OPS")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var body struct {
		NetworkID uint16           `json:"network_id"`
		Count     int              `json:"count"`
		Members   []MemberSnapshot `json:"members"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.NetworkID != 7 || body.Count != 3 || len(body.Members) != 3 {
		t.Fatalf("unexpected body: %+v", body)
	}
}

// GET 404 when MembersList callback isn't wired — the dashboard
// gracefully falls back rather than 500ing.
func TestMembersList_NilCallback404(t *testing.T) {
	t.Parallel()
	cb := minimalCallbacks()
	cb.GetAdminToken = func() string { return "OPS" }
	srv := httptest.NewServer(mountMembershipAdmin(NewHandler(cb)))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/admin/networks/7/members", nil)
	req.Header.Set("X-Admin-Token", "OPS")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// DELETE /api/admin/networks/{id}/members/{nodeID}?reason=... happy path:
// member is removed and the response echoes the kicked node id.
func TestMemberKick_HappyPath(t *testing.T) {
	t.Parallel()
	cb, state, mu := membershipCallbacks(t)
	srv := httptest.NewServer(mountMembershipAdmin(NewHandler(cb)))
	defer srv.Close()

	req, _ := http.NewRequest("DELETE",
		srv.URL+"/api/admin/networks/7/members/3?reason=spammer", nil)
	req.Header.Set("X-Admin-Token", "OPS")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	mu.Lock()
	if _, still := state[7].members[3]; still {
		t.Fatalf("member 3 was not removed")
	}
	mu.Unlock()
}

// DELETE 400 when ?reason= is missing — auditing relies on the operator's note.
func TestMemberKick_MissingReason400(t *testing.T) {
	t.Parallel()
	cb, _, _ := membershipCallbacks(t)
	srv := httptest.NewServer(mountMembershipAdmin(NewHandler(cb)))
	defer srv.Close()

	req, _ := http.NewRequest("DELETE", srv.URL+"/api/admin/networks/7/members/3", nil)
	req.Header.Set("X-Admin-Token", "OPS")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// PUT /api/admin/networks/{id}/members/{nodeID}/role accepts both "admin"
// and "member" (case-insensitive); after the call the stub's role is set.
func TestMemberRole_AcceptsAdminAndMember(t *testing.T) {
	t.Parallel()
	for _, role := range []string{"admin", "member", "ADMIN", "Member"} {
		role := role
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			cb, state, mu := membershipCallbacks(t)
			srv := httptest.NewServer(mountMembershipAdmin(NewHandler(cb)))
			defer srv.Close()

			body := bytes.NewBufferString(`{"role":"` + role + `","reason":"smoke"}`)
			req, _ := http.NewRequest("PUT",
				srv.URL+"/api/admin/networks/7/members/3/role", body)
			req.Header.Set("X-Admin-Token", "OPS")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("PUT: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("status %d for role %q", resp.StatusCode, role)
			}
			mu.Lock()
			got := state[7].members[3].Role
			mu.Unlock()
			expected := strings.ToLower(role)
			if got != expected {
				t.Fatalf("role: want %q, got %q", expected, got)
			}
		})
	}
}

// PUT 400 on "owner" / "junk" / empty — owner-promotion path is blocked
// at the wire format level even before the server callback runs.
func TestMemberRole_RejectsBadRoles(t *testing.T) {
	t.Parallel()
	for _, role := range []string{"owner", "junk", "", "OWNER"} {
		role := role
		t.Run("role="+role, func(t *testing.T) {
			t.Parallel()
			cb, _, _ := membershipCallbacks(t)
			srv := httptest.NewServer(mountMembershipAdmin(NewHandler(cb)))
			defer srv.Close()

			body := bytes.NewBufferString(`{"role":"` + role + `"}`)
			req, _ := http.NewRequest("PUT",
				srv.URL+"/api/admin/networks/7/members/3/role", body)
			req.Header.Set("X-Admin-Token", "OPS")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("PUT: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 400 {
				t.Fatalf("expected 400, got %d for role %q", resp.StatusCode, role)
			}
		})
	}
}

// All three endpoints require the admin token. Without it the server
// rejects with 401 before ever touching the network state.
func TestMembershipAdmin_RequiresAdminToken(t *testing.T) {
	t.Parallel()
	cases := []struct {
		method, path string
		body         string
	}{
		{"GET", "/api/admin/networks/7/members", ""},
		{"DELETE", "/api/admin/networks/7/members/3?reason=x", ""},
		{"PUT", "/api/admin/networks/7/members/3/role", `{"role":"admin"}`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.method+tc.path, func(t *testing.T) {
			t.Parallel()
			cb, _, _ := membershipCallbacks(t)
			srv := httptest.NewServer(mountMembershipAdmin(NewHandler(cb)))
			defer srv.Close()

			var body *bytes.Buffer
			if tc.body != "" {
				body = bytes.NewBufferString(tc.body)
			} else {
				body = &bytes.Buffer{}
			}
			req, _ := http.NewRequest(tc.method, srv.URL+tc.path, body)
			// Deliberately no X-Admin-Token header.
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("req: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 401 {
				t.Fatalf("expected 401, got %d", resp.StatusCode)
			}
		})
	}
}
