// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"encoding/base64"
	"testing"

	"github.com/pilot-protocol/common/crypto"
)

// Adversarial replay for the registration-hijack family (PPA-003 and
// neighbours). Everything runs against an in-process Store — no registry
// process, no network, and emphatically no production traffic.
//
// Attacker capability assumed throughout: the attacker knows the
// victim's public key and current real address. Both are public — the
// directory hands them out via resolve / list_nodes to anyone who asks —
// so this is a bystander-level capability, not an insider one.

type regVictim struct {
	pubB64 string
	sign   func(addr string) string
}

func newRegVictim(t *testing.T) regVictim {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	pub := crypto.EncodePublicKey(id.PublicKey)
	return regVictim{
		pubB64: pub,
		sign: func(addr string) string {
			return base64.StdEncoding.EncodeToString(id.Sign([]byte("register:" + addr + ":" + pub)))
		},
	}
}

// registerAs submits a registration exactly as the wire handler would,
// with the caller connecting from its own address. extra lets a test add
// attacker-chosen fields (hostname, relay_only, …).
func registerAs(st *Store, pubB64, listenAddr, sig string, extra map[string]interface{}) (map[string]interface{}, error) {
	return registerFrom(st, pubB64, listenAddr, listenAddr, sig, extra)
}

// registerFrom is registerAs with the TCP source address decoupled from
// the claimed listen_addr — the off-path attacker case. sanitizeListenAddr
// only substitutes the observed source host for wildcard/private/loopback
// claims, so a claimed *public* address survives verbatim regardless of
// where the connection actually came from.
func registerFrom(st *Store, pubB64, listenAddr, remoteAddr, sig string, extra map[string]interface{}) (map[string]interface{}, error) {
	m := map[string]interface{}{"public_key": pubB64, "listen_addr": listenAddr}
	if sig != "" {
		m["signature"] = sig
	}
	for k, v := range extra {
		m[k] = v
	}
	return st.HandleRegister(m, remoteAddr, nil, nil)
}

func victimNode(t *testing.T, st *Store, pubB64 string) *NodeInfo {
	t.Helper()
	st.mu.RLock()
	defer st.mu.RUnlock()
	id, ok := st.pubKeyIdx[pubB64]
	if !ok {
		t.Fatal("victim key not in the directory")
	}
	n, ok := st.nodes[id]
	if !ok {
		t.Fatal("victim node missing")
	}
	return n
}

// TestAttackReplay_EndpointRelocationRatchet replays the core PPA-003
// attack in the shapes an attacker would actually try: a bare unsigned
// relocation, an unsigned relocation carrying a hostname (which forces
// the slow path, bypassing the fast-path early return), and a relocation
// signed with the attacker's own key over the victim's key material.
func TestAttackReplay_EndpointRelocationRatchet(t *testing.T) {
	v := newRegVictim(t)
	const home = "203.0.113.10:5000"
	const evil = "198.51.100.66:5000"
	const attackerSource = "198.51.100.66:41234"

	attacker := newRegVictim(t) // attacker's own identity

	cases := []struct {
		name  string
		addr  string
		sig   string
		extra map[string]interface{}
	}{
		{"unsigned", evil, "", nil},
		{"unsigned_with_hostname", evil, "", map[string]interface{}{"hostname": "attacker-owned"}},
		{"unsigned_with_owner", evil, "", map[string]interface{}{"owner": "attacker"}},
		{"attacker_signed", evil, attacker.sign(evil), nil},
		{"victim_sig_for_other_addr", evil, v.sign(home), nil},
		{"garbage_sig", evil, "!!!not-base64!!!", nil},
		// Claiming a private address makes sanitizeListenAddr substitute
		// the attacker's own observed IP — still a relocation.
		{"private_addr_rewritten_to_attacker", "10.0.0.1:5000", "", nil},
		{"wildcard_addr_rewritten_to_attacker", "0.0.0.0:5000", "", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			if _, err := registerAs(st, v.pubB64, home, v.sign(home), nil); err != nil {
				t.Fatalf("victim signed register rejected: %v", err)
			}

			_, err := registerFrom(st, v.pubB64, tc.addr, attackerSource, tc.sig, tc.extra)
			if err == nil {
				t.Fatalf("ATTACK SUCCEEDED (%s): registration accepted a relocation of a signature-verified key", tc.name)
			}

			n := victimNode(t, st, v.pubB64)
			sh := st.nodeShard(n.ID)
			sh.RLock()
			addr := n.RealAddr
			sh.RUnlock()
			if addr != home {
				t.Fatalf("ATTACK SUCCEEDED (%s): victim endpoint mutated to %q", tc.name, addr)
			}
		})
	}
}

// TestAttackReplay_SameEndpointUnsignedRecordTamper is the finding the
// endpoint ratchet does NOT cover.
//
// The ratchet's only test is `listenAddr != RealAddr`. An attacker who
// re-registers the victim's key with the victim's *own current address*
// therefore sails past it and lands in the re-register mutation path,
// which rewrites hostname, relay_only, lan_addrs, version and last-seen
// with attacker-supplied values — no signature anywhere.
//
// The hostname rewrite is the sharp end: hostnames are how peers address
// each other, and setNodeHostname deletes the old index entry, so the
// victim becomes unresolvable under the name everyone knows it by.
//
// This is gated by StrictRegistrationAuth, which is OFF by default
// (opt-in --strict-registration-auth / RENDEZVOUS_STRICT_REGISTRATION_AUTH).
// Both settings are asserted below.
func TestAttackReplay_SameEndpointUnsignedRecordTamper(t *testing.T) {
	// Production-style public addresses: the victim's endpoint is a
	// routable IP (so sanitizeListenAddr passes the claim through
	// untouched) and the attacker connects from somewhere else entirely.
	const home = "203.0.113.10:5000"
	const attackerSource = "198.51.100.66:41234"

	for _, strict := range []bool{false, true} {
		strict := strict
		name := "strict_off"
		if strict {
			name = "strict_on"
		}
		t.Run(name, func(t *testing.T) {
			v := newRegVictim(t)
			st := newTestStore(t)
			st.cb.StrictRegistrationAuth = func() bool { return strict }

			if _, err := registerAs(st, v.pubB64, home, v.sign(home), map[string]interface{}{
				"hostname": "victim-agent",
				"version":  "v1.13.3",
			}); err != nil {
				t.Fatalf("victim signed register rejected: %v", err)
			}

			// Unsigned, from an off-path attacker, claiming the victim's
			// own address so the endpoint ratchet sees no relocation.
			_, err := registerFrom(st, v.pubB64, home, attackerSource, "", map[string]interface{}{
				"hostname":   "attacker-agent",
				"relay_only": true,
				"version":    "v0.0.0-attacker",
				"lan_addrs":  []interface{}{"192.168.1.66:5000"},
			})

			// The ratchet now rejects ANY unsigned registration for a
			// signature-verified key, independent of StrictRegistrationAuth.
			if err == nil {
				t.Fatalf("ATTACK SUCCEEDED (strict=%v): unsigned re-register of a signature-verified key was accepted", strict)
			}

			n := victimNode(t, st, v.pubB64)
			sh := st.nodeShard(n.ID)
			sh.RLock()
			hostname, relayOnly, version, lan := n.Hostname, n.RelayOnly, n.Version, n.LANAddrs
			sh.RUnlock()

			st.mu.RLock()
			_, victimNameStillIndexed := st.hostnameIdx["victim-agent"]
			st.mu.RUnlock()

			if hostname != "victim-agent" || relayOnly || version != "v1.13.3" || len(lan) > 0 || !victimNameStillIndexed {
				t.Fatalf("record tampered despite rejection (strict=%v): hostname=%q relay_only=%v version=%q lan=%v indexed=%v",
					strict, hostname, relayOnly, version, lan, victimNameStillIndexed)
			}
		})
	}
}

// TestAttackReplay_HostnameSquatAfterUnsignedRename is the follow-through
// on the tamper above: once the victim's hostname index entry has been
// freed by an unsigned rename, the attacker registers their own key under
// the freed name and inherits every lookup aimed at the victim.
func TestAttackReplay_HostnameSquatAfterUnsignedRename(t *testing.T) {
	const home = "203.0.113.10:5000"
	const attackerHome = "198.51.100.66:5000"
	const attackerSource = "198.51.100.66:41234"
	const name = "victim-agent"

	v := newRegVictim(t)
	attacker := newRegVictim(t)
	st := newTestStore(t)

	if _, err := registerAs(st, v.pubB64, home, v.sign(home), map[string]interface{}{"hostname": name}); err != nil {
		t.Fatalf("victim signed register rejected: %v", err)
	}
	victimID := victimNode(t, st, v.pubB64).ID

	// Step 1: the unsigned rename that would free the name is now rejected by
	// the ratchet, so the squat has no opening.
	if _, err := registerFrom(st, v.pubB64, home, attackerSource, "",
		map[string]interface{}{"hostname": "renamed-by-attacker"}); err == nil {
		t.Fatal("ATTACK SUCCEEDED: unsigned rename of a signature-verified node was accepted")
	}

	// Step 2: the attacker's own signed register cannot claim the name — the
	// victim still holds it.
	resp, err := registerAs(st, attacker.pubB64, attackerHome, attacker.sign(attackerHome),
		map[string]interface{}{"hostname": name})
	if err != nil {
		t.Fatalf("attacker register rejected: %v", err)
	}
	if _, ok := resp["hostname_error"]; !ok {
		t.Fatal("attacker claimed the victim's hostname — squat was NOT prevented")
	}

	st.mu.RLock()
	ownerID := st.hostnameIdx[name]
	st.mu.RUnlock()
	if ownerID != victimID {
		t.Fatalf("victim lost its hostname despite the rename being rejected (owner=%d victim=%d)", ownerID, victimID)
	}
}

// TestAttackReplay_OwnerRebindRejected pins the H2/H3 control next door:
// an attacker who learns an owner string must not be able to rebind that
// owner's node ID to their own key.
func TestAttackReplay_OwnerRebindRejected(t *testing.T) {
	const home = "10.0.0.1:5000"
	const evil = "10.66.66.66:5000"

	v := newRegVictim(t)
	attacker := newRegVictim(t)
	st := newTestStore(t)

	if _, err := registerAs(st, v.pubB64, home, v.sign(home), map[string]interface{}{"owner": "alice"}); err != nil {
		t.Fatalf("victim signed register rejected: %v", err)
	}
	victimID := victimNode(t, st, v.pubB64).ID

	if _, err := registerAs(st, attacker.pubB64, evil, attacker.sign(evil),
		map[string]interface{}{"owner": "alice"}); err == nil {
		t.Fatal("ATTACK SUCCEEDED: owner string alone rebound a node ID to an attacker key")
	}

	st.mu.RLock()
	stillVictim := st.ownerIdx["alice"] == victimID
	st.mu.RUnlock()
	if !stillVictim {
		t.Fatal("ATTACK SUCCEEDED: owner index was repointed at the attacker")
	}
}
