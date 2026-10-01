// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import "testing"

func TestTrustPairSet_Revision(t *testing.T) {
	s := newTrustPairSet()
	if s.revision() != 0 {
		t.Fatalf("initial revision = %d, want 0", s.revision())
	}
	s.add("1:2")
	if s.revision() != 1 {
		t.Fatalf("add new key: revision = %d, want 1", s.revision())
	}
	s.add("1:2") // duplicate
	if s.revision() != 1 {
		t.Fatalf("duplicate add must not bump revision, got %d", s.revision())
	}
	if !s.remove("1:2") {
		t.Fatal("remove present key should return true")
	}
	if s.revision() != 2 {
		t.Fatalf("remove: revision = %d, want 2", s.revision())
	}
	if s.remove("1:2") {
		t.Fatal("remove absent key should return false")
	}
	if s.revision() != 2 {
		t.Fatalf("failed remove must not bump revision, got %d", s.revision())
	}
}
