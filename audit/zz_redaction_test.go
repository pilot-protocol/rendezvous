// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

// Regression for the secret-disclosure issue: BuildEntry surfaced
// every attrs key=value pair verbatim into the Details field, which
// the audit log then persists + the exporter ships to Splunk/syslog.
// Tokens, passwords, signatures, etc. were ending up in plaintext
// audit records — making the log AND any external sink a credential
// disclosure surface.

import (
	"strings"
	"testing"
)

func TestBuildEntryRedactsKnownSecretKeys(t *testing.T) {
	t.Parallel()

	cases := []struct {
		key string
		val string
	}{
		{"token", "abc123secret"},
		{"admin_token", "ROOT-OVERRIDE"},
		{"password", "hunter2"},
		{"api_key", "sk-live-abc"},
		{"private_key", "-----BEGIN PRIVATE KEY-----"},
		{"signature", "MEQCIQD..."},
		{"network_admin_token", "net-secret"}, // suffix _token
		{"db_password", "rootpw"},              // suffix _password
		{"shared_secret", "xyz"},               // suffix _secret
		{"signing_key", "k1"},                  // suffix _key
		{"Bearer", "tok-XYZ"},                  // case-insensitive
	}
	for _, c := range cases {
		e := BuildEntry("test.action", 0, 0, c.key, c.val)
		if strings.Contains(e.Details, c.val) {
			t.Errorf("Details leaked %q for key %q: %q", c.val, c.key, e.Details)
		}
		if !strings.Contains(e.Details, "redacted") {
			t.Errorf("expected 'redacted' marker for key %q; got %q", c.key, e.Details)
		}
	}
}

func TestBuildEntryDoesNotRedactNonSecretKeys(t *testing.T) {
	t.Parallel()
	// Regression guard: legitimate non-secret fields must still appear.

	e := BuildEntry("test.action", 0, 0,
		"hostname", "my-public-host",
		"reason", "trust-decay",
		"member_count", 42,
	)
	for _, want := range []string{"my-public-host", "trust-decay", "42"} {
		if !strings.Contains(e.Details, want) {
			t.Errorf("expected Details to contain %q; got %q", want, e.Details)
		}
	}
}

// TestRedactMap verifies the exported redaction helper used by the
// webhook DLQ read API (PILOT-314).
func TestRedactMap(t *testing.T) {
	t.Parallel()

	t.Run("redacts sensitive keys", func(t *testing.T) {
		in := map[string]interface{}{
			"token":     "abc123",
			"hostname":  "public-host",
			"api_key":   "sk-live",
			"reason":    "ok",
			"db_secret": "pw", // suffix _secret
		}
		got := RedactMap(in)
		if got["token"] != "<redacted>" {
			t.Errorf("token = %v, want <redacted>", got["token"])
		}
		if got["api_key"] != "<redacted>" {
			t.Errorf("api_key = %v, want <redacted>", got["api_key"])
		}
		if got["db_secret"] != "<redacted>" {
			t.Errorf("db_secret = %v, want <redacted>", got["db_secret"])
		}
		if got["hostname"] != "public-host" {
			t.Errorf("hostname = %v, want public-host", got["hostname"])
		}
		if got["reason"] != "ok" {
			t.Errorf("reason = %v, want ok", got["reason"])
		}
	})

	t.Run("nil-safe", func(t *testing.T) {
		if got := RedactMap(nil); got != nil {
			t.Errorf("RedactMap(nil) = %v, want nil", got)
		}
	})

	t.Run("empty map", func(t *testing.T) {
		got := RedactMap(map[string]interface{}{})
		if len(got) != 0 {
			t.Errorf("RedactMap({}) len = %d, want 0", len(got))
		}
	})
}
