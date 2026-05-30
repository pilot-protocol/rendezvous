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

// TestBuildEntryRecursiveRedaction verifies that BuildEntry recurses into
// map values and scans string values for embedded secrets.
func TestBuildEntryRecursiveRedaction(t *testing.T) {
	t.Parallel()

	t.Run("nested map", func(t *testing.T) {
		e := BuildEntry("nested", 0, 0, "config", map[string]interface{}{
			"host":  "example.com",
			"token": "sk-secret",
		})
		if strings.Contains(e.Details, "sk-secret") {
			t.Errorf("leaked nested token: %q", e.Details)
		}
		if !strings.Contains(e.Details, "example.com") {
			t.Errorf("missing non-secret nested value: %q", e.Details)
		}
	})

	t.Run("deeply nested map", func(t *testing.T) {
		e := BuildEntry("deep", 0, 0, "wrap", map[string]interface{}{
			"inner": map[string]interface{}{"api_key": "sk-deep", "name": "svc"},
		})
		if strings.Contains(e.Details, "sk-deep") {
			t.Errorf("leaked deeply nested api_key: %q", e.Details)
		}
	})

	t.Run("stringified JSON", func(t *testing.T) {
		e := BuildEntry("json", 0, 0,
			"raw", `{"host":"ex.com","token":"sk-emb"}`,
		)
		if strings.Contains(e.Details, "sk-emb") {
			t.Errorf("leaked embedded token in JSON string: %q", e.Details)
		}
	})

	t.Run("key=value string", func(t *testing.T) {
		e := BuildEntry("kv", 0, 0,
			"env", "host=ex.com,api_key=sk-kv,debug=true",
		)
		if strings.Contains(e.Details, "sk-kv") {
			t.Errorf("leaked api_key in key=value string: %q", e.Details)
		}
	})

	t.Run("clean string untouched", func(t *testing.T) {
		clean := "host=ex.com,port=8443"
		if result := scanSecrets(clean); result != clean {
			t.Errorf("scanSecrets altered clean string: %q -> %q", clean, result)
		}
	})
}
