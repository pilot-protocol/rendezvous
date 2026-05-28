// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// --- validateHostname ---------------------------------------------------

func TestValidateHostname_AcceptsValid(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"a", "abc", "a-b-c", "n123", "node-7"} {
		if err := validateHostname(name); err != nil {
			t.Errorf("validateHostname(%q): %v", name, err)
		}
	}
}

func TestValidateHostname_EmptyAllowedAsClear(t *testing.T) {
	t.Parallel()
	if err := validateHostname(""); err != nil {
		t.Errorf("empty hostname must be allowed (clear): %v", err)
	}
}

func TestValidateHostname_TooLong(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 64)
	err := validateHostname(long)
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("expected too-long error, got %v", err)
	}
}

func TestValidateHostname_BadFormat(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"-bad", "bad-", "Up", "a..b", "node!", "hi there"} {
		if err := validateHostname(name); err == nil {
			t.Errorf("validateHostname(%q) should have rejected", name)
		}
	}
}

func TestValidateHostname_Reserved(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"localhost", "backbone", "broadcast"} {
		err := validateHostname(name)
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("%q: expected reserved error, got %v", name, err)
		}
	}
}

// --- jsonUint32 / jsonUint16 --------------------------------------------

func TestJSONUint32_ParsesFloat64(t *testing.T) {
	t.Parallel()
	got := jsonUint32(map[string]interface{}{"n": float64(42)}, "n")
	if got != 42 {
		t.Fatalf("got %d", got)
	}
}

func TestJSONUint32_MissingKeyReturnsZero(t *testing.T) {
	t.Parallel()
	if got := jsonUint32(map[string]interface{}{}, "absent"); got != 0 {
		t.Fatalf("missing: %d", got)
	}
}

func TestJSONUint32_NonNumericReturnsZero(t *testing.T) {
	t.Parallel()
	got := jsonUint32(map[string]interface{}{"n": "not a number"}, "n")
	if got != 0 {
		t.Fatalf("non-numeric: %d", got)
	}
}

func TestJSONUint32_OutOfRangeReturnsZero(t *testing.T) {
	t.Parallel()
	if got := jsonUint32(map[string]interface{}{"n": float64(-1)}, "n"); got != 0 {
		t.Fatalf("negative: %d", got)
	}
	huge := float64(^uint32(0)) + 1
	if got := jsonUint32(map[string]interface{}{"n": huge}, "n"); got != 0 {
		t.Fatalf("overflow: %d", got)
	}
}

func TestJSONUint16_ParsesAndBounds(t *testing.T) {
	t.Parallel()
	if got := jsonUint16(map[string]interface{}{"n": float64(5)}, "n"); got != 5 {
		t.Fatalf("got %d", got)
	}
	if got := jsonUint16(map[string]interface{}{"n": float64(-1)}, "n"); got != 0 {
		t.Fatalf("negative: %d", got)
	}
	if got := jsonUint16(map[string]interface{}{"n": float64(70000)}, "n"); got != 0 {
		t.Fatalf("overflow: %d", got)
	}
	if got := jsonUint16(map[string]interface{}{"n": "x"}, "n"); got != 0 {
		t.Fatalf("non-numeric: %d", got)
	}
	if got := jsonUint16(map[string]interface{}{}, "missing"); got != 0 {
		t.Fatalf("missing: %d", got)
	}
}

// --- base64Decode --------------------------------------------------------

func TestBase64Decode_RoundTrip(t *testing.T) {
	t.Parallel()
	got, err := base64Decode("aGVsbG8=")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestBase64Decode_Invalid(t *testing.T) {
	t.Parallel()
	if _, err := base64Decode("not!!base64"); err == nil {
		t.Fatal("expected error from bad base64")
	}
}

// --- readMessage / writeMessage -----------------------------------------

func TestWriteAndReadMessage_RoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	msg := map[string]interface{}{"type": "hello", "n": float64(7)}
	if err := writeMessage(&buf, msg); err != nil {
		t.Fatal(err)
	}
	got, err := readMessage(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got["type"] != "hello" || got["n"].(float64) != 7 {
		t.Fatalf("roundtrip: %+v", got)
	}
}

func TestReadMessage_TruncatedHeaderReturnsErr(t *testing.T) {
	t.Parallel()
	if _, err := readMessage(bytes.NewReader([]byte{0x01, 0x02})); err == nil {
		t.Fatal("expected error on short header")
	}
}

func TestReadMessage_TruncatedBodyReturnsErr(t *testing.T) {
	t.Parallel()
	// Header says 100 bytes, but body is empty.
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 100)
	r := bytes.NewReader(hdr[:])
	if _, err := readMessage(r); err == nil {
		t.Fatal("expected error on truncated body")
	}
}

func TestReadMessage_TooLargeRejected(t *testing.T) {
	t.Parallel()
	var hdr [4]byte
	// MaxMessageSize is 64MB; pick 128MB to guarantee rejection.
	binary.BigEndian.PutUint32(hdr[:], 128*1024*1024)
	r := bytes.NewReader(hdr[:])
	_, err := readMessage(r)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected too-large, got %v", err)
	}
}

func TestReadMessage_BadJSONReturnsErr(t *testing.T) {
	t.Parallel()
	body := []byte("{not json}")
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	r := bytes.NewReader(append(hdr[:], body...))
	if _, err := readMessage(r); err == nil {
		t.Fatal("expected JSON decode error")
	}
}

// errWriter / errReader for failure-path coverage.
type errWriter struct{ n int }

func (w *errWriter) Write(p []byte) (int, error) {
	if w.n > 0 {
		w.n--
		return len(p), nil
	}
	return 0, errors.New("boom")
}

func TestWriteMessage_WriterErrors(t *testing.T) {
	t.Parallel()
	// Fail on first write (header).
	if err := writeMessage(&errWriter{n: 0}, map[string]interface{}{"a": "b"}); err == nil {
		t.Fatal("expected header write error")
	}
	// Fail on second write (body).
	if err := writeMessage(&errWriter{n: 1}, map[string]interface{}{"a": "b"}); err == nil {
		t.Fatal("expected body write error")
	}
}

func TestWriteMessage_RawResponseShortcut(t *testing.T) {
	t.Parallel()
	raw, _ := json.Marshal(map[string]interface{}{"x": 1})
	var buf bytes.Buffer
	if err := writeMessage(&buf, map[string]interface{}{rawResponseKey: raw}); err != nil {
		t.Fatal(err)
	}
	// First 4 bytes = length(raw), then raw.
	got := buf.Bytes()
	wantLen := binary.BigEndian.Uint32(got[:4])
	if int(wantLen) != len(raw) {
		t.Fatalf("len header = %d, want %d", wantLen, len(raw))
	}
	if !bytes.Equal(got[4:], raw) {
		t.Fatalf("body mismatch: %s vs %s", got[4:], raw)
	}
}

func TestWriteMessage_RawShortcutWriteError(t *testing.T) {
	t.Parallel()
	raw, _ := json.Marshal(map[string]interface{}{"x": 1})
	if err := writeMessage(&errWriter{n: 0}, map[string]interface{}{rawResponseKey: raw}); err == nil {
		t.Fatal("expected header write error in raw path")
	}
	if err := writeMessage(&errWriter{n: 1}, map[string]interface{}{rawResponseKey: raw}); err == nil {
		t.Fatal("expected body write error in raw path")
	}
}

// TestWriteMessage_SetsDeadlineOnNetConn — best-effort. We use a real
// net.Pipe to confirm the net.Conn branch executes (no observable error
// because pipes don't enforce write deadlines, but it covers the code path).
func TestWriteMessage_NetConnPathExecutes(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		io.Copy(io.Discard, b)
	}()
	if err := writeMessage(a, map[string]interface{}{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	<-done
}

// --- ShouldLog / nodeShard / StaleNodeThreshold -------------------------

func TestServer_ShouldLog_Delegates(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	// First call for a key returns true.
	ok, _ := s.ShouldLog("first-key")
	if !ok {
		t.Fatal("first call should log")
	}
}

func TestServer_NodeShard_StableForSameID(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	a := s.nodeShard(42)
	b := s.nodeShard(42)
	if a != b {
		t.Fatal("same nodeID must map to same shard")
	}
	if s.nodeShard(numNodeShards+42) != a {
		t.Fatal("modulo mapping broken")
	}
}

func TestServer_StaleNodeThreshold_DefaultAndSet(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if got := s.StaleNodeThreshold(); got != defaultStaleNodeThreshold {
		t.Fatalf("default = %v, want %v", got, defaultStaleNodeThreshold)
	}
	s.SetStaleNodeThreshold(10 * time.Second)
	if got := s.StaleNodeThreshold(); got != 10*time.Second {
		t.Fatalf("after set = %v", got)
	}
	// Zero / negative ignored.
	s.SetStaleNodeThreshold(0)
	if got := s.StaleNodeThreshold(); got != 10*time.Second {
		t.Fatalf("zero overrode: %v", got)
	}
	s.SetStaleNodeThreshold(-1)
	if got := s.StaleNodeThreshold(); got != 10*time.Second {
		t.Fatalf("negative overrode: %v", got)
	}
}

// --- NewRateLimiter alias ------------------------------------------------

func TestNewRateLimiter_FactoryReturnsLimiter(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(5, time.Second, 100)
	if rl == nil {
		t.Fatal("nil limiter")
	}
	if !rl.Allow("1.2.3.4") {
		t.Error("first call should be allowed")
	}
}
