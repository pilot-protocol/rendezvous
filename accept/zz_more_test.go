// SPDX-License-Identifier: AGPL-3.0-or-later

package accept

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

// TestRecoveredPanicCount_AfterRecover increments the counter.
func TestRecoveredPanicCount_AfterRecover(t *testing.T) {
	// Cannot t.Parallel — touches package-level counter.
	before := RecoveredPanicCount()

	func() {
		defer recoverHandler("test-panic", nil)
		panic("synthetic")
	}()

	if after := RecoveredPanicCount(); after <= before {
		t.Errorf("counter did not advance: %d → %d", before, after)
	}
}

// TestRecoverHandler_NoPanicIsNoOp confirms early-return when there's no
// active panic to recover.
func TestRecoverHandler_NoPanicIsNoOp(t *testing.T) {
	t.Parallel()
	// Just call it directly — when there's no panic, it returns silently.
	recoverHandler("nothing", nil)
}

// TestRecoverHandler_OnPanicCallbackInvoked verifies the optional
// callback fires with the panic count.
func TestRecoverHandler_OnPanicCallbackInvoked(t *testing.T) {
	gotCount := uint64(0)
	called := false

	func() {
		defer recoverHandler("with-callback", func(c uint64) {
			gotCount = c
			called = true
		})
		panic("x")
	}()

	if !called {
		t.Error("onPanic callback was not invoked")
	}
	if gotCount == 0 {
		t.Error("onPanic callback received zero count")
	}
}

// TestRecoverHandler_OnPanicCallbackRecoversItsOwnPanic confirms a
// callback that itself panics doesn't propagate.
func TestRecoverHandler_OnPanicCallbackRecoversItsOwnPanic(t *testing.T) {
	t.Parallel()
	func() {
		defer recoverHandler("nested", func(uint64) {
			panic("nested panic")
		})
		panic("outer")
	}()
	// If we reach here, the nested recover worked.
}

// TestLogSampler_FirstCallLogs covers count == 1 branch.
func TestLogSampler_FirstCallLogs(t *testing.T) {
	t.Parallel()
	s := newLogSampler(10)
	logged, count := s.shouldLog("k")
	if !logged || count != 1 {
		t.Errorf("first call: logged=%v count=%d, want true,1", logged, count)
	}
}

// TestLogSampler_SuppressesUntilInterval covers the in-between branch.
func TestLogSampler_SuppressesUntilInterval(t *testing.T) {
	t.Parallel()
	s := newLogSampler(5)
	_, _ = s.shouldLog("k") // count=1, logged
	for i := 0; i < 3; i++ {
		if logged, _ := s.shouldLog("k"); logged {
			t.Errorf("call %d: should suppress", i+2)
		}
	}
	// 5th call → triggers log and reset.
	logged, count := s.shouldLog("k")
	if !logged || count != 5 {
		t.Errorf("interval hit: logged=%v count=%d", logged, count)
	}
}

// TestLogSampler_MapSizeCapForcesLog covers the size-cap branch.
func TestLogSampler_MapSizeCapForcesLog(t *testing.T) {
	t.Parallel()
	s := newLogSampler(100)
	s.maxSamplerKeys = 2
	_, _ = s.shouldLog("k1")
	_, _ = s.shouldLog("k2")
	// 3rd unique key hits the cap → always logs.
	logged, count := s.shouldLog("k3")
	if !logged || count != 0 {
		t.Errorf("cap-hit: logged=%v count=%d, want true,0", logged, count)
	}
}

// TestLogSampler_Cleanup empties the map.
func TestLogSampler_Cleanup(t *testing.T) {
	t.Parallel()
	s := newLogSampler(10)
	_, _ = s.shouldLog("k")
	s.Cleanup()
	if len(s.counts) != 0 {
		t.Errorf("after Cleanup len = %d, want 0", len(s.counts))
	}
}

// TestRateLimiter_AllowAndDeny covers the basic happy + over-rate branches.
func TestRateLimiter_AllowAndDeny(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(2, time.Second, 100)
	if !rl.Allow("1.1.1.1") {
		t.Error("1st: want true")
	}
	if !rl.Allow("1.1.1.1") {
		t.Error("2nd: want true")
	}
	if rl.Allow("1.1.1.1") {
		t.Error("3rd: want false (over rate)")
	}
}

// TestRateLimiter_HasBucketBeforeAndAfter exercises HasBucket.
func TestRateLimiter_HasBucketBeforeAndAfter(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(1, time.Second, 10)
	if rl.HasBucket("1.2.3.4") {
		t.Error("fresh IP should not have a bucket")
	}
	_ = rl.Allow("1.2.3.4")
	if !rl.HasBucket("1.2.3.4") {
		t.Error("after Allow: bucket should exist")
	}
}

// TestRateLimiter_BucketCountAndCleanup exercises Cleanup.
func TestRateLimiter_BucketCountAndCleanup(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(1, 10*time.Millisecond, 100)
	_ = rl.Allow("a")
	_ = rl.Allow("b")
	if got := rl.BucketCount(); got != 2 {
		t.Errorf("BucketCount = %d, want 2", got)
	}
	// Move the clock forward so all buckets become stale.
	rl.SetClock(func() time.Time { return time.Now().Add(time.Hour) })
	rl.Cleanup()
	if got := rl.BucketCount(); got != 0 {
		t.Errorf("after Cleanup BucketCount = %d, want 0", got)
	}
}

// TestRateLimiter_MaxBucketsEvictsStale verifies the cap-hit eviction path.
func TestRateLimiter_MaxBucketsEvictsStale(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(1, 10*time.Millisecond, 2)
	// Use a controllable clock.
	base := time.Now()
	rl.SetClock(func() time.Time { return base })
	_ = rl.Allow("a")
	_ = rl.Allow("b")
	// Advance clock past the eviction threshold (2*window = 20ms).
	rl.SetClock(func() time.Time { return base.Add(100 * time.Millisecond) })
	// 3rd IP should evict the stale ones and succeed.
	if !rl.Allow("c") {
		t.Error("3rd IP: stale buckets should be evicted, allowing the new one")
	}
}

// TestGenerateSelfSignedCert_ReturnsValidCert covers the helper.
func TestGenerateSelfSignedCert_ReturnsValidCert(t *testing.T) {
	t.Parallel()
	cert, err := GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("certificate chain empty")
	}
	if cert.PrivateKey == nil {
		t.Error("private key nil")
	}
}

// TestSanitizeListenAddr_Branches drives the parse-error and happy paths.
func TestSanitizeListenAddr_Branches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		remote string
		client string
		want   string
	}{
		// Malformed remote → returned as-is.
		{"malformed", "1.2.3.4:5", "malformed"},
		// Empty client → remote returned.
		{"10.0.0.1:5", "", "10.0.0.1:5"},
		// Malformed client → remote returned.
		{"10.0.0.1:5", "broken", "10.0.0.1:5"},
		// Both valid → remote host + client port.
		{"10.0.0.1:5", "1.2.3.4:9999", "10.0.0.1:9999"},
	}
	for _, tc := range cases {
		if got := SanitizeListenAddr(tc.remote, tc.client); got != tc.want {
			t.Errorf("(%q, %q) = %q, want %q", tc.remote, tc.client, got, tc.want)
		}
	}
}

// TestReadMessage_Happy and TestWriteMessage_Roundtrip drive both
// directions of the wire framing.
func TestWriteMessage_ReadMessage_Roundtrip(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	msg := map[string]interface{}{"type": "ping", "n": float64(42)}
	if err := writeMessage(buf, msg); err != nil {
		t.Fatalf("writeMessage: %v", err)
	}
	got, err := readMessage(buf)
	if err != nil {
		t.Fatalf("readMessage: %v", err)
	}
	if got["type"] != "ping" || got["n"].(float64) != 42 {
		t.Errorf("roundtrip: got %v", got)
	}
}

// TestReadMessage_Truncated covers the io.ReadFull error branches.
func TestReadMessage_Truncated(t *testing.T) {
	t.Parallel()
	if _, err := readMessage(bytes.NewReader(nil)); err == nil {
		t.Error("expected EOF on empty reader")
	}
	// Length prefix says 100 but only 1 byte of body.
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 100)
	body := append(lenBuf[:], 'a')
	if _, err := readMessage(bytes.NewReader(body)); err == nil {
		t.Error("expected error on truncated body")
	}
}

// TestReadMessage_TooLarge covers the size-cap branch.
func TestReadMessage_TooLarge(t *testing.T) {
	t.Parallel()
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 1<<30) // 1 GiB
	if _, err := readMessage(bytes.NewReader(lenBuf[:])); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("err = %v, want 'too large'", err)
	}
}

// TestReadMessage_BadJSON covers the json.Unmarshal error branch.
func TestReadMessage_BadJSON(t *testing.T) {
	t.Parallel()
	body := []byte("not json")
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := readMessage(bytes.NewReader(append(lenBuf[:], body...))); err == nil {
		t.Error("expected JSON decode error")
	}
}

// TestWriteMessage_RawBytesBypassMarshal covers the rawResponseKey path.
func TestWriteMessage_RawBytesBypassMarshal(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"prebaked":true}`)
	buf := &bytes.Buffer{}
	if err := writeMessage(buf, map[string]interface{}{rawResponseKey: raw}); err != nil {
		t.Fatalf("writeMessage: %v", err)
	}
	// Skip the length prefix and verify the body is the raw bytes.
	if !bytes.Equal(buf.Bytes()[4:], raw) {
		t.Errorf("body mismatch: got %q, want %q", buf.Bytes()[4:], raw)
	}
}

// TestNewAcceptor_DefaultsAndConnCount exercises the constructor.
func TestNewAcceptor_DefaultsAndConnCount(t *testing.T) {
	t.Parallel()
	a := NewAcceptor(100, nil)
	if a == nil {
		t.Fatal("NewAcceptor returned nil")
	}
	if got := a.ConnCount(); got != 0 {
		t.Errorf("ConnCount on fresh acceptor = %d, want 0", got)
	}
	if a.Listener() != nil {
		t.Error("Listener should be nil before Listen")
	}
	if a.TLSConfig() != nil {
		t.Error("TLSConfig should be nil before SetTLS")
	}
}

// TestAcceptor_SetTLS_AutoGenerated covers the self-signed branch.
func TestAcceptor_SetTLS_AutoGenerated(t *testing.T) {
	t.Parallel()
	a := NewAcceptor(10, nil)
	if err := a.SetTLS("", ""); err != nil {
		t.Fatalf("SetTLS: %v", err)
	}
	if a.TLSConfig() == nil {
		t.Error("TLSConfig should be set after SetTLS")
	}
}

// TestAcceptor_SetTLS_LoadFailure covers the LoadX509KeyPair error branch.
func TestAcceptor_SetTLS_LoadFailure(t *testing.T) {
	t.Parallel()
	a := NewAcceptor(10, nil)
	if err := a.SetTLS("/no/such/cert", "/no/such/key"); err == nil {
		t.Error("expected error loading missing cert files")
	}
}

// TestAcceptor_ListenAndShutdown drives Listen + listener accessors.
func TestAcceptor_ListenAndShutdown(t *testing.T) {
	t.Parallel()
	a := NewAcceptor(10, nil)
	if err := a.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if a.Listener() == nil {
		t.Fatal("Listener should be set after Listen")
	}
	_, port, err := net.SplitHostPort(a.Listener().Addr().String())
	if err != nil || port == "0" {
		t.Errorf("port not assigned: %v / %q", err, port)
	}
	_ = a.Listener().Close()
}

// TestAcceptor_SetMaxConnections and LogSamplerCleanup are trivial setters.
func TestAcceptor_SetMaxConnectionsAndCleanup(t *testing.T) {
	t.Parallel()
	a := NewAcceptor(10, nil)
	a.SetMaxConnections(99)
	if a.maxConnections != 99 {
		t.Errorf("maxConnections = %d, want 99", a.maxConnections)
	}
	a.LogSamplerCleanup() // must not panic
}

// TestAcceptor_ShouldLog delegates to the sampler.
func TestAcceptor_ShouldLog(t *testing.T) {
	t.Parallel()
	a := NewAcceptor(10, nil)
	logged, count := a.ShouldLog("test-key")
	if !logged || count != 1 {
		t.Errorf("first ShouldLog: logged=%v count=%d", logged, count)
	}
}

// TestWriteMessage_BadJSON covers the marshal-error branch (channel
// value isn't marshalable).
func TestWriteMessage_BadJSON(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	msg := map[string]interface{}{"ch": make(chan int)}
	if err := writeMessage(buf, msg); err == nil {
		t.Error("expected marshal error for unmarshalable value")
	}
}

// TestWriteMessage_ErrToTextEncoder ensures json encoder errors don't
// crash — round-trip a normal message to confirm the encoder works.
func TestWriteMessage_HappyJSONRoundtrip(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	if err := writeMessage(buf, map[string]interface{}{"type": "x"}); err != nil {
		t.Fatalf("writeMessage: %v", err)
	}
	// Skip 4-byte length, decode body.
	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes()[4:], &decoded); err != nil {
		t.Errorf("body not valid JSON: %v", err)
	}
	if decoded["type"] != "x" {
		t.Errorf("body: %v", decoded)
	}
}
