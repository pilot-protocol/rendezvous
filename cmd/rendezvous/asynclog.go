// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/pilot-protocol/common/logging"
)

// asyncLogBuffer is the queue depth of the async slog handler. At fleet scale
// the registry emits several thousand records/sec; the default slog handler
// formats + writes under a mutex on the caller's goroutine, and the live
// mutex profile showed that as a top contention site. This handler enqueues
// the record and formats/writes it on a dedicated goroutine instead, so hot
// request paths never block on the log mutex.
const asyncLogBuffer = 16384

type asyncLogSink struct {
	next    slog.Handler
	ch      chan slog.Record
	dropped atomic.Uint64
}

func (s *asyncLogSink) run() {
	ctx := context.Background()
	for r := range s.ch {
		_ = s.next.Handle(ctx, r)
	}
}

type asyncHandler struct {
	sink *asyncLogSink
	next slog.Handler
}

func newAsyncHandler(next slog.Handler) slog.Handler {
	sink := &asyncLogSink{next: next, ch: make(chan slog.Record, asyncLogBuffer)}
	go sink.run()
	return &asyncHandler{sink: sink, next: next}
}

func (h *asyncHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.next.Enabled(ctx, lvl)
}

func (h *asyncHandler) Handle(_ context.Context, r slog.Record) error {
	select {
	case h.sink.ch <- r:
	default:
		// Queue full (logging can't keep up with a burst): drop rather than
		// block the caller. The counter is exposed for operators to see.
		h.sink.dropped.Add(1)
	}
	return nil
}

func (h *asyncHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &asyncHandler{sink: h.sink, next: h.next.WithAttrs(attrs)}
}

func (h *asyncHandler) WithGroup(name string) slog.Handler {
	return &asyncHandler{sink: h.sink, next: h.next.WithGroup(name)}
}

// setupLogging installs the configured slog handler and wraps it so log
// formatting/writing happens off the caller's goroutine. Used both at startup
// and by the dynamic log-level endpoint so the async wrapper survives
// level changes.
func setupLogging(level, format string) {
	logging.Setup(level, format)
	slog.SetDefault(slog.New(newAsyncHandler(slog.Default().Handler())))
}
