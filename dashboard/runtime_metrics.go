// SPDX-License-Identifier: AGPL-3.0-or-later

package dashboard

import (
	"os"
	"runtime"
	"runtime/metrics"
	"time"
)

// collectRuntimeMetrics returns the JSON payload for /api/runtime.
// Pulled from runtime/metrics (built into the Go runtime, sampled
// continuously at no measurable cost) plus a /proc/self/fd count on
// Linux. The shape is stable: anything that mid-tier dashboards or
// alerts scrape lives at a fixed key.
//
// Why these specific metrics:
//
//   - goroutines: the simplest leak detector. A monotonic climb over
//     hours is a goroutine leak you'd otherwise discover via OOM.
//   - heap_alloc + heap_objects: same idea for memory leaks. Pair with
//     gc_cycles_total to spot allocation storms (objects spike, GC
//     count spikes, alloc grows).
//   - mutex_wait_total: cumulative time goroutines spent BLOCKED on
//     mutexes. A rate() over this in Prom shows contention pressure.
//     The registry's hottest lock (s.mu) is contended only during
//     flushSave; if this metric ramps with no save in flight, a new
//     hot path was introduced.
//   - sched_latency_p99: time between a goroutine becoming runnable
//     and actually running. Climbs when GOMAXPROCS is saturated even
//     if individual CPU samples look idle — catches the "CPU bound by
//     goroutine count, not work" failure mode.
//   - gc_pause_p99 + gc_pause_max: worst-case STW pause in the most
//     recent window. A 50 ms STW pause on a registry serving 20k rps
//     queues ~1000 in-flight requests behind it.
//   - fd_count: open file descriptors on Linux. Catches leaked
//     sockets / log handles before EMFILE kills the accept loop.
func collectRuntimeMetrics() map[string]any {
	samples := []metrics.Sample{
		{Name: "/sync/mutex/wait/total:seconds"},
		{Name: "/sched/latencies:seconds"},
		{Name: "/gc/pauses:seconds"},
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/heap/free:bytes"},
		{Name: "/gc/cycles/total:gc-cycles"},
		{Name: "/gc/heap/objects:objects"},
	}
	metrics.Read(samples)

	pickFloat := func(name string) float64 {
		for _, s := range samples {
			if s.Name == name {
				if s.Value.Kind() == metrics.KindFloat64 {
					return s.Value.Float64()
				}
			}
		}
		return 0
	}
	pickUint := func(name string) uint64 {
		for _, s := range samples {
			if s.Name == name {
				if s.Value.Kind() == metrics.KindUint64 {
					return s.Value.Uint64()
				}
			}
		}
		return 0
	}
	pickHist := func(name string) *metrics.Float64Histogram {
		for _, s := range samples {
			if s.Name == name && s.Value.Kind() == metrics.KindFloat64Histogram {
				return s.Value.Float64Histogram()
			}
		}
		return nil
	}

	out := map[string]any{
		"goroutines":         runtime.NumGoroutine(),
		"gomaxprocs":         runtime.GOMAXPROCS(0),
		"num_cpu":            runtime.NumCPU(),
		"heap_alloc_bytes":   pickUint("/memory/classes/heap/objects:bytes"),
		"heap_free_bytes":    pickUint("/memory/classes/heap/free:bytes"),
		"heap_objects":       pickUint("/gc/heap/objects:objects"),
		"gc_cycles_total":    pickUint("/gc/cycles/total:gc-cycles"),
		"mutex_wait_seconds": pickFloat("/sync/mutex/wait/total:seconds"),
		"server_time":        time.Now().Unix(),
	}
	if h := pickHist("/sched/latencies:seconds"); h != nil {
		out["sched_latency_p50_seconds"] = histPercentile(h, 0.50)
		out["sched_latency_p99_seconds"] = histPercentile(h, 0.99)
	}
	if h := pickHist("/gc/pauses:seconds"); h != nil {
		out["gc_pause_p50_seconds"] = histPercentile(h, 0.50)
		out["gc_pause_p99_seconds"] = histPercentile(h, 0.99)
		out["gc_pause_max_seconds"] = histMax(h)
	}
	if n, ok := openFDCount(); ok {
		out["open_fds"] = n
	}
	return out
}

// histPercentile interpolates a percentile from a float64 histogram.
// runtime/metrics buckets are right-open: Counts[i] entries fall in
// (Buckets[i], Buckets[i+1]]. We treat the bucket's upper bound as the
// representative value — good enough for operator dashboards where the
// 50/99 ratio matters more than the exact value.
func histPercentile(h *metrics.Float64Histogram, p float64) float64 {
	if h == nil || len(h.Counts) == 0 {
		return 0
	}
	var total uint64
	for _, c := range h.Counts {
		total += c
	}
	if total == 0 {
		return 0
	}
	target := uint64(float64(total) * p)
	var seen uint64
	for i, c := range h.Counts {
		seen += c
		if seen >= target {
			if i+1 < len(h.Buckets) {
				return h.Buckets[i+1]
			}
			return h.Buckets[i]
		}
	}
	return h.Buckets[len(h.Buckets)-1]
}

// histMax returns the upper bound of the highest non-empty bucket.
func histMax(h *metrics.Float64Histogram) float64 {
	if h == nil || len(h.Counts) == 0 {
		return 0
	}
	for i := len(h.Counts) - 1; i >= 0; i-- {
		if h.Counts[i] > 0 {
			if i+1 < len(h.Buckets) {
				return h.Buckets[i+1]
			}
			return h.Buckets[i]
		}
	}
	return 0
}

// openFDCount returns the number of open file descriptors via
// /proc/self/fd on Linux. The (n, false) result on other platforms
// signals the caller to omit the field rather than report 0.
func openFDCount() (int, bool) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	return len(entries), true
}
