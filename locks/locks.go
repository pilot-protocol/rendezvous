// SPDX-License-Identifier: AGPL-3.0-or-later

// Package locks exposes a single HTTP handler at /debug/locks that returns a
// JSON snapshot of mutex/block contention, current goroutine waiters, and
// runtime state.
//
// The package is pure stdlib and adds zero instrumentation overhead on any
// hot path. It reads what the runtime is already collecting:
//
//   - runtime.MutexProfile / runtime.BlockProfile — per-call-site cumulative
//     contention and block delay (sampled at the configured rate; sampling
//     cost is paid regardless of whether anyone reads the profile).
//   - runtime.GoroutineProfile — current stack of every live goroutine, used
//     to count "right now, who is blocked acquiring which lock."
//   - runtime/metrics — exact counters/histograms (no sampling): cumulative
//     mutex wait, scheduler latency, heap, GC, CPU classes.
//
// All work happens on demand inside the HTTP handler. There is no background
// goroutine, no accumulator, no per-lock wrapping.
package locks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"runtime"
	"runtime/metrics"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Snapshot is the full payload returned by /debug/locks.
type Snapshot struct {
	CapturedAt    time.Time        `json:"captured_at"`
	UptimeSeconds float64          `json:"uptime_seconds"`
	SampleRates   SampleRates      `json:"sample_rates"`
	Runtime       RuntimeStats     `json:"runtime"`
	MutexTopSites []Site           `json:"mutex_top_sites"`
	BlockTopSites []Site           `json:"block_top_sites"`
	LiveWaiters   map[string]int   `json:"live_lock_waiters"`
	Heap          HeapStats        `json:"heap"`
	GC            GCStats          `json:"gc"`
	CPUClasses    CPUClassSeconds  `json:"cpu_classes_seconds"`
	SchedLatency  LatencyQuantiles `json:"sched_latency_seconds"`
}

// SampleRates exposes the configured sampling rates so consumers know how to
// interpret cumulative cycle and delay numbers. Mutex profile values scale to
// nanoseconds via Cycles / CyclesPerSecond * 1e9.
type SampleRates struct {
	MutexFraction   int   `json:"mutex_fraction"`
	CyclesPerSecond int64 `json:"cycles_per_second"`
}

// RuntimeStats are exact (non-sampled) runtime counters and gauges.
type RuntimeStats struct {
	Goroutines       int     `json:"goroutines"`
	Threads          int     `json:"threads"`
	GOMAXPROCS       int     `json:"gomaxprocs"`
	CgoCalls         int64   `json:"cgo_calls_total"`
	MutexWaitSeconds float64 `json:"mutex_wait_total_seconds"`
}

// Site is one row of mutex/block contention attributed to a user call site
// (the first non-runtime/non-sync frame walking from the innermost frame
// outward).
type Site struct {
	Function string `json:"function"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Count    int64  `json:"count"`
	Cycles   int64  `json:"cycles"`
	DelayNs  int64  `json:"delay_ns"`
}

// HeapStats are exact heap memory class breakdowns from runtime/metrics.
type HeapStats struct {
	InUseBytes    uint64 `json:"in_use_bytes"`
	UnusedBytes   uint64 `json:"unused_bytes"`
	FreeBytes     uint64 `json:"free_bytes"`
	ReleasedBytes uint64 `json:"released_bytes"`
	StackBytes    uint64 `json:"stack_bytes"`
	GoalBytes     uint64 `json:"goal_bytes"`
	AllocsBytes   uint64 `json:"allocs_total_bytes"`
}

// GCStats summarise GC pause distribution (wall time) and cycle count.
type GCStats struct {
	PausesP50Seconds float64 `json:"pauses_p50_seconds"`
	PausesP99Seconds float64 `json:"pauses_p99_seconds"`
	CyclesTotal      uint64  `json:"cycles_total"`
}

// CPUClassSeconds are cumulative CPU-seconds by category (since process start).
type CPUClassSeconds struct {
	Total       float64 `json:"total"`
	User        float64 `json:"user"`
	Idle        float64 `json:"idle"`
	GCAssist    float64 `json:"gc_mark_assist"`
	GCDedicated float64 `json:"gc_mark_dedicated"`
	Scavenge    float64 `json:"scavenge"`
}

// LatencyQuantiles describe a distribution by p50/p99/p999.
type LatencyQuantiles struct {
	P50  float64 `json:"p50"`
	P99  float64 `json:"p99"`
	P999 float64 `json:"p999"`
}

var (
	startedAt = time.Now()

	cycPerSec     int64
	calibrateOnce sync.Once

	// pcCache symbolicates PCs lazily. PC → function/file/line is immutable
	// for the process lifetime, so a write-once-read-many sync.Map is safe.
	pcCache sync.Map // map[uintptr]runtime.Frame
)

// metricNames is the fixed set of runtime/metrics we read on every snapshot.
// Keep this in sync with the indices in takeSnapshot.
var metricNames = []string{
	"/sync/mutex/wait/total:seconds",        // 0
	"/sched/latencies:seconds",              // 1
	"/sched/goroutines:goroutines",          // 2 (unused but cheap)
	"/cgo/go-to-c-calls:calls",              // 3 (unused — Runtime.CgoCalls uses NumCgoCall)
	"/memory/classes/heap/objects:bytes",    // 4
	"/memory/classes/heap/unused:bytes",     // 5
	"/memory/classes/heap/free:bytes",       // 6
	"/memory/classes/heap/released:bytes",   // 7
	"/memory/classes/heap/stacks:bytes",     // 8
	"/gc/heap/goal:bytes",                   // 9
	"/gc/heap/allocs:bytes",                 // 10
	"/gc/pauses:seconds",                    // 11
	"/gc/cycles/total:gc-cycles",            // 12
	"/cpu/classes/total:cpu-seconds",        // 13
	"/cpu/classes/user:cpu-seconds",         // 14
	"/cpu/classes/idle:cpu-seconds",         // 15
	"/cpu/classes/gc/mark/assist:cpu-seconds",    // 16
	"/cpu/classes/gc/mark/dedicated:cpu-seconds", // 17
	"/cpu/classes/scavenge/total:cpu-seconds",    // 18
}

// Handler returns the HTTP handler for /debug/locks. It writes a JSON
// Snapshot on every request.
func Handler() http.Handler {
	return http.HandlerFunc(serve)
}

func serve(w http.ResponseWriter, r *http.Request) {
	snap := Take()
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(snap)
}

// Take returns a Snapshot of the current registry runtime + lock state. It is
// exported so callers can render the data themselves (e.g. for tests or for
// in-process inspection).
func Take() Snapshot {
	cps := calibrate()

	samples := make([]metrics.Sample, len(metricNames))
	for i, n := range metricNames {
		samples[i].Name = n
	}
	metrics.Read(samples)

	snap := Snapshot{
		CapturedAt:    time.Now(),
		UptimeSeconds: time.Since(startedAt).Seconds(),
		SampleRates: SampleRates{
			MutexFraction:   runtime.SetMutexProfileFraction(-1),
			CyclesPerSecond: cps,
		},
		Runtime: RuntimeStats{
			Goroutines:       runtime.NumGoroutine(),
			Threads:          threadCount(),
			GOMAXPROCS:       runtime.GOMAXPROCS(0),
			CgoCalls:         runtime.NumCgoCall(),
			MutexWaitSeconds: floatValue(samples[0]),
		},
	}

	schedHist := histValue(samples[1])
	snap.SchedLatency = LatencyQuantiles{
		P50:  quantile(schedHist, 0.50),
		P99:  quantile(schedHist, 0.99),
		P999: quantile(schedHist, 0.999),
	}

	snap.Heap = HeapStats{
		InUseBytes:    uint64Value(samples[4]),
		UnusedBytes:   uint64Value(samples[5]),
		FreeBytes:     uint64Value(samples[6]),
		ReleasedBytes: uint64Value(samples[7]),
		StackBytes:    uint64Value(samples[8]),
		GoalBytes:     uint64Value(samples[9]),
		AllocsBytes:   uint64Value(samples[10]),
	}

	gcHist := histValue(samples[11])
	snap.GC = GCStats{
		PausesP50Seconds: quantile(gcHist, 0.50),
		PausesP99Seconds: quantile(gcHist, 0.99),
		CyclesTotal:      uint64Value(samples[12]),
	}

	snap.CPUClasses = CPUClassSeconds{
		Total:       floatValue(samples[13]),
		User:        floatValue(samples[14]),
		Idle:        floatValue(samples[15]),
		GCAssist:    floatValue(samples[16]),
		GCDedicated: floatValue(samples[17]),
		Scavenge:    floatValue(samples[18]),
	}

	snap.MutexTopSites = topSites(readMutexRecords(), 20, cps)
	snap.BlockTopSites = topSites(readBlockRecords(), 20, cps)
	snap.LiveWaiters = liveLockWaiters()
	return snap
}

func readMutexRecords() []runtime.BlockProfileRecord {
	var p []runtime.BlockProfileRecord
	for {
		n, ok := runtime.MutexProfile(p)
		if ok {
			return p[:n]
		}
		p = make([]runtime.BlockProfileRecord, n+32)
	}
}

func readBlockRecords() []runtime.BlockProfileRecord {
	var p []runtime.BlockProfileRecord
	for {
		n, ok := runtime.BlockProfile(p)
		if ok {
			return p[:n]
		}
		p = make([]runtime.BlockProfileRecord, n+32)
	}
}

func readGoroutineRecords() []runtime.StackRecord {
	var p []runtime.StackRecord
	for {
		n, ok := runtime.GoroutineProfile(p)
		if ok {
			return p[:n]
		}
		p = make([]runtime.StackRecord, n+32)
	}
}

// topSites aggregates per-call-site contention. Each BlockProfileRecord's
// Stack0 is walked from the innermost frame outward until the first
// non-runtime/non-sync frame is found — that's the user code call site.
func topSites(rec []runtime.BlockProfileRecord, n int, cps int64) []Site {
	type key struct {
		fn   string
		file string
		line int
	}
	agg := map[key]*Site{}
	for _, r := range rec {
		fn, file, line, ok := userFrame(r.Stack0[:])
		if !ok {
			continue
		}
		k := key{fn, file, line}
		s, exists := agg[k]
		if !exists {
			s = &Site{Function: fn, File: file, Line: line}
			agg[k] = s
		}
		s.Count += r.Count
		s.Cycles += r.Cycles
	}

	out := make([]Site, 0, len(agg))
	for _, s := range agg {
		if cps > 0 {
			s.DelayNs = int64(float64(s.Cycles) / float64(cps) * 1e9)
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Cycles > out[j].Cycles })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// userFrame walks a stack from the innermost frame outward and returns the
// first frame that is not in sync/, runtime/, or internal/. That frame is
// the user code that called Lock/Unlock/Send/Recv and is what an operator
// wants to see attributed.
func userFrame(stack []uintptr) (fn, file string, line int, ok bool) {
	for _, pc := range stack {
		if pc == 0 {
			return "", "", 0, false
		}
		f := lookupFrame(pc)
		if isRuntimeFrame(f.Function) {
			continue
		}
		return f.Function, f.File, f.Line, true
	}
	return "", "", 0, false
}

func lookupFrame(pc uintptr) runtime.Frame {
	if v, ok := pcCache.Load(pc); ok {
		return v.(runtime.Frame)
	}
	fs := runtime.CallersFrames([]uintptr{pc})
	f, _ := fs.Next()
	pcCache.Store(pc, f)
	return f
}

func isRuntimeFrame(fn string) bool {
	return strings.HasPrefix(fn, "sync.") ||
		strings.HasPrefix(fn, "runtime.") ||
		strings.HasPrefix(fn, "internal/")
}

// liveLockWaiters returns the count of goroutines currently parked inside a
// sync acquire, keyed by the user call site immediately above the sync frame.
// This is the *current* state, not cumulative — a complement to MutexTopSites
// for incident response.
func liveLockWaiters() map[string]int {
	rec := readGoroutineRecords()
	out := map[string]int{}
	for _, r := range rec {
		if site := waiterSite(r.Stack0[:]); site != "" {
			out[site]++
		}
	}
	return out
}

// waiterSite checks if a goroutine's stack indicates it is parked inside a
// sync acquire and, if so, returns the first non-runtime caller above the
// acquire frame.
func waiterSite(stack []uintptr) string {
	seenAcquire := false
	for _, pc := range stack {
		if pc == 0 {
			return ""
		}
		f := lookupFrame(pc)
		if !seenAcquire {
			if isAcquireFrame(f.Function) {
				seenAcquire = true
			}
			continue
		}
		if isRuntimeFrame(f.Function) {
			continue
		}
		return fmt.Sprintf("%s (%s:%d)", f.Function, shortFile(f.File), f.Line)
	}
	return ""
}

func isAcquireFrame(fn string) bool {
	switch fn {
	case "sync.(*Mutex).Lock",
		"sync.(*Mutex).lockSlow",
		"sync.(*RWMutex).Lock",
		"sync.(*RWMutex).RLock",
		"sync.(*RWMutex).rLockSlow",
		"sync.(*Cond).Wait",
		"sync.(*WaitGroup).Wait":
		return true
	}
	return false
}

// shortFile trims absolute build paths to "pkg/file.go" for readability.
func shortFile(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		if j := strings.LastIndex(path[:i], "/"); j >= 0 {
			return path[j+1:]
		}
		return path[i+1:]
	}
	return path
}

// calibrate derives cycles-per-second by parsing the header of the legacy
// pprof mutex profile dump. Called at most once across the process lifetime;
// cached forever. If the calibration fails (no records yet) cycPerSec stays
// 0 and DelayNs is reported as 0, which is honest — without the conversion
// factor we can't claim a nanosecond value.
func calibrate() int64 {
	calibrateOnce.Do(func() {
		var buf bytes.Buffer
		if err := pprof.Lookup("mutex").WriteTo(&buf, 1); err != nil {
			return
		}
		for _, line := range strings.Split(buf.String(), "\n") {
			if v, ok := strings.CutPrefix(line, "cycles/second="); ok {
				cycPerSec, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
				return
			}
		}
	})
	return cycPerSec
}

// quantile estimates the q-th quantile of a Float64Histogram by walking the
// cumulative count distribution. Returns the upper bucket boundary unless
// that boundary is +Inf (last bucket), in which case it returns the lower
// boundary as a safer estimate.
func quantile(h *metrics.Float64Histogram, q float64) float64 {
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
	target := uint64(float64(total) * q)
	if target == 0 {
		target = 1
	}
	var seen uint64
	for i, c := range h.Counts {
		seen += c
		if seen >= target {
			upper := h.Buckets[i+1]
			if math.IsInf(upper, 1) {
				return h.Buckets[i]
			}
			return upper
		}
	}
	return 0
}

func floatValue(s metrics.Sample) float64 {
	if s.Value.Kind() == metrics.KindFloat64 {
		return s.Value.Float64()
	}
	return 0
}

func uint64Value(s metrics.Sample) uint64 {
	if s.Value.Kind() == metrics.KindUint64 {
		return s.Value.Uint64()
	}
	return 0
}

func histValue(s metrics.Sample) *metrics.Float64Histogram {
	if s.Value.Kind() == metrics.KindFloat64Histogram {
		return s.Value.Float64Histogram()
	}
	return nil
}

// threadCount returns the number of OS threads the runtime has created. Cheap
// — same as the size of the threadcreate profile.
func threadCount() int {
	n, _ := runtime.ThreadCreateProfile(nil)
	return n
}
