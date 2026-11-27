//go:build ios && cgo && with_gvisor

package main

import (
	"runtime"
	"runtime/debug"
	"time"

	"github.com/MimoProxy/reka/mobile/scriptbridge"
	"github.com/sagernet/sing/common/memory"
)

// The iOS Network Extension is killed above 50 MB, so the extension tunes
// the Go runtime to that budget and resets connections near it.
const guardExtensionMemory = true

func init() {
	// Heap profiling keeps a 1.4 MiB bucket table, which counts against
	// the extension's footprint once samples touch it. Only diagnostics
	// read heap profiles, and a runtime profile restores the default rate
	// when it starts. Allocations during package initialization may still
	// have touched a few pages.
	runtime.MemProfileRate = 0
}

func tuneExtensionRuntime() {
	runtime.GOMAXPROCS(2)
	// The limit covers all memory the Go runtime holds, not just the
	// heap, and under load Go grows until it reaches it. sing-box's
	// libbox sets 4/5 of the extension's 50 MB limit; the same ratio
	// of the 25 MiB steady budget leaves room for the 4–6 MiB the
	// extension holds outside Go (JavaScriptCore, system frameworks)
	// and leaves room for HTTP scripts under their 38 MiB budget. With
	// every ad-blocked app open, memory outside Go reached about
	// 12 MiB, so a higher limit would leave little headroom below the
	// memory guard. On an iPhone with Bilibili and YouTube
	// traffic through HTTPS interception, 28 MiB let Go reach 27.6 MiB
	// and the footprint 31 MiB. With 20 MiB the same kind of load
	// peaked at 24.5 MiB, with collection taking about 8% of two
	// cores; bursts with several hundred goroutines still exceed the
	// limit and spend up to 17% collecting.
	debug.SetMemoryLimit(20 << 20)
	// GOGC 50 matches sing-box libbox's
	// oomkiller.DefaultAppleNetworkExtensionGCPercent. Without HTTPS
	// interception it made no measurable difference, because tunnel
	// memory is live data. Interception allocates per request: on an
	// iPhone, 8 parallel intercepted requests for 30 s peaked at 25.8 MiB
	// with the default and 23.0 MiB with GOGC 50, against a 25 MiB steady
	// budget.
	debug.SetGCPercent(50)
}

// Reka defines these script footprint thresholds for its iOS extension.
const (
	// A run starts only when the footprint plus its estimated cost stays
	// within the 38 MiB script budget. A fixed 28 MiB cutoff skipped every
	// run once real app traffic held the extension at 24-28 MiB, although
	// most runs add little memory. 38 MiB keeps 12 MiB below the 50 MiB
	// Network Extension limit, enough for a 10 MiB run spike the estimate
	// misses.
	scriptSkipAbove = 38 << 20
	// On device, JSC runs with JSON or protobuf bodies up to 512 KiB added
	// 0.2-1.2 MiB, a large bundle about 1.2 MiB more, and a CryptoJS script
	// up to 10 MiB (about 19 times the body). Reused WebView runs added under
	// 1 MiB at 512 KiB, mostly the base64 copy. A 2 MiB base plus 8 times the
	// body covers all but the CryptoJS case, which the post-run discard
	// check still catches.
	scriptRunBaseCost    = 2 << 20
	scriptRunCostPerByte = 8
	// Reka discards results and purges host caches above the same 38 MiB,
	// well before the memory guard resets connections at 45 MiB.
	scriptDiscardAbove = 38 << 20
)

// Before skipping a run or discarding its result, the bridge returns free
// Go memory to the system and checks again. Under app traffic the
// extension held 34-37 MiB while Go held 5-6 MiB of idle heap, so nearly
// every run was skipped although returning that heap would have made
// room. A forced collection costs CPU, so it runs at most once a second,
// the memory guard's armed sampling interval from sing-box's oomkiller.
const scriptReclaimInterval = time.Second

func scriptRunCost(bodyBytes int) uint64 {
	return scriptRunBaseCost + scriptRunCostPerByte*uint64(bodyBytes)
}

var scriptOptions = scriptbridge.Options{
	Footprint: memory.Total, SkipAbove: scriptSkipAbove, RunCost: scriptRunCost, DiscardAbove: scriptDiscardAbove,
	Reclaim: debug.FreeOSMemory, ReclaimInterval: scriptReclaimInterval,
}
