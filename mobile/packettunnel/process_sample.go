//go:build with_gvisor

package packettunnel

import (
	"runtime/metrics"

	"github.com/MimoProxy/reka/internal/api"

	"github.com/sagernet/sing/common/memory"
)

// Process samples let a host keep a day-long record of the process at
// minute resolution. A sample reports the current footprint, the highest
// footprint the memory guard saw since the previous sample, and how the Go
// runtime's share of the process is split between live objects, memory it
// keeps for reuse, stacks and its own bookkeeping. Counters are cumulative
// for the process, so a host that sees one go down knows the process
// restarted. Script counts cover the runs memory limits stopped since the
// previous sample. Reading runtime/metrics does not stop the world.

// ProcessSample is one sample. Sizes are in bytes.
type ProcessSample struct {
	Footprint     uint64 `json:"footprint"`
	PeakFootprint uint64 `json:"peakFootprint"`
	// Go memory the runtime has not returned to the system.
	GoResident  uint64 `json:"goResident"`
	HeapObjects uint64 `json:"heapObjects"`
	// Heap the runtime keeps but no object uses: free pages it has not
	// released yet and unused space inside spans.
	HeapIdle   uint64 `json:"heapIdle"`
	Stacks     uint64 `json:"stacks"`
	HeapGoal   uint64 `json:"heapGoal"`
	GCCycles   uint64 `json:"gcCycles"`
	Goroutines uint64 `json:"goroutines"`
	// Native heap in use, when the host reports it.
	NativeHeap uint64 `json:"nativeHeap,omitempty"`
	GuardState string `json:"guardState,omitempty"`
	// Times usage came near the trigger, so the guard armed.
	GuardArmed  int `json:"guardArmed"`
	GuardResets int `json:"guardResets"`
	GuardClosed int `json:"guardClosed"`
	// Why the latest reset happened: "threshold", "rate" or "escalated".
	GuardReason string              `json:"guardReason,omitempty"`
	Connections int                 `json:"connections"`
	Scripts     *api.ScriptPressure `json:"scripts,omitempty"`
}

// processSampleScripts bounds the scripts a sample names, so it stays
// well inside the host's 4 KB reply buffer.
const processSampleScripts = 5

var processSampleMetrics = [...]string{
	"/memory/classes/total:bytes",
	"/memory/classes/heap/released:bytes",
	"/memory/classes/heap/objects:bytes",
	"/memory/classes/heap/free:bytes",
	"/memory/classes/heap/unused:bytes",
	"/memory/classes/heap/stacks:bytes",
	"/memory/classes/os-stacks:bytes",
	"/gc/heap/goal:bytes",
	"/gc/cycles/total:gc-cycles",
	"/sched/goroutines:goroutines",
}

func (s *Session) processSample() ProcessSample {
	sample := readProcessRuntime()
	sample.Footprint = memory.Total()
	sample.PeakFootprint = sample.Footprint
	if g := s.guard; g != nil {
		peak, closed, armed := g.takePeak()
		stats := g.stats()
		sample.PeakFootprint = max(sample.PeakFootprint, peak)
		sample.GuardState, sample.GuardArmed, sample.GuardResets = stats.State, armed, stats.Resets
		sample.GuardClosed, sample.GuardReason = closed, stats.LastReason
	}
	if s.profile != nil && s.profile.engine != nil {
		if scripts := s.profile.engine.TakeScriptPressure(processSampleScripts); scripts.Skipped+scripts.Discarded+scripts.Oversize != 0 {
			sample.Scripts = &scripts
		}
	}
	if extra := ProfileExtra; extra != nil {
		if inUse, ok := extra()["mallocInUse"]; ok && inUse > 0 {
			sample.NativeHeap = uint64(inUse)
		}
	}
	sample.Connections, _ = s.Counts()
	return sample
}

func readProcessRuntime() ProcessSample {
	var samples [len(processSampleMetrics)]metrics.Sample
	for i, name := range processSampleMetrics {
		samples[i].Name = name
	}
	metrics.Read(samples[:])
	var v [len(processSampleMetrics)]uint64
	for i := range samples {
		if samples[i].Value.Kind() == metrics.KindUint64 {
			v[i] = samples[i].Value.Uint64()
		}
	}
	total, released := v[0], v[1]
	return ProcessSample{
		GoResident:  total - min(released, total),
		HeapObjects: v[2],
		HeapIdle:    v[3] + v[4],
		Stacks:      v[5] + v[6],
		HeapGoal:    v[7],
		GCCycles:    v[8],
		Goroutines:  v[9],
	}
}
