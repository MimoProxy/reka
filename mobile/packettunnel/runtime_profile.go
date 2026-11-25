//go:build with_gvisor

package packettunnel

import (
	"bytes"
	"encoding/json"
	"errors"
	"runtime"
	"runtime/metrics"
	"runtime/pprof"
	"sync"
	"time"

	"github.com/sagernet/sing/common/memory"
)

// Runtime profiles let a host see where the packet tunnel process spends
// CPU and memory under real traffic. One profile runs at a time in the
// process. It records a CPU profile for the requested duration, allocation
// profiles at the start and the end, runtime statistics at both ends, a
// memory sample every second and the goroutines left at the end.

const (
	maxProfileDuration = 2 * time.Minute
	profileChunkSize   = 48 << 10
	profileSampleEvery = time.Second
	// The runtime's default heap profiling rate.
	profileDefaultMemRate = 512 << 10
)

// Runtime metrics recorded in the per-second memory samples, keyed by the
// JSON name used in the samples.
var profileMetrics = []struct{ key, name string }{
	{"total", "/memory/classes/total:bytes"},
	{"released", "/memory/classes/heap/released:bytes"},
	{"heapObjects", "/memory/classes/heap/objects:bytes"},
	{"heapUnused", "/memory/classes/heap/unused:bytes"},
	{"heapFree", "/memory/classes/heap/free:bytes"},
	{"heapStacks", "/memory/classes/heap/stacks:bytes"},
	{"osStacks", "/memory/classes/os-stacks:bytes"},
	{"metadata", "/memory/classes/metadata/other:bytes"},
	{"mspan", "/memory/classes/metadata/mspan/inuse:bytes"},
	{"mcache", "/memory/classes/metadata/mcache/inuse:bytes"},
	{"buckets", "/memory/classes/profiling/buckets:bytes"},
	{"other", "/memory/classes/other:bytes"},
	{"live", "/gc/heap/live:bytes"},
	{"goal", "/gc/heap/goal:bytes"},
	{"gcCycles", "/gc/cycles/total:gc-cycles"},
	{"goroutines", "/sched/goroutines:goroutines"},
	{"gcCPU", "/cpu/classes/gc/total:cpu-seconds"},
	{"gogc", "/gc/gogc:percent"},
	{"memoryLimit", "/gc/gomemlimit:bytes"},
	{"totalCPU", "/cpu/classes/total:cpu-seconds"},
}

// ProfileExtra, when set by the host, adds process measurements that the Go
// runtime cannot see, such as native heap use, to each memory sample.
var ProfileExtra func() map[string]float64

// activeProfileFlows reports the admitted flows of the running session.
var activeProfileFlows struct {
	sync.Mutex
	read func() (tcp, udp int)
}

func setProfileFlows(read func() (tcp, udp int)) {
	activeProfileFlows.Lock()
	activeProfileFlows.read = read
	activeProfileFlows.Unlock()
}

// readProfileSample returns the process footprint and the runtime metrics
// above, without stopping the world.
func readProfileSample(start time.Time, samples []metrics.Sample) map[string]float64 {
	metrics.Read(samples)
	sample := map[string]float64{
		"t":         time.Since(start).Seconds(),
		"footprint": float64(memory.Total()),
	}
	activeProfileFlows.Lock()
	read := activeProfileFlows.read
	activeProfileFlows.Unlock()
	if read != nil {
		tcp, udp := read()
		sample["tcpFlows"], sample["udpFlows"] = float64(tcp), float64(udp)
	}
	if extra := ProfileExtra; extra != nil {
		for key, value := range extra() {
			sample[key] = value
		}
	}
	for i, metric := range profileMetrics {
		switch samples[i].Value.Kind() {
		case metrics.KindUint64:
			sample[metric.key] = float64(samples[i].Value.Uint64())
		case metrics.KindFloat64:
			sample[metric.key] = samples[i].Value.Float64()
		}
	}
	return sample
}

func newProfileSamples() []metrics.Sample {
	samples := make([]metrics.Sample, len(profileMetrics))
	for i, metric := range profileMetrics {
		samples[i].Name = metric.name
	}
	return samples
}

func goroutineProfile() string {
	var buffer bytes.Buffer
	_ = pprof.Lookup("goroutine").WriteTo(&buffer, 1)
	return buffer.String()
}

// Profile part names accepted by profileRead.
const (
	ProfileCPU         = "cpu"
	ProfileAllocsStart = "allocsStart"
	ProfileAllocsEnd   = "allocsEnd"
	ProfileRuntime     = "runtime"
)

var runtimeProfile struct {
	sync.Mutex
	running bool
	parts   map[string][]byte
}

// RuntimeStats is a snapshot of Go runtime memory and collector state.
type RuntimeStats struct {
	NumGC        uint32  `json:"numGC"`
	PauseTotalMS float64 `json:"pauseTotalMs"`
	HeapAlloc    uint64  `json:"heapAlloc"`
	HeapInuse    uint64  `json:"heapInuse"`
	HeapIdle     uint64  `json:"heapIdle"`
	HeapReleased uint64  `json:"heapReleased"`
	StackSys     uint64  `json:"stackSys"`
	GCSys        uint64  `json:"gcSys"`
	OtherSys     uint64  `json:"otherSys"`
	Sys          uint64  `json:"sys"`
	TotalAlloc   uint64  `json:"totalAlloc"`
	Mallocs      uint64  `json:"mallocs"`
	Goroutines   int     `json:"goroutines"`
}

func readRuntimeStats() RuntimeStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return RuntimeStats{
		NumGC: m.NumGC, PauseTotalMS: float64(m.PauseTotalNs) / 1e6,
		HeapAlloc: m.HeapAlloc, HeapInuse: m.HeapInuse, HeapIdle: m.HeapIdle, HeapReleased: m.HeapReleased,
		StackSys: m.StackSys, GCSys: m.GCSys, OtherSys: m.OtherSys, Sys: m.Sys,
		TotalAlloc: m.TotalAlloc, Mallocs: m.Mallocs, Goroutines: runtime.NumGoroutine(),
	}
}

func allocsProfile() []byte {
	var buffer bytes.Buffer
	_ = pprof.Lookup("allocs").WriteTo(&buffer, 0)
	return buffer.Bytes()
}

// startRuntimeProfile begins a profile of the given duration. Results from a
// previous profile are discarded.
func startRuntimeProfile(duration time.Duration) error {
	if duration < time.Second || duration > maxProfileDuration {
		return errors.New("profile duration must be between 1 and 120 seconds")
	}
	runtimeProfile.Lock()
	defer runtimeProfile.Unlock()
	if runtimeProfile.running {
		return errors.New("a profile is already running")
	}
	start, startAllocs := readRuntimeStats(), allocsProfile()
	cpu := new(bytes.Buffer)
	if err := pprof.StartCPUProfile(cpu); err != nil {
		return err
	}
	runtimeProfile.running, runtimeProfile.parts = true, nil
	if runtime.MemProfileRate == 0 {
		// Hosts that turn heap profiling off restore the default for diagnostics.
		runtime.MemProfileRate = profileDefaultMemRate
	}
	began, samples := time.Now(), newProfileSamples()
	timeline := []map[string]float64{readProfileSample(began, samples)}
	ticker := time.NewTicker(profileSampleEvery)
	finished := time.After(duration)
	go func() {
		defer ticker.Stop()
		for running := true; running; {
			select {
			case <-ticker.C:
			case <-finished:
				running = false
			}
			timeline = append(timeline, readProfileSample(began, samples))
		}
		pprof.StopCPUProfile()
		end, endAllocs := readRuntimeStats(), allocsProfile()
		stats, _ := json.Marshal(struct {
			Start      RuntimeStats         `json:"start"`
			End        RuntimeStats         `json:"end"`
			GOMAXPROCS int                  `json:"gomaxprocs"`
			MemRate    int                  `json:"memProfileRate"`
			Timeline   []map[string]float64 `json:"timeline"`
			Goroutines string               `json:"goroutines"`
		}{start, end, runtime.GOMAXPROCS(0), runtime.MemProfileRate, timeline, goroutineProfile()})
		runtimeProfile.Lock()
		defer runtimeProfile.Unlock()
		runtimeProfile.running = false
		runtimeProfile.parts = map[string][]byte{
			ProfileCPU: cpu.Bytes(), ProfileAllocsStart: startAllocs, ProfileAllocsEnd: endAllocs, ProfileRuntime: stats,
		}
	}()
	return nil
}

// ProfileChunk is one piece of a finished profile part. Data holds raw
// bytes; JSON encodes it as base64.
type ProfileChunk struct {
	Running bool   `json:"running"`
	Part    string `json:"part"`
	Size    int    `json:"size"`
	Offset  int    `json:"offset"`
	Data    []byte `json:"data"`
}

func readRuntimeProfile(part string, offset int) (ProfileChunk, error) {
	runtimeProfile.Lock()
	defer runtimeProfile.Unlock()
	chunk := ProfileChunk{Running: runtimeProfile.running, Part: part, Offset: offset}
	if runtimeProfile.running || runtimeProfile.parts == nil {
		return chunk, nil
	}
	data, ok := runtimeProfile.parts[part]
	if !ok {
		return chunk, errors.New("unknown profile part")
	}
	if offset < 0 || offset > len(data) {
		return chunk, errors.New("profile offset out of range")
	}
	chunk.Size = len(data)
	chunk.Data = data[offset:min(len(data), offset+profileChunkSize)]
	return chunk, nil
}
