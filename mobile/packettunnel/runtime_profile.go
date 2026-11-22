//go:build with_gvisor

package packettunnel

import (
	"bytes"
	"encoding/json"
	"errors"
	"runtime"
	"runtime/pprof"
	"sync"
	"time"
)

// Runtime profiles let a host see where the packet tunnel process spends
// CPU and memory under real traffic. One profile runs at a time in the
// process. It records a CPU profile for the requested duration, allocation
// profiles at the start and the end, and runtime statistics at both ends.

const (
	maxProfileDuration = 2 * time.Minute
	profileChunkSize   = 48 << 10
)

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
	time.AfterFunc(duration, func() {
		pprof.StopCPUProfile()
		end, endAllocs := readRuntimeStats(), allocsProfile()
		stats, _ := json.Marshal(struct {
			Start      RuntimeStats `json:"start"`
			End        RuntimeStats `json:"end"`
			GOMAXPROCS int          `json:"gomaxprocs"`
		}{start, end, runtime.GOMAXPROCS(0)})
		runtimeProfile.Lock()
		defer runtimeProfile.Unlock()
		runtimeProfile.running = false
		runtimeProfile.parts = map[string][]byte{
			ProfileCPU: cpu.Bytes(), ProfileAllocsStart: startAllocs, ProfileAllocsEnd: endAllocs, ProfileRuntime: stats,
		}
	})
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
