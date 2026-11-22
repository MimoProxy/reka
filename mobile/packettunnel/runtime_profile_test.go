//go:build with_gvisor

package packettunnel

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func readProfilePart(t *testing.T, part string) []byte {
	t.Helper()
	var data []byte
	for {
		chunk, err := readRuntimeProfile(part, len(data))
		if err != nil {
			t.Fatal(err)
		}
		if chunk.Running {
			t.Fatal("profile still running")
		}
		data = append(data, chunk.Data...)
		if len(data) >= chunk.Size {
			if len(data) != chunk.Size {
				t.Fatalf("%s: read %d of %d bytes", part, len(data), chunk.Size)
			}
			return data
		}
		if len(chunk.Data) == 0 {
			t.Fatalf("%s: empty chunk at %d of %d", part, len(data), chunk.Size)
		}
	}
}

func TestRuntimeProfile(t *testing.T) {
	for _, duration := range []time.Duration{0, 999 * time.Millisecond, maxProfileDuration + time.Second} {
		if startRuntimeProfile(duration) == nil {
			t.Fatalf("accepted duration %s", duration)
		}
	}
	if err := startRuntimeProfile(time.Second); err != nil {
		t.Fatal(err)
	}
	if startRuntimeProfile(time.Second) == nil {
		t.Fatal("started a second profile")
	}
	if chunk, err := readRuntimeProfile(ProfileCPU, 0); err != nil || !chunk.Running || chunk.Data != nil {
		t.Fatalf("read a running profile: %+v %v", chunk, err)
	}
	// Give the CPU profile something to record.
	deadline := time.Now().Add(1500 * time.Millisecond)
	var sink []byte
	for time.Now().Before(deadline) {
		sink = append(sink[:0], bytes.Repeat([]byte("reka"), 1024)...)
	}
	for {
		chunk, err := readRuntimeProfile(ProfileCPU, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !chunk.Running {
			break
		}
		if time.Now().After(deadline.Add(5 * time.Second)) {
			t.Fatal("profile did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, part := range []string{ProfileCPU, ProfileAllocsStart, ProfileAllocsEnd} {
		// pprof writes gzip-compressed protocol buffers.
		if data := readProfilePart(t, part); len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
			t.Fatalf("%s is not a gzip-compressed profile", part)
		}
	}
	var stats struct {
		Start, End struct {
			NumGC      uint32 `json:"numGC"`
			TotalAlloc uint64 `json:"totalAlloc"`
			Sys        uint64 `json:"sys"`
		}
		GOMAXPROCS int `json:"gomaxprocs"`
	}
	if err := json.Unmarshal(readProfilePart(t, ProfileRuntime), &stats); err != nil {
		t.Fatal(err)
	}
	if stats.End.Sys == 0 || stats.End.TotalAlloc < stats.Start.TotalAlloc || stats.GOMAXPROCS < 1 {
		t.Fatalf("unexpected runtime stats %+v", stats)
	}
	if _, err := readRuntimeProfile("heap", 0); err == nil {
		t.Fatal("read an unknown part")
	}
	if _, err := readRuntimeProfile(ProfileCPU, 1<<30); err == nil {
		t.Fatal("read past the end")
	}
	_ = sink
}

func TestRuntimeProfileOperations(t *testing.T) {
	session := &Session{}
	if _, err := session.runDiagnostics(Operation{Action: "profileStart", TimeoutMS: 10}); err == nil {
		t.Fatal("accepted a 10 ms profile")
	}
	value, err := session.runDiagnostics(Operation{Action: "profileRead", Category: ProfileRuntime})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := value.(ProfileChunk); !ok {
		t.Fatalf("unexpected reply %T", value)
	}
}
