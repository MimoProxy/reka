//go:build with_gvisor

package packettunnel

import (
	"runtime"
	"testing"

	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/runtime/generation"
)

func TestMemoryGuardPeakSinceLastTake(t *testing.T) {
	cfg := defaultMemoryGuardConfig()
	g, clock, usage := startTestMemoryGuard(t, cfg)
	for _, value := range []uint64{10 << 20, 30 << 20, 20 << 20} {
		usage.Store(value)
		clock.tick(cfg.MinInterval)
		<-clock.intervals
	}
	if peak, closed, _ := g.takePeak(); peak != 30<<20 || closed != 0 {
		t.Fatalf("takePeak = %d, %d; want %d, 0", peak, closed, uint64(30<<20))
	}
	if peak, _, _ := g.takePeak(); peak != 0 {
		t.Fatalf("second takePeak = %d, want 0", peak)
	}
	usage.Store(15 << 20)
	clock.tick(cfg.MinInterval)
	<-clock.intervals
	if peak, _, _ := g.takePeak(); peak != 15<<20 {
		t.Fatalf("takePeak after a new sample = %d, want %d", peak, uint64(15<<20))
	}
}

func TestMemoryGuardCountsClosedConnections(t *testing.T) {
	cfg := defaultMemoryGuardConfig()
	g, clock, usage := startTestMemoryGuard(t, cfg)
	usage.Store(cfg.Limit)
	clock.tick(cfg.MinInterval)
	<-clock.intervals
	usage.Store(0)
	clock.tick(cfg.MinInterval)
	<-clock.intervals
	usage.Store(cfg.Limit)
	clock.tick(cfg.MinInterval)
	<-clock.intervals
	if _, closed, armed := g.takePeak(); closed != 6 || armed != 2 {
		t.Fatalf("closed, armed = %d, %d; want 6, 2", closed, armed)
	}
}

func TestMemoryGuardCountsArming(t *testing.T) {
	cfg := defaultMemoryGuardConfig()
	g, clock, usage := startTestMemoryGuard(t, cfg)
	armed := g.armThreshold + 1
	for _, value := range []uint64{armed, armed, 0, armed} {
		usage.Store(value)
		clock.tick(cfg.MinInterval)
		<-clock.intervals
	}
	if _, closed, count := g.takePeak(); count != 2 || closed != 0 {
		t.Fatalf("armed, closed = %d, %d; want 2, 0", count, closed)
	}
}

func TestProcessRuntimeSplitsGoMemory(t *testing.T) {
	runtime.GC()
	before := readProcessRuntime()
	keep := make([]byte, 8<<20)
	runtime.GC()
	after := readProcessRuntime()
	runtime.KeepAlive(keep)

	if after.GCCycles <= before.GCCycles {
		t.Fatalf("gc cycles did not grow: %d then %d", before.GCCycles, after.GCCycles)
	}
	if after.HeapObjects < 8<<20 {
		t.Fatalf("heap objects = %d, want at least the kept allocation", after.HeapObjects)
	}
	if parts := after.HeapObjects + after.HeapIdle + after.Stacks; parts > after.GoResident {
		t.Fatalf("heap parts %d exceed resident Go memory %d", parts, after.GoResident)
	}
	if after.Goroutines == 0 || after.HeapGoal == 0 || after.Stacks == 0 {
		t.Fatalf("missing runtime values: %+v", after)
	}
}

func TestProcessSampleOperation(t *testing.T) {
	engine := generation.NewEngine(generation.EngineOptions{HostPacketFlow: true})
	t.Cleanup(engine.Close)
	session := &Session{ctx: t.Context(), profile: &profileSession{engine: engine}, events: history.NewBounded(16, 1<<20)}
	cfg := defaultMemoryGuardConfig()
	g, clock, usage := startTestMemoryGuard(t, cfg)
	session.guard = g
	usage.Store(1 << 40)
	clock.tick(cfg.MinInterval)
	<-clock.intervals

	value, err := session.RunOperation(Operation{Action: "processSample"})
	if err != nil {
		t.Fatal(err)
	}
	sample := value.(ProcessSample)
	if sample.GoResident == 0 || sample.Goroutines == 0 {
		t.Fatalf("missing process values: %+v", sample)
	}
	if sample.PeakFootprint != 1<<40 {
		t.Fatalf("peak = %d, want the guard's sample", sample.PeakFootprint)
	}
	if sample.GuardState != memoryGuardTriggered || sample.GuardResets != 1 || sample.GuardClosed != 3 ||
		sample.GuardArmed != 1 || sample.GuardReason != "threshold" {
		t.Fatalf("guard = %+v", sample)
	}
	if sample.Scripts != nil {
		t.Fatalf("scripts = %+v, want none", sample.Scripts)
	}
	value, _ = session.RunOperation(Operation{Action: "processSample"})
	if next := value.(ProcessSample); next.PeakFootprint != next.Footprint {
		t.Fatalf("peak after read = %d, want the current footprint %d", next.PeakFootprint, next.Footprint)
	}
}
