//go:build with_gvisor

package packettunnel

import (
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestMemoryGuardNormalBackoff(t *testing.T) {
	cfg := defaultMemoryGuardConfig()
	g, clock, usage := startTestMemoryGuard(t, cfg)
	usage.Store(cfg.Limit - 2*cfg.SafetyMargin - 1)
	g.start()
	interval := cfg.MinInterval
	for _, want := range []time.Duration{
		200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond,
		1600 * time.Millisecond, 3200 * time.Millisecond, 6400 * time.Millisecond,
		10 * time.Second, 10 * time.Second,
	} {
		clock.tick(interval)
		clock.checkInterval(t, want)
		checkMemoryGuardStats(t, g, memoryGuardStats{State: "normal"})
		interval = want
	}
}

func TestMemoryGuardThresholdHysteresis(t *testing.T) {
	cfg := defaultMemoryGuardConfig()
	g, clock, usage := startTestMemoryGuard(t, cfg)
	trigger := cfg.Limit - cfg.SafetyMargin
	armed := cfg.Limit - 2*cfg.SafetyMargin
	want := memoryGuardStats{
		State: "triggered", Resets: 1, LastReason: "threshold", LastUsage: trigger, LastClosed: 3,
	}

	for _, footprint := range []uint64{trigger, trigger, armed} {
		usage.Store(footprint)
		clock.tick(cfg.MinInterval)
		clock.checkInterval(t, cfg.MinInterval)
		checkMemoryGuardStats(t, g, want)
	}

	usage.Store(armed - 1)
	clock.tick(cfg.MinInterval)
	clock.checkInterval(t, 2*cfg.MinInterval)
	want.State = "normal"
	checkMemoryGuardStats(t, g, want)

	usage.Store(trigger + 1)
	clock.tick(2 * cfg.MinInterval)
	clock.checkInterval(t, cfg.MinInterval)
	want.State = "triggered"
	want.Resets++
	want.LastUsage = trigger + 1
	checkMemoryGuardStats(t, g, want)
}

func TestMemoryGuardEscalatesWhileRising(t *testing.T) {
	cfg := defaultMemoryGuardConfig()
	g, clock, usage := startTestMemoryGuard(t, cfg)
	trigger := cfg.Limit - cfg.SafetyMargin
	usage.Store(trigger)
	clock.tick(cfg.MinInterval)
	clock.checkInterval(t, cfg.MinInterval)
	want := memoryGuardStats{
		State: "triggered", Resets: 1, LastReason: "threshold", LastUsage: trigger, LastClosed: 3,
	}
	checkMemoryGuardStats(t, g, want)

	// Usage that stays near the trigger keeps the active connections.
	for _, footprint := range []uint64{trigger + cfg.EscalateGrowth - 1, trigger, trigger + cfg.EscalateGrowth - 1} {
		usage.Store(footprint)
		clock.tick(10 * cfg.MinInterval)
		clock.checkInterval(t, cfg.MinInterval)
		checkMemoryGuardStats(t, g, want)
	}

	// Closing idle connections did not stop the growth.
	want = memoryGuardStats{
		State: "triggered", Resets: 2, LastReason: "escalated", LastUsage: trigger + cfg.EscalateGrowth, LastClosed: 7,
	}
	for _, footprint := range []uint64{trigger + cfg.EscalateGrowth, trigger + 3*cfg.EscalateGrowth} {
		usage.Store(footprint)
		clock.tick(cfg.MinInterval)
		clock.checkInterval(t, cfg.MinInterval)
		checkMemoryGuardStats(t, g, want)
	}
}

func TestMemoryGuardArmedInterval(t *testing.T) {
	cfg := defaultMemoryGuardConfig()
	g, clock, usage := startTestMemoryGuard(t, cfg)
	usage.Store(cfg.Limit - 2*cfg.SafetyMargin)
	clock.tick(cfg.MinInterval)
	clock.checkInterval(t, cfg.ArmedInterval)
	checkMemoryGuardStats(t, g, memoryGuardStats{State: "armed"})
}

func TestMemoryGuardPressureRate(t *testing.T) {
	cfg := defaultMemoryGuardConfig()
	g, clock, usage := startTestMemoryGuard(t, cfg)
	usage.Store(22 << 20)
	clock.tick(cfg.MinInterval)
	clock.checkInterval(t, 2*cfg.MinInterval)

	g.notifyPressure()
	clock.checkInterval(t, cfg.MinInterval)
	checkMemoryGuardStats(t, g, memoryGuardStats{State: "normal"})

	const footprint = 43 << 20
	usage.Store(footprint)
	want := memoryGuardStats{
		State: "triggered", Resets: 1, LastReason: "rate", LastUsage: footprint, LastClosed: 5,
	}
	for range 2 {
		clock.tick(cfg.MinInterval)
		clock.checkInterval(t, cfg.MinInterval)
		checkMemoryGuardStats(t, g, want)
	}
}

func TestMemoryGuardPressureBaselineExpires(t *testing.T) {
	cfg := defaultMemoryGuardConfig()
	cfg.ArmedInterval = 200 * time.Millisecond
	cfg.MaxInterval = 250 * time.Millisecond
	g, clock, usage := startTestMemoryGuard(t, cfg)
	usage.Store(8 << 20)
	g.notifyPressure()
	clock.checkInterval(t, cfg.MinInterval)

	// The growth would predict that the limit is 50 ms away with a fresh baseline.
	usage.Store(44 << 20)
	clock.tick(300 * time.Millisecond)
	clock.checkInterval(t, cfg.MinInterval)
	checkMemoryGuardStats(t, g, memoryGuardStats{State: "armed"})
}

func TestMemoryGuardPressureSamplesImmediately(t *testing.T) {
	cfg := defaultMemoryGuardConfig()
	g, clock, usage := startTestMemoryGuard(t, cfg)
	trigger := cfg.Limit - cfg.SafetyMargin
	usage.Store(trigger)
	g.notifyPressure()
	clock.checkInterval(t, cfg.MinInterval)
	checkMemoryGuardStats(t, g, memoryGuardStats{
		State: "triggered", Resets: 1, LastReason: "threshold", LastUsage: trigger, LastClosed: 3,
	})
}

func TestMemoryGuardStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := defaultMemoryGuardConfig()
		entered := make(chan struct{})
		release := make(chan struct{})
		var samples atomic.Int32
		g := newMemoryGuard(cfg, func() uint64 {
			if samples.Add(1) == 1 {
				close(entered)
				<-release
			}
			return cfg.Limit
		}, func(reason string) int {
			t.Errorf("reset called with %q after stop began", reason)
			return 0
		})
		clock := useMemoryGuardTestClock(g)
		g.start()
		clock.checkInterval(t, cfg.MinInterval)
		clock.tick(cfg.MinInterval)
		<-entered

		stopped := make(chan struct{})
		go func() {
			g.stop()
			close(stopped)
		}()
		synctest.Wait()
		close(release)
		<-stopped
		g.stop()
		g.start()
		clock.tick(cfg.MinInterval)
		g.notifyPressure()
		synctest.Wait()
		select {
		case <-clock.stopped:
		default:
			t.Fatal("stop left the timer running")
		}
		if got := samples.Load(); got != 1 {
			t.Fatalf("got %d samples, want only the sample already in progress", got)
		}
		checkMemoryGuardStats(t, g, memoryGuardStats{State: "normal"})
	})
}

func TestMemoryGuardConcurrentPressureAndPoll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := defaultMemoryGuardConfig()
		entered := make(chan struct{})
		release := make(chan struct{})
		var samples, resets atomic.Int32
		var g *memoryGuard
		g = newMemoryGuard(cfg, func() uint64 {
			if samples.Add(1) == 1 {
				close(entered)
				<-release
			}
			return cfg.Limit
		}, func(reason string) int {
			if current := g.stats().State; current != "triggered" || reason != "threshold" {
				t.Errorf("reset in state %q with reason %q", current, reason)
			}
			resets.Add(1)
			return 3
		})
		g.start()
		defer g.stop()
		<-entered
		var callers sync.WaitGroup
		const notices = 8
		for range notices {
			callers.Go(g.notifyPressure)
		}
		synctest.Wait()
		close(release)
		callers.Wait()

		if got := samples.Load(); got != 1+notices {
			t.Fatalf("got %d samples, want %d", got, 1+notices)
		}
		if got := resets.Load(); got != 1 {
			t.Fatalf("got %d reset calls, want one", got)
		}
		checkMemoryGuardStats(t, g, memoryGuardStats{
			State: "triggered", Resets: 1, LastReason: "threshold", LastUsage: cfg.Limit, LastClosed: 3,
		})
	})
}

type memoryGuardTestClock struct {
	elapsed   atomic.Int64
	ticks     chan time.Time
	intervals chan time.Duration
	stopped   chan struct{}
}

func useMemoryGuardTestClock(g *memoryGuard) *memoryGuardTestClock {
	clock := &memoryGuardTestClock{
		ticks:     make(chan time.Time, 1),
		intervals: make(chan time.Duration, 1),
		stopped:   make(chan struct{}),
	}
	g.now = clock.now
	g.newTimer = func(interval time.Duration) memoryGuardTimer {
		clock.intervals <- interval
		return memoryGuardTimer{
			ticks: clock.ticks,
			reset: func(interval time.Duration) bool {
				clock.intervals <- interval
				return true
			},
			stop: func() bool {
				close(clock.stopped)
				return true
			},
		}
	}
	return clock
}

func (c *memoryGuardTestClock) now() time.Time {
	return time.Unix(0, c.elapsed.Load())
}

func (c *memoryGuardTestClock) tick(after time.Duration) {
	c.elapsed.Add(int64(after))
	c.ticks <- c.now()
}

func (c *memoryGuardTestClock) checkInterval(t *testing.T, want time.Duration) {
	t.Helper()
	if got := <-c.intervals; got != want {
		t.Fatalf("next interval = %s, want %s", got, want)
	}
}

func startTestMemoryGuard(t *testing.T, cfg memoryGuardConfig) (*memoryGuard, *memoryGuardTestClock, *atomic.Uint64) {
	t.Helper()
	var usage atomic.Uint64
	g := newMemoryGuard(cfg, usage.Load, func(reason string) int {
		switch reason {
		case "threshold":
			return 3
		case "rate":
			return 5
		case "escalated":
			return 7
		default:
			t.Errorf("unexpected reset reason %q", reason)
			return 0
		}
	})
	clock := useMemoryGuardTestClock(g)
	t.Cleanup(g.stop)
	g.start()
	clock.checkInterval(t, cfg.MinInterval)
	return g, clock, &usage
}

func checkMemoryGuardStats(t *testing.T, g *memoryGuard, want memoryGuardStats) {
	t.Helper()
	if got := g.stats(); got != want {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}
