//go:build with_gvisor

package packettunnel

import (
	"runtime/debug"
	"sync"
	"time"
)

// Reset reasons. The first reset of a trigger closes idle connections;
// memoryResetAll closes every connection.
const (
	memoryResetThreshold = "threshold"
	memoryResetRate      = "rate"
	memoryResetAll       = "escalated"
)

const (
	memoryGuardNormal    = "normal"
	memoryGuardArmed     = "armed"
	memoryGuardTriggered = "triggered"
)

type memoryGuardConfig struct {
	Limit         uint64 // Footprint limit in bytes.
	SafetyMargin  uint64 // Distance in bytes from the limit to the trigger.
	MinInterval   time.Duration
	ArmedInterval time.Duration
	MaxInterval   time.Duration
	// A trigger first closes only ended and idle connections. When usage
	// then grows by EscalateGrowth more while still at the trigger, the
	// guard closes every connection.
	EscalateGrowth uint64
}

// The defaults match sing-box's oomkiller for the iOS Network Extension:
// a 50 MiB limit, a 5 MiB safety margin and 100 ms / 1 s / 10 s sampling.
func defaultMemoryGuardConfig() memoryGuardConfig {
	return memoryGuardConfig{
		Limit:         50 << 20,
		SafetyMargin:  5 << 20,
		MinInterval:   100 * time.Millisecond,
		ArmedInterval: time.Second,
		MaxInterval:   10 * time.Second,
		// sing-box closes every connection at once. Closing the idle ones
		// first keeps active transfers. Escalation waits for continued
		// growth rather than a deadline: on an iPhone, heap fragmentation
		// kept the footprint at the trigger after the idle connections
		// closed, and closing the remaining 74 freed nothing either. 1 MiB
		// is twice the sample-to-sample noise seen at that level.
		EscalateGrowth: 1 << 20,
	}
}

type memoryGuardStats struct {
	State      string
	Resets     int
	LastReason string
	LastUsage  uint64
	LastClosed int
}

type memoryGuardTimer struct {
	ticks <-chan time.Time
	reset func(time.Duration) bool
	stop  func() bool
}

type memoryGuard struct {
	cfg                            memoryGuardConfig
	triggerThreshold, armThreshold uint64
	sample                         func() uint64
	reset                          func(string) int
	now                            func() time.Time
	newTimer                       func(time.Duration) memoryGuardTimer

	mu       sync.Mutex
	started  bool
	stopped  bool
	status   memoryGuardStats
	stopping chan struct{}
	done     chan struct{}
	pressure chan chan struct{}

	// The sampling loop owns the interval and pressure baseline.
	interval         time.Duration
	forceMinInterval bool
	hasBaseline      bool
	baselineUsage    uint64
	baselineTime     time.Time
	escalated        bool
}

// sample reports process footprint in bytes. reset returns the number of closed connections.
func newMemoryGuard(cfg memoryGuardConfig, sample func() uint64, reset func(reason string) int) *memoryGuard {
	trigger := cfg.Limit - min(cfg.SafetyMargin, cfg.Limit)
	return &memoryGuard{
		cfg:              cfg,
		triggerThreshold: trigger,
		armThreshold:     trigger - min(cfg.SafetyMargin, trigger),
		sample:           sample,
		reset:            reset,
		now:              time.Now,
		newTimer: func(interval time.Duration) memoryGuardTimer {
			timer := time.NewTimer(interval)
			return memoryGuardTimer{ticks: timer.C, reset: timer.Reset, stop: timer.Stop}
		},
		status:   memoryGuardStats{State: memoryGuardNormal},
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
		pressure: make(chan chan struct{}),
		interval: cfg.MinInterval,
	}
}

func (g *memoryGuard) start() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.started || g.stopped {
		return
	}
	g.started = true
	go g.run()
}

// stop cancels future samples and waits for the sampling loop to exit.
func (g *memoryGuard) stop() {
	g.mu.Lock()
	if !g.stopped {
		g.stopped = true
		close(g.stopping)
	}
	started := g.started
	g.mu.Unlock()
	if started {
		<-g.done
	}
}

// notifyPressure asks the sampling loop to reclaim memory and sample without waiting for a tick.
func (g *memoryGuard) notifyPressure() {
	g.mu.Lock()
	running := g.started && !g.stopped
	g.mu.Unlock()
	if !running {
		return
	}
	sampled := make(chan struct{})
	select {
	case <-g.stopping:
	case g.pressure <- sampled:
		<-sampled
	}
}

func (g *memoryGuard) stats() memoryGuardStats {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.status
}

func (g *memoryGuard) run() {
	defer close(g.done)
	timer := g.newTimer(g.interval)
	defer timer.stop()
	for {
		var sampled chan struct{}
		select {
		case <-g.stopping:
			return
		case sampled = <-g.pressure:
		case <-timer.ticks:
		}
		g.poll(sampled != nil)
		select {
		case <-g.stopping:
		default:
			timer.reset(g.interval)
		}
		if sampled != nil {
			close(sampled)
		}
	}
}

// poll runs on the sampling loop for both timer ticks and pressure notices.
func (g *memoryGuard) poll(pressure bool) {
	select {
	case <-g.stopping:
		return
	default:
	}
	if pressure {
		debug.FreeOSMemory()
	}
	usage := g.sample()
	now := g.now()

	g.mu.Lock()
	if g.stopped {
		g.mu.Unlock()
		return
	}
	if pressure {
		g.forceMinInterval = true
		g.hasBaseline = true
		g.baselineUsage = usage
		g.baselineTime = now
	}
	previous := g.status.State
	state := g.nextState(previous, usage)
	var reason string
	if previous != memoryGuardTriggered {
		switch {
		case state == memoryGuardTriggered:
			reason = memoryResetThreshold
		case g.reachesLimitTooSoon(usage, now):
			state = memoryGuardTriggered
			reason = memoryResetRate
		}
		if reason != "" {
			g.escalated = false
		}
	} else if state == memoryGuardTriggered && !g.escalated && usage >= g.triggerThreshold &&
		usage >= g.status.LastUsage+g.cfg.EscalateGrowth {
		reason, g.escalated = memoryResetAll, true
	}
	// Give the pressure baseline a follow-up at the minimum interval even when usage is normal.
	if state == memoryGuardNormal && !pressure {
		g.forceMinInterval = false
	}
	g.updateInterval(state)
	g.status.State = state
	g.mu.Unlock()

	if reason != "" {
		closed := g.reset(reason)
		debug.FreeOSMemory()
		g.mu.Lock()
		g.status.Resets++
		g.status.LastReason = reason
		g.status.LastUsage = usage
		g.status.LastClosed = closed
		g.mu.Unlock()
	}
}

func (g *memoryGuard) nextState(current string, usage uint64) string {
	switch {
	case usage >= g.triggerThreshold || (current == memoryGuardTriggered && usage >= g.armThreshold):
		return memoryGuardTriggered
	case usage >= g.armThreshold:
		return memoryGuardArmed
	default:
		return memoryGuardNormal
	}
}

func (g *memoryGuard) reachesLimitTooSoon(usage uint64, now time.Time) bool {
	if !g.hasBaseline || usage <= g.baselineUsage || usage >= g.cfg.Limit {
		return false
	}
	elapsed := now.Sub(g.baselineTime)
	if elapsed <= 0 || elapsed < g.cfg.MinInterval/2 || elapsed > g.cfg.MaxInterval {
		return false
	}
	headroom := g.cfg.Limit - usage
	growth := usage - g.baselineUsage
	return float64(headroom)*float64(elapsed) < float64(growth)*float64(g.cfg.MinInterval)
}

func (g *memoryGuard) updateInterval(state string) {
	switch {
	case g.forceMinInterval || state == memoryGuardTriggered:
		g.interval = g.cfg.MinInterval
	case state == memoryGuardArmed:
		g.interval = g.cfg.ArmedInterval
	default:
		g.interval += min(g.interval, g.cfg.MaxInterval-g.interval)
	}
}
