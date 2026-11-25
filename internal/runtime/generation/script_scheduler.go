package generation

import (
	"net/netip"
	"slices"
	"time"

	"github.com/MimoProxy/reka/internal/script"
)

// Reka coalesces network notifications and bounds waits against wall time.
const (
	networkEventDelay         = time.Second
	cronWallClockInterval     = time.Minute
	networkChangedScriptEvent = "network-changed" // Surge event name.
)

type scriptTimer interface {
	Stop() bool
}

type scriptSchedulerClock struct {
	now       func() time.Time
	afterFunc func(time.Duration, func()) scriptTimer
}

func newScriptSchedulerClock() scriptSchedulerClock {
	return scriptSchedulerClock{now: time.Now, afterFunc: func(delay time.Duration, run func()) scriptTimer {
		return time.AfterFunc(delay, run)
	}}
}

type scriptSchedulerAlarm struct{ timer scriptTimer }

func (e *Engine) armScriptScheduler(now time.Time) {
	b := &e.backgroundScripts
	if b.alarm != nil {
		b.alarm.timer.Stop()
		b.alarm = nil
	}
	delay := b.eventAt.Sub(now)
	armed := !b.eventAt.IsZero()
	wallTime := now.Round(0)
	for _, entry := range b.order {
		if !entry.next.IsZero() {
			wait := entry.next.Sub(wallTime)
			if !armed || wait < delay {
				delay, armed = wait, true
			}
		}
	}
	if !armed {
		return
	}
	alarm := &scriptSchedulerAlarm{}
	b.alarm = alarm
	// A short wait rechecks wall time even if the monotonic clock paused.
	alarm.timer = b.clock.afterFunc(min(delay, cronWallClockInterval), func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if !e.closed && b.alarm == alarm {
			b.alarm = nil
			e.tickScriptScheduler()
		}
	})
}

func (e *Engine) tickScriptScheduler() {
	b := &e.backgroundScripts
	now := b.clock.now()
	wallTime := now.Round(0)
	networkChanged := !b.eventAt.IsZero() && !now.Before(b.eventAt)
	if networkChanged {
		b.eventAt = time.Time{}
	}
	for _, entry := range b.order {
		if !entry.next.IsZero() && !wallTime.Before(entry.next) {
			if wallTime.Sub(entry.next) <= cronWallClockInterval {
				e.startBackgroundScript(entry, "cron", "", nil)
			}
			entry.next = entry.schedule.Next(wallTime)
		}
		if networkChanged && entry.info.Supported && entry.spec.Kind == script.KindEvent && entry.info.EventName == networkChangedScriptEvent {
			e.startBackgroundScript(entry, "event", networkChangedScriptEvent, nil)
		}
	}
	e.armScriptScheduler(now)
}

// NotifyNetworkChanged queues a coalesced event for the active scripts.
func (e *Engine) NotifyNetworkChanged() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.queueNetworkScriptEvent()
}

func (e *Engine) queueNetworkScriptEvent() {
	b := &e.backgroundScripts
	if e.closed || !b.hasNetworkEvent || !b.eventAt.IsZero() {
		return
	}
	now := b.clock.now()
	b.eventAt = now.Add(networkEventDelay)
	e.armScriptScheduler(now)
}

type scriptNetwork struct {
	name      string
	addresses []netip.Addr
}

func (e *Engine) observeScriptNetwork(obs *sceneObservation) {
	current := scriptNetwork{}
	if obs.err == "" && !obs.addressesUnavailable {
		current.name = obs.name
		current.addresses = slices.Clone(obs.addresses)
		slices.SortFunc(current.addresses, netip.Addr.Compare)
		current.addresses = slices.Compact(current.addresses)
	}
	b := &e.backgroundScripts
	previous := b.network
	b.network = &current
	if previous != nil && (previous.name != current.name || !slices.Equal(previous.addresses, current.addresses)) {
		e.queueNetworkScriptEvent()
	}
}
