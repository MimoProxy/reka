package generation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/runtime"
	"github.com/MimoProxy/reka/internal/script"
	"github.com/MimoProxy/reka/internal/script/cron"
)

// Reka bounds retained console output and the default history page.
const (
	scriptLogLines   = 64
	scriptLogBytes   = 16 << 10
	scriptRunDefault = 20
)

// ErrScriptNotFound is returned when the active configuration has no such script.
var ErrScriptNotFound = errors.New("unknown script")

// Engine.mu protects the active entries, scheduler and history.
type backgroundScripts struct {
	host    *script.Host
	ctx     context.Context
	cancel  context.CancelFunc
	workers sync.WaitGroup

	entries         map[string]*backgroundScriptEntry
	order           []*backgroundScriptEntry
	enabled         bool
	running         map[string]bool
	routing         *backgroundScriptRouting
	history         []api.ScriptRun
	lastRunID       uint64
	clock           scriptSchedulerClock
	alarm           *scriptSchedulerAlarm
	hasNetworkEvent bool
	eventAt         time.Time
	network         *scriptNetwork
}

type backgroundScriptEntry struct {
	info     api.ScriptInfo
	spec     script.Script
	schedule *cron.Schedule
	next     time.Time
	last     *api.ScriptRun
}

type backgroundScriptExecution struct {
	done chan struct{}
	run  api.ScriptRun
}

func (e *Engine) initBackgroundScripts(engine script.Engine) {
	b := &e.backgroundScripts
	b.host = script.NewHost(engine, script.Limits{
		Concurrency: backgroundScriptConcurrency, HardMaxSize: compile.ScriptMaxBodySize, StoreValueMax: scriptStoreValueMax,
	}, script.Environment{})
	b.ctx, b.cancel = context.WithCancel(context.Background())
	b.running = make(map[string]bool)
	b.clock = newScriptSchedulerClock()
	if e.opts.scriptClock != nil {
		b.clock = *e.opts.scriptClock
	}
}

func isBackgroundScript(kind script.Kind) bool {
	return kind == script.KindCron || kind == script.KindGeneric || kind == script.KindEvent
}

func (e *Engine) activateBackgroundScripts(defs []compile.Script, sameProfile bool) {
	b := &e.backgroundScripts
	previous := b.entries
	b.entries = make(map[string]*backgroundScriptEntry, len(defs))
	b.order = make([]*backgroundScriptEntry, 0, len(defs))
	b.enabled = false
	b.hasNetworkEvent = false
	b.routing = nil
	var now time.Time
	if b.host != nil {
		now = b.clock.now()
	}
	for _, def := range defs {
		spec := scriptSpec(def)
		if isBackgroundScript(spec.Kind) {
			spec.BinaryBody, spec.MaxSize = false, 0
		}
		entry := &backgroundScriptEntry{spec: spec, info: api.ScriptInfo{
			ID: def.ID, Name: spec.Name, Module: def.Module, Type: def.Type, Supported: def.Supported,
			CronExp: def.CronExp, EventName: def.EventName, Timeout: def.Timeout, Argument: def.Argument,
		}}
		if old := previous[def.ID]; sameProfile && old != nil && isBackgroundScript(spec.Kind) {
			entry.last = old.last
		}
		b.entries[def.ID] = entry
		b.order = append(b.order, entry)
		if b.host == nil || !def.Supported || !isBackgroundScript(spec.Kind) {
			continue
		}
		b.enabled = true
		switch spec.Kind {
		case script.KindCron:
			schedule, err := cron.Parse(def.CronExp)
			if err != nil {
				e.scriptLogger().Warn("invalid cron script schedule", "source", "script", "script_id", def.ID, "err", err)
				continue
			}
			entry.schedule = &schedule
			entry.next = schedule.Next(now.Round(0))
		case script.KindEvent:
			b.hasNetworkEvent = b.hasNetworkEvent || def.EventName == networkChangedScriptEvent
		}
	}
	if !sameProfile || !b.hasNetworkEvent {
		b.eventAt = time.Time{}
		b.network = nil
	}
	e.armScriptScheduler(now)
}

func (e *Engine) stopBackgroundScripts() {
	b := &e.backgroundScripts
	if b.alarm != nil {
		b.alarm.timer.Stop()
		b.alarm = nil
	}
	if b.cancel != nil {
		b.cancel()
	}
}

func (e *Engine) ListScripts() api.ScriptList {
	e.mu.Lock()
	defer e.mu.Unlock()
	b := &e.backgroundScripts
	list := api.ScriptList{Status: "disabled", Scripts: make([]api.ScriptInfo, 0, len(b.order))}
	if b.host == nil {
		list.Status = "unsupported"
	} else if b.enabled && !e.closed {
		list.Status = "enabled"
	}
	for _, entry := range b.order {
		info := entry.info
		if isBackgroundScript(entry.spec.Kind) {
			info.Running = b.running[info.ID]
			if !e.closed && !entry.next.IsZero() {
				next := entry.next
				info.NextRun = &next
			}
			if entry.last != nil {
				last := *entry.last
				info.LastRun = &last
			}
		}
		list.Scripts = append(list.Scripts, info)
	}
	return list
}

func (e *Engine) RunScript(ctx context.Context, id string, argument *string, wait bool) (api.ScriptRun, error) {
	run, waitForRun, err := e.StartScript(ctx, id, argument)
	if err != nil || !wait || waitForRun == nil {
		return run, err
	}
	return waitForRun(ctx)
}

// StartScript admits a manual run and returns a waiter for its completion.
// Callers can release a profile lock after admission, before waiting.
func (e *Engine) StartScript(ctx context.Context, id string, argument *string) (api.ScriptRun, func(context.Context) (api.ScriptRun, error), error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return api.ScriptRun{}, nil, err
	}
	if e.closed {
		return api.ScriptRun{}, nil, errors.New("engine closed")
	}
	entry := e.backgroundScripts.entries[id]
	if entry == nil {
		return api.ScriptRun{}, nil, fmt.Errorf("%w %q", ErrScriptNotFound, id)
	}
	if entry.spec.Kind.IsHTTP() {
		return api.ScriptRun{}, nil, fmt.Errorf("HTTP script %q cannot run manually", id)
	}
	if !entry.info.Supported || !isBackgroundScript(entry.spec.Kind) {
		return api.ScriptRun{}, nil, fmt.Errorf("script %q is unsupported", id)
	}
	if e.backgroundScripts.host == nil {
		run := e.backgroundScripts.newRun(entry, "manual", "", time.Now())
		const message = "script engine is unavailable"
		run.Result, run.Error = "unsupported", message
		e.backgroundScripts.record(run, true)
		e.logScriptRun(run)
		return run, nil, errors.New(message)
	}
	run, execution := e.startBackgroundScript(entry, "manual", "", argument)
	if execution == nil {
		return run, nil, nil
	}
	return run, func(ctx context.Context) (api.ScriptRun, error) {
		// A request can stop waiting while the engine retains ownership of the run.
		select {
		case <-execution.done:
			return cloneScriptRun(execution.run), nil
		case <-ctx.Done():
			return run, ctx.Err()
		}
	}, nil
}

func (e *Engine) GetScriptRuns(id string, limit int) []api.ScriptRun {
	e.mu.Lock()
	defer e.mu.Unlock()
	b := &e.backgroundScripts
	if limit <= 0 {
		limit = scriptRunDefault
	}
	limit = min(limit, len(b.history))
	runs := make([]api.ScriptRun, 0, limit)
	for offset := uint64(0); offset < min(b.lastRunID, uint64(len(b.history))) && len(runs) < limit; offset++ {
		run := b.history[b.historyIndex(b.lastRunID-offset)]
		if id == "" || id == run.ID {
			runs = append(runs, cloneScriptRun(run))
		}
	}
	return runs
}

func cloneScriptRun(run api.ScriptRun) api.ScriptRun {
	run.Value = slices.Clone(run.Value)
	run.Logs = slices.Clone(run.Logs)
	return run
}

func (b *backgroundScripts) newRun(entry *backgroundScriptEntry, trigger, event string, started time.Time) api.ScriptRun {
	b.lastRunID++
	info := entry.info
	return api.ScriptRun{RunID: b.lastRunID, ID: info.ID, Name: info.Name, Module: info.Module, Type: info.Type,
		Trigger: trigger, Event: event, StartedAt: started.UTC(), Result: "running"}
}

func (b *backgroundScripts) historyIndex(id uint64) uint64 { return (id - 1) % uint64(len(b.history)) }

func (b *backgroundScripts) record(run api.ScriptRun, started bool) {
	if b.history == nil {
		b.history = make([]api.ScriptRun, scriptRunCapacity)
	}
	index := b.historyIndex(run.RunID)
	if b.history[index].RunID <= run.RunID {
		b.history[index] = run
	}
	if entry := b.entries[run.ID]; entry != nil && isBackgroundScript(entry.spec.Kind) &&
		(started || entry.last != nil && entry.last.RunID == run.RunID) {
		// A completion for an older start must not overwrite an overlap or a newer run.
		run.Value, run.Logs = nil, nil
		entry.last = &run
	}
}

func (e *Engine) startBackgroundScript(entry *backgroundScriptEntry, trigger, event string, argument *string) (api.ScriptRun, *backgroundScriptExecution) {
	b := &e.backgroundScripts
	run := b.newRun(entry, trigger, event, b.clock.now().Round(0))
	if b.running[run.ID] {
		run.Result = "overlap"
		b.record(run, true)
		e.logScriptRun(run)
		return run, nil
	}
	snap, g := e.current()
	routing, err := b.retainRouting(g, snap)
	if err != nil {
		run.Result, run.Error = scriptRunOutcome(err)
		b.record(run, true)
		e.logScriptRun(run)
		return run, nil
	}
	spec := entry.spec
	if argument != nil {
		value := *argument
		spec.Argument = &value
	}
	state := e.routingState(g)
	execution := &backgroundScriptExecution{done: make(chan struct{})}
	b.running[run.ID] = true
	b.record(run, true)
	b.workers.Add(1)
	go func(run api.ScriptRun) {
		defer b.workers.Done()
		defer close(execution.done)
		defer routing.release()
		start := time.Now()
		var logs backgroundScriptLogs
		log := func(level, message string) {
			logs.append(level, message)
			if g.eff.MITM.ScriptLog {
				e.debugScriptLog(b.ctx, run.ID, level, message)
			}
		}
		readSource := g.readScriptSource
		if readSource == nil {
			readSource = g.eff.ScriptSource
		}
		services := e.scriptServices(snap, state, routing, run.ID, run.Module, log)
		result, err := b.host.RunWithSource(b.ctx, &spec, &script.Input{}, services, readSource)
		run.Value, run.ValueTruncated = result.Value, result.ValueTruncated
		run.Result, run.Error = scriptRunOutcome(err)
		e.scriptPressure.noteError(run.ID, err)
		run.DurationMS = time.Since(start).Milliseconds()
		run.Logs, run.LogsTruncated = logs.finish()
		e.mu.Lock()
		delete(b.running, run.ID)
		b.record(run, false)
		e.mu.Unlock()
		e.logScriptRun(run)
		execution.run = run
	}(run)
	return run, execution
}

func scriptRunOutcome(err error) (string, string) {
	switch {
	case err == nil:
		return "done", ""
	case errors.Is(err, script.ErrNoDone):
		return "no-done", ""
	case errors.Is(err, script.ErrTimeout):
		return "timeout", ""
	case errors.Is(err, script.ErrCircuitOpen):
		return "circuit-open", ""
	case errors.Is(err, script.ErrBusy):
		return "busy", ""
	case errors.Is(err, script.ErrLowMemory), errors.Is(err, script.ErrMemoryExceeded):
		return "low-memory", ""
	}
	var scriptErr *script.ScriptError
	if errors.As(err, &scriptErr) {
		return "failed", script.NewScriptError("", scriptErr.Message).Message
	}
	return "failed", script.NewScriptError("", err.Error()).Message
}

func (e *Engine) logScriptRun(run api.ScriptRun) {
	level := slog.LevelWarn
	if run.Result == "done" || run.Result == "overlap" {
		level = slog.LevelInfo
	}
	e.scriptLogger().Log(context.Background(), level, "script run", "source", "script", "script_id", run.ID,
		"trigger", run.Trigger, "result", run.Result, "duration_ms", run.DurationMS)
}

type backgroundScriptLogs struct {
	mu        sync.Mutex
	lines     []api.ScriptLogLine
	bytes     int
	truncated bool
	sealed    bool
}

func (l *backgroundScriptLogs) append(level, message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sealed || l.truncated {
		return
	}
	n := len(level) + len(message)
	if len(l.lines) >= scriptLogLines || n > scriptLogBytes-l.bytes {
		l.truncated = true
		return
	}
	l.lines = append(l.lines, api.ScriptLogLine{Level: strings.Clone(level), Message: strings.Clone(message)})
	l.bytes += n
}

func (l *backgroundScriptLogs) finish() ([]api.ScriptLogLine, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sealed = true
	return l.lines, l.truncated
}

// Runs on one generation share pins, which are released when its last run and
// any HTTP work detached by net/http finish.
type backgroundScriptRouting struct {
	refs atomic.Int64
	pins map[*sagernet.Outbound]*sagernet.PinnedOutbound
}

func (b *backgroundScripts) retainRouting(g *generation, snap *runtime.Snapshot[*sagernet.Outbound]) (*backgroundScriptRouting, error) {
	if b.routing != nil && b.routing.retain() {
		return b.routing, nil
	}
	outbounds := make([]*sagernet.Outbound, 0, len(snap.Resources))
	for _, out := range snap.Resources {
		outbounds = append(outbounds, out)
	}
	pins, err := pinProbeOutbounds(g, snap, outbounds...)
	if err != nil {
		return nil, err
	}
	routing := &backgroundScriptRouting{pins: pins}
	routing.refs.Store(1)
	b.routing = routing
	return routing, nil
}

func (r *backgroundScriptRouting) retain() bool { return retainMITMRef(&r.refs) }

func (r *backgroundScriptRouting) release() {
	if r.refs.Add(-1) == 0 {
		closeSniffPins(r.pins)
		r.pins = nil
	}
}

func (r *backgroundScriptRouting) outboundPins() map[*sagernet.Outbound]*sagernet.PinnedOutbound {
	return r.pins
}
