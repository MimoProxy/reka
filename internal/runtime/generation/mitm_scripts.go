package generation

import (
	"container/list"
	"context"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/runtime"
	"github.com/MimoProxy/reka/internal/script"
)

// Reka budgets diagnostics for several full modules while bounding the memory
// retained for script IDs and error messages across generations.
const mitmScriptItemCapacity = 4 * model.MaxModuleScripts

type mitmScriptTable struct {
	requests, responses []mitmScriptEntry
}

type mitmScriptEntry struct {
	pattern      *regexp.Regexp
	id, module   string
	requiresBody bool
	spec         script.Script
}

func newMITMScriptTable(defs []compile.Script, logger *slog.Logger) mitmScriptTable {
	var table mitmScriptTable
	for _, def := range defs {
		kind := script.Kind(def.Type)
		if !def.Supported || kind != script.KindHTTPRequest && kind != script.KindHTTPResponse {
			continue
		}
		pattern, err := regexp.Compile(def.Pattern)
		if err != nil {
			logger.Warn("invalid HTTP script pattern", "source", "script", "script_id", def.ID, "err", err)
			continue
		}
		entry := mitmScriptEntry{
			pattern: pattern, id: def.ID, module: def.Module, requiresBody: def.RequiresBody,
			spec: scriptSpec(def),
		}
		if kind == script.KindHTTPRequest {
			table.requests = append(table.requests, entry)
		} else {
			table.responses = append(table.responses, entry)
		}
	}
	return table
}

func scriptSpec(def compile.Script) script.Script {
	name, path := def.Name, def.Path
	if name == "" {
		name = def.ID
	}
	if path == "" {
		path = def.ID
	}
	var argument *string
	if def.Argument != "" {
		argument = &def.Argument
	}
	return script.Script{
		Key: def.Hash, Name: name, Path: path, Kind: script.Kind(def.Type), Dialect: script.Dialect(def.Format),
		Engine: def.Engine, BinaryBody: def.BinaryBodyMode, Argument: argument,
		ArgumentObject: def.ArgumentType == "object",
		Timeout:        time.Duration(def.Timeout) * time.Second, MaxSize: def.MaxSize,
	}
}

func (t *mitmScriptTable) count() int { return len(t.requests) + len(t.responses) }

func (t *mitmScriptTable) match(kind script.Kind, url string) *mitmScriptEntry {
	var entries []mitmScriptEntry
	switch kind {
	case script.KindHTTPRequest:
		entries = t.requests
	case script.KindHTTPResponse:
		entries = t.responses
	}
	for i := range entries {
		if entries[i].pattern.MatchString(url) {
			return &entries[i]
		}
	}
	return nil
}

func (e *Engine) initScripts() {
	engine := platformScriptEngine(e.opts.ScriptEngine)
	if engine == nil {
		return
	}
	e.scriptHost = script.NewHost(engine, script.Limits{
		Concurrency: platformScriptConcurrency, HardMaxSize: compile.ScriptMaxBodySize, StoreValueMax: scriptStoreValueMax,
	}, script.Environment{})
	e.initBackgroundScripts(engine)
	stateDir := e.opts.ScriptStateDir
	if stateDir == "" {
		stateDir = e.opts.StateRoot
	}
	e.scriptStore = newScriptStore(stateDir, e.scriptLogger())
	e.scriptNotifications = newScriptNotifications()
}

func (e *Engine) debugScriptLog(ctx context.Context, id, level, message string) {
	logger := e.scriptLogger()
	if logger.Enabled(ctx, slog.LevelDebug) {
		logger.DebugContext(ctx, "script "+id+": "+message,
			"source", "script", "script_id", id, "console_level", level)
	}
}

func (e *Engine) scriptLogger() *slog.Logger {
	if e.opts.Backend.Logger != nil {
		return e.opts.Backend.Logger
	}
	return slog.Default()
}

func (e *Engine) mitmScriptMatcher(snap *runtime.Snapshot[*sagernet.Outbound], state routingState) func(script.Kind, string) *sagernet.MITMScript {
	g := snap.Value.(*generation)
	readSource := g.readScriptSource
	if readSource == nil {
		readSource = g.eff.ScriptSource
	}
	return func(kind script.Kind, url string) *sagernet.MITMScript {
		ent := g.scripts.match(kind, url)
		if ent == nil {
			return nil
		}
		matched := &sagernet.MITMScript{
			ID: ent.id, RequiresBody: ent.requiresBody, MaxSize: int(min(ent.spec.MaxSize, compile.ScriptMaxBodySize)),
		}
		if e.scriptHost != nil {
			matched.Run = func(ctx context.Context, input *script.Input) (script.Result, error) {
				// The locked source hash lets the host share compiled programs
				// across generations.
				source, err := readSource(ent.spec.Key)
				if err != nil {
					return script.Result{}, err
				}
				spec := ent.spec
				spec.Source = string(source)
				var log func(string, string)
				if g.eff.MITM.ScriptLog {
					log = func(level, message string) {
						e.debugScriptLog(ctx, ent.id, level, message)
					}
				}
				return e.scriptHost.Run(ctx, &spec, input, e.scriptServices(snap, state, g.mitm, ent.id, ent.module, log))
			}
		}
		return matched
	}
}

type mitmScriptCounters struct {
	mu sync.Mutex

	runs, modified, failed                     uint64
	timeouts, oversize, circuitOpen, lowMemory uint64

	items  map[string]*list.Element
	recent list.List
}

func (c *mitmScriptCounters) record(run api.MITMScriptRun, executed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if executed {
		c.runs++
	}
	switch run.Result {
	case "modified":
		c.modified++
	case "failed":
		c.failed++
	case "timeout":
		c.timeouts++
	case "oversize":
		c.oversize++
	case "circuit-open":
		c.circuitOpen++
	case "low-memory":
		c.lowMemory++
	}
	elem := c.items[run.ID]
	if elem == nil {
		if len(c.items) >= mitmScriptItemCapacity {
			oldest := c.recent.Back()
			delete(c.items, oldest.Value.(*api.MITMScriptItem).ID)
			c.recent.Remove(oldest)
		}
		if c.items == nil {
			c.items = make(map[string]*list.Element)
		}
		elem = c.recent.PushFront(&api.MITMScriptItem{ID: run.ID})
		c.items[run.ID] = elem
	} else {
		c.recent.MoveToFront(elem)
	}
	item := elem.Value.(*api.MITMScriptItem)
	if executed {
		item.Runs++
	}
	item.Matches++
	item.LastResult, item.LastError = run.Result, run.Error
	item.LastDurationMS, item.LastAt = run.DurationMS, time.Now().UTC()
}

func (c *mitmScriptCounters) status(status string, table *mitmScriptTable) api.MITMScriptStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	info := api.MITMScriptStatus{
		Status: status, Count: table.count(), Runs: c.runs, Modified: c.modified,
		Failed: c.failed, Timeouts: c.timeouts, Oversize: c.oversize,
		CircuitOpen: c.circuitOpen, LowMemory: c.lowMemory,
	}
	if info.Count != 0 {
		info.Items = make([]api.MITMScriptItem, 0, info.Count)
	}
	for _, entries := range [...][]mitmScriptEntry{table.requests, table.responses} {
		for _, entry := range entries {
			var item api.MITMScriptItem
			if elem := c.items[entry.id]; elem != nil {
				item = *elem.Value.(*api.MITMScriptItem)
			}
			item.ID, item.Module, item.Name, item.Type = entry.id, entry.module, entry.spec.Name, string(entry.spec.Kind)
			info.Items = append(info.Items, item)
		}
	}
	return info
}

func (e *Engine) scriptStatus(g *generation) api.MITMScriptStatus {
	status := "disabled"
	if e.scriptHost == nil {
		status = "unsupported"
	} else if g.eff != nil && g.eff.MITM.Enabled && g.scripts.count() != 0 {
		status = "enabled"
	}
	info := e.scriptRuns.status(status, &g.scripts)
	if e.scriptNotifications != nil {
		info.Notifications, info.NotificationsDropped = e.scriptNotifications.counts()
	}
	return info
}
