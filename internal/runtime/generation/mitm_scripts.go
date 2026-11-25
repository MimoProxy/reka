package generation

import (
	"context"
	"log/slog"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/runtime"
	"github.com/MimoProxy/reka/internal/script"
)

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
		entry := mitmScriptEntry{
			pattern: pattern, id: def.ID, module: def.Module, requiresBody: def.RequiresBody,
			spec: script.Script{
				Key: def.Hash, Name: name, Path: path, Kind: kind, Dialect: script.Dialect(def.Format),
				BinaryBody: def.BinaryBodyMode, Argument: argument,
				Timeout: time.Duration(def.Timeout) * time.Second, MaxSize: def.MaxSize,
			},
		}
		if kind == script.KindHTTPRequest {
			table.requests = append(table.requests, entry)
		} else {
			table.responses = append(table.responses, entry)
		}
	}
	return table
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
		HardMaxSize: compile.ScriptMaxBodySize, StoreValueMax: scriptStoreValueMax,
	}, script.Environment{})
	e.scriptStore = newScriptStore(e.opts.StateRoot, e.scriptLogger())
	e.scriptNotifications = newScriptNotifications()
}

func (e *Engine) scriptLogger() *slog.Logger {
	if e.opts.Backend.Logger != nil {
		return e.opts.Backend.Logger
	}
	return slog.Default()
}

func (e *Engine) mitmScriptMatcher(snap *runtime.Snapshot[*sagernet.Outbound], state routingState) func(script.Kind, string) *sagernet.MITMScript {
	g := snap.Value.(*generation)
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
				// Keep source bytes only for this run. The host shares compiled
				// programs across generations through the locked source hash.
				source, err := g.eff.ScriptSource(ent.spec.Key)
				if err != nil {
					return script.Result{}, err
				}
				spec := ent.spec
				spec.Source = string(source)
				var log func(string, string)
				if g.eff.MITM.ScriptLog {
					logger := e.scriptLogger()
					log = func(level, message string) {
						logger.DebugContext(ctx, "script "+ent.id+": "+message,
							"source", "script", "script_id", ent.id, "console_level", level)
					}
				}
				return e.scriptHost.Run(ctx, &spec, input, e.scriptServices(snap, state, ent.id, ent.module, log))
			}
		}
		return matched
	}
}

type mitmScriptCounters struct {
	runs, modified, failed, timeouts, oversize, circuitOpen atomic.Uint64
}

func (c *mitmScriptCounters) record(run api.MITMScriptRun, executed bool) {
	if executed {
		c.runs.Add(1)
	}
	switch run.Result {
	case "modified":
		c.modified.Add(1)
	case "failed":
		c.failed.Add(1)
	case "timeout":
		c.timeouts.Add(1)
	case "oversize":
		c.oversize.Add(1)
	case "circuit-open":
		c.circuitOpen.Add(1)
	}
}

func (e *Engine) scriptStatus(g *generation) api.MITMScriptStatus {
	status := "disabled"
	count := g.scripts.count()
	if e.scriptHost == nil {
		status = "unsupported"
	} else if g.eff != nil && g.eff.MITM.Enabled && count != 0 {
		status = "enabled"
	}
	c := &e.scriptRuns
	info := api.MITMScriptStatus{
		Status: status, Count: count, Runs: c.runs.Load(), Modified: c.modified.Load(),
		Failed: c.failed.Load(), Timeouts: c.timeouts.Load(), Oversize: c.oversize.Load(),
		CircuitOpen: c.circuitOpen.Load(),
	}
	if e.scriptNotifications != nil {
		info.Notifications, info.NotificationsDropped = e.scriptNotifications.counts()
	}
	return info
}
