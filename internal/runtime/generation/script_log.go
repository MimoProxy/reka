package generation

import (
	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/history"
)

// The script history keeps one entry per finished run, so a client can list
// what scripts did with their time and result.

// scriptLogURLBytes bounds the URL kept with a run, like a request row's path.
const scriptLogURLBytes = 2048

func (e *Engine) recordMITMScriptRun(g *generation, run api.MITMScriptRun, request sagernet.MITMScriptRequest) {
	if e.history == nil {
		return
	}
	name, module := g.scripts.describe(run.ID)
	entry := api.ScriptLogEntry{
		Scope: g.historyScope, ID: run.ID, Name: name, Module: module, Type: "http-" + run.Phase,
		Method: request.Method, URL: history.Text(request.URL, scriptLogURLBytes),
		RequestID: request.RequestID, ConnectionID: request.ConnectionID,
		StartedAt: request.Started.UTC(), DurationMS: run.DurationMS, Result: run.Result, Error: run.Error,
	}
	e.history.Record(history.Scripts, g.historyScope, request.Started, entry, nil)
}

// recordBackgroundScriptRun keeps the run's logs and value as the entry's detail.
func (e *Engine) recordBackgroundScriptRun(run api.ScriptRun) {
	if e.history == nil || run.Result == "running" {
		return
	}
	_, g := e.current()
	entry := api.ScriptLogEntry{
		Scope: g.historyScope, ID: run.ID, Name: run.Name, Module: run.Module, Type: run.Type,
		Trigger: run.Trigger, Event: run.Event, RunID: run.RunID,
		StartedAt: run.StartedAt, DurationMS: run.DurationMS, Result: run.Result, Error: run.Error,
	}
	e.history.Record(history.Scripts, g.historyScope, run.StartedAt, entry, run)
}
