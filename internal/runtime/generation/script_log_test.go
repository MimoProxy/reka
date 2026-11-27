package generation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/script"
)

func TestScriptHistoryRecordsRuns(t *testing.T) {
	opts, _ := backgroundTestOptions(func(_ context.Context, job *script.Job) (script.Done, error) {
		job.Services.Log("info", "hello")
		return script.Done{Called: true, Value: json.RawMessage(`1`)}, nil
	})
	e := NewEngine(opts)
	t.Cleanup(e.Close)
	activateScriptTestProfile(t, e, 1, "source", false,
		compile.Script{ID: "widget", Name: "Widget", Type: "generic", Supported: true},
		compile.Script{ID: "ads", Name: "Remove ads", Type: "http-response", Supported: true, Pattern: ".*"})
	if _, err := e.RunScript(t.Context(), "widget", nil, true); err != nil {
		t.Fatal(err)
	}
	_, g := e.current()
	started := time.Now()
	e.recordMITMScriptRun(g, api.MITMScriptRun{ID: "ads", Phase: "response", DurationMS: 12, Result: "modified"},
		sagernet.MITMScriptRequest{Method: "GET", URL: "https://example.test/feed", RequestID: 7, ConnectionID: 3, Started: started})
	e.SetScriptCapture(true)
	if !e.ScriptCapture() {
		t.Fatal("capture did not turn on")
	}
	e.recordMITMScriptRun(g, api.MITMScriptRun{ID: "ads", Phase: "response", Result: "passed"},
		sagernet.MITMScriptRequest{Started: started, Capture: &api.ScriptCapture{
			Request: api.ScriptMessage{URL: "https://example.test/feed"}, Output: &api.ScriptOutput{Action: "pass"},
		}})

	store, scope := e.History()
	page, err := store.List(history.Scripts, scope.ProfileID, history.ListOptions{})
	if err != nil || len(page.Rows) != 3 {
		t.Fatalf("script history = %+v, %v", page, err)
	}
	var capture api.ScriptCapture
	if data, ok := store.Detail(history.Scripts, scope.ProfileID, page.Rows[0].Cursor); !ok ||
		json.Unmarshal(data, &capture) != nil || capture.Output == nil || capture.Output.Action != "pass" {
		t.Errorf("captured detail = %s, %v", data, ok)
	}
	page.Rows = page.Rows[1:]
	var http, background api.ScriptLogEntry
	if json.Unmarshal(page.Rows[0].Data, &http) != nil || json.Unmarshal(page.Rows[1].Data, &background) != nil {
		t.Fatalf("rows = %s, %s", page.Rows[0].Data, page.Rows[1].Data)
	}
	if http.Type != "http-response" || http.Name != "Remove ads" || http.URL != "https://example.test/feed" ||
		http.RequestID != 7 || http.ConnectionID != 3 || http.Result != "modified" || http.DurationMS != 12 || !http.StartedAt.Equal(started.UTC()) {
		t.Errorf("HTTP run = %+v", http)
	}
	if background.Type != "generic" || background.Name != "Widget" || background.Trigger != "manual" ||
		background.Result != "done" || background.RunID == 0 {
		t.Errorf("background run = %+v", background)
	}
	var detail api.ScriptRun
	data, ok := store.Detail(history.Scripts, scope.ProfileID, page.Rows[1].Cursor)
	if !ok || json.Unmarshal(data, &detail) != nil || len(detail.Logs) != 1 || detail.Logs[0].Message != "hello" || string(detail.Value) != "1" {
		t.Errorf("background detail = %s, %v", data, ok)
	}
	if _, ok := store.Detail(history.Scripts, scope.ProfileID, page.Rows[0].Cursor); ok {
		t.Error("an HTTP run kept a detail")
	}
}
