package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/internal/script"
	"github.com/MimoProxy/reka/internal/secret"
)

func TestBackgroundScriptAPI(t *testing.T) {
	for _, method := range []string{"ListScripts", "RunScript", "GetScriptRuns"} {
		if !slices.Contains(Methods, method) {
			t.Fatalf("%s missing from the advertised methods", method)
		}
	}
	engine := generation.NewEngine(generation.EngineOptions{
		Backend:      sagernet.Options{Logger: quiet()},
		ScriptEngine: func() script.Engine { return argumentScriptEngine{} },
	})
	svc, err := service.Open(service.Options{StateRoot: t.TempDir(), Engine: engine, Logger: quiet(), InitialProfile: []byte(testProfile)})
	if err != nil {
		engine.Close()
		t.Fatal(err)
	}
	defer svc.Close()
	server := NewServer(NewHandler(svc))
	defer server.Close()
	clientConn, serverConn := net.Pipe()
	go server.ServeConn(serverConn)
	client, err := api.NewClient(clientConn, "background-scripts")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	source := []byte("$done($argument)")
	hash := resource.Hash(source)
	var resource api.StageResourceResult
	if err := client.Call("StageResource", api.StageResourceRequest{Hash: hash, Size: len(source), Data: source}, &resource); err != nil || !resource.Ready {
		t.Fatalf("staging script = %+v, %v", resource, err)
	}
	var cfg api.Configuration
	if err := client.Call("GetConfiguration", nil, &cfg); err != nil {
		t.Fatal(err)
	}
	profile := testProfile + fmt.Sprintf(`scripts:
  - {id: sample, type: generic, hash: %s, argument: configured}
  - {id: rewrite, type: http-request, hash: %s, pattern: example}
`, hash, hash)
	var commit api.Result
	if err := client.Call("CommitConfiguration", api.CommitRequest{ChangeRequest: api.ChangeRequest{BaseRevision: cfg.Revision, Profile: &profile}}, &commit); err != nil || commit.State != "committed" {
		t.Fatalf("committing script = %+v, %v", commit, err)
	}
	list, err := client.ListScripts()
	if err != nil || list.Status != "enabled" || len(list.Scripts) != 2 {
		t.Fatalf("script list = %+v, %v", list, err)
	}
	argument := ""
	run, err := client.RunScript(api.RunScriptRequest{ID: "sample", Argument: &argument})
	if err != nil || run.ID != "sample" || run.RunID == 0 || run.Trigger != "manual" || run.Result != "done" || string(run.Value) != `""` {
		t.Fatalf("script run = %+v, %v", run, err)
	}
	runs, err := client.GetScriptRuns(api.GetScriptRunsRequest{ID: "sample", Limit: 1})
	if err != nil || len(runs) != 1 || runs[0].RunID != run.RunID || string(runs[0].Value) != `""` {
		t.Fatalf("script runs = %+v, %v", runs, err)
	}
	wait := false
	if run, err := client.RunScript(api.RunScriptRequest{ID: "sample", Wait: &wait}); err != nil || run.Result != "running" {
		t.Fatalf("asynchronous script run = %+v, %v", run, err)
	}
	for _, tc := range []struct{ id, code, message string }{
		{"", service.CodeBadRequest, "script ID required"},
		{"missing", service.CodeNotFound, "missing"},
		{"rewrite", service.CodeBadRequest, "rewrite"},
	} {
		_, err := client.RunScript(api.RunScriptRequest{ID: tc.id})
		var apiErr *api.Error
		if !errors.As(err, &apiErr) || apiErr.Code != tc.code || !strings.Contains(apiErr.Message, tc.message) {
			t.Errorf("RunScript(%q) = %v, want %s with %q", tc.id, err, tc.code, tc.message)
		}
	}
}

type argumentScriptEngine struct{}

func (argumentScriptEngine) Run(_ context.Context, job *script.Job) (script.Done, error) {
	value, err := json.Marshal(job.Script.Argument)
	return script.Done{Called: true, Value: value}, err
}

func (argumentScriptEngine) Purge() {}

func TestProfileSwitchWhileWaitingForScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("profile workspaces are unavailable")
	}
	workspace, err := service.OpenProfileWorkspace(t.TempDir(), "before", false, true)
	if err != nil {
		t.Fatal(err)
	}
	state, err := workspace.StateRoot()
	if err != nil {
		workspace.Close()
		t.Fatal(err)
	}
	resources, err := resource.Open(state)
	if err != nil {
		workspace.Close()
		t.Fatal(err)
	}
	hash, err := resources.Put([]byte("$done()"))
	if err != nil {
		workspace.Close()
		t.Fatal(err)
	}
	blocking := blockingScriptEngine{started: make(chan struct{}), finish: make(chan struct{})}
	engine := generation.NewEngine(generation.EngineOptions{
		ProfileID: "before", Backend: sagernet.Options{Logger: quiet()},
		ScriptEngine: func() script.Engine { return blocking },
	})
	profile := testProfile + fmt.Sprintf("scripts: [{id: sample, type: generic, hash: %s, timeout: 30}]\n", hash)
	svc, err := service.Open(service.Options{
		StateRoot: state, Engine: engine, Logger: quiet(), InitialProfile: []byte(profile),
		ProfileSecrets: func(string) (secret.Store, error) { return nil, nil },
	})
	if err != nil {
		engine.Close()
		workspace.Close()
		t.Fatal(err)
	}
	defer svc.Close()
	if err := svc.BindProfiles(workspace); err != nil {
		t.Fatal(err)
	}
	before, err := svc.ProfileState("")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(svc)
	runner, switcher := handler.NewSession(nil), handler.NewSession(nil)
	defer runner.Close()
	defer switcher.Close()
	finish := sync.OnceFunc(func() { close(blocking.finish) })
	var calls sync.WaitGroup
	defer func() {
		finish()
		calls.Wait()
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	type reply struct {
		value any
		err   error
	}
	dispatch := func(session *Session, req Request) <-chan reply {
		result := make(chan reply, 1)
		calls.Go(func() {
			value, err := session.dispatch(req)
			result <- reply{value: value, err: err}
		})
		return result
	}
	run := dispatch(runner, Request{
		Method: "RunScript", Params: json.RawMessage(`{"id":"sample"}`), ProfileID: before.ProfileID, ProfileEpoch: before.Epoch,
	})
	select {
	case <-blocking.started:
	case result := <-run:
		t.Fatalf("script did not start: %+v", result)
	case <-ctx.Done():
		t.Fatal("waiting for script start", ctx.Err())
	}
	params, err := json.Marshal(api.SwitchProfileRequest{
		ProfileID: "after", BaseProfile: before.ProfileID, BaseEpoch: before.Epoch,
		BaseRevision: before.Revision, OperationID: "switch-during-script",
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-dispatch(switcher, Request{Method: "SwitchProfile", Params: params}):
		switched, ok := result.value.(api.SwitchProfileResult)
		if result.err != nil || !ok || switched.State != "committed" || switched.ProfileID != "after" {
			t.Fatalf("profile switch = %+v, %v", result.value, result.err)
		}
	case <-ctx.Done():
		t.Fatal("profile switch blocked while the script was running", ctx.Err())
	}
	finish()
	select {
	case result := <-run:
		completed, ok := result.value.(api.ScriptRun)
		if result.err != nil || !ok || completed.Result != "done" {
			t.Fatalf("script run = %+v, %v", result.value, result.err)
		}
	case <-ctx.Done():
		t.Fatal("waiting for script completion", ctx.Err())
	}
}

type blockingScriptEngine struct{ started, finish chan struct{} }

func (e blockingScriptEngine) Run(ctx context.Context, _ *script.Job) (script.Done, error) {
	close(e.started)
	select {
	case <-e.finish:
		return script.Done{Called: true}, nil
	case <-ctx.Done():
		return script.Done{}, ctx.Err()
	}
}

func (blockingScriptEngine) Purge() {}
