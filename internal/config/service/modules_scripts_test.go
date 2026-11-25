package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
	"github.com/MimoProxy/reka/internal/resource"
)

func TestModuleScriptRefreshHTTP(t *testing.T) {
	exerciseModuleScriptRefresh(t, func(handler http.Handler) (string, *http.Client, func()) {
		server := httptest.NewServer(handler)
		return server.URL, server.Client(), server.Close
	})
}

func TestModuleScriptRefreshInMemory(t *testing.T) {
	exerciseModuleScriptRefresh(t, func(handler http.Handler) (string, *http.Client, func()) {
		client := &http.Client{Transport: moduleTestTransport(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			return rec.Result(), nil
		})}
		return "https://example.com", client, func() {}
	})
}

func exerciseModuleScriptRefresh(t *testing.T, serve func(http.Handler) (string, *http.Client, func())) {
	t.Helper()
	const scriptPath = "/script.js?access=hidden"
	const scriptBody = "// script\n$done();"
	var existingMissing, allAvailable atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/root":
			baseURL := "https://" + r.Host
			if r.URL.Scheme == "http" || r.URL.Scheme == "" && r.TLS == nil {
				baseURL = "http://" + r.Host
			}
			fmt.Fprintf(w, "[Rule]\nDOMAIN,filter.example.com,REJECT\n[Script]\n"+
				"test = type=http-response,pattern=example,script-path=%s%s\n"+
				"missing = type=http-request,pattern=example,script-path=%s/missing.js\n", baseURL, scriptPath, baseURL)
		case "/script.js":
			if existingMissing.Load() {
				if r.Header.Get("If-None-Match") != "script" {
					t.Errorf("missing validator: %v", r.Header)
				}
				http.NotFound(w, r)
				return
			}
			w.Header().Set("ETag", "script")
			if r.Header.Get("If-None-Match") == "script" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			fmt.Fprint(w, scriptBody)
		case "/missing.js":
			if !allAvailable.Load() {
				http.NotFound(w, r)
				return
			}
			fmt.Fprint(w, "$done({});")
		default:
			http.NotFound(w, r)
		}
	})
	baseURL, client, closeServer := serve(handler)
	defer closeServer()
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer func() { s.Close() }()
	if _, err := s.manager(RefreshOptions{Client: client}); err != nil {
		t.Fatal(err)
	}
	add, err := s.AddModule(t.Context(), api.AddModuleRequest{
		Module: model.Module{ID: "scripts", URL: baseURL + "/root"}, BaseRevision: s.ActiveRevision(),
	})
	if err != nil || add.State != "committed" {
		t.Fatalf("install with missing script: %+v %v", add, err)
	}
	good := s.GetConfiguration(true)
	sources, _, ds := model.ParseSources([]byte(good.Sources))
	if ds.HasErrors() || len(sources.Sources) != 1 || sources.Sources[0].Lock == nil || len(sources.Sources[0].Lock.Resources) != 1 {
		t.Fatalf("source snapshot: %s %v", good.Sources, ds)
	}
	locked := sources.Sources[0].Lock.Resources[0]
	if locked.Kind != "script" || locked.Request != resource.Hash([]byte(baseURL+scriptPath)) || locked.ID != locked.Request[:24] || locked.Hash != resource.Hash([]byte(scriptBody)) {
		t.Fatalf("script lock: %+v", locked)
	}
	missing := api.ModuleScriptError{Request: resource.Hash([]byte(baseURL + "/missing.js")), Code: "http_status_404"}
	list, err := s.ListModules()
	if err != nil || len(list) != 1 || list[0].Report == nil || list[0].Report.Scripts.Total != 2 || list[0].Report.Scripts.Imported != 1 ||
		!slices.Equal(list[0].Status.ScriptErrors, []api.ModuleScriptError{missing}) {
		t.Fatalf("module list: %+v %v", list, err)
	}
	report, err := s.GetModuleReport("scripts")
	if err != nil || !report.CanApply || !report.Partial || report.Rules.Imported != 1 || len(report.ScriptItems) != 2 ||
		!report.ScriptItems[0].Locked || report.ScriptItems[0].Hash != locked.Hash || report.ScriptItems[1].Locked ||
		!slices.ContainsFunc(report.Lines, func(line module.Line) bool { return line.Code == "module.script-unavailable" }) {
		t.Fatalf("module report: %+v %v", report, err)
	}
	encoded, _ := json.Marshal(list)
	if strings.Contains(string(encoded), "access=hidden") || strings.Contains(string(encoded), "$done") {
		t.Fatalf("script source or URL in module list: %s", encoded)
	}

	existingMissing.Store(true)
	status, err := s.RefreshModule(t.Context(), "scripts", true)
	wantErrors := []api.ModuleScriptError{{Request: locked.Request, Code: "http_status_404"}, missing}
	if err != nil || status.State != "current" || status.Revision != good.Revision || !slices.Equal(status.ScriptErrors, wantErrors) || s.GetConfiguration(true).Sources != good.Sources {
		t.Fatalf("retain last script lock: %+v %v", status, err)
	}
	s.Close()
	s = e.open("", "")
	if _, err := s.manager(RefreshOptions{Client: client}); err != nil {
		t.Fatal(err)
	}
	list, err = s.ListModules()
	if err != nil || len(list) != 1 || !slices.Equal(list[0].Status.ScriptErrors, wantErrors) {
		t.Fatalf("persisted script errors: %+v %v", list, err)
	}
	existingMissing.Store(false)
	allAvailable.Store(true)
	status, err = s.RefreshModule(t.Context(), "scripts", true)
	if err != nil || status.State != "current" || len(status.ScriptErrors) != 0 || status.Revision <= good.Revision {
		t.Fatalf("recover failed scripts: %+v %v", status, err)
	}
}

func TestModuleArgumentsDownloadNewScript(t *testing.T) {
	var requests atomic.Int32
	client := &http.Client{Transport: moduleTestTransport(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		if req.URL.Path == "/root" {
			fmt.Fprint(rec, "#!arguments=FILE:one\n[Script]\nrewrite = type=http-response,pattern=example,script-path=https://example.com/{{{FILE}}}.js\n")
		} else {
			requests.Add(1)
			fmt.Fprintf(rec, "// %s\n$done();", req.URL.Path)
		}
		return rec.Result(), nil
	})}
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	if _, err := s.manager(RefreshOptions{Client: client}); err != nil {
		t.Fatal(err)
	}
	add, err := s.AddModule(t.Context(), api.AddModuleRequest{
		Module: model.Module{ID: "scripts", URL: "https://example.com/root"}, BaseRevision: s.ActiveRevision(),
	})
	if err != nil || add.State != "committed" || requests.Load() != 1 {
		t.Fatalf("install script: %+v %v, %d downloads", add, err, requests.Load())
	}
	update, err := s.SetModuleArguments(t.Context(), api.SetModuleArgumentsRequest{
		ModuleID: "scripts", Arguments: map[string]string{"FILE": "two"}, BaseRevision: add.Revision,
	})
	if err != nil || update.State != "committed" || requests.Load() != 2 {
		t.Fatalf("update script argument: %+v %v, %d downloads", update, err, requests.Load())
	}
	sources, _, ds := model.ParseSources([]byte(s.GetConfiguration(true).Sources))
	if ds.HasErrors() || len(sources.Sources) != 1 {
		t.Fatalf("source snapshot: %+v %v", sources, ds)
	}
	if lock := sources.Sources[0].Lock; lock == nil || len(lock.Resources) != 1 || lock.Resources[0].Kind != "script" ||
		lock.Resources[0].Request != resource.Hash([]byte("https://example.com/two.js")) {
		t.Fatalf("new script lock: %+v", lock)
	}
}
