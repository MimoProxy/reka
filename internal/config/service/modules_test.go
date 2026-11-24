package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/moduleacquire"
	"github.com/MimoProxy/reka/internal/resource"
)

func TestModuleFileTransactions(t *testing.T) {
	e := newEnv(t)
	s := e.open("schema-version: 1\noutbounds: [{id: alternate, type: direct}]\n", "")
	defer s.Close()
	ctx := context.Background()
	path := filepath.Join(e.root, "example.sgmodule")
	body := []byte("#!name=Example\n#!arguments=POLICY:DIRECT\n[Rule]\nDOMAIN,filter.example.com,{{{POLICY}}}\n")
	// Declaring a disabled module does not touch the file or write a snapshot.
	profile := fmt.Sprintf("schema-version: 1\noutbounds: [{id: alternate, type: direct}]\nmodules: [{id: example, enabled: false, file: %q}]\nrules: [{id: marker, module: example}, {id: final, match: {all: true}, outbound: direct}]\n", path)
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Profile: &profile})
	if _, err := s.GetModuleReport("example"); err == nil || !strings.Contains(err.Error(), "refresh the module") {
		t.Fatalf("report should explain missing snapshot: %v", err)
	}
	failed, err := s.RefreshModule(ctx, "example", true)
	if err != nil || failed.State != "failed" || !failed.NextAttempt.IsZero() {
		t.Fatalf("missing module file: %+v %v", failed, err)
	}
	if _, err := s.GetModuleReport("example"); err == nil || !strings.Contains(err.Error(), "module_file_unavailable") {
		t.Fatalf("report should explain failed refresh: %v", err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	enabled := true
	res, err := s.SetModuleEnabled(ctx, api.SetModuleEnabledRequest{ModuleID: "example", Enabled: &enabled, BaseRevision: s.ActiveRevision()})
	if err != nil || res.State != "committed" {
		t.Fatalf("first enable: %+v %v", res, err)
	}
	report, err := s.GetModuleReport("example")
	if err != nil || report.Name != "Example" || report.Rules.Imported != 1 {
		t.Fatalf("report: %+v %v", report, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	frozen := s.GetConfiguration(true).Sources
	res, err = s.SetModuleArguments(ctx, api.SetModuleArgumentsRequest{
		ModuleID: "example", Arguments: map[string]string{"POLICY": "alternate"}, BaseRevision: res.Revision,
	})
	if err != nil || res.State != "committed" || s.GetConfiguration(true).Sources != frozen {
		t.Fatalf("offline argument change: %+v %v", res, err)
	}
	report, err = s.GetModuleReport("example")
	if err != nil || len(report.Arguments) != 1 || report.Arguments[0].Value != "alternate" {
		t.Fatalf("updated report: %+v %v", report, err)
	}
	res, err = s.SetModuleArguments(ctx, api.SetModuleArgumentsRequest{
		ModuleID: "example", Arguments: map[string]string{"POLICY": "unavailable"}, BaseRevision: res.Revision,
	})
	if err != nil || res.State != "rejected" || !res.Diagnostics.HasErrors() {
		t.Fatalf("bad policy transaction: %+v %v", res, err)
	}
	enabled = false
	res, err = s.SetModuleEnabled(ctx, api.SetModuleEnabledRequest{ModuleID: "example", Enabled: &enabled, BaseRevision: s.ActiveRevision()})
	if err != nil || res.State != "committed" || s.GetConfiguration(true).Sources != frozen {
		t.Fatalf("disable: %+v %v", res, err)
	}
	list, err := s.ListModules()
	if err != nil || len(list) != 1 || list[0].Enabled || list[0].SourceType != "file" || list[0].Status.RootHash != resource.Hash(body) ||
		len(list[0].Arguments) != 1 || list[0].Arguments[0].Value != "alternate" || list[0].Report != nil {
		t.Fatalf("disabled module list: %+v %v", list, err)
	}
	enabled = true
	res, err = s.SetModuleEnabled(ctx, api.SetModuleEnabledRequest{ModuleID: "example", Enabled: &enabled, BaseRevision: res.Revision})
	if err != nil || res.State != "committed" || s.GetConfiguration(true).Sources != frozen {
		t.Fatalf("offline re-enable: %+v %v", res, err)
	}
	res, err = s.RemoveModule(ctx, api.RemoveModuleRequest{ModuleID: "example", BaseRevision: res.Revision})
	if err != nil || res.State != "committed" {
		t.Fatalf("remove: %+v %v", res, err)
	}
	got := s.GetConfiguration(true)
	if strings.Contains(got.Profile, "marker") || strings.Contains(got.Profile, "example") || strings.Contains(got.Sources, "example") ||
		!strings.Contains(got.Profile, "final") {
		t.Fatalf("removal left references or removed unrelated rules: %+v", got)
	}
}

func TestModuleRefreshHTTP(t *testing.T) {
	exerciseModuleHTTP(t, func(handler http.Handler) (string, *http.Client, func()) {
		server := httptest.NewServer(handler)
		return server.URL, server.Client(), server.Close
	})
}

type moduleTestTransport func(*http.Request) (*http.Response, error)

func (f moduleTestTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestModuleRefreshInMemory(t *testing.T) {
	exerciseModuleHTTP(t, func(handler http.Handler) (string, *http.Client, func()) {
		client := &http.Client{Transport: moduleTestTransport(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			return rec.Result(), nil
		})}
		return "https://example.com", client, func() {}
	})
}

func exerciseModuleHTTP(t *testing.T, serve func(http.Handler) (string, *http.Client, func())) {
	t.Helper()
	var mode, rootRequests, assetRequests atomic.Int32
	rootRequest := func(w http.ResponseWriter, r *http.Request) {
		rootRequests.Add(1)
		if mode.Load() == 4 {
			http.Error(w, "", http.StatusServiceUnavailable)
			return
		}
		etag, policy := "root", "DIRECT"
		if mode.Load() == 1 {
			etag, policy = "bad", "Missing"
		}
		w.Header().Set("ETag", etag)
		validator := r.Header.Get("If-None-Match")
		if rootRequests.Load() >= 2 && validator != "root" {
			t.Errorf("root validator = %q", validator)
		}
		if validator == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		fmt.Fprintf(w, "#!name=Remote example\n[Rule]\nDOMAIN,filter.example.com,%s\n[Map Local]\n"+
			"^https://one\\.example\\.net/ data-type=text data=%s\n"+
			"^https://two\\.example\\.net/ data-type=json data=%s\n",
			policy, assetURL(r), assetURL(r))
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/root":
			rootRequest(w, r)
		case "/asset":
			assetRequests.Add(1)
			mode := mode.Load()
			if mode == 2 {
				http.Error(w, "", http.StatusBadGateway)
				return
			}
			version := 0
			if mode == 3 {
				version = 1
			}
			etag := "asset-" + strconv.Itoa(version)
			validator := r.Header.Get("If-None-Match")
			if assetRequests.Load() >= 2 && validator != "asset-0" && mode != 4 {
				t.Errorf("asset validator = %q", validator)
			}
			w.Header().Set("ETag", etag)
			if validator == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			fmt.Fprintf(w, "{\"version\":%d}", version)
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
	ctx := context.Background()
	rootURL := baseURL + "/root?access=masked-value"
	mode.Store(4)
	first, err := s.AddModule(ctx, api.AddModuleRequest{Module: model.Module{ID: "failed", URL: rootURL}, BaseRevision: s.ActiveRevision()})
	if err == nil || first.State == "committed" || len(s.GetConfiguration(true).Sources) != 0 {
		t.Fatalf("first failure wrote a snapshot: %+v %v", first, err)
	}
	mode.Store(0)
	rootRequests.Store(0)
	added, err := s.AddModule(ctx, api.AddModuleRequest{Module: model.Module{ID: "remote", URL: rootURL}, BaseRevision: s.ActiveRevision()})
	if err != nil || added.State != "committed" {
		t.Fatalf("install: %+v %v", added, err)
	}
	good := s.GetConfiguration(true)
	sources, _, ds := model.ParseSources([]byte(good.Sources))
	if ds.HasErrors() || len(sources.Sources) != 1 {
		t.Fatal(ds, good.Sources)
	}
	src := sources.Sources[0]
	if src.Module.Request != resource.Hash([]byte(rootURL)) || len(src.Lock.Resources) != 1 || assetRequests.Load() != 1 {
		t.Fatalf("bundle did not deduplicate URLs: %+v, requests %d", src.Lock, assetRequests.Load())
	}
	child := src.Lock.Resources[0]
	if child.Kind != "map-local" || child.Request != resource.Hash([]byte(baseURL+"/asset")) ||
		child.Hash != resource.Hash([]byte(`{"version":0}`)) {
		t.Fatalf("child lock: %+v", child)
	}
	masked := s.GetConfiguration(false)
	list, err := s.ListModules()
	encoded, _ := json.Marshal(list)
	if err != nil || len(list) != 1 || list[0].Report == nil || list[0].Report.Rewrites.Imported != 2 || list[0].Status.State != "current" ||
		strings.Contains(string(encoded), baseURL) || strings.Contains(masked.Profile, rootURL) || strings.Contains(good.Sources, baseURL) {
		t.Fatalf("safe list or masked definition: %s, %+v, %v", encoded, masked, err)
	}
	res, err := s.Commit(ctx, CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: good.Revision, Profile: &masked.Profile}})
	if err != nil || res.State != "committed" || !res.NoChange {
		t.Fatalf("masked URL round trip: %+v, %v", res, err)
	}

	refresh := func() api.ModuleStatus {
		t.Helper()
		status, err := s.RefreshModule(ctx, "remote", true)
		if err != nil {
			t.Fatal(err)
		}
		return status
	}
	if status := refresh(); status.State != "current" || status.Revision != good.Revision {
		t.Fatalf("304 refresh should keep revision: %+v", status)
	}
	mode.Store(1)
	if status := refresh(); status.State != "stale" || status.ErrorCode != "commit_rejected" || status.RootHash != src.Lock.Root ||
		!status.NextAttempt.After(time.Now().Add(20*time.Second)) || s.ActiveRevision() != good.Revision {
		t.Fatalf("rejected module refresh changed the snapshot: %+v", status)
	}
	mode.Store(2)
	if status := refresh(); status.State != "stale" || status.ErrorCode != "http_status_502" || s.GetConfiguration(true).Sources != good.Sources {
		t.Fatalf("failed child refresh changed the snapshot: %+v", status)
	}
	// A restart retains the old validators from the last committed bundle.
	s.Close()
	s = e.open("", "")
	if _, err := s.manager(RefreshOptions{Client: client}); err != nil {
		t.Fatal(err)
	}
	mode.Store(3)
	if status := refresh(); status.State != "current" || status.Revision == good.Revision || status.RootHash != src.Lock.Root {
		t.Fatalf("child change under unchanged root: %+v", status)
	}
}

func assetURL(r *http.Request) string {
	scheme := "http"
	if r.URL.Scheme == "https" || r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/asset"
}

func TestModuleFileBounds(t *testing.T) {
	dir := t.TempDir()
	large := filepath.Join(dir, "large.sgmodule")
	f, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(model.MaxDocumentSize + 1)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, large, filepath.Join(dir, "missing.sgmodule")} {
		if _, err := moduleacquire.ReadFile(path, model.MaxDocumentSize); err == nil {
			t.Fatal("invalid module file was accepted")
		}
	}
}

func TestModuleSchedulerUsesSecretAndSkipsDisabledAndFileModules(t *testing.T) {
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	ctx := context.Background()
	const secretURL = "https://example.com/secret.sgmodule"
	if err := e.sec.Set("module-url", secretURL); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	client := &http.Client{Transport: moduleTestTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != secretURL {
			t.Errorf("unresolved or unexpected URL: %s", req.URL)
		}
		requests.Add(1)
		rec := httptest.NewRecorder()
		fmt.Fprint(rec, "#!name=Scheduled example\n[Rule]\nDOMAIN,filter.example.com,REJECT\n")
		return rec.Result(), nil
	})}
	m, err := s.manager(RefreshOptions{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(e.root, "local.sgmodule")
	if err := os.WriteFile(path, []byte("#!name=Local example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	disabled := false
	local := model.Module{ID: "local", File: path}
	auto := model.Module{ID: "auto", URL: "secret://module-url", Interval: model.ModuleMinInterval}
	paused := model.Module{ID: "paused", URL: "secret://module-url", Enabled: &disabled}
	position := 0
	for _, def := range []model.Module{local, paused, auto} {
		added, err := s.AddModule(ctx, api.AddModuleRequest{Module: def, BaseRevision: s.ActiveRevision(), Position: &position})
		if err != nil || added.State != "committed" {
			t.Fatalf("install %s: %+v %v", def.ID, added, err)
		}
	}
	c := s.GetConfiguration(false)
	if strings.Contains(c.Profile, secretURL) || !strings.Contains(c.Profile, auto.URL) || strings.Contains(c.Sources, "module-url") {
		t.Fatalf("secret reference not isolated in the profile: %s\n%s", c.Profile, c.Sources)
	}
	list, err := s.ListModules()
	if err != nil || len(list) != 3 || list[0].ID != auto.ID || list[1].ID != paused.ID || list[2].ID != local.ID {
		t.Fatalf("module order: %+v %v", list, err)
	}
	localRoot := list[2].Status.RootHash
	if err := os.WriteFile(path, []byte("#!name=Edited example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Expire check times without waiting for the production update interval.
	m.mu.Lock()
	for _, def := range []model.Module{local, paused, auto} {
		key := refreshKey{id: def.ID, module: true}
		cache := m.records[key]
		cache.Status.NextAttempt = time.Now().Add(-time.Hour)
		root := cache.Entries["root"]
		root.Checked, root.Next = time.Now().Add(-time.Hour), cache.Status.NextAttempt
		cache.Entries["root"] = root
		m.records[key] = cache
	}
	m.mu.Unlock()
	m.runDue()
	m.wg.Wait()
	list, err = s.ListModules()
	if err != nil || requests.Load() != 3 || list[2].Status.RootHash != localRoot {
		t.Fatalf("scheduler refreshed a disabled or file module: %+v %v, requests: %d", list, err, requests.Load())
	}
	manual, err := s.RefreshModule(ctx, paused.ID, true)
	if err != nil || manual.State != "current" || requests.Load() != 4 {
		t.Fatalf("manual refresh of disabled module: %+v %v", manual, err)
	}
}

func TestModuleResourceLimitPrecedesChildDownloads(t *testing.T) {
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	var raw strings.Builder
	raw.WriteString("[Map Local]\n")
	for i := range model.MaxModuleResources + 1 {
		fmt.Fprintf(&raw, "^https://local\\.example\\.com/%d data=https://cdn.example.net/%d\n", i, i)
	}
	var requests atomic.Int32
	client := &http.Client{Transport: moduleTestTransport(func(req *http.Request) (*http.Response, error) {
		requests.Add(1)
		rec := httptest.NewRecorder()
		fmt.Fprint(rec, raw.String())
		return rec.Result(), nil
	})}
	if _, err := s.manager(RefreshOptions{Client: client}); err != nil {
		t.Fatal(err)
	}
	added, err := s.AddModule(context.Background(), api.AddModuleRequest{
		Module: model.Module{ID: "example", URL: "https://example.com/root"}, BaseRevision: s.ActiveRevision(),
	})
	if added.State == "committed" || err == nil || !strings.Contains(err.Error(), "too_many_module_resources") || requests.Load() != 1 {
		t.Fatalf("resource bound: %+v %v, requests: %d", added, err, requests.Load())
	}
}

func TestModuleArgumentsDownloadNewMapLocalFile(t *testing.T) {
	var assets atomic.Int32
	client := &http.Client{Transport: moduleTestTransport(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		switch req.URL.Path {
		case "/root":
			fmt.Fprint(rec, "#!arguments=FILE:one\n[Map Local]\n^https://ads\\.example\\.net/ data-type=json data=https://example.com/{{{FILE}}}.json\n")
		default:
			assets.Add(1)
			fmt.Fprintf(rec, "{%q:true}", req.URL.Path)
		}
		return rec.Result(), nil
	})}
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	if _, err := s.manager(RefreshOptions{Client: client}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	res, err := s.AddModule(ctx, api.AddModuleRequest{Module: model.Module{ID: "ads", URL: "https://example.com/root"}, BaseRevision: s.ActiveRevision()})
	if err != nil || res.State != "committed" || assets.Load() != 1 {
		t.Fatalf("install: %+v %v, downloads %d", res, err, assets.Load())
	}
	res, err = s.SetModuleArguments(ctx, api.SetModuleArgumentsRequest{ModuleID: "ads", Arguments: map[string]string{"FILE": "two"}, BaseRevision: res.Revision})
	if err != nil || res.State != "committed" || assets.Load() != 2 {
		t.Fatalf("argument change: %+v %v, downloads %d", res, err, assets.Load())
	}
	sources, _, _ := model.ParseSources([]byte(s.GetConfiguration(true).Sources))
	if lock := sources.Sources[0].Lock; len(lock.Resources) != 1 || lock.Resources[0].Request != resource.Hash([]byte("https://example.com/two.json")) {
		t.Fatalf("lock after argument change: %+v", lock)
	}
}
