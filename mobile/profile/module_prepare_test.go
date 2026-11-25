package profile

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/resource"
)

func TestPrepareAcquiredModuleHTTP(t *testing.T) {
	exercisePrepareAcquiredModule(t, func(handler http.Handler) (string, *http.Client) {
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		return server.URL, nil
	})
}

type modulePrepareTransport func(*http.Request) (*http.Response, error)

func (f modulePrepareTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestPrepareAcquiredModuleInMemory(t *testing.T) {
	exercisePrepareAcquiredModule(t, func(handler http.Handler) (string, *http.Client) {
		return "https://module.example.test", &http.Client{Transport: modulePrepareTransport(func(req *http.Request) (*http.Response, error) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			return recorder.Result(), nil
		})}
	})
}

func exercisePrepareAcquiredModule(t *testing.T, serve func(http.Handler) (string, *http.Client)) {
	t.Helper()
	const payload = `{"from":"module"}`
	const lastModified = "Wed, 21 Oct 2015 07:28:00 GMT"
	var version, rootChecks, dataChecks atomic.Int32
	address, client := serve(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Last-Modified", lastModified)
		check := func(count int32, tag string) bool {
			w.Header().Set("ETag", tag)
			if count > 1 && (req.Header.Get("If-None-Match") == "" || req.Header.Get("If-Modified-Since") != lastModified) {
				t.Errorf("%s missing previous HTTP validators", req.URL.Path)
			}
			if req.Header.Get("If-None-Match") == tag {
				w.WriteHeader(http.StatusNotModified)
				return true
			}
			return false
		}
		switch req.URL.Path {
		case "/module":
			v := version.Load()
			if check(rootChecks.Add(1), fmt.Sprintf(`"module-%d"`, v)) {
				return
			}
			host := "old.example.test"
			if v == 1 {
				host = "new.example.test"
			}
			scheme := req.URL.Scheme
			if scheme == "" {
				scheme = "http"
			}
			fmt.Fprintf(w, `#!name=Example filter
#!desc=Module fixture
#!arguments=First:default.example.test
[URL Rewrite]
^https://rewrite\.example\.test/reject$ - reject
[Map Local]
^https://rewrite\.example\.test/data$ data-type=json data=%s://%s/data
[MITM]
hostname = %%INSERT%% {{{First}}}
hostname = %%APPEND%% %s
h2 = true
skip-server-cert-verify = true
[Script]
demo = type=http-request,pattern=https://rewrite.example.test
`, scheme, req.Host, host)
		case "/data":
			if !check(dataChecks.Add(1), `"data-0"`) {
				fmt.Fprint(w, payload)
			}
		default:
			http.NotFound(w, req)
		}
	}))
	def := model.Module{ID: "filter", URL: address + "/module", Arguments: map[string]string{"First": "first.example.test"}}
	dir := t.TempDir()
	firstFile := filepath.Join(dir, "module.json")
	request := ModuleAcquireRequest{Module: def, OutputSnapshot: firstFile}
	acquire := func(request ModuleAcquireRequest) ModuleAcquireResult {
		return AcquireModule(t.Context(), request, ModuleAcquireOptions{Client: client})
	}
	first := acquire(request)
	if first.Status != "updated" || first.Metadata == nil || first.Metadata.Name != "Example filter" || first.Hostnames == nil ||
		!slices.Equal(first.Hostnames.Insert, []string{"first.example.test"}) || !slices.Equal(first.Hostnames.Append, []string{"old.example.test"}) {
		t.Fatalf("first acquire = %+v", first)
	}
	source, sourceFile := prepareSourceFixture(t, `schema-version: 1
mitm: {hostnames: [source.example.test], quic-block: false}
`, PrepareOptions{})
	if source.Summary.MITM == nil || source.Summary.MITM.Hostnames[0].Layer != "profile" {
		t.Fatalf("source's own hostname origin = %+v", source.Summary.MITM)
	}
	const rawTemplate = `schema-version: 1
imports: [{source: subscription, rewrites: true}]
modules:
  - id: filter
    url: %q
    arguments: {First: first.example.test}
mitm: {hostnames: [profile.example.test], skip-server-cert-verify: false}
`
	raw := fmt.Sprintf(rawTemplate, def.URL)
	options := PrepareOptions{Modules: map[string]string{def.ID: firstFile}, Sources: map[string]string{"subscription": sourceFile}, MITM: &LocalMITM{Enabled: true}}
	bundle, bundleFile := prepareSourceFixture(t, raw, options)
	compiled, err := bundle.Compile()
	if err != nil {
		t.Fatal(err)
	}
	wantHosts := []string{"first.example.test", "profile.example.test", "source.example.test", "old.example.test"}
	if !slices.Equal(compiled.MITM.Hostnames, wantHosts) || !compiled.MITM.Enabled || compiled.HTTPRewrite == nil || compiled.Modules[def.ID].Rewrites.Imported != 2 {
		t.Fatalf("module did not compile: MITM %+v, reports %+v", compiled.MITM, compiled.Modules)
	}
	if got := compiled.HTTPRewrite.Request(httprewrite.Request{URL: "https://rewrite.example.test/data"}); got.Local == nil || string(got.Local.Body) != payload {
		t.Fatal("Map Local did not return the locked data")
	}
	sources, _, diagnostics := model.ParseSources(bundle.Sources)
	if diagnostics.HasErrors() || len(sources.Sources) != 2 || sources.Sources[1].Lock == nil {
		t.Fatalf("missing module source lock: %s (%v)", bundle.Sources, diagnostics)
	}
	lock := sources.Sources[1].Lock
	if len(lock.Resources) != 1 || lock.Resources[0].Hash != resource.Hash([]byte(payload)) || string(bundle.Resources[lock.Resources[0].Hash]) != payload {
		t.Fatalf("map-local lock = %+v", lock)
	}
	summary := bundle.Summary
	wantOrigins := []MITMHostname{{wantHosts[0], "module", "filter"}, {wantHosts[1], "profile", ""}, {wantHosts[2], "source", "subscription"}, {wantHosts[3], "module", "filter"}}
	if summary.MITM == nil || !slices.Equal(summary.MITM.Hostnames, wantOrigins) || !summary.MITM.H2 || summary.MITM.SkipServerCertVerify || summary.MITM.QUICBlock {
		t.Fatalf("MITM summary = %+v", summary.MITM)
	}
	if len(summary.Modules) != 1 || summary.Modules[0].Report == nil || summary.Modules[0].Name != "Example filter" || summary.Modules[0].Desc != "Module fixture" ||
		!slices.Equal(summary.Modules[0].Hostnames, append(slices.Clone(first.Hostnames.Insert), first.Hostnames.Append...)) || summary.Modules[0].Report.Hostnames.Imported != 2 ||
		len(summary.Modules[0].Arguments) != 1 || summary.Modules[0].Arguments[0].Value != "first.example.test" {
		t.Fatalf("module summary = %+v", summary.Modules)
	}
	isScriptLine := func(line module.Line) bool { return line.Section == "script" && line.Status == module.Unsupported }
	full, err := ModuleReport(t.Context(), bundleFile, def.ID, nil)
	if err != nil || !slices.ContainsFunc(full.Lines, isScriptLine) {
		t.Fatalf("full report = %+v, err %v", full, err)
	}
	preview, err := PreviewModule(t.Context(), ModulePreviewRequest{ModuleInput: ModuleInput{Snapshot: firstFile}, ProfileSnapshot: bundleFile}, nil)
	if err != nil || !slices.ContainsFunc(preview.Report.Lines, isScriptLine) || preview.Report.Rewrites.Imported != 2 || rootChecks.Load() != 1 || dataChecks.Load() != 1 {
		t.Fatalf("offline preview = %+v, err %v, requests %d/%d", preview, err, rootChecks.Load(), dataChecks.Load())
	}
	request.PreviousSnapshot, request.OutputSnapshot, request.Force = firstFile, filepath.Join(dir, "checked.json"), true
	unchanged := acquire(request)
	if unchanged.Status != "not-modified" || len(unchanged.Added) != 0 || len(unchanged.Removed) != 0 || rootChecks.Load() != 2 || dataChecks.Load() != 2 {
		t.Fatalf("conditional acquire = %+v, requests %d/%d", unchanged, rootChecks.Load(), dataChecks.Load())
	}
	version.Store(1)
	request.PreviousSnapshot, request.OutputSnapshot = request.OutputSnapshot, filepath.Join(dir, "updated.json")
	updated := acquire(request)
	if updated.Status != "updated" || !slices.Equal(updated.Added, []string{"new.example.test"}) || !slices.Equal(updated.Removed, []string{"old.example.test"}) {
		t.Fatalf("changed hostname diff = %+v", updated)
	}

	if err := os.Remove(firstFile); err != nil {
		t.Fatal(err)
	}
	offline, _ := prepareSourceFixture(t, raw, PrepareOptions{MITM: &LocalMITM{}, RebindSnapshot: bundleFile})
	if offline.Summary.MITM == nil || offline.Summary.MITM.Enabled || !bytes.Equal(offline.Sources, bundle.Sources) || rootChecks.Load() != 3 || dataChecks.Load() != 3 {
		t.Fatalf("MITM toggle did not preserve archived sources offline: %+v", offline.Summary.MITM)
	}
	refreshed, _ := prepareSourceFixture(t, raw, PrepareOptions{Modules: map[string]string{def.ID: request.OutputSnapshot}, RebindSnapshot: bundleFile})
	if refreshed.Resources[lock.Root] != nil || !slices.Equal(refreshed.Summary.Modules[0].Hostnames, []string{"first.example.test", "new.example.test"}) ||
		refreshed.Summary.MITM.Hostnames[2].Source != "subscription" || rootChecks.Load() != 3 || dataChecks.Load() != 3 {
		t.Fatalf("module rebind did not refresh just the module offline: %+v", refreshed.Summary)
	}
}

func TestPrepareModuleRequiresMatchingSnapshotOnlyWhenEnabled(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "module.sgmodule")
	writeFixtureFile(t, file, []byte("#!name=Offline\n[MITM]\nhostname = %APPEND% module.example.test\n"))
	moduleSnapshot := filepath.Join(dir, "module.json")
	def := model.Module{ID: "offline", File: file}
	result := AcquireModule(t.Context(), ModuleAcquireRequest{Module: def, OutputSnapshot: moduleSnapshot}, ModuleAcquireOptions{})
	if result.Status != "updated" {
		t.Fatalf("acquire file module = %+v", result)
	}
	input, output := filepath.Join(dir, "profile.yaml"), filepath.Join(dir, "profile.json")
	for _, tc := range []struct {
		name, file, message string
		paths               map[string]string
	}{
		{name: "missing", file: file, message: "snapshot is missing"},
		{name: "moved", file: file + ".new", message: "declared ID, location, or format", paths: map[string]string{def.ID: moduleSnapshot}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeFixtureFile(t, input, fmt.Appendf(nil, "schema-version: 1\nmodules: [{id: offline, file: %q}]\n", tc.file))
			err := PrepareFileWithOptions(t.Context(), input, output, dir, PrepareOptions{Modules: tc.paths})
			var validation *ValidationError
			if !errors.As(err, &validation) || !strings.Contains(validation.Message, tc.message) ||
				!strings.Contains(validation.Message, def.ID) || validation.Diagnostics[0].Path != "/modules/offline" {
				t.Fatalf("missing specific module diagnostic: %v", err)
			}
		})
	}
	const disabled = "schema-version: 1\nmodules: [{id: offline, url: 'https://offline.example.test', enabled: false}]\n"
	bundle, _ := prepareSourceFixture(t, disabled, PrepareOptions{})
	if bundle.Sources != nil || len(bundle.Summary.Modules) != 1 || bundle.Summary.Modules[0].Enabled || bundle.Summary.Modules[0].Report != nil {
		t.Fatalf("disabled module expected without a source lock: %+v", bundle.Summary.Modules)
	}
}
