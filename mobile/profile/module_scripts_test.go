package profile

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/resource"
)

func TestAcquiredModuleScriptInExtensionSnapshot(t *testing.T) {
	const origin = "https://module.example.test"
	const source = "$done({url: 'https://rewrite.example.test/next'});"
	const root = `[Map Local]
^https://rewrite\.example\.test/data$ data-type=text data=` + origin + `/shared.js
[Script]
rewrite = type=http-request,pattern=^https://rewrite\.example\.test/,script-path=` + origin + `/shared.js,engine=jsc
optional = type=http-response,pattern=^https://rewrite\.example\.test/,script-path=` + origin + `/optional.js
`
	var failScript, recoverOptional atomic.Bool
	var sharedChecks atomic.Int32
	client := &http.Client{Transport: modulePrepareTransport(func(req *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		switch req.URL.Path {
		case "/module":
			fmt.Fprint(recorder, root)
		case "/shared.js":
			if sharedChecks.Add(1)%2 == 1 {
				recorder.Header().Set("ETag", `"map"`)
				fmt.Fprint(recorder, "mapped response")
				break
			}
			if failScript.Load() {
				if req.Header.Get("If-None-Match") != `"script"` {
					t.Errorf("script validator = %q", req.Header.Get("If-None-Match"))
				}
				http.NotFound(recorder, req)
				break
			}
			recorder.Header().Set("ETag", `"script"`)
			fmt.Fprint(recorder, source)
		case "/optional.js":
			if recoverOptional.Load() {
				fmt.Fprint(recorder, "$done();")
				break
			}
			http.NotFound(recorder, req)
		default:
			t.Errorf("unexpected module resource request to %s", req.URL.Path)
			http.NotFound(recorder, req)
		}
		return recorder.Result(), nil
	})}
	def := model.Module{ID: "script-filter", URL: origin + "/module"}
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first.json")
	req := ModuleAcquireRequest{Module: def, OutputSnapshot: firstPath}
	acquire := func() ModuleAcquireResult {
		return AcquireModule(t.Context(), req, ModuleAcquireOptions{Client: client})
	}
	optionalRequest := resource.Hash([]byte(origin + "/optional.js"))
	sharedRequest := resource.Hash([]byte(origin + "/shared.js"))
	assertFailures := func(result ModuleAcquireResult, requests ...string) {
		t.Helper()
		if len(result.ScriptErrors) != len(requests) {
			t.Fatalf("script failures = %+v, want %v", result.ScriptErrors, requests)
		}
		for i, failure := range result.ScriptErrors {
			if failure.Request != requests[i] || failure.Code != "http_status_404" {
				t.Fatalf("script failure = %+v", failure)
			}
		}
	}
	first := acquire()
	if first.Status != "updated" {
		t.Fatalf("acquire = %+v", first)
	}
	assertFailures(first, optionalRequest)
	preview, err := PreviewModule(t.Context(), ModulePreviewRequest{ModuleInput: ModuleInput{Snapshot: firstPath}}, nil)
	if err != nil || len(preview.Report.ScriptItems) != 2 || !preview.Report.ScriptItems[0].Locked || preview.Report.ScriptItems[1].Locked ||
		preview.Report.Rewrites.Imported != 1 {
		t.Fatalf("offline module preview = %+v, err %v", preview, err)
	}

	failScript.Store(true)
	req.PreviousSnapshot, req.OutputSnapshot, req.Force = firstPath, filepath.Join(dir, "retained.json"), true
	retained := acquire()
	if retained.Status != "not-modified" {
		t.Fatalf("refresh = %+v", retained)
	}
	assertFailures(retained, sharedRequest, optionalRequest)
	snapshot, err := LoadModuleSnapshot(req.OutputSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(snapshot.ScriptErrors, retained.ScriptErrors) {
		t.Fatalf("retained script errors = %+v, want %+v", snapshot.ScriptErrors, retained.ScriptErrors)
	}
	const profileDocument = `schema-version: 1
modules: [{id: %s, url: %q}]
`
	bundle, path := prepareSourceFixture(t, fmt.Sprintf(profileDocument, def.ID, def.URL), PrepareOptions{
		Modules: map[string]string{def.ID: req.OutputSnapshot},
	})
	hash := resource.Hash([]byte(source))
	if string(bundle.Resources[hash]) != source || slices.Contains(bundle.OmittedResources, hash) {
		t.Fatalf("script source is missing from the prepared bundle, hash %q", hash)
	}
	data, err := readBundleFile(path)
	if err != nil {
		t.Fatal(err)
	}
	effective, readScript, err := CompileSnapshotWithScripts(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	clear(data)
	if len(effective.Scripts) != 1 || !effective.Scripts[0].Supported || effective.Scripts[0].Engine != "jsc" || effective.Scripts[0].Hash != hash {
		t.Fatalf("effective scripts = %+v", effective.Scripts)
	}
	if readScript == nil {
		t.Fatal("extension script reader is missing")
	}
	got, err := readScript(hash)
	if err != nil || string(got) != source {
		t.Fatalf("extension script source = %q, err %v", got, err)
	}
	if runtime.GOOS != "ios" {
		got, err := effective.ScriptSource(hash)
		if err != nil || string(got) != source {
			t.Fatalf("effective script source = %q, err %v", got, err)
		}
	}
	mapLocal := effective.HTTPRewrite.Request(httprewrite.Request{URL: "https://rewrite.example.test/data"})
	if mapLocal.Local == nil || string(mapLocal.Local.Body) != "mapped response" {
		t.Fatalf("locked Map Local response = %+v, err %v", mapLocal.Local, mapLocal.ResourceError)
	}

	failScript.Store(false)
	recoverOptional.Store(true)
	req.PreviousSnapshot, req.OutputSnapshot = req.OutputSnapshot, filepath.Join(dir, "recovered.json")
	recovered := acquire()
	if recovered.Status != "updated" {
		t.Fatalf("recovery = %+v", recovered)
	}
	assertFailures(recovered)
}
