package moduleacquire

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/subscription"
)

type moduleTransport func(*http.Request) (*http.Response, error)

func (transport moduleTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return transport(req)
}

func acquireTestOptions(t *testing.T, handler http.HandlerFunc) Options {
	t.Helper()
	blobs, err := resource.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return Options{Blobs: blobs, IncludeScripts: true, Client: &http.Client{Transport: moduleTransport(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Result(), nil
	})}}
}

func TestAcquireLoonAndStashScriptLocks(t *testing.T) {
	const scriptURL = "https://example.com/filter.js"
	const scriptBody = "$done();"
	for _, tt := range []struct {
		name, location, explicit, format, document string
		interval                                   time.Duration
	}{
		{
			name: "Loon URL extension", location: "/filter.plugin?download=true", format: model.ModuleFormatLoon,
			document: "#!name=Example filter\n[Script]\nhttp-response example script-path=" + scriptURL + ", tag=Filter\n",
			interval: 600 * time.Second,
		},
		{
			name: "Stash explicit format", location: "/filter.plugin", explicit: model.ModuleFormatStash, format: model.ModuleFormatStash,
			document: "name: Example filter\nhttp:\n  script:\n    - {match: example, name: filter, type: response}\n" +
				"script-providers:\n  filter: {url: " + scriptURL + ", interval: 300}\n",
			interval: 300 * time.Second,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := acquireTestOptions(t, func(w http.ResponseWriter, req *http.Request) {
				switch req.URL.RequestURI() {
				case tt.location:
					fmt.Fprint(w, tt.document)
				case "/filter.js":
					fmt.Fprint(w, scriptBody)
				default:
					t.Errorf("unexpected resource request %q", req.URL.RequestURI())
					http.NotFound(w, req)
				}
			})
			def := model.Module{ID: "filter", URL: "https://example.com" + tt.location, Format: tt.explicit, Interval: 600}
			got, err := Acquire(t.Context(), def, opts)
			if err != nil || got.Snapshot.Module.Format != tt.format || got.Metadata.Name != "Example filter" ||
				got.Snapshot.Lock.Root != resource.Hash([]byte(tt.document)) || len(got.Snapshot.Lock.Resources) != 1 {
				t.Fatalf("module acquisition: %+v, error %v", got, err)
			}
			lock := got.Snapshot.Lock.Resources[0]
			entry := got.Entries[EntryKey(lock)]
			if lock.Kind != "script" || lock.Request != resource.Hash([]byte(scriptURL)) ||
				lock.Hash != resource.Hash([]byte(scriptBody)) || entry.Next.Sub(entry.Checked) != tt.interval {
				t.Fatalf("script lock: %+v, entry %+v", lock, entry)
			}
			src := model.Source{ID: def.ID, Module: &got.Snapshot.Module, Lock: &got.Snapshot.Lock}
			if !Matches(def, src) {
				t.Fatal("snapshot should match the acquisition declaration")
			}
			def.Format = model.ModuleFormatSurge
			if Matches(def, src) {
				t.Fatal("snapshot should require reacquisition when the explicit format changes")
			}
		})
	}
}

func TestAcquireScriptLimits(t *testing.T) {
	var root strings.Builder
	root.WriteString("[Script]\n")
	for i := range model.MaxModuleScripts + 1 {
		fmt.Fprintf(&root, "script %d = type=http-request,pattern=^https://example.com/%d,script-path=https://cdn.example.net/%d.js\n", i, i, i)
	}
	opts := acquireTestOptions(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/module" {
			t.Fatalf("unexpected child request %s", req.URL.Path)
		}
		fmt.Fprint(w, root.String())
	})
	_, err := Acquire(t.Context(), model.Module{ID: "limits", URL: "https://example.com/module"}, opts)
	if subscription.Code(err) != "too_many_module_scripts" {
		t.Fatalf("script limit error = %v", err)
	}
}

func TestAcquireScriptsShareBundleWithMapLocal(t *testing.T) {
	const url = "https://example.com/shared"
	const body = "$done();"
	var requests int
	opts := acquireTestOptions(t, func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/module":
			fmt.Fprintf(w, "[Map Local]\n^https://example.com/item data=%s\n[Script]\ncustom = type=http-response,pattern=^https://example.com/item,script-path=%s,script-update-interval=300\n", url, url)
		case "/shared":
			requests++
			fmt.Fprint(w, body)
		default:
			http.NotFound(w, req)
		}
	})
	result, err := Acquire(t.Context(), model.Module{ID: "shared", URL: "https://example.com/module", Interval: 600}, opts)
	if err != nil || len(result.Snapshot.Lock.Resources) != 2 || len(result.Entries) != 3 || requests != 2 {
		t.Fatalf("shared request: %+v, requests %d, error %v", result, requests, err)
	}
	request := resource.Hash([]byte(url))
	want := resource.Hash([]byte(body))
	mapLock, scriptLock := result.Snapshot.Lock.Resources[0], result.Snapshot.Lock.Resources[1]
	if mapLock.Kind != "map-local" || scriptLock.Kind != "script" || mapLock.Request != request || scriptLock.Request != request ||
		mapLock.ID != request[:24] || scriptLock.ID != request[:24] || mapLock.Hash != want || scriptLock.Hash != want {
		t.Fatalf("shared locks: %+v", result.Snapshot.Lock.Resources)
	}
	script := result.Entries[EntryKey(scriptLock)]
	if script.Next.Sub(script.Checked) != 300*time.Second || !result.Next.Equal(script.Next) {
		t.Fatalf("next %v should use the script's interval, entry %+v", result.Next, script)
	}
	opts.IncludeScripts = false
	compat, err := Acquire(t.Context(), model.Module{ID: "shared", URL: "https://example.com/module", Interval: 600}, opts)
	if err != nil || len(compat.Snapshot.Lock.Resources) != 1 || compat.Snapshot.Lock.Resources[0] != mapLock || requests != 3 {
		t.Fatalf("Map Local-only consumer: %+v, requests %d, error %v", compat, requests, err)
	}
}

func TestAcquireScriptTooLarge(t *testing.T) {
	const url = "https://example.com/oversized.js"
	var scriptRequests int
	opts := acquireTestOptions(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/module" {
			fmt.Fprintf(w, "[Script]\nlarge = type=http-response,pattern=example,script-path=%s,script-update-interval=300\n", url)
			return
		}
		scriptRequests++
		fmt.Fprint(w, strings.Repeat("a", model.MaxScriptSize+1))
	})
	begin := time.Now().UTC()
	def := model.Module{ID: "oversized", URL: "https://example.com/module", Interval: 600}
	result, err := Acquire(t.Context(), def, opts)
	if err != nil || result.Snapshot.Lock.Root == "" || len(result.Snapshot.Lock.Resources) != 0 || len(result.ScriptErrors) != 1 ||
		result.ScriptErrors[0].Request != resource.Hash([]byte(url)) || result.ScriptErrors[0].Code != "body_too_large" {
		t.Fatalf("oversized optional script: %+v %v", result, err)
	}
	if result.Next.Before(begin.Add(300*time.Second)) || result.Next.After(time.Now().UTC().Add(300*time.Second)) {
		t.Fatalf("missing script retry not scheduled at its interval: %v", result.Next)
	}
	opts.Previous = model.Source{ID: def.ID, Module: &result.Snapshot.Module, Lock: &result.Snapshot.Lock}
	opts.PreviousEntries, opts.PreviousScriptErrors = result.Entries, result.ScriptErrors
	cached, err := Acquire(t.Context(), def, opts)
	if err != nil || scriptRequests != 1 || len(cached.ScriptErrors) != 1 || cached.ScriptErrors[0] != result.ScriptErrors[0] || !cached.Next.Equal(result.Next) {
		t.Fatalf("cached failure: %+v, requests %d, error %v", cached, scriptRequests, err)
	}
	opts.Force = true
	forced, err := Acquire(t.Context(), def, opts)
	if err != nil || scriptRequests != 2 || len(forced.ScriptErrors) != 1 || forced.ScriptErrors[0].Code != "body_too_large" {
		t.Fatalf("forced retry: %+v, requests %d, error %v", forced, scriptRequests, err)
	}
}

func TestAcquireScriptRetainsValidatedCache(t *testing.T) {
	const url = "https://example.com/script.js"
	var unavailable bool
	var scriptRequests int
	opts := acquireTestOptions(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/module" {
			fmt.Fprintf(w, "[Script]\nscript = type=http-request,pattern=example,script-path=%s\n", url)
			return
		}
		scriptRequests++
		if unavailable {
			if got := req.Header.Get("If-None-Match"); scriptRequests == 2 && got != "script" || scriptRequests == 3 && got != "" {
				t.Errorf("request %d used unexpected validator %q", scriptRequests, got)
			}
			http.NotFound(w, req)
			return
		}
		w.Header().Set("ETag", "script")
		fmt.Fprint(w, "$done();")
	})
	def := model.Module{ID: "script", URL: "https://example.com/module"}
	first, err := Acquire(t.Context(), def, opts)
	if err != nil || len(first.Snapshot.Lock.Resources) != 1 {
		t.Fatalf("initial lock: %+v %v", first, err)
	}
	lock := first.Snapshot.Lock.Resources[0]
	opts.Previous = model.Source{ID: def.ID, Module: &first.Snapshot.Module, Lock: &first.Snapshot.Lock}
	opts.PreviousEntries, opts.Force, unavailable = first.Entries, true, true
	retained, err := Acquire(t.Context(), def, opts)
	if err != nil || len(retained.Snapshot.Lock.Resources) != 1 || retained.Snapshot.Lock.Resources[0] != lock || len(retained.ScriptErrors) != 1 ||
		retained.ScriptErrors[0].Request != lock.Request || retained.ScriptErrors[0].Code != "http_status_404" {
		t.Fatalf("retained script: %+v %v", retained, err)
	}
	opts.PreviousEntries, opts.Force = retained.Entries, false
	cached, err := Acquire(t.Context(), def, opts)
	if err != nil || scriptRequests != 2 || len(cached.ScriptErrors) != 1 || cached.ScriptErrors[0] != retained.ScriptErrors[0] {
		t.Fatalf("cached script status: %+v, requests %d, error %v", cached, scriptRequests, err)
	}
	key := EntryKey(lock)
	entry := retained.Entries[key]
	entry.Hash = resource.Hash([]byte("different"))
	retained.Entries[key] = entry
	opts.Force = true
	dropped, err := Acquire(t.Context(), def, opts)
	if err != nil || scriptRequests != 3 || len(dropped.Snapshot.Lock.Resources) != 0 || len(dropped.ScriptErrors) != 1 ||
		dropped.ScriptErrors[0].Request != lock.Request || dropped.ScriptErrors[0].Code != "http_status_404" {
		t.Fatalf("mismatched cached script: %+v, requests %d, error %v", dropped, scriptRequests, err)
	}
}

func TestAcquireScriptCancellationAndBundleLimit(t *testing.T) {
	def := model.Module{ID: "scripts", URL: "https://example.com/module"}
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		opts := acquireTestOptions(t, func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path == "/module" {
				fmt.Fprint(w, "[Script]\nscript = type=http-request,pattern=example,script-path=https://example.com/script.js\n")
				return
			}
			cancel()
			http.NotFound(w, req)
		})
		if _, err := Acquire(ctx, def, opts); subscription.Code(err) != "cancelled" {
			t.Fatalf("cancelled script download: %v", err)
		}
	})
	t.Run("bundle limit", func(t *testing.T) {
		var root strings.Builder
		root.WriteString("[Script]\n")
		for i := range MaxBundleSize / model.MaxScriptSize {
			fmt.Fprintf(&root, "script %d = type=http-request,pattern=example,script-path=https://example.com/%d.js\n", i, i)
		}
		large := strings.Repeat(" ", model.MaxScriptSize)
		opts := acquireTestOptions(t, func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path == "/module" {
				fmt.Fprint(w, root.String())
				return
			}
			w.Header().Set("Content-Length", fmt.Sprint(len(large)))
			io.WriteString(w, large)
		})
		if _, err := Acquire(t.Context(), def, opts); subscription.Code(err) != "bundle_too_large" {
			t.Fatalf("bundle limit error = %v", err)
		}
	})
}
