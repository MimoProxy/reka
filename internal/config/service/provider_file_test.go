package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

func TestProviderFilesStayInsideExplicitRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(root, "nodes.yaml"), []byte("safe"), 0600)
	os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0600)
	if data, err := readProviderFile(root, "nodes.yaml"); err != nil || string(data) != "safe" {
		t.Fatal(err)
	}
	for _, path := range []string{"../secret", filepath.Join(outside, "secret"), "."} {
		if _, err := readProviderFile(root, path); err == nil {
			t.Fatal("unsafe path accepted")
		}
	}
	if _, err := readProviderFile("", "nodes.yaml"); err == nil {
		t.Fatal("implicit root accepted")
	}
	if os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "escape")) == nil {
		if _, err := readProviderFile(root, "escape"); err == nil {
			t.Fatal("symlink escaped root")
		}
	}
}
func TestRefreshFileProviderAndFallbackLockActualBytes(t *testing.T) {
	for _, kind := range []string{"file", "http"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			os.WriteFile(filepath.Join(directory, "nodes.yaml"), []byte("proxies: [{name: from-file, type: direct}]"), 0600)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/nodes" {
					w.WriteHeader(503)
					return
				}
				text := "proxy-providers: {one: {type: " + kind + ", path: nodes.yaml, url: 'http://" + r.Host + "/nodes', payload: [{name: from-fallback, type: direct}]}}\nproxy-groups: [{name: Choice, type: select, use: [one]}]"
				w.Write([]byte(text))
			}))
			defer server.Close()
			e := newEnv(t)
			s := e.open(DefaultProfile, "")
			result, err := s.ConfigureSubscription(context.Background(), s.ActiveRevision(), "airport", &model.Subscription{URL: server.URL, ProviderDirectory: directory})
			if err != nil || result.State != "committed" {
				t.Fatal(result, err)
			}
			status := refreshNow(t, s, "airport")
			if status.State != "current" {
				t.Fatal(status)
			}
			sources, _, ds := model.ParseSources([]byte(s.GetConfiguration(true).Sources))
			if ds.HasErrors() {
				t.Fatal(ds)
			}
			src := sources.Sources[0]
			if src.Lock == nil || len(src.Lock.Resources) != 2 || len(src.Outbounds) != 1 {
				t.Fatal(src)
			}
			if kind == "file" && src.Outbounds[0].Name != "from-file" || kind == "http" && src.Outbounds[0].Name != "from-fallback" {
				t.Fatal(src.Outbounds)
			}
			if kind == "http" && len(status.FallbackResources) != 1 {
				t.Fatal("fallback hidden in status", status)
			}
			if kind == "file" {
				os.WriteFile(filepath.Join(directory, "nodes.yaml"), []byte("proxies: [{name: changed, type: direct}]"), 0600)
				status = refreshNow(t, s, "airport")
				if status.State != "current" || !strings.Contains(s.GetConfiguration(true).Sources, "changed") {
					t.Fatal(status)
				}
			}
			b, _ := json.Marshal(s.GetConfiguration(false))
			if len(b) == 0 {
				t.Fatal("configuration unavailable")
			}
		})
	}
}
