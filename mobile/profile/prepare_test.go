package profile

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/secret"
)

func TestSharingLinksUseSelectedNodeInRuleAndGlobalModes(t *testing.T) {
	links := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@first.example.test:443?security=tls#First\n" +
		"trojan://test-only@second.example.test:443?sni=second.example.test#Second\n"
	for _, raw := range []string{links, base64.StdEncoding.EncodeToString([]byte(links))} {
		bundle, err := prepare(t.Context(), []byte(raw), nil)
		if err != nil {
			t.Fatal(err)
		}
		summary := bundle.Summary
		if len(summary.Groups) != 1 || summary.Nodes != 2 || summary.Format != "links" || len(summary.Outbounds) != 2 {
			t.Fatalf("unexpected sharing link summary: %+v", summary)
		}
		group := summary.Groups[0]
		if group.ID != NodeGroup || len(group.Members) != 2 {
			t.Fatalf("missing selector: %+v", group)
		}
		base, err := bundle.Compile()
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"rule", "global"} {
			config, err := ApplyControls(base, summary, Controls{Mode: mode, Selections: map[string]string{group.ID: group.Members[1]}})
			if err != nil {
				t.Fatal(err)
			}
			decision := config.RoutingRouter().Route(t.Context(), router.Metadata{Domain: "example.test", Network: "tcp"}, nil)
			if decision.Outbound != group.Members[1] {
				t.Fatalf("%s chose %q, want %q", mode, decision.Outbound, group.Members[1])
			}
		}
	}
}

func TestNativePreparationReportsSourcePosition(t *testing.T) {
	raw := []byte("schema-version: 1\noutbounds:\n  - id: invalid\n    type: vless\n    server: host.test\n    port: 70000\n")
	_, err := prepare(t.Context(), raw, nil)
	var report *ValidationError
	if !errors.As(err, &report) {
		t.Fatalf("expected compiler diagnostics: %v", err)
	}
	for _, diagnostic := range report.Diagnostics {
		if strings.HasSuffix(diagnostic.Path, "/port") && diagnostic.Line == 6 && diagnostic.Column > 0 {
			return
		}
	}
	t.Fatalf("missing original position for port diagnostic: %+v", report.Diagnostics)
}

func TestPrepareFileRefreshesOnlyRequestedAsset(t *testing.T) {
	var first, second, routed atomic.Int32
	content := atomic.Value{}
	content.Store("before.test\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/first":
			first.Add(1)
			_, _ = fmt.Fprint(w, content.Load().(string))
		case "/second":
			second.Add(1)
			_, _ = fmt.Fprintln(w, "unchanged.test")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	input, snapshot, state := filepath.Join(dir, "profile.yaml"), filepath.Join(dir, "snapshot.json"), filepath.Join(dir, "state.json")
	raw := fmt.Sprintf(`
proxy-providers:
  file-nodes: {type: file, path: nodes.yaml}
proxy-groups:
  - {name: Choice, type: select, use: [file-nodes]}
rule-providers:
  first: {type: http, behavior: domain, format: text, url: %s/first, proxy: Choice}
  second: {type: http, behavior: domain, format: text, url: %s/second}
rules:
  - RULE-SET,first,REJECT
  - RULE-SET,second,Choice
  - MATCH,DIRECT
`, server.URL, server.URL)
	write := func(path, text string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(input, raw)
	nodePath := filepath.Join(dir, "nodes.yaml")
	write(nodePath, "proxies: [{name: First node, type: direct}]")
	options := PrepareOptions{
		ProviderDirectory: dir,
		OutputState:       state,
		ClientFor: func(name string) (*http.Client, error) {
			if name != "Choice" {
				return nil, fmt.Errorf("unexpected route %q", name)
			}
			routed.Add(1)
			return server.Client(), nil
		},
	}
	materialize := func() *Bundle {
		t.Helper()
		if err := PrepareFileWithOptions(t.Context(), input, snapshot, dir, options); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		return bundle
	}
	old := materialize()
	for _, asset := range old.Summary.Resources {
		if asset.Name == "first" {
			options.RefreshAsset = asset.ID
		}
		if asset.Name == "file-nodes" && len(asset.Members) != 1 {
			t.Fatalf("provider members not in summary: %+v", asset)
		}
	}
	if options.RefreshAsset == "" || first.Load() != 1 || second.Load() != 1 || routed.Load() != 1 {
		t.Fatalf("unexpected initial resource requests: %d %d %d", first.Load(), second.Load(), routed.Load())
	}
	options.PreviousState = state
	content.Store("after.test\n")
	if err := os.Remove(nodePath); err != nil {
		t.Fatal(err)
	}
	updated := materialize()
	eff, err := updated.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if result := eff.Router.Route(context.Background(), router.Metadata{Domain: "after.test", Network: "tcp"}, nil); result.Outbound != "reject" {
		t.Fatalf("updated rule did not activate: %+v", result)
	}
	if first.Load() != 2 || second.Load() != 1 || routed.Load() != 2 {
		t.Fatalf("unrelated resource refreshed: %d %d %d", first.Load(), second.Load(), routed.Load())
	}
}

func TestNativeGeodataUsesDownloadedDigestAndSchedulesRefresh(t *testing.T) {
	data, err := os.ReadFile("../../testdata/rules/geosite.dat")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write(data)
	}))
	defer server.Close()
	raw := fmt.Sprintf(`
schema-version: 1
geodata:
  - id: geosite
    format: dat
    download: {url: %q, interval: 300, automatic: true}
rules:
  - {match: {geosite: test}, outbound: reject}
  - {match: {all: true}, outbound: direct}
`, server.URL)
	dir := t.TempDir()
	input, output := filepath.Join(dir, "source.yaml"), filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(input, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := PrepareFileWithOptions(t.Context(), input, output, dir, PrepareOptions{RefreshAsset: "geodata/geosite"}); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Summary.Resources) != 1 || !bundle.Summary.Resources[0].Automatic ||
		bundle.Summary.Resources[0].NextMS <= bundle.Summary.Resources[0].UpdatedMS {
		t.Fatalf("missing resource schedule: %+v", bundle.Summary)
	}
	eff, err := bundle.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if got := eff.Router.Route(t.Context(), router.Metadata{Domain: "x.suffix.test"}, nil); got.Outbound != "reject" {
		t.Fatalf("downloaded geosite did not match: %+v", got)
	}
}

func TestOfflineArchiveReusesResourcesAndResolvesCurrentCredentials(t *testing.T) {
	var fetches atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		_, _ = w.Write([]byte("archive.example.test\n"))
	}))
	defer server.Close()
	raw := fmt.Sprintf(`
schema-version: 1
outbounds:
  - {id: fixture, type: shadowsocks, server: 127.0.0.1, port: 2525, method: aes-128-gcm, password: 'secret://test/fixture'}
rule-sets:
  - id: sites
    behavior: domain
    format: text
    download: {url: %q, interval: 300}
rules: [{match: {rule-set: sites}, outbound: reject}, {match: {all: true}, outbound: direct}]
`, server.URL)

	dir := t.TempDir()
	input, original, rebound := filepath.Join(dir, "source.yaml"), filepath.Join(dir, "original.json"), filepath.Join(dir, "restored.json")
	if err := os.WriteFile(input, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := secret.NewFileStore(filepath.Join(dir, "secrets"), nil)
	if err != nil {
		t.Fatal(err)
	}
	const password = "local-fixture-value"
	if err := store.Set("test/fixture", password); err != nil {
		t.Fatal(err)
	}
	opts := PrepareOptions{Secrets: store, Scenes: []SceneDefinition{{ID: "local"}}}
	if err := PrepareFileWithOptions(t.Context(), input, original, dir, opts); err != nil {
		var validation *ValidationError
		if errors.As(err, &validation) {
			t.Fatal(validation.Diagnostics)
		}
		t.Fatal(err)
	}
	saved, err := os.ReadFile(original)
	if err != nil || strings.Contains(string(saved), password) {
		t.Fatal("snapshot must only retain the credential reference", err)
	}
	server.Close()
	opts.RebindSnapshot = original
	opts.Scenes = []SceneDefinition{{ID: "restored"}}
	if err := store.Delete("test/fixture"); err != nil {
		t.Fatal(err)
	}
	if err := PrepareFileWithOptions(t.Context(), input, rebound, dir, opts); err == nil {
		t.Fatal("restored snapshot bypassed missing credential")
	}
	if err := store.Set("test/fixture", "rotated-test-value"); err != nil {
		t.Fatal(err)
	}
	if err := PrepareFileWithOptions(t.Context(), input, rebound, dir, opts); err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(rebound)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Decode(bytes)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := bundle.CompileWithSecrets(store)
	if err != nil || len(effective.NetworkScenes) != 1 || effective.NetworkScenes[0].ID != "restored" {
		t.Fatal("restored local scenes are invalid", err)
	}
	if match := effective.Router.Route(t.Context(), router.Metadata{Domain: "archive.example.test"}, nil); match.Outbound != "reject" {
		t.Fatal("archived rule asset did not match", match)
	}
	if fetches.Load() != 1 {
		t.Fatalf("archive rebind fetched the rule provider %d times", fetches.Load())
	}
}

func TestControlsChooseGlobalTarget(t *testing.T) {
	links := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@first.example.test:443?security=tls#First\n" +
		"trojan://test-only@second.example.test:443?sni=second.example.test#Second\n"
	bundle, err := prepare(t.Context(), []byte(links), nil)
	if err != nil {
		t.Fatal(err)
	}
	summary := bundle.Summary
	group := summary.Groups[0]
	if summary.Global != group.ID {
		t.Fatalf("default global target = %q, want the first group %q", summary.Global, group.ID)
	}
	base, err := bundle.Compile()
	if err != nil {
		t.Fatal(err)
	}
	route := func(global string) string {
		t.Helper()
		config, err := ApplyControls(base, summary, Controls{Mode: "global", Global: global,
			Selections: map[string]string{group.ID: group.Members[0]}})
		if err != nil {
			t.Fatal(err)
		}
		return config.RoutingRouter().Route(t.Context(), router.Metadata{Domain: "example.test", Network: "tcp"}, nil).Outbound
	}
	if got := route(group.Members[1]); got != group.Members[1] {
		t.Fatalf("chosen global target routed to %q, want %q", got, group.Members[1])
	}
	if got := route("direct"); got != "direct" {
		t.Fatalf("direct global target routed to %q", got)
	}
	if got := route("missing"); got != group.Members[0] {
		t.Fatalf("unknown global target routed to %q, want the group's selection %q", got, group.Members[0])
	}
}
