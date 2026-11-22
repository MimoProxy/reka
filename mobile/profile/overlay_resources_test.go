package profile

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/MimoProxy/reka/internal/router"
)

func prepareWithOverlay(t *testing.T, raw, overlay string) *Bundle {
	t.Helper()
	var options PrepareOptions
	if err := json.Unmarshal([]byte(`{"overlay":`+overlay+`}`), &options); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "source.yaml"), filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(input, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := PrepareFileWithOptions(t.Context(), input, output, dir, options); err != nil {
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
	return bundle
}

func ruleSetServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/first":
			_, _ = w.Write([]byte("first.example.test\n"))
		case "/second":
			_, _ = w.Write([]byte("second.example.test\n"))
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func assertRoute(t *testing.T, bundle *Bundle, domain, outbound string) {
	t.Helper()
	eff, err := bundle.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if got := eff.Router.Route(t.Context(), router.Metadata{Domain: domain}, nil); got.Outbound != outbound {
		t.Fatalf("%s routed to %q, want %q", domain, got.Outbound, outbound)
	}
}

func TestPrepareOverlayDownloadsInsertedRuleSet(t *testing.T) {
	server := ruleSetServer(t)
	const raw = `
schema-version: 1
rules:
  - {id: final, match: {all: true}, outbound: direct}
`
	overlay := fmt.Sprintf(`{"schema-version":1,"patches":[
		{"op":"insert","path":"/rule-sets","value":{"id":"blocked","behavior":"domain","format":"text","download":{"url":%q,"interval":3600,"automatic":true}}},
		{"op":"insert","path":"/rules","before":"final","value":{"id":"block","match":{"rule-set":"blocked"},"outbound":"reject"}}
	]}`, server.URL+"/first")
	bundle := prepareWithOverlay(t, raw, overlay)
	for _, status := range bundle.Summary.Patches {
		if !status.Applied {
			t.Fatalf("patch %d not applied: %s", status.Index, status.Reason)
		}
	}
	assertRoute(t, bundle, "first.example.test", "reject")
	assertRoute(t, bundle, "other.example.test", "direct")
	found := false
	for _, asset := range bundle.Summary.Resources {
		if asset.ID == "rule-sets/blocked" {
			found = asset.Source == "http" && asset.Automatic
		}
	}
	if !found {
		t.Fatalf("inserted rule set is not listed as a downloaded resource: %+v", bundle.Summary.Resources)
	}
}

func TestPrepareOverlayDownloadsChangedRuleSetURL(t *testing.T) {
	server := ruleSetServer(t)
	raw := fmt.Sprintf(`
schema-version: 1
rule-sets:
  - {id: blocked, behavior: domain, format: text, download: {url: %q, interval: 3600}}
rules:
  - {id: block, match: {rule-set: blocked}, outbound: reject}
  - {id: final, match: {all: true}, outbound: direct}
`, server.URL+"/first")
	overlay := fmt.Sprintf(`{"schema-version":1,"patches":[
		{"op":"set","path":"/rule-sets/blocked/download","value":{"url":%q,"interval":3600}}
	]}`, server.URL+"/second")
	bundle := prepareWithOverlay(t, raw, overlay)
	assertRoute(t, bundle, "second.example.test", "reject")
	assertRoute(t, bundle, "first.example.test", "direct")
}
