package profile

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/internal/secret"
)

func TestPrepareLocalLink(t *testing.T) {
	accept := false
	link := &LocalLink{
		WireGuard: []LocalWireGuardLink{{Outbound: "home-wg", Routes: []string{"10.0.0.0/24"}}},
		Tailscale: &LocalTailscale{ID: "home", AuthKeySecret: "link/tailscale/home/auth-key", AcceptRoutes: &accept, Routes: []string{"10.1.0.0/24"}},
	}
	store, err := secret.NewFileStore(filepath.Join(t.TempDir(), "secrets"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("link/tailscale/home/auth-key", "test-auth-key"); err != nil {
		t.Fatal(err)
	}
	bundle, _ := prepareSourceFixture(t, "schema-version: 1\n", PrepareOptions{Link: link, Secrets: store})
	if strings.Contains(string(bundle.Local), "test-auth-key") {
		t.Fatalf("auth key reached the snapshot: %s", bundle.Local)
	}
	settings, _, diagnostics := model.ParseLocal(bundle.Local)
	if diagnostics.HasErrors() || settings.Link == nil {
		t.Fatalf("local settings = %s, diagnostics %v", bundle.Local, diagnostics)
	}
	if wg := settings.Link.WireGuard; len(wg) != 1 || wg[0].Outbound != "home-wg" || len(wg[0].Routes) != 1 {
		t.Fatalf("WireGuard link = %+v", wg)
	}
	ts := settings.Link.Tailscale
	if len(ts) != 1 || ts[0].ID != "home" || ts[0].AuthKey != secret.Ref("link/tailscale/home/auth-key") ||
		ts[0].AcceptRoutes == nil || *ts[0].AcceptRoutes || len(ts[0].Routes) != 1 {
		t.Fatalf("Tailscale link = %+v", ts)
	}

	// An empty link adds nothing, and a WireGuard entry without routes
	// inherits the outbound's allowed IPs.
	empty, _ := prepareSourceFixture(t, "schema-version: 1\n", PrepareOptions{Link: &LocalLink{}})
	if empty.Local != nil {
		t.Fatalf("empty link generated %s", empty.Local)
	}
	inherit, _ := prepareSourceFixture(t, "schema-version: 1\n", PrepareOptions{Link: &LocalLink{WireGuard: []LocalWireGuardLink{{Outbound: "home-wg"}}}})
	var document struct {
		Link struct {
			WireGuard []map[string]json.RawMessage `json:"wireguard"`
		} `json:"link"`
	}
	if json.Unmarshal(inherit.Local, &document) != nil || len(document.Link.WireGuard) != 1 || document.Link.WireGuard[0]["routes"] != nil {
		t.Fatalf("inherited routes were not omitted: %s", inherit.Local)
	}

	for _, name := range []string{"mitm/ca", "bad name", "tailscale/home/auth-key"} {
		if _, err := localSettings(nil, nil, &LocalLink{Tailscale: &LocalTailscale{ID: "home", AuthKeySecret: name}}); err == nil {
			t.Fatalf("auth key secret %q was accepted", name)
		}
	}
}

func TestPrepareLocalSettings(t *testing.T) {
	scenes := []SceneDefinition{{ID: "home", Interface: "en0"}}
	for _, tc := range []struct {
		name   string
		scenes []SceneDefinition
		mitm   *LocalMITM
	}{
		{name: "neither"},
		{name: "scenes", scenes: scenes},
		{name: "mitm", mitm: &LocalMITM{Enabled: true}},
		{name: "both", scenes: scenes, mitm: &LocalMITM{Enabled: false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle, _ := prepareSourceFixture(t, "schema-version: 1\n", PrepareOptions{Scenes: tc.scenes, MITM: tc.mitm})
			if tc.scenes == nil && tc.mitm == nil {
				if bundle.Local != nil {
					t.Fatalf("empty local settings generated %s", bundle.Local)
				}
				return
			}
			settings, _, diagnostics := model.ParseLocal(bundle.Local)
			if diagnostics.HasErrors() || len(settings.NetworkScenes) != len(tc.scenes) {
				t.Fatalf("local settings = %s, diagnostics %v", bundle.Local, diagnostics)
			}
			if tc.mitm == nil {
				if settings.MITM != nil {
					t.Fatalf("unexpected MITM setting in %s", bundle.Local)
				}
				return
			}
			if settings.MITM == nil || settings.MITM.Enabled != tc.mitm.Enabled || settings.MITM.CA != secret.Ref(ca.SecretName) {
				t.Fatalf("MITM setting = %s", bundle.Local)
			}
			var document struct {
				MITM map[string]json.RawMessage `json:"mitm"`
			}
			if json.Unmarshal(bundle.Local, &document) != nil || len(document.MITM["enabled"]) == 0 {
				t.Fatalf("MITM switch was omitted from %s", bundle.Local)
			}
		})
	}
}
