package profile

import (
	"encoding/json"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/internal/secret"
)

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
