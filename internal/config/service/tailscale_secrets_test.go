package service

import (
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/store"
)

func TestTailscaleAuthKeyInConfigurationAndExport(t *testing.T) {
	const key = "inline-auth-key"
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// The document paths work without starting the runtime or the local node.
	s := &Service{store: st, active: 1, profile: []byte(DefaultProfile),
		local: []byte("link: {tailscale: [{id: home, auth-key: " + key + "}]}\n")}
	cfg := s.GetConfiguration(false)
	export, err := s.ExportManifest(api.ExportManifestRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range []struct {
		local  string
		masked int
	}{
		{cfg.Local, cfg.Masked}, {export.Local, export.Masked},
	} {
		if result.masked != 1 || strings.Contains(result.local, key) || !strings.Contains(result.local, model.Mask) {
			t.Fatal("Tailscale auth key was not masked")
		}
	}
	update := cfg.Local + "log: {level: warn}\n"
	_, local, _, _, err := s.candidate(ChangeRequest{Local: &update})
	if err != nil || !strings.Contains(string(local), key) || strings.Contains(string(local), model.Mask) {
		t.Fatal("a masked Tailscale auth key did not survive the update", err)
	}
}
