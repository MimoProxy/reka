package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLayerIntegrityAndLegacyRevision(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rev, err := s.WriteRevision(Revision{Number: 1}, []byte("profile"), []byte("local"), []byte("sources"), []byte("overlay"))
	if err != nil {
		t.Fatal(err)
	}
	if rev.Sources != Hash([]byte("sources")) || rev.Overlay != Hash([]byte("overlay")) {
		t.Fatal("missing hashes")
	}
	if _, _, _, err = s.ReadRevision(1); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(s.revDir(1), "sources.yaml"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = s.ReadRevision(1); err == nil {
		t.Fatal("tampered layer accepted")
	}
	// Recreate the original layout: no layer hashes or files.
	rev.Sources, rev.Overlay = "", ""
	b, _ := json.Marshal(rev)
	if err = os.WriteFile(filepath.Join(s.revDir(1), "meta.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sources.yaml", "overlay.yaml"} {
		if err = os.Remove(filepath.Join(s.revDir(1), name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err = s.ReadRevision(1); err != nil {
		t.Fatal("legacy revision:", err)
	}
	sources, overlay, err := s.ReadLayers(1)
	if err != nil || len(sources) != 0 || len(overlay) != 0 {
		t.Fatal("legacy layers", err)
	}
}
