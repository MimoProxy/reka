package service

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
)

func TestExportAndRestoreModuleResources(t *testing.T) {
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	ctx := context.Background()
	path := filepath.Join(e.root, "rules.sgmodule")
	original := []byte("#!name=Example export\n[Rule]\nDOMAIN,ads.example.com,REJECT\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	spec := model.Module{ID: "example", File: path}
	added, err := s.AddModule(ctx, api.AddModuleRequest{Module: spec, BaseRevision: s.ActiveRevision()})
	if err != nil || added.State != "committed" {
		t.Fatalf("install: %+v %v", added, err)
	}
	originalHash := resource.Hash(original)

	// Stage a different snapshot and child resource to exercise export and
	// restore without fetching from a network listener.
	const remote = "https://cdn.example.net/replacement.txt"
	const scriptURL = "https://cdn.example.net/script.js"
	body := []byte("replacement")
	script := []byte("$done();")
	root := []byte("#!name=Example export\n[Map Local]\n^https://ads\\.example\\.com/ data-type=text data=" + remote +
		"\n[Script]\nresponse = type=http-response,pattern=example,script-path=" + scriptURL + "\n")
	blobs := resource.At(e.root)
	hash, err := blobs.Put(root)
	if err != nil {
		t.Fatal(err)
	}
	childHash, err := blobs.Put(body)
	if err != nil {
		t.Fatal(err)
	}
	scriptHash, err := blobs.Put(script)
	if err != nil {
		t.Fatal(err)
	}
	request := resource.Hash([]byte(remote))
	scriptRequest := resource.Hash([]byte(scriptURL))
	url := model.Module{ID: spec.ID, URL: "https://example.com/rules.sgmodule?token=synthetic"}
	profile := fmt.Sprintf("schema-version: 1\nmodules: [{id: %s, url: %q}]\n", url.ID, url.URL)
	snapshot := fmt.Sprintf("sources:\n - id: example\n   module: {format: surge, request: %s}\n   lock:\n     root: %s\n     resources:\n"+
		"     - {kind: map-local, id: %s, request: %s, hash: %s}\n     - {kind: script, id: %s, request: %s, hash: %s}\n",
		url.RequestHash(), hash, request[:16], request, childHash, scriptRequest[:24], scriptRequest, scriptHash)
	updated := mustLayerCommit(t, s, ChangeRequest{BaseRevision: added.Revision, Profile: &profile, Sources: &snapshot})

	manifest, err := s.ExportManifest(api.ExportManifestRequest{})
	if err != nil {
		t.Fatal(err)
	}
	bodies := map[string][]byte{hash: root, childHash: body, scriptHash: script}
	if len(manifest.Resources) != len(bodies) || manifest.Revision != updated.Revision {
		t.Fatalf("manifest: %+v", manifest)
	}
	if manifest.Masked != 1 || strings.Contains(manifest.Profile, url.URL) {
		t.Fatal("module URL was not masked in export")
	}
	for _, entry := range manifest.Resources {
		want, ok := bodies[entry.Hash]
		got, err := s.ReadResource(api.ReadResourceRequest{BaseRevision: manifest.Revision, Hash: entry.Hash, Reveal: true})
		if !ok || err != nil || !got.EOF || !bytes.Equal(got.Data, want) {
			t.Fatalf("current resource %s: %+v %v", entry.Hash, got, err)
		}
	}
	archive, err := s.ExportProfileArchive(api.ExportManifestRequest{Reveal: true})
	if err != nil {
		t.Fatal(err)
	}
	bodies[originalHash] = original
	if len(archive.Resources) != len(bodies)+1 {
		t.Fatalf("archive: %+v", archive)
	}
	for key, want := range bodies {
		got, err := s.ReadResource(api.ReadResourceRequest{BaseRevision: archive.Revision, ArchiveHash: archive.ArchiveHash, Hash: key, Reveal: true})
		if err != nil || !bytes.Equal(got.Data, want) {
			t.Fatalf("archive resource %s: %+v %v", key, got, err)
		}
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	restored, err := s.RestoreRevision(ctx, RestoreRequest{Revision: added.Revision, BaseRevision: updated.Revision})
	if err != nil || restored.State != "committed" {
		t.Fatalf("restore: %+v %v", restored, err)
	}
	manifest, err = s.ExportManifest(api.ExportManifestRequest{})
	if err != nil || len(manifest.Resources) != 1 || manifest.Resources[0].Hash != originalHash {
		t.Fatalf("restored manifest: %+v %v", manifest, err)
	}
}
