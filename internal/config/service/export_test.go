package service

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/resource"
)

func exportErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	var result *Error
	if !errors.As(err, &result) || result.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

func TestExportManifestAndReferencedResourceChunks(t *testing.T) {
	e := newEnv(t)
	blobs, err := resource.Open(e.root)
	if err != nil {
		t.Fatal(err)
	}
	put := func(data []byte) string {
		t.Helper()
		hash, err := blobs.Put(data)
		if err != nil {
			t.Fatal(err)
		}
		return hash
	}
	localHash := put([]byte("+.local.test\n"))
	sourceHash := put([]byte("+.source.test\n"))
	overlayHash := put([]byte("+.overlay.test\n"))
	large := bytes.Repeat([]byte("private-subscription-body\n"), 90000)
	rootHash := put(large)
	orphan := put([]byte("unreferenced staged resource"))
	s := e.open(DefaultProfile, "network: {mode: off}\n")
	defer s.Close()
	profile := fmt.Sprintf("schema-version: 1\noutbounds: [{id: private, type: socks, server: 127.0.0.1, port: 9, username: Alice, password: inline-private-password}]\nrule-sets: [{id: local, behavior: domain, format: text, hash: %s}]\nrules: [{id: final, match: {all: true}, outbound: direct}]\n", localHash)
	sources := fmt.Sprintf("sources: [{id: source, lock: {root: %s, resources: [{id: root, kind: root, hash: %s, request: %s}, {id: provider, kind: rule, name: provider, hash: %s, request: %s}]}, rule-sets: [{id: domains, behavior: domain, format: text, hash: %s}]}]\n", rootHash, rootHash, resource.Hash([]byte("root-request")), sourceHash, resource.Hash([]byte("provider-request")), sourceHash)
	overlay := fmt.Sprintf("patches: [{op: insert, path: /rule-sets, value: {id: overlay, behavior: domain, format: text, hash: %s}}]\n", overlayHash)
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Profile: &profile, Sources: &sources, Overlay: &overlay})
	manifest, err := s.ExportManifest(api.ExportManifestRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Revision != s.ActiveRevision() || manifest.SchemaVersion != 1 || len(manifest.Resources) != 4 {
		t.Fatalf("bad manifest: %+v", manifest)
	}
	if manifest.Masked == 0 || strings.Contains(manifest.Profile, "inline-private-password") {
		t.Fatal("default export exposed native credentials")
	}
	revealed, err := s.ExportManifest(api.ExportManifestRequest{BaseRevision: manifest.Revision, Reveal: true})
	if err != nil || revealed.Profile != profile || revealed.Local != "network: {mode: off}\n" || revealed.Sources != sources || revealed.Overlay != overlay {
		t.Fatalf("revealed snapshot is inconsistent: %+v %v", revealed, err)
	}
	if _, err := s.ReadResource(api.ReadResourceRequest{BaseRevision: manifest.Revision, Hash: rootHash}); err == nil {
		t.Fatal("credential-bearing original resource did not require explicit reveal")
	}
	var downloaded []byte
	for offset := 0; ; {
		chunk, err := s.ReadResource(api.ReadResourceRequest{BaseRevision: manifest.Revision, Hash: rootHash, Offset: offset, Limit: 1 << 20, Reveal: true})
		if err != nil {
			t.Fatal(err)
		}
		if chunk.Hash != rootHash || chunk.Revision != manifest.Revision || chunk.Size != len(large) || chunk.Offset != offset || len(chunk.Data) > 1<<20 {
			t.Fatalf("invalid chunk: %+v", chunk)
		}
		downloaded = append(downloaded, chunk.Data...)
		offset += len(chunk.Data)
		if chunk.EOF {
			break
		}
		if len(chunk.Data) == 0 {
			t.Fatal("nonterminal zero length chunk")
		}
	}
	if !bytes.Equal(downloaded, large) {
		t.Fatal("resource changed during export")
	}
	for _, hash := range []string{localHash, sourceHash, overlayHash} {
		if _, err := s.ReadResource(api.ReadResourceRequest{BaseRevision: manifest.Revision, Hash: hash, Reveal: true}); err != nil {
			t.Fatalf("a referenced profile/source/overlay blob was not exportable: %v", err)
		}
	}
	_, err = s.ReadResource(api.ReadResourceRequest{BaseRevision: manifest.Revision, Hash: orphan, Reveal: true})
	exportErrorCode(t, err, CodeNotFound)
	for _, req := range []api.ReadResourceRequest{
		{Hash: rootHash, Reveal: true},
		{BaseRevision: manifest.Revision, Hash: "../../secrets/private", Reveal: true},
		{BaseRevision: manifest.Revision, Hash: rootHash, Offset: -1, Reveal: true},
		{BaseRevision: manifest.Revision, Hash: rootHash, Offset: len(large) + 1, Reveal: true},
		{BaseRevision: manifest.Revision, Hash: rootHash, Limit: 1<<20 + 1, Reveal: true},
	} {
		_, err = s.ReadResource(req)
		exportErrorCode(t, err, CodeBadRequest)
	}
	local := "network: {mode: off}\nlog: {level: warn}\n"
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: manifest.Revision, Local: &local})
	_, err = s.ReadResource(api.ReadResourceRequest{BaseRevision: manifest.Revision, Hash: rootHash, Reveal: true})
	exportErrorCode(t, err, CodeConflict)
	_, err = s.ExportManifest(api.ExportManifestRequest{BaseRevision: manifest.Revision})
	exportErrorCode(t, err, CodeConflict)
}

func TestExportDoesNotReadRemovedCorruptOrSymlinkedResource(t *testing.T) {
	e := newEnv(t)
	blobs, _ := resource.Open(e.root)
	data := []byte("+.export.test\n")
	hash, err := blobs.Put(data)
	if err != nil {
		t.Fatal(err)
	}
	s := e.open(DefaultProfile, "")
	defer s.Close()
	profile := fmt.Sprintf("schema-version: 1\nrule-sets: [{id: export, behavior: domain, format: text, hash: %s}]\nrules: [{id: final, match: {all: true}, outbound: direct}]\n", hash)
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Profile: &profile})
	path := filepath.Join(e.root, "resources", "sha256", hash)
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = s.ExportManifest(api.ExportManifestRequest{Reveal: true})
	exportErrorCode(t, err, CodeInvalid)
	_, err = s.ReadResource(api.ReadResourceRequest{BaseRevision: s.ActiveRevision(), Hash: hash, Reveal: true})
	exportErrorCode(t, err, CodeInvalid)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(e.root, "original-credentials")
	if err := os.WriteFile(outside, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err == nil {
		_, err = s.ReadResource(api.ReadResourceRequest{BaseRevision: s.ActiveRevision(), Hash: hash, Reveal: true})
		exportErrorCode(t, err, CodeInvalid)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := blobs.Put(data); err != nil {
		t.Fatal(err)
	}
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Profile: ptr(DefaultProfile)})
	_, err = s.ReadResource(api.ReadResourceRequest{BaseRevision: s.ActiveRevision(), Hash: hash, Reveal: true})
	exportErrorCode(t, err, CodeNotFound)
}

func TestExportReferencesRecognizeWholeAndChildOverlayOperations(t *testing.T) {
	first := resource.Hash([]byte("first"))
	second := resource.Hash([]byte("second"))
	third := resource.Hash([]byte("third"))
	overlay := fmt.Sprintf("patches:\n - {op: set, path: /rule-sets, value: [{id: first, hash: %s}]}\n - {op: set, path: /rule-sets/source~1second, value: {id: source/second, hash: %s}}\n - {op: set, path: /rule-sets/third/hash, value: %s}\n - {op: set, path: /outbounds/not-a-resource/password, value: %s}\n", first, second, third, resource.Hash([]byte("not-a-resource")))
	refs, err := exportReferences([]byte(DefaultProfile), nil, []byte(overlay))
	if err != nil || len(refs) != 3 || !containsExportHash(refs, first) || !containsExportHash(refs, second) || !containsExportHash(refs, third) {
		t.Fatal(refs, err)
	}
}
