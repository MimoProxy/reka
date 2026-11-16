package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/resource"
)

// ExportProfileArchive snapshots independent history for privilege migration.
// The archive and its historic blobs are readable only with this capability,
// an explicit reveal flag, and the unchanged active revision/profile context.
func (s *Service) ExportProfileArchive(req api.ExportManifestRequest) (api.ProfileArchiveManifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := api.ProfileArchiveManifest{Revision: s.active}
	if !req.Reveal {
		return result, errf(CodeBlocked, "history archives contain credentials; reveal is required")
	}
	if req.BaseRevision != 0 && req.BaseRevision != s.active {
		return result, errf(CodeConflict, "configuration revision changed")
	}
	active, err := s.store.ReadActive()
	if err != nil || active == nil {
		return result, errf(CodeInvalid, "active profile is unavailable")
	}
	encodedActive, _ := json.Marshal(active)
	archive := api.ProfileArchive{Version: 1, Active: encodedActive, Subscriptions: map[string]json.RawMessage{}}
	refs := map[string]bool{}
	inputBytes := 0
	numbers, err := s.store.RevisionNumbers()
	if err != nil {
		return result, err
	}
	for _, number := range numbers {
		if number > s.active {
			continue
		}
		meta, p, l, err := s.store.ReadRevision(number)
		if err != nil {
			return result, err
		}
		ss, oo, err := s.store.ReadLayers(number)
		if err != nil {
			return result, err
		}
		inputBytes += len(p) + len(l) + len(ss) + len(oo)
		if inputBytes > 96<<20 || len(archive.Revisions) >= 2000 {
			return result, errf(CodeBlocked, "profile history exceeds migration archive limit")
		}
		raw, _ := json.Marshal(meta)
		archive.Revisions = append(archive.Revisions, api.ProfileArchiveRevision{Meta: raw, Profile: string(p), Local: string(l), Sources: string(ss), Overlay: string(oo)})
		hashes, err := exportReferences(p, ss, oo)
		if err != nil {
			return result, err
		}
		for _, hash := range hashes {
			refs[hash] = true
		}
	}
	operations, err := s.store.ListOperations()
	if err != nil {
		return result, err
	}
	if len(operations) > 10000 {
		return result, errf(CodeBlocked, "profile operation history exceeds migration limit")
	}
	for _, op := range operations {
		if op.Revision > s.active {
			continue
		}
		raw, _ := json.Marshal(op)
		inputBytes += len(raw)
		archive.Operations = append(archive.Operations, raw)
	}
	entries, err := os.ReadDir(filepath.Join(s.store.Root(), "subscriptions"))
	if err != nil && !os.IsNotExist(err) {
		return result, err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := entry.Name()[:len(entry.Name())-5]
		if !profileIDPattern.MatchString(id) {
			return result, errf(CodeInvalid, "invalid subscription cache identity")
		}
		raw, err := os.ReadFile(filepath.Join(s.store.Root(), "subscriptions", entry.Name()))
		if err != nil {
			return result, err
		}
		if len(raw) > 2<<20 || !json.Valid(raw) {
			return result, errf(CodeInvalid, "invalid subscription cache")
		}
		inputBytes += len(raw)
		archive.Subscriptions[id] = raw
	}
	if inputBytes > 96<<20 || len(archive.Subscriptions) > 1024 || len(refs) > 4096 {
		return result, errf(CodeBlocked, "profile history exceeds migration archive limit")
	}
	data, err := json.Marshal(archive)
	if err != nil {
		return result, err
	}
	blobs := resource.At(s.store.Root())
	hash, err := blobs.Put(data)
	if err != nil {
		return result, fmt.Errorf("history archive exceeds 128 MiB or cannot be saved: %w", err)
	}
	result.ArchiveHash = hash
	refs[hash] = true
	names := make([]string, 0, len(refs))
	for hash := range refs {
		names = append(names, hash)
	}
	sort.Strings(names)
	total := 0
	for _, hash := range names {
		body, err := blobs.Read(hash)
		if err != nil {
			return result, err
		}
		total += len(body)
		if total > 512<<20 {
			return result, errf(CodeBlocked, "profile migration resources exceed 512 MiB")
		}
		result.Resources = append(result.Resources, api.ExportResource{Hash: hash, Size: len(body)})
	}
	s.profileArchives = map[string]map[string]bool{result.ArchiveHash: refs}
	return result, nil
}
