package service

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
)

const maxExportResources = 1024
const maxExportBytes = 128 << 20

// ExportManifest snapshots documents and immutable referenced blobs under one
// revision. A caller must retry the backup if a later ReadResource conflicts.
func (s *Service) ExportManifest(req api.ExportManifestRequest) (api.ExportManifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := api.ExportManifest{SchemaVersion: model.SchemaVersion, Revision: s.active, Resources: []api.ExportResource{}}
	if req.BaseRevision != 0 && req.BaseRevision != s.active {
		return result, errf(CodeConflict, "configuration revision changed")
	}
	refs, err := exportReferences(s.profile, s.sources, s.overlay)
	if err != nil {
		return result, err
	}
	var total int
	for _, hash := range refs {
		data, err := resource.At(s.store.Root()).Read(hash)
		if err != nil {
			return result, errf(CodeInvalid, "a referenced resource is missing or corrupt")
		}
		total += len(data)
		if total > maxExportBytes {
			return result, errf(CodeBlocked, "export resources exceed 128 MiB")
		}
		result.Resources = append(result.Resources, api.ExportResource{Hash: hash, Size: len(data)})
	}
	for _, item := range []struct {
		name string
		data []byte
		dest *string
	}{
		{model.DocProfile, s.profile, &result.Profile}, {model.DocLocal, s.local, &result.Local},
		{model.DocSources, s.sources, &result.Sources}, {model.DocOverlay, s.overlay, &result.Overlay},
	} {
		*item.dest = string(item.data)
		if !req.Reveal {
			doc, ds := model.LoadDoc(item.name, item.data)
			if ds.HasErrors() {
				return result, errf(CodeInvalid, "cannot safely mask an invalid export document")
			}
			if n := doc.MaskSecrets(); n > 0 {
				*item.dest = string(doc.Bytes())
				result.Masked += n
			}
		}
	}
	// The control protocol caps each frame at 16 MiB. Leave room for its reply
	// envelope and fail clearly instead of returning a truncated backup.
	wire, err := json.Marshal(result)
	if err != nil {
		return result, err
	}
	if len(wire) > 15<<20 {
		return result, errf(CodeBlocked, "export manifest exceeds the bounded control frame")
	}
	return result, nil
}

// ReadResource never accepts a path. It requires explicit permission to reveal
// original provider bodies, which may include credentials even if the native
// source document is masked. The authenticated control owner's active revision
// is the complete export allowlist; staged orphan blobs are not downloadable.
func (s *Service) ReadResource(req api.ReadResourceRequest) (api.ReadResourceResult, error) {
	result := api.ReadResourceResult{Hash: req.Hash, Offset: req.Offset, Data: []byte{}}
	if !req.Reveal {
		return result, errf(CodeBlocked, "resource bodies can contain credentials; explicit reveal is required")
	}
	if req.BaseRevision == 0 || !resource.ValidHash(req.Hash) || req.Offset < 0 || req.Limit < 0 || req.Limit > 1<<20 {
		return result, errf(CodeBadRequest, "revision, resource hash, nonnegative offset and chunk limit up to 1 MiB are required")
	}
	if req.Limit == 0 {
		req.Limit = 1 << 20
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result.Revision = s.active
	if req.BaseRevision != s.active {
		return result, errf(CodeConflict, "configuration revision changed")
	}
	refs, err := exportReferences(s.profile, s.sources, s.overlay)
	if err != nil {
		return result, err
	}
	if !containsExportHash(refs, req.Hash) {
		return result, errf(CodeNotFound, "resource is not referenced by the active configuration")
	}
	data, err := resource.At(s.store.Root()).Read(req.Hash)
	if err != nil {
		return result, errf(CodeInvalid, "referenced resource is missing or corrupt")
	}
	result.Size = len(data)
	if req.Offset > len(data) {
		return result, errf(CodeBadRequest, "resource offset exceeds its size")
	}
	end := min(len(data), req.Offset+req.Limit)
	result.Data = append(result.Data, data[req.Offset:end]...)
	result.EOF = end == len(data)
	return result, nil
}

func containsExportHash(refs []string, hash string) bool {
	index := sort.SearchStrings(refs, hash)
	return index < len(refs) && refs[index] == hash
}

func exportReferences(profile, sources, overlay []byte) ([]string, error) {
	refs := make(map[string]bool)
	add := func(hash string) error {
		if hash == "" {
			return nil
		}
		if !resource.ValidHash(hash) {
			return errf(CodeInvalid, "configuration contains an invalid resource reference")
		}
		refs[hash] = true
		if len(refs) > maxExportResources {
			return errf(CodeBlocked, "export contains more than 1024 resources")
		}
		return nil
	}
	p, _, pd := model.ParseProfile(profile)
	ss, _, sd := model.ParseSources(sources)
	o, _, od := model.ParseOverlay(overlay)
	if pd.HasErrors() || sd.HasErrors() || od.HasErrors() {
		return nil, errf(CodeInvalid, "cannot determine resource references from invalid documents")
	}
	for _, rs := range p.RuleSets {
		if err := add(rs.Hash); err != nil {
			return nil, err
		}
	}
	for _, src := range ss.Sources {
		for _, rs := range src.RuleSets {
			if err := add(rs.Hash); err != nil {
				return nil, err
			}
		}
		if src.Lock != nil {
			if err := add(src.Lock.Root); err != nil {
				return nil, err
			}
			for _, lock := range src.Lock.Resources {
				if err := add(lock.Hash); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, patch := range o.Patches {
		if patch.Op != "set" && patch.Op != "insert" {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(patch.Path, "/"), "/")
		if len(parts) == 0 || parts[0] != "rule-sets" {
			continue
		}
		if len(parts) == 3 && parts[2] == "hash" {
			var hash string
			if json.Unmarshal(patch.Value, &hash) != nil {
				return nil, errf(CodeInvalid, "invalid overlay resource reference")
			}
			if err := add(hash); err != nil {
				return nil, err
			}
		} else if len(parts) <= 2 {
			var single struct {
				Hash string `json:"hash"`
			}
			var list []struct {
				Hash string `json:"hash"`
			}
			if json.Unmarshal(patch.Value, &single) == nil {
				if err := add(single.Hash); err != nil {
					return nil, err
				}
			} else if json.Unmarshal(patch.Value, &list) == nil {
				for _, item := range list {
					if err := add(item.Hash); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	result := make([]string, 0, len(refs))
	for hash := range refs {
		result = append(result, hash)
	}
	sort.Strings(result)
	return result, nil
}
