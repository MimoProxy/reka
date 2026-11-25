package profile

import (
	"encoding/json"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/moduleacquire"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/subscription"
)

const moduleSnapshotVersion = 1

// Allow Base64 encoding of the shared 32 MiB download limit and leave room
// for the source lock, arguments, and HTTP validators.
const maxModuleSnapshotBytes = 2 * moduleacquire.MaxBundleSize

// ModuleSnapshot is an app-owned JSON file. Source is a sources document
// entry. Resources contains Base64 blobs named by SHA-256, including the
// module text at source.lock.root. Entries holds HTTP validators and check
// times keyed by "root" or moduleacquire.EntryKey. Arguments and Interval
// record the settings used to acquire this version for comparison on refresh.
type ModuleSnapshot struct {
	Version      int                           `json:"version"`
	Source       moduleacquire.Snapshot        `json:"source"`
	Resources    map[string][]byte             `json:"resources"`
	Entries      map[string]subscription.Entry `json:"entries"`
	Arguments    map[string]string             `json:"arguments,omitempty"`
	Interval     int                           `json:"interval,omitempty"`
	NextCheckMS  int64                         `json:"nextCheckMs,omitempty"`
	ScriptErrors []moduleacquire.ScriptError   `json:"scriptErrors,omitempty"`
}

type moduleResourceKey struct{ kind, value string }

// LoadModuleSnapshot reads and verifies the resource lock and its blobs.
func LoadModuleSnapshot(path string) (*ModuleSnapshot, error) {
	data, err := moduleacquire.ReadFile(path, maxModuleSnapshotBytes)
	if err != nil {
		return nil, err
	}
	var snapshot ModuleSnapshot
	if json.Unmarshal(data, &snapshot) != nil || !snapshot.valid() {
		return nil, &subscription.Error{Code: "module_snapshot_invalid"}
	}
	return &snapshot, nil
}

func (s *ModuleSnapshot) valid() bool {
	source := s.Source
	if s.Version != moduleSnapshotVersion || source.ID == "" ||
		!model.ValidModuleFormat(source.Module.Format) || !resource.ValidHash(source.Module.Request) ||
		len(source.Lock.Resources) > model.MaxModuleResources+model.MaxModuleScripts ||
		len(s.ScriptErrors) > model.MaxModuleScripts {
		return false
	}
	limits := map[string]int{source.Lock.Root: model.MaxDocumentSize}
	requests, ids := make(map[moduleResourceKey]bool), make(map[moduleResourceKey]bool)
	counts := make(map[string]int)
	total := len(s.Resources[source.Lock.Root])
	for _, lock := range source.Lock.Resources {
		request, id := moduleResourceKey{lock.Kind, lock.Request}, moduleResourceKey{lock.Kind, lock.ID}
		if len(lock.ID) != 24 || !strings.HasPrefix(lock.Request, lock.ID) ||
			!resource.ValidHash(lock.Request) || requests[request] || ids[id] {
			return false
		}
		requests[request], ids[id] = true, true
		counts[lock.Kind]++
		var limit int
		switch lock.Kind {
		case "map-local":
			limit = httprewrite.MaxMapLocalSize
		case "script":
			limit = model.MaxScriptSize
		default:
			return false
		}
		if previous, exists := limits[lock.Hash]; exists {
			limit = min(limit, previous)
		}
		limits[lock.Hash] = limit
		total += len(s.Resources[lock.Hash])
	}
	if counts["map-local"] > model.MaxModuleResources || counts["script"] > model.MaxModuleScripts ||
		len(s.Resources) != len(limits) || total > moduleacquire.MaxBundleSize {
		return false
	}
	for hash, limit := range limits {
		data := s.Resources[hash]
		if len(data) == 0 || len(data) > limit || resource.Hash(data) != hash {
			return false
		}
	}
	return true
}

func (s *ModuleSnapshot) source() model.Source {
	return model.Source{ID: s.Source.ID, Module: &s.Source.Module, Lock: &s.Source.Lock}
}

func (s *ModuleSnapshot) matches(def model.Module) bool {
	return s.Source.ID == def.ID && moduleacquire.Matches(def, s.source())
}

func (s *ModuleSnapshot) readRoot() []byte {
	return s.Resources[s.Source.Lock.Root]
}

func (s *ModuleSnapshot) resourceResolver() func(string, string) (string, bool) {
	locked := make(map[moduleResourceKey]string, len(s.Source.Lock.Resources))
	for _, lock := range s.Source.Lock.Resources {
		locked[moduleResourceKey{lock.Kind, lock.Request}] = lock.Hash
	}
	return func(kind, url string) (string, bool) {
		hash, ok := locked[moduleResourceKey{kind, resource.Hash([]byte(url))}]
		return hash, ok
	}
}
