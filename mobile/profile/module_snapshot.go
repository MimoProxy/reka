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
// times keyed by "root" or source.lock.resources[].id. Arguments records the
// values used to acquire this version so hostname changes can be compared.
type ModuleSnapshot struct {
	Version     int                           `json:"version"`
	Source      moduleacquire.Snapshot        `json:"source"`
	Resources   map[string][]byte             `json:"resources"`
	Entries     map[string]subscription.Entry `json:"entries"`
	Arguments   map[string]string             `json:"arguments,omitempty"`
	NextCheckMS int64                         `json:"nextCheckMs,omitempty"`
}

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
		source.Module.Format != model.ModuleFormatSurge || !resource.ValidHash(source.Module.Request) ||
		len(source.Lock.Resources) > model.MaxModuleResources || len(s.Resources) > model.MaxModuleResources+1 {
		return false
	}
	limits := map[string]int{source.Lock.Root: model.MaxDocumentSize}
	requests, ids := make(map[string]bool), make(map[string]bool)
	total := len(s.Resources[source.Lock.Root])
	for _, lock := range source.Lock.Resources {
		if lock.Kind != "map-local" || len(lock.ID) != 24 || !strings.HasPrefix(lock.Request, lock.ID) ||
			!resource.ValidHash(lock.Request) || requests[lock.Request] || ids[lock.ID] {
			return false
		}
		requests[lock.Request], ids[lock.ID] = true, true
		limits[lock.Hash] = httprewrite.MaxMapLocalSize
		total += len(s.Resources[lock.Hash])
	}
	if len(s.Resources) != len(limits) || total > moduleacquire.MaxBundleSize {
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

func (s *ModuleSnapshot) readRoot() []byte {
	return s.Resources[s.Source.Lock.Root]
}

func (s *ModuleSnapshot) resourceResolver() func(string) (string, bool) {
	locked := make(map[string]string, len(s.Source.Lock.Resources))
	for _, lock := range s.Source.Lock.Resources {
		locked[lock.Request] = lock.Hash
	}
	return func(url string) (string, bool) {
		hash, ok := locked[resource.Hash([]byte(url))]
		return hash, ok
	}
}
