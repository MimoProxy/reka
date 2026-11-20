package api

import "time"

type InstallManagedResourceRequest struct {
	BaseRevision uint64 `json:"base_revision"`
	Kind         string `json:"kind"`
	ID           string `json:"id"`
	URL          string `json:"url"`
	Format       string `json:"format"`
	Behavior     string `json:"behavior,omitempty"`
	Interval     int    `json:"interval,omitempty"`
	Automatic    bool   `json:"automatic"`
}

type RefreshManagedResourceRequest struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Wait bool   `json:"wait"`
}

type ManagedResourceStatus struct {
	Kind        string    `json:"kind"`
	ID          string    `json:"id"`
	Format      string    `json:"format"`
	Behavior    string    `json:"behavior,omitempty"`
	Automatic   bool      `json:"automatic"`
	Hash        string    `json:"hash"`
	Revision    uint64    `json:"revision"`
	State       string    `json:"state"`
	ErrorCode   string    `json:"error_code,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	NextAttempt time.Time `json:"next_attempt,omitempty"`
}

type StageResourceRequest struct {
	ProfileID string `json:"profile_id,omitempty"`
	Hash      string `json:"hash"`
	Size      int    `json:"size"`
	Offset    int    `json:"offset"`
	Data      []byte `json:"data"`
}

type StageResourceResult struct {
	Hash     string `json:"hash"`
	Size     int    `json:"size"`
	Received int    `json:"received"`
	Ready    bool   `json:"ready"`
}

type ExportManifestRequest struct {
	BaseRevision uint64 `json:"base_revision"`
	Reveal       bool   `json:"reveal"`
}

type ExportResource struct {
	Hash string `json:"hash"`
	Size int    `json:"size"`
}

// ExportManifest contains one consistent revision, without expanded runtime
// state. Resources can include credential-bearing original provider bodies.
type ExportManifest struct {
	SchemaVersion int              `json:"schema_version"`
	Revision      uint64           `json:"revision"`
	Profile       string           `json:"profile"`
	Local         string           `json:"local"`
	Sources       string           `json:"sources"`
	Overlay       string           `json:"overlay"`
	Masked        int              `json:"masked"`
	Resources     []ExportResource `json:"resources"`
}

type ReadResourceRequest struct {
	ArchiveHash  string `json:"archive_hash,omitempty"`
	BaseRevision uint64 `json:"base_revision"`
	Hash         string `json:"hash"`
	Offset       int    `json:"offset"`
	Limit        int    `json:"limit"`
	Reveal       bool   `json:"reveal"`
}

type ReadResourceResult struct {
	Revision uint64 `json:"revision"`
	Hash     string `json:"hash"`
	Offset   int    `json:"offset"`
	Size     int    `json:"size"`
	Data     []byte `json:"data"`
	EOF      bool   `json:"eof"`
}

type ProfileArchiveManifest struct {
	Revision    uint64           `json:"revision"`
	ArchiveHash string           `json:"archive_hash"`
	Resources   []ExportResource `json:"resources"`
}
