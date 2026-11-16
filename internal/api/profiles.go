package api

import "encoding/json"

// Profile IDs are native stable IDs beneath a CLI-authorized workspace, never paths.
type ProfileState struct {
	Enabled        bool   `json:"enabled"`
	RuntimeID      string `json:"runtime_profile,omitempty"`
	ProfileID      string `json:"profile_id"`
	Epoch          uint64 `json:"profile_epoch"`
	Revision       uint64 `json:"revision"`
	TargetID       string `json:"target_id,omitempty"`
	TargetExists   bool   `json:"target_exists,omitempty"`
	TargetRevision uint64 `json:"target_revision,omitempty"`
}
type SwitchProfileRequest struct {
	InitialProfile  *string `json:"initial_profile,omitempty"`
	ProfileID       string  `json:"profile_id"`
	BaseProfile     string  `json:"base_profile"`
	BaseEpoch       uint64  `json:"base_epoch"`
	BaseRevision    uint64  `json:"base_revision"`
	OperationID     string  `json:"operation_id"`
	PreserveNetwork bool    `json:"preserve_network"`
}
type SwitchProfileResult struct {
	State       string `json:"state"`
	OperationID string `json:"operation_id"`
	ProfileID   string `json:"profile_id"`
	Epoch       uint64 `json:"profile_epoch"`
	Revision    uint64 `json:"revision"`
	Generation  uint64 `json:"generation,omitempty"`
	Degraded    bool   `json:"degraded,omitempty"`
	Error       *Error `json:"error,omitempty"`
}
type InstallProfileRequest struct {
	ProfileID   string `json:"profile_id"`
	ArchiveHash string `json:"archive_hash"`
}
type ProfileArchiveRevision struct {
	Meta    json.RawMessage `json:"meta"`
	Profile string          `json:"profile"`
	Local   string          `json:"local"`
	Sources string          `json:"sources"`
	Overlay string          `json:"overlay"`
}

// Archives import immutable history into an uninitialized, inactive namespace.
// Resource bodies are uploaded separately by hash; no filesystem paths cross IPC.
type ProfileArchive struct {
	Version       int                        `json:"version"`
	Active        json.RawMessage            `json:"active"`
	Revisions     []ProfileArchiveRevision   `json:"revisions"`
	Operations    []json.RawMessage          `json:"operations"`
	Subscriptions map[string]json.RawMessage `json:"subscriptions"`
}
