package api

import "time"

type ProcessTrafficRow struct {
	ID                string  `json:"id"`
	ProcessPath       string  `json:"process_path,omitempty"`
	ProcessUID        *uint32 `json:"process_uid,omitempty"`
	Unknown           bool    `json:"unknown,omitempty"`
	Overflow          bool    `json:"overflow,omitempty"`
	UploadTotal       uint64  `json:"upload_total"`
	DownloadTotal     uint64  `json:"download_total"`
	ActiveConnections uint64  `json:"active_connections"`
	TotalConnections  uint64  `json:"total_connections"`
}

type ProcessTrafficPage struct {
	Epoch      string              `json:"epoch,omitempty"`
	SampledAt  time.Time           `json:"sampled_at"`
	Total      int                 `json:"total"`
	Offset     int                 `json:"offset"`
	Limit      int                 `json:"limit"`
	Mode       string              `json:"mode"`
	Supported  bool                `json:"supported"`
	MaxEntries int                 `json:"max_entries"`
	Rows       []ProcessTrafficRow `json:"rows"`
}
