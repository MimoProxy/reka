package api

import "time"

// MITMStatus reports the active configuration and runtime counters.
type MITMStatus struct {
	Enabled         bool             `json:"enabled"`
	CALoaded        bool             `json:"ca_loaded"`
	CAError         string           `json:"ca_error,omitempty"`
	H2              string           `json:"h2"`
	HostnameCount   int              `json:"hostname_count"`
	PinningBypasses []MITMBypassInfo `json:"pinning_bypasses"`
	Connections     uint64           `json:"connections_total"`
	Requests        uint64           `json:"requests_total"`
}

type MITMBypassInfo struct {
	Hostname  string    `json:"hostname"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}
