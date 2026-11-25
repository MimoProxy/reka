package api

import (
	"encoding/json"
	"time"
)

// MITMStatus reports the active configuration and runtime counters.
type MITMStatus struct {
	Enabled              bool             `json:"enabled"`
	CALoaded             bool             `json:"ca_loaded"`
	CAError              string           `json:"ca_error,omitempty"`
	H2                   string           `json:"h2"`
	HostnameCount        int              `json:"hostname_count"`
	PinningBypasses      []MITMBypassInfo `json:"pinning_bypasses"`
	Connections          uint64           `json:"connections_total"` // TLS MITM connections.
	Requests             uint64           `json:"requests_total"`    // Requests on TLS MITM connections.
	PlainHTTPConnections uint64           `json:"plain_http_connections_total"`
	PlainHTTPRequests    uint64           `json:"plain_http_requests_total"`
	Scripts              MITMScriptStatus `json:"scripts"`
}

type MITMBypassInfo struct {
	Hostname  string    `json:"hostname"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MITMScriptStatus reports the active table and engine-wide counters.
type MITMScriptStatus struct {
	Status               string           `json:"status"`
	Count                int              `json:"count"`
	Runs                 uint64           `json:"runs"`
	Modified             uint64           `json:"modified"`
	Failed               uint64           `json:"failed"`
	Timeouts             uint64           `json:"timeouts"`
	Oversize             uint64           `json:"oversize"`
	CircuitOpen          uint64           `json:"circuit_open"`
	LowMemory            uint64           `json:"low_memory"`
	Notifications        uint64           `json:"notifications"`
	NotificationsDropped uint64           `json:"notifications_dropped"`
	Items                []MITMScriptItem `json:"items,omitempty"`
}

// MITMScriptItem reports the definition and most recent activity for a script.
type MITMScriptItem struct {
	ID             string    `json:"id"`
	Module         string    `json:"module,omitempty"`
	Name           string    `json:"name,omitempty"`
	Type           string    `json:"type"`
	Runs           uint64    `json:"runs"`    // Matches that reached the engine.
	Matches        uint64    `json:"matches"` // Includes skipped matches.
	LastResult     string    `json:"last_result,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	LastDurationMS int64     `json:"last_duration_ms"`
	LastAt         time.Time `json:"last_at,omitempty"`
}

type MITMScriptRun struct {
	ID         string `json:"id"`
	Phase      string `json:"phase"`
	DurationMS int64  `json:"duration_ms"`
	Result     string `json:"result"`
	Error      string `json:"error,omitempty"`
}

type MITMScriptStats struct {
	ID         string `json:"id"`
	Count      uint64 `json:"count"`
	LastResult string `json:"last_result"`
}

type ScriptNotification struct {
	ScriptID string          `json:"script_id"`
	Module   string          `json:"module,omitempty"`
	Title    string          `json:"title"`
	Subtitle string          `json:"subtitle"`
	Body     string          `json:"body"`
	Options  json.RawMessage `json:"options,omitempty"`
	Time     time.Time       `json:"time"`
}
