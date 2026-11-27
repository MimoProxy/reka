package api

import (
	"time"

	"github.com/MimoProxy/reka/internal/history"
)

// ScriptLogEntry is one finished script run in the script history: an HTTP
// script that ran for a request, or a cron, generic or event script.
type ScriptLogEntry struct {
	history.Scope
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Module string `json:"module,omitempty"`
	// Type is http-request, http-response, cron, generic or event.
	Type    string `json:"type"`
	Trigger string `json:"trigger,omitempty"`
	Event   string `json:"event,omitempty"`
	// RunID links a background run to its logs and value in the entry's detail.
	RunID        uint64    `json:"run_id,omitempty"`
	Method       string    `json:"method,omitempty"`
	URL          string    `json:"url,omitempty"`
	RequestID    uint64    `json:"request_id,omitempty"`
	ConnectionID uint64    `json:"connection_id,omitempty"`
	StartedAt    time.Time `json:"started_at"`
	DurationMS   int64     `json:"duration_ms"`
	Result       string    `json:"result"`
	Error        string    `json:"error,omitempty"`
}
