package api

import (
	"encoding/json"
	"time"
)

type ScriptList struct {
	Status  string       `json:"status"`
	Scripts []ScriptInfo `json:"scripts"`
}

type ScriptInfo struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Module    string     `json:"module,omitempty"`
	Type      string     `json:"type"`
	Supported bool       `json:"supported"`
	CronExp   string     `json:"cronexp,omitempty"`
	EventName string     `json:"event_name,omitempty"`
	Timeout   int        `json:"timeout"`
	Argument  string     `json:"argument,omitempty"`
	Running   bool       `json:"running"`
	NextRun   *time.Time `json:"next_run,omitempty"`
	LastRun   *ScriptRun `json:"last_run,omitempty"`
}

type ScriptRun struct {
	RunID          uint64          `json:"run_id"`
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Module         string          `json:"module,omitempty"`
	Type           string          `json:"type"`
	Trigger        string          `json:"trigger"`
	Event          string          `json:"event,omitempty"`
	StartedAt      time.Time       `json:"started_at"`
	DurationMS     int64           `json:"duration_ms"`
	Result         string          `json:"result"`
	Error          string          `json:"error,omitempty"`
	Value          json.RawMessage `json:"value,omitempty"`
	ValueTruncated bool            `json:"value_truncated,omitempty"`
	Logs           []ScriptLogLine `json:"logs,omitempty"`
	LogsTruncated  bool            `json:"logs_truncated,omitempty"`
}

type ScriptLogLine struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

type RunScriptRequest struct {
	ID       string  `json:"id"`
	Argument *string `json:"argument,omitempty"`
	Wait     *bool   `json:"wait,omitempty"` // The server waits when omitted.
}

type GetScriptRunsRequest struct {
	ID    string `json:"id,omitempty"`
	Limit int    `json:"limit,omitempty"`
}
