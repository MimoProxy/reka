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

// ScriptCapture is what an HTTP script saw and what it returned. Bodies are
// previews: a client sees their full size and whether they were cut.
type ScriptCapture struct {
	Request  ScriptMessage  `json:"request"`
	Response *ScriptMessage `json:"response,omitempty"`
	Output   *ScriptOutput  `json:"output,omitempty"`
}

// ScriptMessage is an HTTP request or response as a script handled it.
type ScriptMessage struct {
	Method  string         `json:"method,omitempty"`
	URL     string         `json:"url,omitempty"`
	Status  int            `json:"status,omitempty"`
	Headers []ScriptHeader `json:"headers,omitempty"`
	Body    *ScriptBody    `json:"body,omitempty"`
}

type ScriptHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ScriptBody holds the start of a body as UTF-8 text or, for binary data, as
// standard base64.
type ScriptBody struct {
	Size      int    `json:"size"`
	Text      string `json:"text,omitempty"`
	Base64    string `json:"base64,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// ScriptOutput is a script's $done result. Action is pass, modify, respond
// or abort. Fields a script left unchanged are omitted.
type ScriptOutput struct {
	Action     string         `json:"action"`
	URL        string         `json:"url,omitempty"`
	Status     int            `json:"status,omitempty"`
	HeadersSet bool           `json:"headers_set,omitempty"`
	Headers    []ScriptHeader `json:"headers,omitempty"`
	Body       *ScriptBody    `json:"body,omitempty"`
	Response   *ScriptMessage `json:"response,omitempty"`
}
