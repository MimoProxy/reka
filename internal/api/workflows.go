package api

import (
	"encoding/json"
	"time"

	"github.com/MimoProxy/reka/internal/history"
)

type ConnectionTrace struct {
	history.Scope
	Connection
	SniffStartedAt  time.Time  `json:"sniff_started_at,omitzero"`
	SniffFinishedAt time.Time  `json:"sniff_finished_at,omitzero"`
	RoutedAt        time.Time  `json:"routed_at,omitzero"`
	DialStartedAt   time.Time  `json:"dial_started_at,omitzero"`
	DialFinishedAt  time.Time  `json:"dial_finished_at,omitzero"`
	DialDestination string     `json:"dial_destination,omitempty"`
	DialPeer        string     `json:"dial_peer,omitempty"`
	TargetIP        string     `json:"target_ip,omitempty"`
	ReadyAt         *time.Time `json:"ready_at,omitempty"`
	EndedAt         time.Time  `json:"ended_at,omitzero"`
	DurationMS      int64      `json:"duration_ms"`
	DialMS          *int64     `json:"dial_ms,omitempty"`
	CloseReason     string     `json:"close_reason,omitempty"`
	ErrorStage      string     `json:"error_stage,omitempty"`
}

type TimelineRequest struct {
	ID    uint64 `json:"id"`
	Epoch string `json:"epoch,omitempty"`
}

type TimelineEvent struct {
	Stage  string          `json:"stage"`
	At     time.Time       `json:"at"`
	Cursor string          `json:"cursor,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

type ConnectionTimeline struct {
	Epoch     string          `json:"epoch"`
	Live      bool            `json:"live"`
	Truncated bool            `json:"truncated,omitempty"`
	Trace     ConnectionTrace `json:"connection"`
	Events    []TimelineEvent `json:"events"`
}
