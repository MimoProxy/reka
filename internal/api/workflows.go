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

type TemporaryRuleRequest struct {
	Rule       string `json:"rule"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

type TemporaryRule struct {
	ID        string    `json:"id"`
	Rule      string    `json:"rule"`
	Outbound  string    `json:"outbound"`
	ExpiresAt time.Time `json:"expires_at"`
	Active    bool      `json:"active"`
}

type ArenaRequest struct {
	Outbounds []string `json:"outbounds"`
	URL       string   `json:"url"`
	Rounds    int      `json:"rounds,omitempty"`
	TimeoutMS int      `json:"timeout_ms,omitempty"`
}

type ArenaSample struct {
	DelayMS    int64  `json:"delay_ms,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
}

type ArenaEntry struct {
	Outbound         string        `json:"outbound"`
	ResolvedOutbound string        `json:"resolved_outbound"`
	Successes        int           `json:"successes"`
	MedianMS         int64         `json:"median_ms,omitempty"`
	SpreadMS         int64         `json:"spread_ms,omitempty"`
	Samples          []ArenaSample `json:"samples"`
}

type ArenaResult struct {
	Generation uint64       `json:"generation"`
	Revision   uint64       `json:"revision"`
	Winner     string       `json:"winner,omitempty"`
	Ranking    []ArenaEntry `json:"ranking"`
}

type NetworkSceneStatus struct {
	Current    string    `json:"current,omitempty"`
	Manual     string    `json:"manual,omitempty"`
	Scenes     []string  `json:"scenes"`
	Interface  string    `json:"interface,omitempty"`
	Addresses  []string  `json:"addresses,omitempty"`
	ObservedAt time.Time `json:"observed_at,omitzero"`
	Error      string    `json:"error,omitempty"`
}
