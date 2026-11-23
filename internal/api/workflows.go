package api

import (
	"encoding/json"
	"time"

	"github.com/MimoProxy/reka/internal/history"
)

// ConnEvent is one step in a connection's life. T is microseconds since
// the connection started. Fields are optional and depend on Kind.
type ConnEvent struct {
	T    int64    `json:"t"`
	Kind string   `json:"k"`
	Code string   `json:"code,omitempty"`
	Name string   `json:"name,omitempty"`
	Addr string   `json:"addr,omitempty"`
	Peer string   `json:"peer,omitempty"`
	Path []string `json:"path,omitempty"`
	MS   *float64 `json:"ms,omitempty"` // Elapsed milliseconds rounded to a tenth.
	N    []int    `json:"n,omitempty"`
}

type ConnectionTrace struct {
	history.Scope
	Connection
	SniffStartedAt  time.Time   `json:"sniff_started_at,omitzero"`
	SniffFinishedAt time.Time   `json:"sniff_finished_at,omitzero"`
	RouteStartedAt  time.Time   `json:"route_started_at,omitzero"`
	RoutedAt        time.Time   `json:"routed_at,omitzero"`
	DialStartedAt   time.Time   `json:"dial_started_at,omitzero"`
	DialFinishedAt  time.Time   `json:"dial_finished_at,omitzero"`
	DialDestination string      `json:"dial_destination,omitempty"`
	DialPeer        string      `json:"dial_peer,omitempty"`
	TargetIP        string      `json:"target_ip,omitempty"`
	ServerAddr      string      `json:"server_addr,omitempty"`
	LocalAddr       string      `json:"local_addr,omitempty"`
	Interface       string      `json:"interface,omitempty"`
	ReadyAt         *time.Time  `json:"ready_at,omitempty"`
	EndedAt         time.Time   `json:"ended_at,omitzero"`
	DurationMS      int64       `json:"duration_ms"`
	PeakUpBPS       int64       `json:"peak_up_bps,omitempty"`
	PeakDownBPS     int64       `json:"peak_down_bps,omitempty"`
	DialMS          *int64      `json:"dial_ms,omitempty"`
	CloseReason     string      `json:"close_reason,omitempty"`
	ErrorStage      string      `json:"error_stage,omitempty"`
	Events          []ConnEvent `json:"events,omitempty"`
	EventsDropped   int         `json:"events_dropped,omitempty"`
}

func (trace *ConnectionTrace) UnmarshalJSON(data []byte) error {
	type connectionTraceJSON ConnectionTrace
	if err := json.Unmarshal(data, (*connectionTraceJSON)(trace)); err != nil {
		return err
	}
	// Large history rows may store the route path once in Chain.
	for i := range trace.Events {
		event := &trace.Events[i]
		if event.Kind == "path" && event.Path == nil {
			event.Path = trace.Chain
		}
	}
	return nil
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

type TrafficBudgetStatus struct {
	SourceID       string     `json:"source_id"`
	State          string     `json:"state"`
	Stale          bool       `json:"stale"`
	ObservedAt     time.Time  `json:"observed_at,omitzero"`
	TotalBytes     *uint64    `json:"total_bytes,omitempty"`
	UsedBytes      *uint64    `json:"used_bytes,omitempty"`
	RemainingBytes *uint64    `json:"remaining_bytes,omitempty"`
	ReserveBytes   uint64     `json:"reserve_bytes"`
	SpendableBytes *uint64    `json:"spendable_bytes,omitempty"`
	EndsAt         *time.Time `json:"ends_at,omitempty"`
	EndReason      string     `json:"end_reason,omitempty"`
	DaysRemaining  *uint64    `json:"days_remaining,omitempty"`
	DailyBytes     *uint64    `json:"daily_bytes,omitempty"`
	WarnPercent    int        `json:"warn_remaining_percent"`
}
