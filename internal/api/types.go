// Package api holds the control API's wire types, framing and client.
// It does not depend on the runtime, so clients such as rekactl stay small.
package api

import (
	"time"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/platform"
)

// Error is a request error with a stable code.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// ChangeRequest describes a candidate configuration relative to a base
// revision: whole documents, patches, or both (patches apply after the
// documents).
type ChangeRequest struct {
	Import *importer.Request `json:"import,omitempty"`
	// BaseRevision is the revision the client edited. It must be the
	// active revision.
	BaseRevision uint64     `json:"base_revision"`
	Profile      *string    `json:"profile,omitempty"`
	Local        *string    `json:"local,omitempty"`
	Patch        []model.Op `json:"patch,omitempty"`
	LocalPatch   []model.Op `json:"local_patch,omitempty"`
	Sources      *string    `json:"sources,omitempty"`
	Overlay      *string    `json:"overlay,omitempty"`
	SourcesPatch []model.Op `json:"sources_patch,omitempty"`
	OverlayPatch []model.Op `json:"overlay_patch,omitempty"`
}

// CommitRequest is a ChangeRequest to activate.
type CommitRequest struct {
	ChangeRequest
	// OperationID makes the commit idempotent: retrying with the same ID
	// and content returns the first result. Generated when empty.
	OperationID string `json:"operation_id,omitempty"`
	// PlanHash, if set, must match the hash PlanConfiguration returned,
	// so the client commits exactly what it reviewed.
	PlanHash string `json:"plan_hash,omitempty"`
	Source   string `json:"source,omitempty"`
	Message  string `json:"message,omitempty"`
}

// FieldChange is one differing field between two revisions.
type FieldChange struct {
	Path string `json:"path"`
	From any    `json:"from,omitempty"`
	To   any    `json:"to,omitempty"`
}

// Conflict explains a stale base revision.
type Conflict struct {
	Base    uint64        `json:"base"`
	Active  uint64        `json:"active"`
	Changes []FieldChange `json:"changes"`
}

// Result is the outcome of a commit; it is also what GetOperation
// returns.
type Result struct {
	OperationID string            `json:"operation_id"`
	State       string            `json:"state"`
	Revision    uint64            `json:"revision,omitempty"`
	Generation  uint64            `json:"generation,omitempty"`
	NoChange    bool              `json:"no_change,omitempty"`
	Plan        *Plan             `json:"plan,omitempty"`
	Diagnostics model.Diagnostics `json:"diagnostics,omitempty"`
	Conflict    *Conflict         `json:"conflict,omitempty"`
	Error       *Error            `json:"error,omitempty"`
	Degraded    bool              `json:"degraded,omitempty"`
}

// ValidateResult is the answer to Validate.
type ValidateResult struct {
	Valid       bool              `json:"valid"`
	Diagnostics model.Diagnostics `json:"diagnostics,omitempty"`
}

// PlanResult is the answer to Plan.
type PlanResult struct {
	Base        uint64            `json:"base_revision"`
	Valid       bool              `json:"valid"`
	Plan        *Plan             `json:"plan,omitempty"`
	PlanHash    string            `json:"plan_hash,omitempty"`
	Diagnostics model.Diagnostics `json:"diagnostics,omitempty"`
	Conflict    *Conflict         `json:"conflict,omitempty"`
}

// Configuration is the answer to GetConfiguration.
type Configuration struct {
	ProfileID    string             `json:"profile_id,omitempty"`
	ProfileEpoch uint64             `json:"profile_epoch,omitempty"`
	Revision     uint64             `json:"revision"`
	Profile      string             `json:"profile"`
	Local        string             `json:"local"`
	Sources      string             `json:"sources"`
	Overlay      string             `json:"overlay"`
	Masked       int                `json:"masked,omitempty"`
	Effective    *compile.Effective `json:"effective,omitempty"`
	Diagnostics  model.Diagnostics  `json:"diagnostics,omitempty"`
	StartError   string             `json:"start_error,omitempty"`
}

// RestoreRequest restores an old revision as a new one.
type RestoreRequest struct {
	Revision     uint64 `json:"revision"`
	BaseRevision uint64 `json:"base_revision"`
	OperationID  string `json:"operation_id,omitempty"`
}

type SubscriptionStatus struct {
	Usage             *SubscriptionUsage `json:"usage,omitempty"`
	FallbackResources []string           `json:"fallback_resources,omitempty"`
	SourceID          string             `json:"source_id"`
	State             string             `json:"state"`
	Stale             bool               `json:"stale"`
	LastAttempt       time.Time          `json:"last_attempt,omitempty"`
	LastSuccess       time.Time          `json:"last_success,omitempty"`
	NextAttempt       time.Time          `json:"next_attempt,omitempty"`
	ErrorCode         string             `json:"error_code,omitempty"`
	Revision          uint64             `json:"revision,omitempty"`
	RootHash          string             `json:"root_hash,omitempty"`
}

// Event is one entry of the event stream. Seq increases by one per event
// within an epoch; a new epoch starts with every process start.
type Event struct {
	Epoch string    `json:"epoch"`
	Seq   uint64    `json:"seq"`
	Type  string    `json:"type"`
	Time  time.Time `json:"time"`
	Data  any       `json:"data,omitempty"`
	// Dropped counts events this subscriber missed because it read too
	// slowly, since the previous event it received.
	Dropped uint64 `json:"dropped,omitempty"`
}

// Change actions in a plan.
const (
	ActionKeep    = "keep"
	ActionCreate  = "create"
	ActionReplace = "replace"
	ActionRemove  = "remove"
	ActionRebind  = "rebind"
	ActionRestart = "restart"
)

// ResourceChange is one line of an impact plan.
type ResourceChange struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	// Connections is how many connections use the instance being replaced
	// or removed; they keep running on it while it drains.
	Connections int64  `json:"connections,omitempty"`
	Listen      string `json:"listen,omitempty"`
	Note        string `json:"note,omitempty"`
}

// GroupChange is a selection change.
type GroupChange struct {
	ID   string `json:"id"`
	From string `json:"from,omitempty"`
	To   string `json:"to"`
}

// Plan describes what activating a configuration changes. Nothing in it
// has happened yet.
type Plan struct {
	ProcessChanged         bool             `json:"process_changed"`
	RoutingChanged         bool             `json:"routing_changed"`
	SniffChanged           bool             `json:"sniff_changed"`
	NetworkChanged         bool             `json:"network_changed"`
	NetworkNote            string           `json:"network_note,omitempty"`
	DNSChanged             bool             `json:"dns_changed"`
	AutomaticGroupsChanged bool             `json:"automatic_groups_changed"`
	Outbounds              []ResourceChange `json:"outbounds"`
	Listeners              []ResourceChange `json:"listeners"`
	RulesChanged           bool             `json:"rules_changed"`
	Rules                  int              `json:"rules"`
	Groups                 []GroupChange    `json:"groups,omitempty"`
	LogLevel               string           `json:"log_level,omitempty"`
	// RestartRequired lists settings that only take effect after the
	// process restarts.
	RestartRequired []string `json:"restart_required,omitempty"`
	// Draining is the number of instances that will be draining after the
	// switch; Blocked is set when that exceeds the limit.
	Draining   int    `json:"draining"`
	Blocked    string `json:"blocked,omitempty"`
	Interrupts bool   `json:"interrupts,omitempty"`
}

// FlowInfo is attached to every routed connection.
type FlowInfo struct {
	RuleSource    string   `json:"rule_source,omitempty"`
	RejectReason  string   `json:"reject_reason,omitempty"`
	NetworkScene  string   `json:"network_scene,omitempty"`
	ProcessPID    uint32   `json:"process_pid,omitempty"`
	ProcessPath   string   `json:"process_path,omitempty"`
	ProcessUID    *uint32  `json:"process_uid,omitempty"`
	SniffedDomain string   `json:"sniffed_domain,omitempty"`
	Protocol      string   `json:"protocol,omitempty"`
	Generation    uint64   `json:"generation"`
	Revision      uint64   `json:"revision"`
	RuleIndex     int      `json:"rule_index"`
	RuleID        string   `json:"rule_id,omitempty"`
	Rule          string   `json:"rule,omitempty"`
	Chain         []string `json:"chain,omitempty"`
	Outbound      string   `json:"outbound"`
	Fingerprint   string   `json:"fingerprint"`

	// DestinationDomain includes names recovered from Fake IP mappings.
	DestinationDomain string `json:"destination_domain,omitempty"`

	// RuleLookup carries routing diagnostics to the connection event recorder.
	RuleLookup *RuleLookupInfo `json:"-"`

	// Display names captured from the packet-flow profile that routed this flow.
	PolicyName   string `json:"-"`
	OutboundName string `json:"-"`
}

type RuleLookupInfo struct {
	Rule, Domain, Source  string
	StartedAt, FinishedAt time.Time
	Addresses             history.DNSAddresses
	Err                   error
}

// ExplainRequest describes a hypothetical connection.
type ExplainRequest struct {
	InboundType string  `json:"inbound_type,omitempty"`
	InboundPort uint16  `json:"inbound_port,omitempty"`
	InboundUser string  `json:"inbound_user,omitempty"`
	ProcessUID  *uint32 `json:"process_uid,omitempty"`
	Inbound     string  `json:"inbound,omitempty"`
	Network     string  `json:"network,omitempty"`
	Source      string  `json:"source,omitempty"`
	// Destination is "host:port" or "address:port".
	Destination string `json:"destination"`
	// Addresses are used for ip rules instead of resolving the domain.
	Addresses []string `json:"addresses,omitempty"`
	// Resolve allows a DNS lookup when an ip rule needs one. Without it
	// the explanation stops there and says so.
	Resolve bool `json:"resolve,omitempty"`
	// Process stands in for the owning process.
	Process string `json:"process,omitempty"`
}

// Explanation is the answer to ExplainRoute.
type Explanation struct {
	RuleSource   string   `json:"rule_source,omitempty"`
	NetworkScene string   `json:"network_scene,omitempty"`
	Generation   uint64   `json:"generation"`
	Revision     uint64   `json:"revision"`
	Matched      bool     `json:"matched"`
	RuleIndex    int      `json:"rule_index"`
	RuleID       string   `json:"rule_id,omitempty"`
	Rule         string   `json:"rule,omitempty"`
	Final        bool     `json:"final,omitempty"`
	Chain        []string `json:"chain,omitempty"`
	Outbound     string   `json:"outbound,omitempty"`
	OutboundType string   `json:"outbound_type,omitempty"`
	Fingerprint  string   `json:"fingerprint,omitempty"`
	Resolved     []string `json:"resolved,omitempty"`
	ResolveError string   `json:"resolve_error,omitempty"`
	Undetermined string   `json:"undetermined,omitempty"`
}

// Connection is one active connection for listings.
type Connection struct {
	ID          uint64    `json:"id"`
	Inbound     string    `json:"inbound"`
	Network     string    `json:"network"`
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	Outbound    string    `json:"outbound"`
	Start       time.Time `json:"start"`
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	FlowInfo
	MITMConnectionInfo

	// OriginalDestination is set when the active destination was rewritten.
	OriginalDestination string `json:"original_destination,omitempty"`
	// State is used by the Packet Tunnel connection list.
	State string `json:"-"`
}

type MITMConnectionInfo struct {
	MITM                  bool              `json:"mitm,omitempty"`
	MITMRequests          uint64            `json:"mitm_requests,omitempty"`
	MITMMatchedIDs        []string          `json:"mitm_matched_ids,omitempty"`
	MITMBodyPassthroughs  uint64            `json:"mitm_body_passthroughs,omitempty"`
	MITMScripts           []MITMScriptStats `json:"mitm_scripts,omitempty"`
	MITMClientProtocol    string            `json:"mitm_client_protocol,omitempty"`
	MITMUpstreamProtocols []string          `json:"mitm_upstream_protocols,omitempty"`
}

// RuntimeStatus is a summary of the running state.
type RuntimeStatus struct {
	Network     platform.NetworkStatus `json:"network"`
	Generation  uint64                 `json:"generation"`
	Revision    uint64                 `json:"revision"`
	Connections int                    `json:"connections"`
	Outbounds   []string               `json:"outbounds"`
	Listeners   []ResourceChange       `json:"listeners"`
	Draining    int64                  `json:"draining"`
	Forced      int64                  `json:"forced_closes"`
	Retries     int64                  `json:"acquire_retries"`
}

// Status is the answer to GetStatus.
type Status struct {
	Revision   uint64        `json:"revision"`
	Runtime    RuntimeStatus `json:"runtime"`
	StartError string        `json:"start_error,omitempty"`
	Goroutines int           `json:"goroutines"`
}
