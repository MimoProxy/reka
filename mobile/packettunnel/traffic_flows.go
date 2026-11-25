//go:build with_gvisor

package packettunnel

import (
	"maps"
	"slices"
	"strings"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/history"
)

const (
	// Neither sing-box nor mihomo persists these statistics or sets a cap for
	// them. Allow twice the host cap since a host usually uses one or two nodes
	// and the iOS Packet Tunnel has a memory limit of about 50 MB.
	maxTrafficFlows         = 2 * maxTrafficHosts
	defaultTrafficFlowLimit = 200
	maxTrafficFlowLimit     = 200
	// Routes are per policy and node totals across every host. They rarely
	// exceed a few dozen, and a client can take deltas of them because a
	// route only leaves the list when it is folded into Other for good.
	maxTrafficRoutes = 64

	// Each row has up to 128 bytes of JSON syntax, field names and counters.
	// With quoted label budgets of 128, 96 and 96 bytes, a flow row uses at
	// most 448 bytes and a route row (empty host) 322. The reply then needs at
	// most 200*448 + 64*322 + 263 commas + 180 bytes for the envelope and its
	// counters, or 110659 bytes (< 128 KiB).
	trafficFlowOutboundJSONBudget = 96
)

type TrafficFlowRow struct {
	Host   string `json:"host"`
	Policy string `json:"policy"`
	Node   string `json:"node,omitempty"`
	TrafficTotals
}

type TrafficFlows struct {
	SinceMS int64            `json:"sinceMs"`
	Flows   []TrafficFlowRow `json:"flows"`
	Other   TrafficTotals    `json:"other"`
	// Routes holds session totals per policy and node with an empty host.
	Routes      []TrafficFlowRow `json:"routes"`
	OtherRoutes TrafficTotals    `json:"otherRoutes"`
}

// Keep each bounded component separate since labels and digests may contain
// arbitrary bytes, including a delimiter.
type trafficFlowKey struct {
	host, policy, node string
}

type trafficFlowTable struct {
	rows  map[trafficFlowKey]TrafficFlowRow
	other TrafficTotals
}

func (t *trafficFlowTable) add(row TrafficFlowRow) {
	if t.rows == nil {
		t.rows = make(map[trafficFlowKey]TrafficFlowRow)
	}
	key := trafficFlowKey{
		host:   trafficNameKey(row.Host, maxTrafficHostName),
		policy: trafficNameKey(row.Policy, maxTrafficOutboundName),
		node:   trafficNameKey(row.Node, maxTrafficOutboundName),
	}
	entry, exists := t.rows[key]
	if !exists {
		entry.Host = strings.Clone(history.Text(row.Host, maxTrafficHostName))
		entry.Policy = strings.Clone(history.Text(row.Policy, maxTrafficOutboundName))
		entry.Node = strings.Clone(history.Text(row.Node, maxTrafficOutboundName))
	}
	// Reuse the retained strings for short keys so a lookup cannot keep a
	// larger source string alive.
	if len(row.Host) <= maxTrafficHostName {
		key.host = entry.Host
	}
	if len(row.Policy) <= maxTrafficOutboundName {
		key.policy = entry.Policy
	}
	if len(row.Node) <= maxTrafficOutboundName {
		key.node = entry.Node
	}
	entry.TrafficTotals.add(row.TrafficTotals)
	t.rows[key] = entry
}

func (t *trafficFlowTable) evictSmallest(capacity int) {
	if len(t.rows) <= capacity {
		return
	}
	var smallest trafficFlowKey
	var lowest TrafficFlowRow
	first := true
	for key, row := range t.rows {
		if first || compareTrafficFlow(key, row, smallest, lowest) > 0 {
			smallest, lowest = key, row
			first = false
		}
	}
	t.other.add(lowest.TrafficTotals)
	delete(t.rows, smallest)
}

func compareTrafficFlow(aKey trafficFlowKey, a TrafficFlowRow, bKey trafficFlowKey, b TrafficFlowRow) int {
	if order := compareTraffic(a.Host, a.TrafficTotals, b.Host, b.TrafficTotals); order != 0 {
		return order
	}
	if order := strings.Compare(a.Policy, b.Policy); order != 0 {
		return order
	}
	if order := strings.Compare(a.Node, b.Node); order != 0 {
		return order
	}
	// Distinct long labels can have identical display names. Use their keys
	// to keep the cutoff stable when those rows have equal byte totals.
	if order := strings.Compare(aKey.host, bKey.host); order != 0 {
		return order
	}
	if order := strings.Compare(aKey.policy, bKey.policy); order != 0 {
		return order
	}
	return strings.Compare(aKey.node, bKey.node)
}

func (s *Session) trafficFlows(limit int) TrafficFlows {
	if limit <= 0 {
		limit = defaultTrafficFlowLimit
	}
	limit = min(limit, maxTrafficFlowLimit)
	var flows, routes trafficFlowTable
	var sinceMS int64
	s.withTrafficConnections(func(active []sagernet.ConnInfo) {
		sinceMS = s.ranking.sinceMS
		flows = s.ranking.flows
		flows.rows = maps.Clone(flows.rows)
		routes = s.ranking.routes
		routes.rows = maps.Clone(routes.rows)
		for _, conn := range active {
			if row, ok := s.ranking.connectionTraffic(conn); ok {
				flows.add(row)
				routes.add(row.route())
			}
		}
	})
	result := TrafficFlows{SinceMS: sinceMS}
	result.Flows, result.Other = flows.top(limit)
	result.Routes, result.OtherRoutes = routes.top(maxTrafficRoutes)
	return result
}

func (r TrafficFlowRow) route() TrafficFlowRow {
	r.Host = ""
	return r
}

// top returns the largest rows, folding the rest and the table's own
// overflow into the returned totals. It leaves the table's rows unchanged.
func (t trafficFlowTable) top(limit int) ([]TrafficFlowRow, TrafficTotals) {
	keys := make([]trafficFlowKey, 0, len(t.rows))
	for key := range t.rows {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b trafficFlowKey) int {
		return compareTrafficFlow(a, t.rows[a], b, t.rows[b])
	})
	limit = min(limit, len(keys))
	rows, other := make([]TrafficFlowRow, limit), t.other
	for i, key := range keys[:limit] {
		row := t.rows[key]
		row.Host = rankingJSONName(row.Host)
		row.Policy = rankingJSONNameWithin(row.Policy, trafficFlowOutboundJSONBudget)
		row.Node = rankingJSONNameWithin(row.Node, trafficFlowOutboundJSONBudget)
		rows[i] = row
	}
	for _, key := range keys[limit:] {
		other.add(t.rows[key].TrafficTotals)
	}
	return rows, other
}
