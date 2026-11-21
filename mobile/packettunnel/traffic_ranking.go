//go:build with_gvisor

package packettunnel

import (
	"cmp"
	"crypto/sha256"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/router"
)

const (
	maxTrafficHosts        = 512
	maxTrafficOutbounds    = 256
	maxTrafficHostName     = 255
	maxTrafficOutboundName = 128
	defaultTrafficLimit    = 50
	maxTrafficLimit        = 200
)

type TrafficTotals struct {
	Uploaded    uint64 `json:"uploaded"`
	Downloaded  uint64 `json:"downloaded"`
	Connections uint64 `json:"connections"`
}

func (t *TrafficTotals) add(other TrafficTotals) {
	t.Uploaded += other.Uploaded
	t.Downloaded += other.Downloaded
	t.Connections += other.Connections
}

func (t TrafficTotals) bytes() uint64 { return t.Uploaded + t.Downloaded }

type TrafficRow struct {
	Name string `json:"name"`
	// Node is the final outbound of the most recently started contributing connection.
	Node string `json:"node,omitempty"`
	TrafficTotals
}

type TrafficRanking struct {
	SinceMS        int64         `json:"sinceMs"`
	Hosts          []TrafficRow  `json:"hosts"`
	Outbounds      []TrafficRow  `json:"outbounds"`
	Other          TrafficTotals `json:"other"`
	OtherOutbounds TrafficTotals `json:"otherOutbounds,omitzero"`
}

type trafficEntry struct {
	TrafficRow
	startMS int64
	lastID  uint64
}

type trafficTable struct {
	rows  map[string]trafficEntry
	other TrafficTotals
}

// The backend connection table's lock guards the live ranking. A connection
// is visible either in its active snapshot or in these completed totals.
type trafficRanking struct {
	sinceMS   int64
	hosts     trafficTable
	outbounds trafficTable
	baseline  map[uint64]TrafficTotals
}

func (r *trafficRanking) recordClosed(conn sagernet.ConnInfo) {
	r.record(conn)
	delete(r.baseline, conn.ID)
	r.hosts.evictSmallest(maxTrafficHosts)
	r.outbounds.evictSmallest(maxTrafficOutbounds)
}

func (r *trafficRanking) record(conn sagernet.ConnInfo) {
	totals := TrafficTotals{Uploaded: uint64(conn.Upload), Downloaded: uint64(conn.Download), Connections: 1}
	if base, ok := r.baseline[conn.ID]; ok {
		totals.Uploaded -= base.Uploaded
		totals.Downloaded -= base.Downloaded
		// A connection spanning a reset counts once it carries new traffic.
		if totals.Uploaded == 0 && totals.Downloaded == 0 {
			return
		}
	}
	host, policy, node := trafficLabels(conn)
	r.hosts.add(trafficEntry{TrafficRow: TrafficRow{Name: host, TrafficTotals: totals}}, maxTrafficHostName)
	r.outbounds.add(trafficEntry{
		TrafficRow: TrafficRow{Name: policy, Node: node, TrafficTotals: totals},
		startMS:    conn.Start.UnixMilli(), lastID: conn.ID,
	}, maxTrafficOutboundName)
}

func trafficLabels(conn sagernet.ConnInfo) (host, policy, node string) {
	dest := conn.Metadata.Destination
	domain, sniffed := dest.Domain, conn.Metadata.SniffedDomain
	policy, node = conn.Outbound, conn.Outbound
	if flow, ok := conn.Info.(*api.FlowInfo); ok {
		if flow.DestinationDomain != "" {
			domain = flow.DestinationDomain
		}
		if flow.SniffedDomain != "" {
			sniffed = flow.SniffedDomain
		}
		if len(flow.Chain) > 0 {
			policy = flow.Chain[0]
		}
		if flow.PolicyName != "" {
			policy = flow.PolicyName
		}
		if flow.OutboundName != "" {
			node = flow.OutboundName
		}
	}
	host = router.NormalizeDomain(domain)
	if host == "" {
		host = router.NormalizeDomain(sniffed)
	}
	if host == "" {
		host = dest.Addr.Unmap().String()
	}
	return host, policy, node
}

func (t *trafficTable) add(current trafficEntry, nameLimit int) {
	if t.rows == nil {
		t.rows = make(map[string]trafficEntry)
	}
	key := current.Name
	longName := len(key) > nameLimit
	if longName {
		// Keep distinct names separate even when their displayed prefixes match.
		digest := sha256.Sum256([]byte(key))
		key = key[:nameLimit] + string(digest[:])
	}
	entry, exists := t.rows[key]
	if !exists {
		entry.Name = strings.Clone(history.Text(current.Name, nameLimit))
	}
	entry.TrafficTotals.add(current.TrafficTotals)
	if current.Node != "" && (entry.Node == "" || current.startMS > entry.startMS ||
		current.startMS == entry.startMS && current.lastID > entry.lastID) {
		entry.startMS, entry.lastID = current.startMS, current.lastID
		if node := history.Text(current.Node, nameLimit); node != entry.Node {
			entry.Node = strings.Clone(node)
		}
	}
	if !longName {
		key = entry.Name
	}
	t.rows[key] = entry
}

// A close adds at most one name to each table. Fold the smallest entry even
// when it is the new one, so a low-traffic flow cannot displace a larger one.
func (t *trafficTable) evictSmallest(capacity int) {
	if len(t.rows) <= capacity {
		return
	}
	var smallest string
	var lowest TrafficTotals
	first := true
	for name, entry := range t.rows {
		if first || compareTraffic(name, entry.TrafficTotals, smallest, lowest) > 0 {
			smallest, lowest = name, entry.TrafficTotals
			first = false
		}
	}
	t.other.add(lowest)
	delete(t.rows, smallest)
}

func compareTraffic(aName string, a TrafficTotals, bName string, b TrafficTotals) int {
	if byBytes := cmp.Compare(b.bytes(), a.bytes()); byBytes != 0 {
		return byBytes
	}
	return strings.Compare(aName, bName)
}

func (t *trafficTable) top(capacity, limit int) []TrafficRow {
	rows := make([]TrafficRow, 0, len(t.rows))
	for _, entry := range t.rows {
		rows = append(rows, entry.TrafficRow)
	}
	slices.SortFunc(rows, func(a, b TrafficRow) int {
		return compareTraffic(a.Name, a.TrafficTotals, b.Name, b.TrafficTotals)
	})
	for _, row := range rows[min(capacity, len(rows)):] {
		t.other.add(row.TrafficTotals)
	}
	rows = rows[:min(capacity, limit, len(rows))]
	for i := range rows {
		rows[i].Name = rankingJSONName(rows[i].Name)
		rows[i].Node = rankingJSONName(rows[i].Node)
	}
	return rows
}

// Budget up to 128 JSON bytes per quoted label, including escaping. Two
// hundred rows in each list then fit in the bridge's 128 KiB response buffer
// even with a node label on every outbound and full-width counters.
func rankingJSONName(name string) string {
	remaining := 128 - 2
	for i, r := range name {
		size := utf8.RuneLen(r)
		switch {
		case r < 0x20, r == '<', r == '>', r == '&', r == '\u2028', r == '\u2029', r == utf8.RuneError:
			size = 6
		case r == '"', r == '\\':
			size = 2
		}
		remaining -= size
		if remaining < 0 {
			return history.Text(name, i)
		}
	}
	return name
}

func (s *Session) withTrafficConnections(visit func([]sagernet.ConnInfo)) {
	if s.profile != nil {
		s.profile.engine.WithPacketFlowConnections(visit)
	} else {
		s.backend.WithConnectionSnapshot(visit)
	}
}

func (s *Session) trafficRanking(limit int) TrafficRanking {
	if limit <= 0 {
		limit = defaultTrafficLimit
	}
	limit = min(limit, maxTrafficLimit)
	var snapshot trafficRanking
	s.withTrafficConnections(func(active []sagernet.ConnInfo) {
		snapshot = s.ranking
		snapshot.hosts.rows = maps.Clone(snapshot.hosts.rows)
		snapshot.outbounds.rows = maps.Clone(snapshot.outbounds.rows)
		for _, conn := range active {
			snapshot.record(conn)
		}
	})
	hosts := snapshot.hosts.top(maxTrafficHosts, limit)
	outbounds := snapshot.outbounds.top(maxTrafficOutbounds, limit)
	return TrafficRanking{SinceMS: snapshot.sinceMS, Hosts: hosts, Outbounds: outbounds,
		Other: snapshot.hosts.other, OtherOutbounds: snapshot.outbounds.other}
}

func (s *Session) resetTrafficRanking() {
	s.withTrafficConnections(func(active []sagernet.ConnInfo) {
		s.ranking = trafficRanking{sinceMS: time.Now().UnixMilli(), baseline: make(map[uint64]TrafficTotals, len(active))}
		for _, conn := range active {
			s.ranking.baseline[conn.ID] = TrafficTotals{Uploaded: uint64(conn.Upload), Downloaded: uint64(conn.Download)}
		}
	})
}
