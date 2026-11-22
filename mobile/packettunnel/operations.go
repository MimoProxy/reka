//go:build with_gvisor

package packettunnel

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/runtime/generation"
)

type Operation struct {
	Action     string               `json:"action"`
	ID         uint64               `json:"id,omitempty"`
	Member     string               `json:"member,omitempty"`
	IDs        []uint64             `json:"ids,omitempty"`
	Category   string               `json:"category,omitempty"`
	Cursor     string               `json:"cursor,omitempty"`
	Search     string               `json:"search,omitempty"`
	Offset     int                  `json:"offset,omitempty"`
	Limit      int                  `json:"limit,omitempty"`
	Target     string               `json:"target,omitempty"`
	Network    string               `json:"network,omitempty"`
	Resolve    bool                 `json:"resolve,omitempty"`
	Rule       string               `json:"rule,omitempty"`
	TTLSeconds int                  `json:"ttl_seconds,omitempty"`
	URL        string               `json:"url,omitempty"`
	URL4       string               `json:"url4,omitempty"`
	URL6       string               `json:"url6,omitempty"`
	Local4     []string             `json:"local4,omitempty"`
	Local6     []string             `json:"local6,omitempty"`
	LocalQUIC  []string             `json:"localQuic,omitempty"`
	NodeQUIC   []string             `json:"nodeQuic,omitempty"`
	TimeoutMS  int                  `json:"timeout_ms,omitempty"`
	Members    []string             `json:"members,omitempty"`
	Rounds     int                  `json:"rounds,omitempty"`
	DNS        *api.DNSQueryRequest `json:"dns,omitempty"`
}

type ConnectionRow struct {
	ID          uint64   `json:"id"`
	StartMS     int64    `json:"startMs"`
	Destination string   `json:"destination"`
	Network     string   `json:"network"`
	Rule        string   `json:"rule,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	Outbound    string   `json:"outbound"`
	Uploaded    int64    `json:"uploaded"`
	Downloaded  int64    `json:"downloaded"`
}

type Latency struct {
	Member   string `json:"member"`
	Resolved string `json:"resolved,omitempty"`
	DelayMS  *int64 `json:"delayMs,omitempty"`
	Status   int    `json:"status,omitempty"`
}

type tunnelLogHandler struct {
	events    *history.Store
	component string
}

func (h tunnelLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	// Library components log each dial at Info. Keep those messages out of the
	// extension's small ring, leaving room for lifecycle events and errors.
	if h.component != "" {
		return level >= slog.LevelWarn
	}
	return level >= slog.LevelInfo
}

func (h tunnelLogHandler) Handle(_ context.Context, record slog.Record) error {
	entry := struct {
		TimeMS    int64  `json:"timeMs"`
		Level     string `json:"level"`
		Message   string `json:"message"`
		Component string `json:"component,omitempty"`
	}{record.Time.UnixMilli(), strings.ToLower(record.Level.String()), history.Text(record.Message, 320), h.component}
	h.events.Record(history.Logs, history.Scope{}, record.Time, entry, nil)
	return nil
}

func (h tunnelLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	for _, attr := range attrs {
		if attr.Key == "component" && attr.Value.Kind() == slog.KindString {
			h.component = history.Text(attr.Value.String(), 64)
		}
	}
	return h
}

func (h tunnelLogHandler) WithGroup(string) slog.Handler { return h }

func (s *Session) Counts() (connections, dns int) {
	if s.profile != nil {
		connections = s.profile.engine.PacketFlowConnections()
	} else {
		connections = s.backend.ConnectionCount()
	}
	return connections, s.events.CountProfile(history.DNS, s.historyProfile())
}

func (s *Session) historyProfile() string {
	if s.profile == nil {
		return ""
	}
	_, scope := s.profile.engine.History()
	return scope.ProfileID
}

func (s *Session) RunOperation(op Operation) (any, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	switch op.Action {
	case "connections":
		return s.connections(), nil
	case "trafficRanking":
		return s.trafficRanking(op.Limit), nil
	case "resetTrafficRanking":
		s.resetTrafficRanking()
		return true, nil
	case "close":
		if op.ID == 0 {
			return nil, errors.New("connection ID required")
		}
		return s.closeConnection(op.ID), nil
	case "dns":
		return s.historyPage(history.DNS, op)
	case "logs":
		return s.historyPage(history.Logs, op)
	case "probe":
		return s.probe(op)
	case "ipCheck":
		if s.profile == nil {
			return nil, errors.New("the operation requires a profile")
		}
		return s.profile.engine.RunIPCheck(s.ctx, generation.IPCheckOptions{
			Member: op.Member, URL4: op.URL4, URL6: op.URL6, Local4: op.Local4, Local6: op.Local6,
			LocalQUIC: op.LocalQUIC, NodeQUIC: op.NodeQUIC, TimeoutMS: op.TimeoutMS,
		})
	default:
		return s.runDiagnostics(op)
	}
}

func (s *Session) connections() []ConnectionRow {
	if s.profile == nil {
		active := s.backend.Connections()
		rows := make([]ConnectionRow, 0, len(active))
		for _, conn := range active {
			rows = append(rows, ConnectionRow{
				ID: conn.ID, StartMS: conn.Start.UnixMilli(), Network: conn.Metadata.Network,
				Destination: conn.Metadata.Destination.String(),
				Outbound:    conn.Outbound, Uploaded: conn.Upload, Downloaded: conn.Download,
			})
		}
		sortConnectionRows(rows)
		return rows
	}
	p := s.profile
	p.mu.Lock()
	names := p.summary.Names
	p.mu.Unlock()
	active := p.engine.Connections()
	rows := make([]ConnectionRow, 0, len(active))
	for _, conn := range active {
		destination := conn.DestinationDomain
		if destination == "" {
			destination = conn.SniffedDomain
		}
		if destination == "" {
			destination = conn.Destination
		}
		target := conn.Outbound
		if len(conn.Chain) > 0 {
			target = conn.Chain[0]
		}
		targetName := connectionDisplayName(target, conn.PolicyName)
		groups := make([]string, 0, min(8, len(conn.Chain)))
		for i, id := range conn.Chain[:min(8, len(conn.Chain))] {
			name := targetName
			if i != 0 {
				name = connectionDisplayName(id, names[id])
			}
			groups = append(groups, name)
		}
		rule := conn.Rule
		if targetName != target {
			prefix, noResolve := strings.CutSuffix(rule, ",no-resolve")
			if match, ok := strings.CutSuffix(prefix, ","+target); ok {
				rule = match + "," + targetName
				if noResolve {
					rule += ",no-resolve"
				}
			}
		}
		rows = append(rows, ConnectionRow{
			ID: conn.ID, StartMS: conn.Start.UnixMilli(), Destination: history.Text(destination, 255), Network: conn.Network,
			Rule: history.Text(rule, 384), Groups: groups, Outbound: connectionDisplayName(conn.Outbound, conn.OutboundName),
			Uploaded: conn.Upload, Downloaded: conn.Download,
		})
	}
	sortConnectionRows(rows)
	return rows
}

func connectionDisplayName(id, name string) string {
	if name == "" {
		return id
	}
	return history.Text(name, 128)
}

func sortConnectionRows(rows []ConnectionRow) {
	slices.SortFunc(rows, func(a, b ConnectionRow) int {
		if byStart := cmp.Compare(b.StartMS, a.StartMS); byStart != 0 {
			return byStart
		}
		return cmp.Compare(b.ID, a.ID)
	})
}

func (s *Session) closeConnection(id uint64) bool {
	var count int
	if s.profile != nil {
		count = s.profile.engine.CloseConnections([]uint64{id})
	} else {
		count = s.backend.CloseConnections([]uint64{id})
	}
	return count > 0
}

func (s *Session) probe(op Operation) (Latency, error) {
	member := op.Member
	if s.profile == nil || member == "" || len(member) > 128 {
		return Latency{}, errors.New("probe requires a profile member")
	}
	if op.URL == "" {
		op.URL = "https://www.gstatic.com/generate_204"
	}
	result, err := s.profile.engine.ProbeOutbound(s.ctx, api.ProbeRequest{
		Outbound: member, URL: op.URL, TimeoutMS: op.TimeoutMS,
	})
	latency := Latency{Member: member, Resolved: result.ResolvedOutbound, Status: result.StatusCode}
	if err == nil {
		latency.DelayMS = &result.DelayMS
	}
	return latency, nil
}

// NetworkChanged retires sockets associated with the previous path. DNS
// answer caches are reset while fake address leases remain valid.
func (s *Session) NetworkChanged(available, changed bool) {
	if s.ctx.Err() != nil {
		return
	}
	if s.profile != nil {
		p := s.profile
		p.mu.Lock()
		defer p.mu.Unlock()
		if s.ctx.Err() != nil {
			return
		}
		p.engine.ResetNetwork()
		if changed {
			p.engine.CloseConnections(nil)
		}
	} else {
		s.outbound.CloseIdleConnections()
		if changed {
			s.backend.CloseConnections(nil)
		}
	}
	if available {
		s.logger.Info("Network available")
	} else {
		s.logger.Warn("Network unavailable")
	}
}

func (s *Session) SetNetworkInterface(name string) {
	if s.profile != nil && s.ctx.Err() == nil && len(name) <= 64 {
		s.profile.engine.SetPacketFlowInterface(name)
	}
}
