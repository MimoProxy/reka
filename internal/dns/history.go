package dns

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/MimoProxy/reka/internal/history"
	D "github.com/miekg/dns"
)

type upstreamHistory struct {
	Endpoint  string `json:"endpoint"`
	Transport string `json:"transport"`
	Outbound  string `json:"outbound,omitempty"`
}

type resolutionHistory struct {
	ResultSource    string           `json:"result_source,omitempty"`
	Upstream        *upstreamHistory `json:"upstream,omitempty"`
	Fallback        bool             `json:"fallback,omitempty"`
	Coalesced       bool             `json:"coalesced,omitempty"`
	UpstreamQueryID uint64           `json:"upstream_query_id,omitempty"`
}

type recordHistory struct {
	history.Scope
	resolutionHistory
	ID           uint64    `json:"id"`
	ConnectionID uint64    `json:"connection_id,omitempty"`
	ParentID     uint64    `json:"parent_id,omitempty"`
	Start        time.Time `json:"start"`
	DurationMS   int64     `json:"duration_ms"`
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Origin       string    `json:"origin"`
	Network      string    `json:"network,omitempty"`
	Client       string    `json:"client,omitempty"`
	Requested    string    `json:"requested_server,omitempty"`
	Resolver     string    `json:"scope"`
	RCode        *int      `json:"rcode,omitempty"`
	Answers      []rrView  `json:"answers,omitempty"`
	Truncated    bool      `json:"truncated,omitempty"`
	Error        string    `json:"error,omitempty"`
}

type rrView struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

var queryID atomic.Uint64

// SetHistoryScope is called before the containing configuration is published.
func (s *Service) SetHistoryScope(scope history.Scope) { s.historyScope = scope }

func (s *Service) record(ctx context.Context, id, parent uint64, start time.Time, scope string, q, m *D.Msg, outcome resolutionHistory, err error) {
	if s.opts.History == nil || len(q.Question) != 1 {
		return
	}
	origin := history.Origin(ctx)
	if origin.Kind == "" {
		origin.Kind = "resolver"
	}
	r := recordHistory{Scope: s.historyScope, resolutionHistory: outcome, ID: id, ParentID: parent,
		ConnectionID: history.Flow(ctx), Start: start.UTC(), DurationMS: time.Since(start).Milliseconds(),
		Name: history.Text(q.Question[0].Name, 255), Type: displayType(q.Question[0].Qtype),
		Origin: origin.Kind, Network: origin.Network, Client: origin.Client, Requested: origin.Requested, Resolver: scope}
	if outcome.ResultSource == "" && err != nil {
		r.ResultSource = "error"
	}
	if m != nil {
		rcode := m.Rcode
		r.RCode = &rcode
		r.Truncated = m.Truncated || len(m.Answer) > 16
		for _, answer := range m.Answer[:min(16, len(m.Answer))] {
			h := answer.Header()
			data := strings.TrimPrefix(answer.String(), h.String())
			r.Truncated = r.Truncated || len(data) > 192
			r.Answers = append(r.Answers, rrView{history.Text(h.Name, 255), displayType(h.Rrtype), h.Ttl, history.Text(data, 192)})
		}
	}
	if err != nil {
		var nerr net.Error
		switch {
		case errors.Is(err, context.Canceled):
			r.Error = "cancelled"
		case errors.Is(err, context.DeadlineExceeded), errors.As(err, &nerr) && nerr.Timeout():
			r.Error = "timeout"
		default:
			r.Error = "resolution_failed"
		}
	}
	s.opts.History.Record(history.DNS, s.historyScope, start, r, nil)
}

func displayType(typ uint16) string {
	if name := D.TypeToString[typ]; name != "" {
		return name
	}
	return "TYPE" + strconv.FormatUint(uint64(typ), 10)
}

type upstreamKey struct{}

// ReportUpstream is called by transports after the actual route or protocol is
// determined. The attempt context is private to a single racing worker.
func ReportUpstream(ctx context.Context, outbound, transport string) {
	if selected, ok := ctx.Value(upstreamKey{}).(*upstreamHistory); ok {
		if outbound != "" {
			selected.Outbound = history.Text(outbound, 128)
		}
		if transport != "" {
			selected.Transport = transport
		}
	}
}

func attemptContext(ctx context.Context, endpoint Endpoint) (context.Context, *upstreamHistory) {
	upstream := &upstreamHistory{Endpoint: history.Text(net.JoinHostPort(endpoint.Host, endpoint.Port), 300),
		Transport: endpoint.Scheme, Outbound: history.Text(endpoint.Via, 128)}
	return context.WithValue(ctx, upstreamKey{}, upstream), upstream
}
