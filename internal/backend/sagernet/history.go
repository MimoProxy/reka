package sagernet

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
)

type connectionAttempt struct {
	store *history.Store
	history.Scope
	api.Connection
	DialDestination string     `json:"dial_destination,omitempty"`
	DialPeer        string     `json:"dial_peer,omitempty"`
	TargetIP        string     `json:"target_ip,omitempty"`
	ReadyAt         *time.Time `json:"ready_at,omitempty"`
	EndedAt         time.Time  `json:"ended_at"`
	DurationMS      int64      `json:"duration_ms"`
	DialMS          *int64     `json:"dial_ms,omitempty"`
	CloseReason     string     `json:"close_reason"`
	ErrorStage      string     `json:"error_stage,omitempty"`
}

func (b *Backend) beginConnection(md Metadata) *connectionAttempt {
	c := api.Connection{
		ID: b.conns.next.Add(1), Start: time.Now(), Inbound: md.Inbound, Network: md.Network,
		Destination: md.Destination.String(), FlowInfo: api.FlowInfo{RuleIndex: -1},
	}
	if md.Source.IsValid() {
		c.Source = md.Source.String()
	}
	attempt := &connectionAttempt{store: b.history, Connection: c}
	if b.historyScope != nil {
		attempt.Scope = b.historyScope()
	}
	return attempt
}

func (a *connectionAttempt) setRoute(rt Route) {
	if rt.Scope.Generation != 0 {
		a.Scope = rt.Scope
	}
	if info, ok := rt.Info.(*api.FlowInfo); ok {
		a.FlowInfo = *info
		a.FlowInfo.Rule = history.Text(info.Rule, 512)
		a.FlowInfo.ProcessPath = history.Text(info.ProcessPath, 512)
		a.FlowInfo.Chain = make([]string, min(32, len(info.Chain)))
		for i := range a.FlowInfo.Chain {
			a.FlowInfo.Chain[i] = history.Text(info.Chain[i], 128)
		}
		a.Outbound = info.Outbound
	} else if rt.Outbound != nil {
		a.Outbound = rt.Outbound.Tag()
	}
	a.DialDestination = a.Destination
	if rt.Destination != nil {
		a.DialDestination = rt.Destination.String()
	}
}

func (a *connectionAttempt) dialed(start time.Time, err error) {
	ms := time.Since(start).Milliseconds()
	a.DialMS = &ms
	if err == nil {
		now := time.Now().UTC()
		a.ReadyAt = &now
	}
}

func (a *connectionAttempt) peer(addr net.Addr, direct bool) {
	// Some proxy streams return a synthetic destination as RemoteAddr.
	// Report IP peers only when the connection exposes a socket address.
	if remote, ok := addr.(*net.TCPAddr); ok {
		peer := remote.AddrPort()
		if peer.IsValid() {
			a.DialPeer = peer.String()
			if direct {
				a.TargetIP = peer.Addr().Unmap().String()
			}
		}
	}
}

func (a *connectionAttempt) complete(reason, stage string, up, down int64) {
	if a.store == nil {
		return
	}
	a.EndedAt = time.Now().UTC()
	a.DurationMS = time.Since(a.Start).Milliseconds()
	a.Upload, a.Download = up, down
	a.CloseReason, a.ErrorStage = reason, stage
	a.store.Record(history.Connections, a.Scope, a.Start, a, nil)
}

func connectionReason(err error, otherwise string) string {
	var nerr net.Error
	switch {
	case err == nil:
		return otherwise
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &nerr) && nerr.Timeout():
		return "timeout"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, net.ErrClosed), errors.Is(err, io.ErrClosedPipe):
		return "closed"
	default:
		return "error"
	}
}
