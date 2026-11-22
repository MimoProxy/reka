package sagernet

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
)

type packetFlowReleaseKey struct{}

type connectionAttempt struct {
	store             *history.Store
	releasePacketFlow func() bool // Reports whether the flow was evicted.
	mu                sync.Mutex
	api.ConnectionTrace
}

func (b *Backend) beginConnection(ctx context.Context, md Metadata) *connectionAttempt {
	c := api.Connection{
		ID: b.conns.next.Add(1), Start: time.Now(), Inbound: md.Inbound, Network: md.Network,
		Destination: md.Destination.String(), FlowInfo: api.FlowInfo{RuleIndex: -1},
	}
	if md.Source.IsValid() {
		c.Source = md.Source.String()
	}
	release, _ := ctx.Value(packetFlowReleaseKey{}).(func() bool)
	attempt := &connectionAttempt{store: b.history, releasePacketFlow: release, ConnectionTrace: api.ConnectionTrace{Connection: c}}
	if b.historyScope != nil {
		attempt.Scope = b.historyScope()
	}
	return attempt
}

func (a *connectionAttempt) setRoute(rt Route) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.RoutedAt = time.Now().UTC()
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

func (a *connectionAttempt) sniffing(start time.Time, md Metadata) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.EndedAt.IsZero() {
		return
	}
	a.SniffStartedAt, a.SniffFinishedAt = start.UTC(), time.Now().UTC()
	a.SniffedDomain, a.Protocol = md.SniffedDomain, md.Protocol
}

func (a *connectionAttempt) dialing(start time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.EndedAt.IsZero() {
		a.DialStartedAt = start.UTC()
	}
}

func (a *connectionAttempt) dialed(start time.Time, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.DialFinishedAt = time.Now().UTC()
	ms := time.Since(start).Milliseconds()
	a.DialMS = &ms
	if err == nil {
		now := a.DialFinishedAt
		a.ReadyAt = &now
	}
}

func (a *connectionAttempt) peer(addr net.Addr, direct bool) {
	// Some proxy streams return a synthetic destination as RemoteAddr.
	// Report IP peers only when the connection exposes a socket address.
	if remote, ok := addr.(*net.TCPAddr); ok {
		peer := remote.AddrPort()
		if peer.IsValid() {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.DialPeer = peer.String()
			if direct {
				a.TargetIP = peer.Addr().Unmap().String()
			}
		}
	}
}

func (a *connectionAttempt) complete(reason, stage string, up, down int64) {
	if a.releasePacketFlow != nil && a.releasePacketFlow() {
		reason, stage = "evicted", ""
	}
	if a.store == nil {
		return
	}
	a.mu.Lock()
	a.EndedAt = time.Now().UTC()
	a.DurationMS = time.Since(a.Start).Milliseconds()
	a.Upload, a.Download = up, down
	a.CloseReason, a.ErrorStage = reason, stage
	trace := a.ConnectionTrace
	a.mu.Unlock()
	a.store.RecordFlow(history.Connections, trace.Scope, trace.Start, trace.ID, trace, nil)
}

func (a *connectionAttempt) trace(up, down int64) api.ConnectionTrace {
	a.mu.Lock()
	defer a.mu.Unlock()
	trace := a.ConnectionTrace
	if trace.EndedAt.IsZero() {
		trace.Upload, trace.Download = up, down
		trace.DurationMS = time.Since(trace.Start).Milliseconds()
	}
	return trace
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
