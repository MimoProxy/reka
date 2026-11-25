package sagernet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
	N "github.com/sagernet/sing/common/network"
)

type packetFlowReleaseKey struct{}
type connectionAttemptKey struct{}

type connectionAttempt struct {
	store             *history.Store
	releasePacketFlow func() bool // Reports whether the flow was evicted.
	mu                sync.Mutex
	api.ConnectionTrace
	events   []connectionEvent
	up, down rateCounter
}

func withAttempt(ctx context.Context, attempt *connectionAttempt) context.Context {
	if attempt != nil {
		ctx = history.WithFlow(ctx, attempt.ID)
	}
	return context.WithValue(ctx, connectionAttemptKey{}, attempt)
}

func attemptFromContext(ctx context.Context) *connectionAttempt {
	attempt, _ := ctx.Value(connectionAttemptKey{}).(*connectionAttempt)
	// Detached DNS refreshes clear the flow ID while retaining other values.
	if attempt != nil && history.Flow(ctx) == attempt.ID {
		return attempt
	}
	return nil
}

func (b *Backend) beginConnection(ctx context.Context, md Metadata) *connectionAttempt {
	return b.beginConnectionAt(ctx, md, time.Now())
}

func (b *Backend) beginConnectionAt(ctx context.Context, md Metadata, start time.Time) *connectionAttempt {
	c := api.Connection{
		ID: b.conns.next.Add(1), Start: start, Inbound: md.Inbound, Network: md.Network,
		Destination: md.Destination.String(), FlowInfo: api.FlowInfo{RuleIndex: -1},
	}
	if md.Source.IsValid() {
		c.Source = md.Source.String()
	}
	release, _ := ctx.Value(packetFlowReleaseKey{}).(func() bool)
	attempt := &connectionAttempt{
		store: b.history, releasePacketFlow: release, ConnectionTrace: api.ConnectionTrace{Connection: c},
		up: rateCounter{start: c.Start}, down: rateCounter{start: c.Start},
	}
	if b.historyScope != nil {
		attempt.Scope = b.historyScope()
	}
	kind := eventAccepted
	if md.Network == N.NetworkUDP {
		kind = eventUDPFirst
	}
	attempt.mu.Lock()
	attempt.appendEventLocked(connectionEvent{kind: kind, code: md.InboundType})
	attempt.mu.Unlock()
	return attempt
}

func (a *connectionAttempt) routing(start time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.EndedAt.IsZero() {
		a.RouteStartedAt = start.UTC()
	}
}

func (a *connectionAttempt) setRoute(rt Route, originalAddr netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.EndedAt.IsZero() {
		return
	}
	a.RoutedAt = time.Now().UTC()
	if rt.Scope.Generation != 0 {
		a.Scope = rt.Scope
	}
	var lookup *api.RuleLookupInfo
	if info, ok := rt.Info.(*api.FlowInfo); ok {
		a.FlowInfo = *info
		lookup = info.RuleLookup
		a.FlowInfo.RuleLookup = nil
		a.FlowInfo.Rule = history.Text(info.Rule, connectionRuleBytes)
		a.FlowInfo.ProcessPath = history.Text(info.ProcessPath, 512)
		a.FlowInfo.Chain = make([]string, min(32, len(info.Chain)))
		for i := range a.FlowInfo.Chain {
			a.FlowInfo.Chain[i] = history.Text(info.Chain[i], connectionLabelBytes)
		}
		a.Outbound = info.Outbound
	} else if rt.Outbound != nil {
		a.Outbound = rt.Outbound.Tag()
	}
	a.DialDestination = a.Destination
	if rt.Destination != nil {
		a.DialDestination = rt.Destination.String()
	}
	if a.DestinationDomain != "" && originalAddr.IsValid() {
		event := connectionEvent{kind: eventFakeIP, name: a.DestinationDomain, addr: originalAddr.String()}
		if lookup != nil {
			// The mapped domain was recovered before the timed rule lookup.
			a.appendEventAtLocked(lookup.StartedAt, event)
		} else {
			a.appendEventLocked(event)
		}
	}
	if lookup != nil {
		a.ruleLookupEventsLocked(lookup)
	}
	matched := connectionEvent{kind: eventMatched, n: [2]int32{int32(a.RuleIndex)}, nCount: 1}
	if a.RuleSource == "temporary" {
		matched.code = a.RuleSource
	}
	if a.RuleIndex >= 0 || matched.code != "" {
		matched.name = a.Rule
	}
	a.appendEventLocked(matched)
	if len(a.Chain) != 0 {
		a.appendEventLocked(connectionEvent{kind: eventPath, name: a.Outbound})
	}
	if rt.Outbound == nil {
		reason := a.RejectReason
		if reason == "" {
			reason = "reject"
		}
		a.appendEventLocked(connectionEvent{kind: eventRejected, code: reason})
	}
}

func (a *connectionAttempt) ruleLookupEventsLocked(lookup *api.RuleLookupInfo) {
	a.appendEventAtLocked(lookup.StartedAt, connectionEvent{kind: eventRuleLookup, name: lookup.Rule})
	addresses := lookup.Addresses
	failed := lookup.Err != nil || !addresses.IPv4.IsValid() && !addresses.IPv6.IsValid()
	code := lookup.Source
	if failed {
		code = "error"
	}
	a.appendEventAtLocked(lookup.FinishedAt, connectionEvent{
		kind: eventDNS, name: lookup.Domain, code: code,
		n: [2]int32{int32(addresses.Counts[0]), int32(addresses.Counts[1])}, nCount: 2,
		duration: lookup.FinishedAt.Sub(lookup.StartedAt), hasDuration: true,
	})
	if failed {
		return
	}
	event := connectionEvent{kind: eventRuleAddr}
	if addresses.IPv4.IsValid() {
		event.addr = addresses.IPv4.String()
	}
	if addresses.IPv6.IsValid() {
		event.name = addresses.IPv6.String()
	}
	a.appendEventAtLocked(lookup.FinishedAt, event)
}

func (a *connectionAttempt) serverDNS(domain, source string, counts [2]int, duration time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.appendEventLocked(connectionEvent{
		kind: eventServerDNS, name: domain, code: source,
		n: [2]int32{int32(counts[0]), int32(counts[1])}, nCount: 2,
		duration: duration, hasDuration: true,
	})
}

func (a *connectionAttempt) sniffing(start time.Time, md Metadata, observed sniffObservation) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.EndedAt.IsZero() {
		return
	}
	finished := time.Now()
	a.SniffStartedAt, a.SniffFinishedAt = start.UTC(), finished.UTC()
	a.SniffedDomain, a.Protocol = md.SniffedDomain, md.Protocol
	if observed != (sniffObservation{}) {
		a.appendEventLocked(connectionEvent{
			kind: eventSniffed, code: observed.protocol, name: observed.domain,
			duration: finished.Sub(start), hasDuration: true,
		})
	}
}

func (a *connectionAttempt) dialing(start time.Time, out *Outbound) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.EndedAt.IsZero() {
		a.DialStartedAt = start.UTC()
		a.appendEventAtLocked(start, connectionEvent{kind: eventDial, name: out.Tag(), code: out.Type()})
	}
}

func (a *connectionAttempt) dialed(start, finished time.Time, err error, observed socketDialResult, direct bool) *int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.EndedAt.IsZero() {
		return nil
	}
	a.DialFinishedAt = finished.UTC()
	elapsed := finished.Sub(start)
	ms := elapsed.Milliseconds()
	a.DialMS = &ms
	event := connectionEvent{kind: eventReady, duration: elapsed, hasDuration: true}
	if err != nil {
		event.kind, event.code = eventDialFail, connectionReason(err, "error")
	} else {
		now := a.DialFinishedAt
		if !a.MITM || a.ReadyAt == nil {
			a.ReadyAt = &now
		}
		a.socketEventsLocked(observed, direct)
		event.addr = a.ServerAddr
	}
	a.appendEventAtLocked(finished, event)
	return &ms
}

func (a *connectionAttempt) socketEventsLocked(observed socketDialResult, direct bool) {
	if observed.muxCode != "" {
		a.appendEventAtLocked(observed.muxAt, connectionEvent{kind: eventMux, code: observed.muxCode})
	}
	if observed.local.IsValid() {
		a.LocalAddr = observed.local.String()
		a.Interface = observed.interfaceName
	}
	if observed.server.IsValid() {
		a.ServerAddr = observed.server.String()
		if a.Network == N.NetworkTCP {
			a.DialPeer = a.ServerAddr
		}
		if direct {
			a.TargetIP = observed.server.Addr().String()
		}
	}
	if !observed.connect.finished.IsZero() {
		a.appendEventAtLocked(observed.connect.started, connectionEvent{kind: eventConnect})
		a.appendEventAtLocked(observed.connect.finished, connectionEvent{
			kind: eventConnected, duration: observed.connect.finished.Sub(observed.connect.started), hasDuration: observed.tcp,
		})
	}
	for _, tls := range observed.tls {
		a.appendEventAtLocked(tls.finished, tls.event)
	}
}

func (a *connectionAttempt) recordMITMUpstreamProtocol(protocol string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.EndedAt.IsZero() && !slices.Contains(a.MITMUpstreamProtocols, protocol) {
		a.MITMUpstreamProtocols = append(a.MITMUpstreamProtocols, protocol)
	}
}

func (a *connectionAttempt) setMITMPassthrough(reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.EndedAt.IsZero() {
		a.MITMSkipped = reason
	}
}

func (a *connectionAttempt) mitmInfoLocked() api.MITMConnectionInfo {
	info := a.MITMConnectionInfo
	info.MITMMatchedIDs = slices.Clone(info.MITMMatchedIDs)
	info.MITMScripts = slices.Clone(info.MITMScripts)
	info.MITMUpstreamProtocols = slices.Clone(info.MITMUpstreamProtocols)
	return info
}

func (a *connectionAttempt) activeInfo() (string, api.MITMConnectionInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()
	info := a.mitmInfoLocked()
	if a.EndedAt.IsZero() {
		if a.ReadyAt == nil {
			return "connecting", info
		}
		return "active", info
	}
	return "", info
}

func (a *connectionAttempt) complete(reason, stage string) {
	if a.releasePacketFlow != nil && a.releasePacketFlow() {
		reason, stage = "evicted", ""
	}
	a.mu.Lock()
	if !a.EndedAt.IsZero() {
		a.mu.Unlock()
		return
	}
	a.appendEventLocked(connectionEvent{kind: eventClosed, code: reason, name: stage})
	a.EndedAt = time.Now().UTC()
	a.DurationMS = time.Since(a.Start).Milliseconds()
	a.copyTraffic(&a.ConnectionTrace)
	a.CloseReason, a.ErrorStage = reason, stage
	if a.store == nil {
		a.mu.Unlock()
		return
	}
	trace := a.snapshotLocked()
	a.mu.Unlock()
	a.store.RecordFlow(history.Connections, trace.Scope, trace.Start, trace.ID, connectionHistoryTrace(trace), nil)
}

func (a *connectionAttempt) trace() api.ConnectionTrace {
	a.mu.Lock()
	defer a.mu.Unlock()
	trace := a.snapshotLocked()
	if trace.EndedAt.IsZero() {
		a.copyTraffic(&trace)
		trace.DurationMS = time.Since(trace.Start).Milliseconds()
	}
	return trace
}

func (a *connectionAttempt) copyTraffic(trace *api.ConnectionTrace) {
	trace.PeakUpBPS, trace.PeakDownBPS = a.up.Peak(), a.down.Peak()
	trace.Upload, trace.Download = a.up.Load(), a.down.Load()
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
