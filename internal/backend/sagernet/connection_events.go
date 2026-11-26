package sagernet

import (
	"cmp"
	"slices"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
)

const (
	initialConnectionEvents = 8
	// Match the iOS timeline limit to bound Packet Tunnel memory per flow.
	maxConnectionEvents   = 24
	firstConnectionEvents = 20
	lastConnectionEvents  = maxConnectionEvents - firstConnectionEvents
	connectionRuleBytes   = 512
	connectionLabelBytes  = 128
)

type connectionEventKind uint8

const (
	eventAccepted connectionEventKind = iota
	eventUDPFirst
	eventSniffed
	eventFakeIP
	eventDNSMapping // A real address recovered from a client DNS answer.
	eventRuleLookup
	eventDNS
	eventRuleAddr
	eventMatched
	eventPath
	eventRejected
	eventDial
	eventServerDNS
	eventConnect
	eventConnected
	eventTLS
	eventMux
	eventReady
	eventDialFail
	eventClosed
)

var connectionEventKinds = [...]string{
	eventAccepted:   "accepted",
	eventUDPFirst:   "udp_first",
	eventSniffed:    "sniffed",
	eventFakeIP:     "fakeip",
	eventDNSMapping: "dns_mapping",
	eventRuleLookup: "rule_lookup",
	eventDNS:        "dns",
	eventRuleAddr:   "rule_addr",
	eventMatched:    "matched",
	eventPath:       "path",
	eventRejected:   "rejected",
	eventDial:       "dial",
	eventServerDNS:  "server_dns",
	eventConnect:    "connect",
	eventConnected:  "connected",
	eventTLS:        "tls",
	eventMux:        "mux",
	eventReady:      "ready",
	eventDialFail:   "dial_fail",
	eventClosed:     "closed",
}

// The first endpoints and the route path already live in the trace. Reuse
// those values to keep each retained event within 80 bytes on 64-bit builds.
type connectionEvent struct {
	atUS        int64
	duration    time.Duration
	code        string
	name        string
	addr        string
	n           [2]int32
	kind        connectionEventKind
	nCount      uint8
	hasDuration bool
}

func (a *connectionAttempt) appendEventLocked(event connectionEvent) {
	a.appendEventAtLocked(time.Now(), event)
}

func (a *connectionAttempt) appendEventAtLocked(at time.Time, event connectionEvent) {
	if !a.EndedAt.IsZero() {
		return
	}
	event.atUS = max(0, at.Sub(a.Start).Microseconds())
	event.code = history.Text(event.code, connectionLabelBytes)
	event.addr = history.Text(event.addr, connectionLabelBytes)
	nameLimit := connectionLabelBytes
	switch event.kind {
	case eventMatched, eventRuleLookup:
		nameLimit = connectionRuleBytes
	case eventDNS, eventServerDNS, eventTLS:
		nameLimit = 255
	}
	event.name = history.Text(event.name, nameLimit)
	if len(a.events) == maxConnectionEvents {
		a.events[firstConnectionEvents+a.EventsDropped%lastConnectionEvents] = event
		a.EventsDropped++
		return
	}
	if len(a.events) == cap(a.events) {
		capacity := min(maxConnectionEvents, max(initialConnectionEvents, 2*cap(a.events)))
		grown := make([]connectionEvent, len(a.events), capacity)
		copy(grown, a.events)
		a.events = grown
	}
	a.events = append(a.events, event)
}

func (a *connectionAttempt) snapshotLocked() api.ConnectionTrace {
	trace := a.ConnectionTrace
	trace.MITMConnectionInfo = a.mitmInfoLocked()
	if len(a.events) == 0 {
		return trace
	}
	// Share a single copy of the path in the snapshot, away from live state.
	trace.Chain = slices.Clone(trace.Chain)
	trace.Events = make([]api.ConnEvent, len(a.events))
	tailStart := a.EventsDropped % lastConnectionEvents
	inOrder := true
	for i := range trace.Events {
		index := i
		if i >= firstConnectionEvents && a.EventsDropped != 0 {
			index = firstConnectionEvents + (i-firstConnectionEvents+tailStart)%lastConnectionEvents
		}
		stored := a.events[index]
		event := api.ConnEvent{T: stored.atUS, Kind: connectionEventKinds[stored.kind], Code: stored.code, Name: stored.name, Addr: stored.addr}
		switch stored.kind {
		case eventAccepted, eventUDPFirst:
			event.Addr = history.Text(trace.Source, connectionLabelBytes)
			event.Peer = history.Text(trace.Destination, connectionLabelBytes)
		case eventPath:
			event.Path = trace.Chain
		case eventRuleAddr:
			// Reuse the unused name slot for the IPv6 address.
			event.Peer, event.Name = stored.name, ""
		case eventConnect:
			event.Addr = trace.ServerAddr
		case eventConnected:
			event.Addr, event.Peer, event.Name = trace.ServerAddr, trace.LocalAddr, trace.Interface
		}
		if stored.hasDuration {
			ms := float64((stored.duration.Microseconds()+50)/100) / 10
			event.MS = &ms
		}
		if stored.nCount != 0 {
			event.N = make([]int, stored.nCount)
			for i := range event.N {
				event.N[i] = int(stored.n[i])
			}
		}
		trace.Events[i] = event
		if i > 0 && event.T < trace.Events[i-1].T {
			inOrder = false
		}
	}
	// Socket timings are added once the dial identifies the winning socket.
	if !inOrder {
		slices.SortStableFunc(trace.Events, func(a, b api.ConnEvent) int {
			return cmp.Compare(a.T, b.T)
		})
	}
	return trace
}

type connectionHistoryTrace api.ConnectionTrace

func (trace connectionHistoryTrace) CompactHistorySummary() any {
	// The closed snapshot owns its event slice, and Chain holds the same path.
	for i := range trace.Events {
		event := &trace.Events[i]
		if event.Kind == "path" {
			event.Path = nil
		}
	}
	return trace
}
