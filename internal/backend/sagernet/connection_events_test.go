package sagernet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

func TestConnectionEventBuffer(t *testing.T) {
	if size := unsafe.Sizeof(connectionEvent{}); size > 80 {
		t.Fatalf("retained event uses %d bytes", size)
	}
	var attempt connectionAttempt
	attempt.Start = time.Now()
	if attempt.events != nil {
		t.Fatal("empty attempt allocated events")
	}
	for count := 1; count <= 30; count++ {
		appendTestConnectionEvent(&attempt, connectionEvent{kind: eventMatched, n: [2]int32{int32(count)}, nCount: 1})
		switch count {
		case 1:
			if cap(attempt.events) != 8 {
				t.Fatalf("initial event capacity = %d", cap(attempt.events))
			}
		case 24, 25, 30:
			trace := attempt.trace(0, 0)
			want := make([]int, 0, 24)
			for n := 1; n <= 20; n++ {
				want = append(want, n)
			}
			for n := count - 3; n <= count; n++ {
				want = append(want, n)
			}
			got := make([]int, 0, len(trace.Events))
			for i, event := range trace.Events {
				if len(event.N) != 1 || i > 0 && event.T < trace.Events[i-1].T {
					t.Fatalf("invalid event at %d after %d appends: %+v", i, count, event)
				}
				got = append(got, event.N[0])
			}
			if !slices.Equal(got, want) || trace.EventsDropped != count-24 || cap(attempt.events) != 24 {
				t.Fatalf("after %d appends, got %v and %d dropped, want %v and %d dropped",
					count, got, trace.EventsDropped, want, count-24)
			}
		}
	}
	attempt.complete("manual", "", 11, 22)
	closed := attempt.trace(0, 0)
	if event := closed.Events[23]; event.Kind != "closed" || event.Code != "manual" || closed.EventsDropped != 7 {
		t.Fatalf("after completion, last event = %+v, dropped = %d", event, closed.EventsDropped)
	}
	appendTestConnectionEvent(&attempt, connectionEvent{kind: eventDial})
	attempt.sniffing(time.Now(), Metadata{Protocol: "tls"}, sniffObservation{protocol: "tls"})
	attempt.routing(time.Now())
	attempt.setRoute(Route{}, netip.Addr{})
	attempt.dialing(time.Now(), &Outbound{})
	attempt.dialed(time.Now(), nil, nil, false)
	attempt.complete("error", "relay", 33, 44)
	if after := attempt.trace(33, 44); !reflect.DeepEqual(closed, after) {
		t.Fatalf("completed trace changed: %+v", after)
	}
}

func TestConnectionEventSnapshotsConcurrent(t *testing.T) {
	attempt := (&Backend{}).beginConnection(t.Context(), Metadata{})
	const writers, writes = 4, 128
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range writers {
		workers.Go(func() {
			<-start
			for range writes {
				appendTestConnectionEvent(attempt, connectionEvent{kind: eventDial})
			}
		})
	}
	close(start)
	for range writes {
		trace := attempt.trace(0, 0)
		if count := len(trace.Events); count == 0 || count > 24 || trace.Events[0].Kind != "accepted" {
			t.Errorf("invalid concurrent snapshot with %d events", count)
			break
		}
		for i := 1; i < len(trace.Events); i++ {
			if trace.Events[i].T < trace.Events[i-1].T {
				t.Error("concurrent snapshot is out of order")
				break
			}
		}
	}
	workers.Wait()
	trace := attempt.trace(0, 0)
	if trace.EventsDropped != 1+writers*writes-24 {
		t.Fatalf("concurrent appends dropped %d events", trace.EventsDropped)
	}
}

func TestTCPConnectionEvents(t *testing.T) {
	records := history.New()
	backend := New(Options{History: records, Logger: testLogger(t)})
	defer backend.Close()
	client, local := connectionEventPipe(t)
	remote, target := connectionEventPipe(t)
	peer := netip.MustParseAddrPort("203.0.113.1:443")
	out := &Outbound{tag: "leaf", typ: "direct", out: eventTestOutbound{conn: eventTestConn{remote, net.TCPAddrFromAddrPort(peer)}}}
	info := &api.FlowInfo{
		DestinationDomain: "mapped.test", RuleIndex: 3, Rule: "DOMAIN,mapped.test,group",
		Chain: []string{"group", "leaf"}, Outbound: "leaf",
	}
	backend.SetPrepareFlow(func(context.Context, Metadata) PreparedFlow {
		return PreparedFlow{
			Sniff: SniffOptions{Enabled: true, Timeout: time.Second},
			Route: func(context.Context, Metadata) Route { return Route{Info: info, Outbound: out} },
		}
	})
	source := netip.MustParseAddrPort("192.0.2.2:12345")
	destination := netip.MustParseAddrPort("198.18.0.1:443")
	metadata := adapter.InboundContext{Inbound: "mixed-in", InboundType: "mixed", Source: M.SocksaddrFromNetIP(source), Destination: M.SocksaddrFromNetIP(destination)}
	done := make(chan struct{})
	go backend.router.RouteConnectionEx(t.Context(), local, metadata, func(error) { close(done) })
	passConnectionEventPayload(t, client, target, "GET / HTTP/1.1\r\nHost: sniff.test\r\n\r\n")
	id := backend.conns.next.Load()
	active, ok := backend.ConnectionTrace(id, "")
	if !ok || !active.EndedAt.IsZero() {
		t.Fatalf("missing active connection trace: %+v", active)
	}
	want := []string{"accepted", "sniffed", "fakeip", "matched", "path", "dial", "ready"}
	checkConnectionEventKinds(t, active.Events, want...)
	accepted, sniffed, fakeIP, matched, path, dial, ready :=
		active.Events[0], active.Events[1], active.Events[2], active.Events[3], active.Events[4], active.Events[5], active.Events[6]
	if accepted.Code != "mixed" || accepted.Addr != source.String() || accepted.Peer != destination.String() ||
		sniffed.Code != "http" || sniffed.Name != "sniff.test" || sniffed.MS == nil ||
		fakeIP.Name != "mapped.test" || fakeIP.Addr != destination.Addr().String() ||
		matched.Name != info.Rule || matched.Code != "" || !slices.Equal(matched.N, []int{3}) ||
		path.Name != "leaf" || !slices.Equal(path.Path, info.Chain) ||
		dial.Code != "direct" || dial.Name != "leaf" || ready.MS == nil || ready.Addr != peer.String() {
		t.Fatalf("unexpected event fields: %+v", active.Events)
	}
	if active.RouteStartedAt.IsZero() || active.RouteStartedAt.Before(active.SniffFinishedAt) ||
		active.RouteStartedAt.After(active.RoutedAt) || active.DialPeer != peer.String() || active.TargetIP != peer.Addr().String() {
		t.Fatalf("unexpected route or dial trace: %+v", active)
	}
	// A snapshot can be edited independently of live state and history.
	path.Path[0], matched.N[0] = "changed", -1
	closeConnectionEventFlow(t, backend, id, done)
	closed := readClosedConnectionEventTrace(t, records, id)
	checkConnectionEventKinds(t, closed.Events, append(want, "closed")...)
	if closed.Events[7].Code != "manual" || closed.Events[7].Name != "" ||
		!slices.Equal(closed.Events[4].Path, info.Chain) || !slices.Equal(closed.Events[3].N, []int{3}) {
		t.Fatalf("unexpected persisted events: %+v", closed.Events)
	}
}

func TestTCPConnectionFailureEvents(t *testing.T) {
	for _, tt := range []struct {
		name      string
		route     Route
		err       error
		wantKinds []string
		wantCode  string
		wantStage string
	}{
		{
			name: "dial", route: Route{
				Outbound: &Outbound{tag: "leaf", typ: "socks", out: eventTestOutbound{err: syscall.ECONNREFUSED}},
				Info:     &api.FlowInfo{RuleIndex: -1, Rule: "unused", Outbound: "leaf"},
			},
			err: syscall.ECONNREFUSED, wantKinds: []string{"accepted", "matched", "dial", "dial_fail", "closed"},
			wantCode: "refused", wantStage: "dial",
		},
		{
			name: "rule rejection", route: Route{Info: &api.FlowInfo{RuleIndex: -1, RuleSource: "temporary", Rule: "MATCH,reject", RejectReason: "block-quic"}},
			err: errRejected, wantKinds: []string{"accepted", "matched", "rejected", "closed"},
			wantCode: "block-quic", wantStage: "route",
		},
		{
			name: "default rejection", err: errRejected, wantKinds: []string{"accepted", "matched", "rejected", "closed"},
			wantCode: "reject", wantStage: "route",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			records := history.New()
			backend := New(Options{History: records, Logger: testLogger(t)})
			defer backend.Close()
			backend.SetRoute(func(context.Context, Metadata) Route { return tt.route })
			_, local := connectionEventPipe(t)
			md := adapter.InboundContext{InboundType: "socks", Destination: M.ParseSocksaddr("destination.test:443")}
			if err := backend.router.RouteConnection(t.Context(), local, md); !errors.Is(err, tt.err) {
				t.Fatalf("connection error = %v, want %v", err, tt.err)
			}
			trace := readClosedConnectionEventTrace(t, records, backend.conns.next.Load())
			checkConnectionEventKinds(t, trace.Events, tt.wantKinds...)
			reason := trace.Events[len(trace.Events)-2]
			closed, matched := trace.Events[len(trace.Events)-1], trace.Events[1]
			if reason.Code != tt.wantCode || closed.Name != tt.wantStage || closed.Code != trace.CloseReason ||
				!slices.Equal(matched.N, []int{-1}) || trace.RouteStartedAt.IsZero() {
				t.Fatalf("unexpected failure trace: %+v", trace)
			}
			if tt.wantStage == "dial" && (reason.MS == nil || trace.ReadyAt != nil) {
				t.Fatalf("unexpected dial failure: %+v", trace)
			}
			if tt.name == "rule rejection" {
				if matched.Code != "temporary" || matched.Name != "MATCH,reject" {
					t.Fatalf("unexpected temporary match: %+v", matched)
				}
			} else if matched.Code != "" || matched.Name != "" {
				t.Fatalf("unexpected fallback match: %+v", matched)
			}
		})
	}
}

func TestUDPConnectionEvents(t *testing.T) {
	records := history.New()
	done := make(chan struct{})
	backend := New(Options{History: records, Logger: testLogger(t), OnConnectionClosed: func(ConnInfo) { close(done) }})
	defer backend.Close()
	client, local := connectionEventPipe(t)
	remote, target := connectionEventPipe(t)
	source := netip.MustParseAddrPort("192.0.2.2:12345")
	destination := netip.MustParseAddrPort("203.0.113.1:53")
	addr := net.UDPAddrFromAddrPort(destination)
	out := &Outbound{tag: "udp-leaf", typ: "direct", out: eventTestOutbound{packet: eventTestPacketConn{eventTestConn{remote, addr}}}}
	backend.SetRoute(func(context.Context, Metadata) Route { return Route{Outbound: out} })
	md := adapter.InboundContext{InboundType: "tun", Source: M.SocksaddrFromNetIP(source)}
	backend.router.RoutePacketConnectionEx(t.Context(), bufio.NewPacketConn(eventTestPacketConn{eventTestConn{local, addr}}), md, nil)
	passConnectionEventPayload(t, client, target, "datagram")
	id := backend.conns.next.Load()
	active, ok := backend.ConnectionTrace(id, "")
	if !ok || active.RouteStartedAt.IsZero() || active.RouteStartedAt.After(active.RoutedAt) {
		t.Fatalf("missing active UDP route: %+v", active)
	}
	checkConnectionEventKinds(t, active.Events, "udp_first", "matched", "dial", "ready")
	first, dial, ready := active.Events[0], active.Events[2], active.Events[3]
	if first.Code != "tun" || first.Addr != source.String() || first.Peer != destination.String() ||
		dial.Code != "direct" || dial.Name != "udp-leaf" || ready.MS == nil || ready.Addr != destination.String() {
		t.Fatalf("unexpected UDP events: %+v", active.Events)
	}
	closeConnectionEventFlow(t, backend, id, done)
	closed := readClosedConnectionEventTrace(t, records, id)
	checkConnectionEventKinds(t, closed.Events, "udp_first", "matched", "dial", "ready", "closed")
}

func TestConnectionEventHistoryRowSize(t *testing.T) {
	records := history.New()
	attempt := (&Backend{history: records}).beginConnection(t.Context(), Metadata{InboundType: "tun", Network: "tcp"})
	chain := make([]string, 32)
	for i := range chain {
		chain[i] = strings.Repeat("g", 150)
	}
	label := strings.Repeat("a", 160)
	rule := "DOMAIN-KEYWORD," + strings.Repeat("ab<cd", 205)
	info := &api.FlowInfo{RuleIndex: 3, Rule: rule, Chain: chain, Outbound: label, ProcessPath: strings.Repeat("p", 600)}
	out := &Outbound{tag: label, typ: "direct"}
	attempt.sniffing(time.Now(), Metadata{Protocol: "tls", SniffedDomain: label}, sniffObservation{protocol: "tls", domain: label})
	attempt.setRoute(Route{Info: info, Outbound: out}, netip.Addr{})
	attempt.dialing(time.Now(), out)
	for len(attempt.events) < 23 {
		appendTestConnectionEvent(attempt, connectionEvent{
			kind: eventReady, addr: "[2001:db8::1]:443", duration: 1250 * time.Microsecond, hasDuration: true,
		})
	}
	attempt.complete("eof", "", 1024, 2048)
	persisted := readClosedConnectionEventTrace(t, records, attempt.ID)
	if len(persisted.Events) != 24 {
		t.Fatalf("persisted events = %d", len(persisted.Events))
	}
	sniffed, matched, path, ready := persisted.Events[1], persisted.Events[2], persisted.Events[3], persisted.Events[22]
	if len(sniffed.Name) != 128 || len(matched.Name) != 512 || len(path.Path) != 32 ||
		len(path.Path[0]) != 128 || len(path.Name) != 128 || ready.MS == nil || *ready.MS != 1.3 {
		t.Fatalf("unexpected bounded event payloads")
	}
}

func appendTestConnectionEvent(attempt *connectionAttempt, event connectionEvent) {
	attempt.mu.Lock()
	attempt.appendEventLocked(event)
	attempt.mu.Unlock()
}

func checkConnectionEventKinds(t *testing.T, events []api.ConnEvent, want ...string) {
	t.Helper()
	got := make([]string, len(events))
	for i, event := range events {
		got[i] = event.Kind
		if event.T < 0 || i > 0 && event.T < events[i-1].T {
			t.Fatalf("unexpected relative time at event %d: %+v", i, event)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("event sequence = %v, want %v", got, want)
	}
}

func readClosedConnectionEventTrace(t *testing.T, store *history.Store, id uint64) api.ConnectionTrace {
	t.Helper()
	rows, _ := store.FlowRows("", id)
	connections := rows[history.Connections]
	if len(connections) != 1 {
		t.Fatalf("expected one history row for connection %d, got %d", id, len(connections))
	}
	if size := len(connections[0].Data); size >= 12<<10 {
		t.Fatalf("connection history row uses %d bytes", size)
	}
	var trace api.ConnectionTrace
	if err := json.Unmarshal(connections[0].Data, &trace); err != nil || trace.EndedAt.IsZero() {
		t.Fatalf("invalid closed connection trace: %+v, %v", trace, err)
	}
	return trace
}

func connectionEventPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	left, right := net.Pipe()
	t.Cleanup(func() {
		left.Close()
		right.Close()
	})
	return left, right
}

func passConnectionEventPayload(t *testing.T, from, to net.Conn, payload string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	from.SetWriteDeadline(deadline)
	to.SetReadDeadline(deadline)
	if _, err := io.WriteString(from, payload); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, len(payload))
	if _, err := io.ReadFull(to, data); err != nil || string(data) != payload {
		t.Fatalf("relayed data = %q, error = %v", data, err)
	}
}

func closeConnectionEventFlow(t *testing.T, backend *Backend, id uint64, done <-chan struct{}) {
	t.Helper()
	if backend.CloseConnections([]uint64{id}) != 1 {
		t.Fatal("could not close the active connection")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("connection did not finish closing")
	}
}

type eventTestOutbound struct {
	adapter.Outbound
	conn   net.Conn
	packet net.PacketConn
	err    error
}

func (o eventTestOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return o.conn, o.err
}

func (o eventTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return o.packet, o.err
}

type eventTestConn struct {
	net.Conn
	peer net.Addr
}

func (c eventTestConn) RemoteAddr() net.Addr { return c.peer }

type eventTestPacketConn struct{ eventTestConn }

func (c eventTestPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.peer, err
}

func (c eventTestPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}
