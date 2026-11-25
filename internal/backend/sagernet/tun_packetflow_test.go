//go:build with_gvisor

package sagernet

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestPacketFlowConnWaiterTouchesOnData(t *testing.T) {
	const payload = "stream data"
	flow := new(admittedPacketFlow)
	source := &packetFlowConn{
		Conn: &relayWaitTestConn{input: relayWaitTestInput("", payload)},
		flow: flow,
	}
	waiter, ok := bufio.CreateReadWaiter(source)
	if !ok || waiter.InitializeReadWaiter(N.ReadWaitOptions{}) {
		t.Fatal("packet flow did not expose a usable read waiter")
	}

	empty, err := waiter.WaitReadBuffer()
	defer empty.Release()
	if err != nil || empty == nil || !empty.IsEmpty() || flow.last.Load() != 0 {
		t.Fatalf("empty read buffer = %v, read error = %v, last activity = %d", empty, err, flow.last.Load())
	}

	buffer, err := waiter.WaitReadBuffer()
	defer buffer.Release()
	if err != nil || buffer == nil || string(buffer.Bytes()) != payload {
		t.Fatalf("waiter did not return the payload: %v", err)
	}
	if flow.last.Load() == 0 {
		t.Fatal("reading data through the waiter did not touch the flow")
	}

	flow.last.Store(1)
	if b, err := waiter.WaitReadBuffer(); b != nil || err != io.EOF || flow.last.Load() != 1 {
		t.Fatalf("after EOF, buffer = %v, read error = %v, last activity = %d", b, err, flow.last.Load())
	}
}

func TestPacketFlowEvictsOldestIdle(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			lab := newPacketFlowLab(t, 3, 3)
			first := lab.open(t, network)
			oldest := lab.open(t, network)
			newer := lab.open(t, network)

			conn, err := lab.dial(network)
			if conn != nil {
				defer conn.Close()
			}
			if network == "tcp" && err == nil {
				t.Fatal("TCP connection exceeded the active limit")
			}
			if network == "udp" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := conn.Write([]byte("echo")); err != nil {
					t.Fatal(err)
				}
			}
			waitPacketFlow(t, func() bool { return lab.flow.Stats() == packetFlowTestStats(network, 1, 0) })

			now := time.Now()
			lab.setLast(t, network, first, now.Add(-20*time.Second))
			lab.setLast(t, network, oldest, now.Add(-15*time.Second))
			lab.setLast(t, network, newer, now.Add(-10*time.Second))
			echoPacketFlow(t, first)
			lab.open(t, network)

			waitPacketFlow(t, func() bool { return lab.history.Count(history.Connections) > 0 })
			page, err := lab.history.List(history.Connections, "", history.ListOptions{Limit: 4})
			if err != nil || len(page.Rows) != 1 {
				t.Fatalf("evicted connection history: %+v, %v", page, err)
			}
			var trace api.ConnectionTrace
			if err := json.Unmarshal(page.Rows[0].Data, &trace); err != nil {
				t.Fatal(err)
			}
			if trace.Source != oldest.LocalAddr().String() || trace.CloseReason != "evicted" || trace.ErrorStage != "" {
				t.Fatalf("unexpected evicted connection: %+v", trace)
			}
			if got := lab.flow.Stats(); got != packetFlowTestStats(network, 1, 1) {
				t.Fatalf("flow limit statistics: %+v", got)
			}
			if network == "tcp" {
				_ = oldest.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := oldest.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("evicted TCP connection did not close: %v", err)
				}
			}
			echoPacketFlow(t, first)
			echoPacketFlow(t, newer)
		})
	}
}

func TestPacketFlowConcurrentAdmissionRejectsWhenActive(t *testing.T) {
	const limit, attempts = 4, 24
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			lab := newPacketFlowLab(t, limit, limit)
			start := make(chan struct{})
			var workers sync.WaitGroup
			var clients [attempts]net.Conn
			var failures [attempts]error
			for i := range clients {
				workers.Go(func() {
					<-start
					conn, err := lab.dial(network)
					if network == "udp" && err == nil {
						_, err = conn.Write([]byte("echo"))
					}
					clients[i], failures[i] = conn, err
				})
			}
			close(start)
			workers.Wait()
			t.Cleanup(func() {
				for _, conn := range clients {
					if conn != nil {
						conn.Close()
					}
				}
			})
			if network == "tcp" {
				accepted := 0
				for _, err := range failures {
					if err == nil {
						accepted++
					}
				}
				if accepted != limit {
					t.Fatalf("accepted %d TCP connections, expected %d: %v", accepted, limit, failures)
				}
			}
			want := packetFlowTestStats(network, attempts-limit, 0)
			waitPacketFlow(t, func() bool {
				return lab.flow.Stats() == want && lab.backend.ConnectionCount() == limit
			})
			waitPacketFlow(t, func() bool { return lab.logs.String() != "" })
			logs := lab.logs.String()
			if strings.Count(logs, "level=WARN") != 1 || !strings.Contains(logs, network+" connection limit reached (limit 4)") {
				t.Fatalf("expected one warning about the saturated %s limit: %s", network, logs)
			}
		})
	}
}

func TestPacketFlowReservationSurvivesAsyncClose(t *testing.T) {
	h := &packetFlowHandler{tcp: newPacketFlowTable(1)}
	reserve := func(key packetFlowKey, want tun.FlowAction) {
		t.Helper()
		if got, _ := h.reserve(&h.tcp, key); got != want {
			t.Fatalf("reserve %v: got %v, want %v", key, got, want)
		}
	}
	old := packetFlowKey{netip.MustParseAddrPort("198.18.0.2:50000"), netip.MustParseAddrPort("192.0.2.1:443")}
	replacement, other := old, old
	replacement.source = netip.AddrPortFrom(old.source.Addr(), 50001)
	other.source = netip.AddrPortFrom(old.source.Addr(), 50002)
	reserve(old, tun.ActionAccept)
	victim := h.tcp.flows[old]
	closing, resume, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(resume)
	victim.reserved = time.Time{}
	victim.last.Store(time.Now().Add(-packetFlowEvictionIdle).UnixNano())
	victim.close = func() {
		close(closing)
		<-resume
		victim.release()
		close(closed)
	}
	t.Cleanup(func() {
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Error("evicted transport did not finish closing")
		}
	})
	reserve(replacement, tun.ActionAccept)
	select {
	case <-closing:
	case <-time.After(time.Second):
		t.Fatal("evicted transport did not start closing")
	}
	reserve(other, tun.ActionReject)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_, flow, done := h.claim(t.Context(), &h.tcp, client, M.SocksaddrFromNetIP(replacement.source), M.SocksaddrFromNetIP(replacement.target), nil)
	if flow == nil {
		t.Fatal("replacement could not claim its reserved slot")
	}
	reserve(replacement, tun.ActionAccept)
	done(nil)
	reserve(other, tun.ActionReject)
	_, flow, done = h.claim(t.Context(), &h.tcp, server, M.SocksaddrFromNetIP(replacement.source), M.SocksaddrFromNetIP(replacement.target), nil)
	if flow == nil {
		t.Fatal("closing transport released the reservation for its successor")
	}
	done(nil)
	reserve(other, tun.ActionAccept)
}

func TestPacketFlowUDPCountsEachDestination(t *testing.T) {
	lab := newPacketFlowLab(t, 1, 2)
	conn, err := gonet.DialUDP(lab.client, nil, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	destination := tun.AddrFromAddress(lab.target.Addr)
	for i := range 3 {
		peer := net.UDPAddrFromAddrPort(netip.AddrPortFrom(destination, lab.target.Port+uint16(i)))
		if _, err := conn.WriteTo([]byte("echo"), peer); err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			break
		}
		reply := make([]byte, 4)
		if n, source, err := conn.ReadFrom(reply); err != nil || string(reply[:n]) != "echo" || source.String() != peer.String() {
			t.Fatalf("echo from %v: %q, %v, %v", peer, reply[:n], source, err)
		}
	}
	waitPacketFlow(t, func() bool {
		return lab.flow.Stats() == (PacketFlowStats{UDPRejected: 1}) && lab.backend.ConnectionCount() == 2
	})
}

type packetFlowLab struct {
	ctx     context.Context
	client  *stack.Stack
	target  tcpip.FullAddress
	backend *Backend
	flow    *PacketFlow
	history *history.Store
	logs    *packetFlowTestLog
}

func newPacketFlowLab(t *testing.T, tcpLimit, udpLimit int) *packetFlowLab {
	t.Helper()
	const mtu = 1280
	ctx, cancel := context.WithCancel(t.Context())
	logs := new(packetFlowTestLog)
	events := history.NewBounded(16, 64<<10, history.Connections)
	backend := New(Options{History: events, Logger: slog.New(slog.NewTextHandler(logs, nil)), OnConnectionClosed: func(ConnInfo) {}})
	t.Cleanup(func() { _ = backend.Close() })
	t.Cleanup(cancel)
	backend.SetRoute(func(context.Context, Metadata) Route {
		return Route{Outbound: &Outbound{tag: "echo", typ: "direct", out: packetFlowEchoOutbound{}}}
	})

	device := &packetFlowTestDevice{Endpoint: channel.New(64, mtu, "")}
	flow, err := backend.AttachPacketFlow(device, mtu, netip.MustParsePrefix("198.18.0.1/30"), netip.MustParsePrefix("2001:db8::1/64"), tcpLimit, udpLimit, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = flow.Close() })

	endpoint := channel.New(64, mtu, "")
	client, err := tun.NewGVisorStack(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.Close)
	t.Cleanup(client.Close)
	address := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address: tun.AddressFromAddr(netip.MustParseAddr("198.18.0.2")), PrefixLen: 30,
		},
	}
	if err := client.AddProtocolAddress(tun.DefaultNIC, address, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	var link sync.WaitGroup
	link.Go(func() { relayPacketFlowTestLink(ctx, endpoint, device.Endpoint) })
	link.Go(func() { relayPacketFlowTestLink(ctx, device.Endpoint, endpoint) })
	t.Cleanup(func() { cancel(); link.Wait() })
	return &packetFlowLab{
		ctx: ctx, client: client, flow: flow, backend: backend, history: events, logs: logs,
		target: tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tun.AddressFromAddr(netip.MustParseAddr("192.0.2.1")), Port: 8000},
	}
}

func relayPacketFlowTestLink(ctx context.Context, from, to *channel.Endpoint) {
	for {
		packet := from.ReadContext(ctx)
		if packet == nil {
			return
		}
		frame := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithView(packet.ToView())})
		packet.DecRef()
		to.InjectInbound(ipv4.ProtocolNumber, frame)
		frame.DecRef()
	}
}

func (l *packetFlowLab) dial(network string) (net.Conn, error) {
	var conn net.Conn
	var err error
	if network == "tcp" {
		ctx, cancel := context.WithTimeout(l.ctx, 5*time.Second)
		defer cancel()
		conn, err = gonet.DialContextTCP(ctx, l.client, l.target, ipv4.ProtocolNumber)
	} else {
		conn, err = gonet.DialUDP(l.client, nil, &l.target, ipv4.ProtocolNumber)
	}
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (l *packetFlowLab) open(t *testing.T, network string) net.Conn {
	t.Helper()
	conn, err := l.dial(network)
	if err != nil {
		t.Fatalf("dial: %v, logs: %s", err, l.logs.String())
	}
	t.Cleanup(func() { _ = conn.Close() })
	echoPacketFlow(t, conn)
	return conn
}

func echoPacketFlow(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("echo")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, payload) {
		t.Fatalf("unexpected echo %q: %v", reply, err)
	}
	_ = conn.SetDeadline(time.Time{})
}

func (l *packetFlowLab) setLast(t *testing.T, network string, conn net.Conn, at time.Time) {
	t.Helper()
	h := l.flow.handler
	h.mu.Lock()
	defer h.mu.Unlock()
	table := &h.tcp
	if network == "udp" {
		table = &h.udp
	}
	key := packetFlowKey{netip.MustParseAddrPort(conn.LocalAddr().String()), netip.MustParseAddrPort(conn.RemoteAddr().String())}
	flow := table.flows[key]
	if flow == nil || flow.close == nil {
		t.Fatalf("missing admitted %s flow: %+v", network, key)
	}
	flow.last.Store(at.UnixNano())
}

func packetFlowTestStats(network string, rejected, evicted uint64) PacketFlowStats {
	if network == "tcp" {
		return PacketFlowStats{TCPRejected: rejected, TCPEvicted: evicted}
	}
	return PacketFlowStats{UDPRejected: rejected, UDPEvicted: evicted}
}

func waitPacketFlow(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-deadline:
			t.Fatal("packet flow did not reach expected state")
		case <-tick.C:
		}
	}
}

type packetFlowTestDevice struct{ *channel.Endpoint }

func (d *packetFlowTestDevice) Name() (string, error)                { return "packet-flow-test", nil }
func (d *packetFlowTestDevice) Start() error                         { return nil }
func (d *packetFlowTestDevice) Close() error                         { d.Endpoint.Close(); return nil }
func (d *packetFlowTestDevice) Read([]byte) (int, error)             { return 0, io.ErrClosedPipe }
func (d *packetFlowTestDevice) Write([]byte) (int, error)            { return 0, io.ErrClosedPipe }
func (d *packetFlowTestDevice) UpdateRouteOptions(tun.Options) error { return io.ErrClosedPipe }

func (d *packetFlowTestDevice) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return d.Endpoint, stack.NICOptions{}, nil
}

func (d *packetFlowTestDevice) WritePacket(packet *stack.PacketBuffer) (int, error) {
	var packets stack.PacketBufferList
	packets.PushBack(packet)
	if n, _ := d.WritePackets(packets); n != 1 {
		return 0, io.ErrShortWrite
	}
	return packet.Size(), nil
}

type packetFlowEchoOutbound struct{ adapter.Outbound }

func (packetFlowEchoOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.CopyBuffer(server, server, make([]byte, 128))
	}()
	return client, nil
}

func (packetFlowEchoOutbound) ListenPacket(_ context.Context, target M.Socksaddr) (net.PacketConn, error) {
	conn, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.CopyBuffer(server, server, make([]byte, 128))
	}()
	return packetFlowEchoPacketConn{conn, target.UDPAddr()}, nil
}

type packetFlowEchoPacketConn struct {
	net.Conn
	source net.Addr
}

func (c packetFlowEchoPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.source, err
}

func (c packetFlowEchoPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }

type packetFlowTestLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *packetFlowTestLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *packetFlowTestLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
