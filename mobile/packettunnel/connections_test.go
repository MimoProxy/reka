//go:build with_gvisor

package packettunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/packettunnellab"
	"github.com/MimoProxy/reka/internal/testnet"
	"github.com/MimoProxy/reka/mobile/profile"
	D "github.com/miekg/dns"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
)

func TestConnectionsIncludeStartTime(t *testing.T) {
	peer := startPacketTestPeer(t)
	for _, test := range []struct {
		name    string
		start   func(t *testing.T) (*Session, error)
		address string
	}{
		{"standalone", func(_ *testing.T) (*Session, error) {
			return Start(Node{Server: netip.MustParseAddr(peer.Node.Server), Port: peer.Node.Port,
				Method: peer.Node.Method, Password: peer.Node.Password})
		}, "198.18.0.2"},
		{"profile", func(t *testing.T) (*Session, error) {
			return StartProfile(packetTestProfile(t, peer), profile.Controls{Mode: "rule"}, false)
		}, "172.27.255.2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			session, err := test.start(t)
			if err != nil {
				t.Fatal(err)
			}
			client, ctx := attachTestClient(t, session, test.address)
			destination := packetTestAddress(peer.Destination, peer.TCPPort)
			began := time.Now().UnixMilli()
			dialPacketTestTCP(t, ctx, client, destination)
			first := readConnectionRows(t, session)
			if len(first) != 1 || first[0].StartMS < began || first[0].StartMS > time.Now().UnixMilli() {
				t.Fatalf("unexpected first connection: %+v", first)
			}
			dialPacketTestTCP(t, ctx, client, destination)
			rows := readConnectionRows(t, session)
			if len(rows) != 2 || rows[1] != first[0] || rows[0].ID <= rows[1].ID ||
				rows[0].StartMS < rows[1].StartMS || rows[0].StartMS > time.Now().UnixMilli() {
				t.Fatalf("connections were not returned newest first: %+v", rows)
			}
		})
	}
}

func TestConnectionRowsSortByStartThenID(t *testing.T) {
	rows := []ConnectionRow{{ID: 1, StartMS: 20}, {ID: 3, StartMS: 15}, {ID: 2, StartMS: 20}}
	sortConnectionRows(rows)
	if got := [3]uint64{rows[0].ID, rows[1].ID, rows[2].ID}; got != [3]uint64{2, 1, 3} {
		t.Fatalf("connection order = %v", got)
	}
}

func TestPacketFlowLimitDiagnostics(t *testing.T) {
	session := startPacketFlowDiagnosticsSession(t, nil)
	client, ctx := attachTestClient(t, session, "198.18.0.2")
	destination := packetTestAddress("192.0.2.1", 443)
	for range 2 {
		conn, err := gonet.DialContextTCP(ctx, client, destination, ipv4.ProtocolNumber)
		if err == nil {
			conn.Close()
			t.Fatal("TCP connection exceeded the configured limit")
		}
	}
	value, err := session.RunOperation(Operation{Action: "flowLimits"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var counts map[string]uint64
	if err := json.Unmarshal(payload, &counts); err != nil || len(counts) != 5 || counts["tcpRejected"] != 2 {
		t.Fatalf("unexpected flow limits response %s: %v", payload, err)
	}
	for _, field := range []string{"udpRejected", "tcpEvicted", "udpEvicted", "dnsOverflow"} {
		if count, ok := counts[field]; !ok || count != 0 {
			t.Fatalf("unexpected %s in %s", field, payload)
		}
	}
	value, err = session.RunOperation(Operation{Action: "logs"})
	if err != nil {
		t.Fatal(err)
	}
	page := value.(history.Page)
	if len(page.Rows) != 1 || !strings.Contains(string(page.Rows[0].Data), `"level":"warn"`) ||
		!strings.Contains(string(page.Rows[0].Data), "tcp connection limit reached (limit 0)") {
		t.Fatalf("unexpected rejection logs: %+v", page.Rows)
	}
}

func TestPacketTunnelDNSOverflow(t *testing.T) {
	const limit = 64
	started := make(chan struct{}, limit)
	release := make(chan struct{})
	session := startPacketFlowDiagnosticsSession(t, func(ctx context.Context, q *D.Msg) (*D.Msg, error) {
		select {
		case started <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		select {
		case <-release:
			return new(D.Msg).SetReply(q), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	client, ctx := attachTestClient(t, session, "198.18.0.2")
	destination := packetTestAddress("192.0.2.1", 53)
	udp, err := gonet.DialUDP(client, nil, &destination, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udpDNS := &D.Conn{Conn: udp}
	query := new(D.Msg).SetQuestion("example.test.", D.TypeA)
	for i := range limit {
		query.Id = uint16(i)
		if err := udpDNS.WriteMsg(query); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.After(3 * time.Second)
	for range limit {
		select {
		case <-started:
		case <-deadline:
			t.Fatal("DNS queries did not fill all slots")
		}
	}

	exchange := func(conn *D.Conn, rcode int) {
		t.Helper()
		query.Id++
		if err := conn.WriteMsg(query); err != nil {
			t.Fatal(err)
		}
		reply, err := conn.ReadMsg()
		if err != nil {
			t.Fatal(err)
		}
		if !reply.Response || reply.Id != query.Id || reply.Rcode != rcode || !slices.Equal(reply.Question, query.Question) {
			t.Fatalf("unexpected DNS reply, want %s: %v", D.RcodeToString[rcode], reply)
		}
	}
	checkOverflow := func(want uint64) {
		t.Helper()
		value, err := session.RunOperation(Operation{Action: "flowLimits"})
		if err != nil {
			t.Fatal(err)
		}
		if got := value.(sagernet.PacketFlowStats).DNSOverflow; got != want {
			t.Fatalf("DNS overflow count = %d, want %d", got, want)
		}
	}

	if _, err := udp.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	if err := udpDNS.WriteMsg(new(D.Msg).SetReply(query)); err != nil {
		t.Fatal(err)
	}
	_ = udpDNS.SetDeadline(time.Now().Add(time.Second))
	for i := range 2 {
		exchange(udpDNS, D.RcodeServerFailure)
		checkOverflow(uint64(i + 1))
	}
	value, err := session.RunOperation(Operation{Action: "logs"})
	if err != nil {
		t.Fatal(err)
	}
	page := value.(history.Page)
	if len(page.Rows) != 1 || !strings.Contains(string(page.Rows[0].Data), `"level":"warn"`) ||
		!strings.Contains(string(page.Rows[0].Data), "TUN DNS concurrency limit reached (limit 64)") {
		t.Fatalf("unexpected DNS overflow logs: %+v", page.Rows)
	}

	tcp, err := gonet.DialContextTCP(ctx, client, destination, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	tcpDNS := &D.Conn{Conn: tcp}
	_ = tcpDNS.SetDeadline(time.Now().Add(time.Second))
	exchange(tcpDNS, D.RcodeServerFailure)
	checkOverflow(3)

	close(release)
	_ = udpDNS.SetDeadline(time.Now().Add(time.Second))
	for range limit {
		if reply, err := udpDNS.ReadMsg(); err != nil || reply.Rcode != D.RcodeSuccess {
			t.Fatalf("unexpected blocked query reply: %v, %v", reply, err)
		}
	}
	exchange(udpDNS, D.RcodeSuccess)
	checkOverflow(3)
}

func startPacketFlowDiagnosticsSession(t *testing.T, dns func(context.Context, *D.Msg) (*D.Msg, error)) *Session {
	t.Helper()
	session := newSession()
	session.backend = sagernet.New(session.backendOptions())
	var err error
	session.outbound, err = session.backend.NewOutbound("direct", sagernet.DirectSpec{})
	if err != nil {
		_ = session.backend.Close()
		session.cancel()
		t.Fatal(err)
	}
	session.tunnel, err = session.backend.AttachPacketFlow(session.device, session.MTU(), netip.MustParsePrefix(Address4), netip.MustParsePrefix(Address6), 0, 0, dns)
	if err != nil {
		_ = session.outbound.Close()
		_ = session.backend.Close()
		session.cancel()
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	return session
}

type connectionStamp struct {
	ID      uint64 `json:"id"`
	StartMS int64  `json:"startMs"`
}

func readConnectionRows(t *testing.T, session *Session) []connectionStamp {
	t.Helper()
	result, err := session.RunOperation(Operation{Action: "connections"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var rows []connectionStamp
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func startPacketTestPeer(t *testing.T) *packettunnellab.Peer {
	t.Helper()
	var peer *packettunnellab.Peer
	testnet.RetryAddr(t, func(address netip.AddrPort) error {
		var err error
		peer, err = packettunnellab.Start(address.Addr(), address.Port())
		return err
	})
	t.Cleanup(peer.Close)
	return peer
}

func packetTestProfile(t *testing.T, peer *packettunnellab.Peer) []byte {
	t.Helper()
	return prepareSnapshot(t, fmt.Sprintf(`
proxies:
  - {name: Relay, type: ss, server: %s, port: %d, cipher: %s, password: %q, udp: true}
proxy-groups:
  - {name: Choice, type: select, proxies: [Relay]}
rules:
  - MATCH,Choice
`, peer.Node.Server, peer.Node.Port, peer.Node.Method, peer.Node.Password))
}

func packetTestAddress(ip string, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tun.AddressFromAddr(netip.MustParseAddr(ip)), Port: port}
}

func dialPacketTestTCP(t *testing.T, ctx context.Context, client *stack.Stack, dest tcpip.FullAddress) {
	t.Helper()
	conn, err := gonet.DialContextTCP(ctx, client, dest, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	echoPacketTestPayload(t, conn, []byte("echo"))
}

func echoPacketTestPayload(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, payload) {
		t.Fatalf("echo did not match payload: %v", err)
	}
}
