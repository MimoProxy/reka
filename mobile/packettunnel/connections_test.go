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
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/packettunnellab"
	"github.com/MimoProxy/reka/internal/testnet"
	"github.com/MimoProxy/reka/mobile/profile"
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
