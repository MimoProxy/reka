//go:build with_gvisor

package packettunnel

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/packettunnellab"
	"github.com/miekg/dns"
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
)

func TestPacketFlowOverOneShadowsocksNode(t *testing.T) {
	peer, err := packettunnellab.Start(netip.MustParseAddr("127.0.0.1"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	session, err := Start(Node{
		Server: netip.MustParseAddr(peer.Node.Server), Port: peer.Node.Port,
		Method: peer.Node.Method, Password: peer.Node.Password,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	endpoint := channel.New(64, MTU, "")
	defer endpoint.Close()
	client, err := tun.NewGVisorStack(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	address := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address: tun.AddressFromAddr(netip.MustParseAddr("198.18.0.2")), PrefixLen: 30,
		},
	}
	if failure := client.AddProtocolAddress(tun.DefaultNIC, address, stack.AddressProperties{}); failure != nil {
		t.Fatal(failure)
	}

	inputDone, outputDone := make(chan struct{}), make(chan struct{})
	defer func() {
		session.Close()
		cancel()
		select {
		case <-inputDone:
		case <-time.After(3 * time.Second):
			t.Error("packet submission did not stop")
		}
		select {
		case <-outputDone:
		case <-time.After(3 * time.Second):
			t.Error("packet read did not stop")
		}
	}()
	go func() {
		defer close(inputDone)
		packet := make([]byte, MTU)
		for {
			p := endpoint.ReadContext(ctx)
			if p == nil {
				return
			}
			n := copyPacket(packet, p)
			p.DecRef()
			session.Submit(packet[:n])
		}
	}()
	go func() {
		defer close(outputDone)
		packets := make([]byte, MTU*MaxBatch)
		lengths := make([]uint16, MaxBatch)
		for {
			count := session.ReadBatch(packets, lengths)
			if count == 0 {
				return
			}
			for i, length := range lengths[:count] {
				p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packets[i*MTU : i*MTU+int(length)])})
				endpoint.InjectInbound(ipv4.ProtocolNumber, p)
				p.DecRef()
			}
		}
	}()

	target := func(ip string, port uint16) tcpip.FullAddress {
		return tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tun.AddressFromAddr(netip.MustParseAddr(ip)), Port: port}
	}
	tcp, err := gonet.DialContextTCP(ctx, client, target(peer.Destination, peer.TCPPort), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal("TCP dial:", err)
	}
	_ = tcp.SetDeadline(time.Now().Add(4 * time.Second))
	tcpData := bytes.Repeat([]byte("reka tcp"), 512)
	if _, err = tcp.Write(tcpData); err != nil {
		t.Fatal("TCP write:", err)
	}
	read := make([]byte, len(tcpData))
	if _, err = io.ReadFull(tcp, read); err != nil || !bytes.Equal(tcpData, read) {
		t.Fatalf("TCP echo mismatch: %v", err)
	}
	_ = tcp.Close()

	udp := func(address tcpip.FullAddress) *gonet.UDPConn {
		conn, dialErr := gonet.DialUDP(client, nil, &address, ipv4.ProtocolNumber)
		if dialErr != nil {
			t.Fatal("UDP dial:", dialErr)
		}
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		return conn
	}
	packetConn := udp(target(peer.Destination, peer.UDPPort))
	udpData := []byte("reka udp")
	if _, err = packetConn.Write(udpData); err != nil {
		t.Fatal("UDP write:", err)
	}
	size, err := packetConn.Read(read)
	if err != nil || !bytes.Equal(udpData, read[:size]) {
		t.Fatalf("UDP echo mismatch: %v", err)
	}
	_ = packetConn.Close()

	dnsConn := udp(target(peer.DNSServer, 53))
	defer dnsConn.Close()
	query := new(dns.Msg).SetQuestion("probe."+peer.Domain+".", dns.TypeA)
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = dnsConn.Write(payload); err != nil {
		t.Fatal("DNS write:", err)
	}
	size, err = dnsConn.Read(read)
	if err != nil {
		t.Fatal("DNS read:", err)
	}
	answer := new(dns.Msg)
	if err = answer.Unpack(read[:size]); err != nil || answer.Id != query.Id || len(answer.Answer) != 1 {
		t.Fatalf("invalid DNS reply: %v", err)
	}
	record, ok := answer.Answer[0].(*dns.A)
	if !ok || record.A.String() != peer.Destination {
		t.Fatal("unexpected DNS result")
	}
	upload, download := session.Traffic()
	if upload < uint64(len(tcpData)+len(udpData)) || download < uint64(len(tcpData)+len(udpData)) {
		t.Fatalf("missing tunnel traffic: upload %d download %d", upload, download)
	}
}
