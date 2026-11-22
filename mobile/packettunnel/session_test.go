//go:build with_gvisor

package packettunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/packettunnellab"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/mobile/profile"
	"github.com/miekg/dns"
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
)

func TestReplaceProfileKeepsPacketFlowAndRejectsInvalidUpdate(t *testing.T) {
	ctx := context.Background()
	prepare := func(target string) []byte {
		t.Helper()
		return prepareSnapshot(t, "rules:\n  - DOMAIN,refresh.example.test,"+target+"\n  - MATCH,DIRECT\n")
	}

	controls := profile.Controls{Mode: "rule"}
	session, err := StartProfile(prepare("DIRECT"), controls, false)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	link, engine := session.tunnel, session.profile.engine
	outbound := func() string {
		effective, _ := engine.Effective()
		return effective.RoutingRouter().Route(ctx, router.Metadata{Domain: "refresh.example.test", Network: "tcp"}, nil).Outbound
	}
	replacement := prepare("REJECT")
	if err := session.ReplaceProfile(replacement, profile.Controls{Mode: "invalid"}); err == nil {
		t.Fatal("accepted invalid routing mode")
	}
	if got := outbound(); got != "direct" {
		t.Fatalf("invalid update changed outbound to %q", got)
	}
	if err := session.ReplaceProfile(replacement, controls); err != nil {
		t.Fatal(err)
	}
	if session.tunnel != link || session.profile.engine != engine {
		t.Fatal("profile replacement rebuilt the packet tunnel")
	}
	if got := outbound(); got != "reject" {
		t.Fatalf("replaced profile routed to %q", got)
	}
}

func TestApplyIPVersionWhilePacketFlowIsActive(t *testing.T) {
	snapshot := prepareSnapshot(t, `
schema-version: 1
outbounds:
  - {id: node, type: shadowsocks, server: proxy.test, port: 443, method: aes-128-gcm, password: example}
  - {id: detoured, type: direct, dialer: {proxy: hop}}
groups: [{id: hop, type: select, members: [node, direct]}]
rules: [{match: {all: true}, outbound: direct}]
dns: {ipv6: true, enhanced-mode: fake-ip, nameserver: [192.0.2.53]}
`)
	session, err := StartProfile(snapshot, profile.Controls{}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	link, engine := session.tunnel, session.profile.engine
	query := new(dns.Msg).SetQuestion("target.test.", dns.TypeAAAA)
	check := func(version string, answers int) {
		t.Helper()
		status, err := session.ProfileStatus()
		if err != nil {
			t.Fatal(err)
		}
		if status.IPVersion != version {
			t.Fatalf("reported IP version %q, want %q", status.IPVersion, version)
		}
		data, err := json.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		if version == "" {
			if bytes.Contains(data, []byte(`"ipVersion"`)) {
				t.Fatal("status included an empty IP version")
			}
		} else if !bytes.Contains(data, []byte(`"ipVersion":`+strconv.Quote(version))) {
			t.Fatal("status JSON is missing the IP version")
		}
		response, err := engine.ExchangeDNS(t.Context(), query)
		if err != nil {
			t.Fatal(err)
		}
		if response.Rcode != dns.RcodeSuccess || len(response.Answer) != answers {
			t.Fatalf("unexpected AAAA response: %v", response)
		}
		if session.tunnel != link || session.profile.engine != engine {
			t.Fatal("controls rebuilt the packet tunnel")
		}
	}
	check("", 1)
	direct := engine.OutboundInstance("direct")
	node := engine.OutboundInstance("node")
	detoured := engine.OutboundInstance("detoured")
	var controls profile.Controls
	if err := json.Unmarshal([]byte(`{"ipVersion":"ipv4"}`), &controls); err != nil {
		t.Fatal(err)
	}
	if err := session.ApplyControls(controls); err != nil {
		t.Fatal(err)
	}
	check("ipv4", 0)
	if direct == engine.OutboundInstance("direct") || node == engine.OutboundInstance("node") || detoured == engine.OutboundInstance("detoured") {
		t.Fatal("IP version change did not replace all affected outbounds")
	}
	detoured = engine.OutboundInstance("detoured")
	if err := session.ApplyControls(controls); err != nil {
		t.Fatal(err)
	}
	if detoured != engine.OutboundInstance("detoured") {
		t.Fatal("the same IP version did not reuse the detoured outbound")
	}
	if err := session.ApplyControls(profile.Controls{IPVersion: "invalid"}); err == nil {
		t.Fatal("accepted an invalid IP version")
	}
	check("ipv4", 0)
	if err := session.ApplyControls(profile.Controls{}); err != nil {
		t.Fatal(err)
	}
	check("", 1)
}

func TestApplyIPVersionReplacesLargeProfile(t *testing.T) {
	session, err := StartProfile(prepareSnapshot(t, "schema-version: 1\n"), profile.Controls{}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	var input strings.Builder
	input.WriteString("schema-version: 1\noutbounds:\n")
	for i := range generation.DefaultMaxRetiring {
		fmt.Fprintf(&input, "  - {id: route-%d, type: direct}\n", i)
	}
	input.WriteString("rules: [{match: {all: true}, outbound: direct}]\n")
	if err := session.ReplaceProfile(prepareSnapshot(t, input.String()), profile.Controls{}); err != nil {
		t.Fatal(err)
	}
	if err := session.ApplyControls(profile.Controls{IPVersion: "ipv4"}); err != nil {
		t.Fatal(err)
	}
	status, err := session.ProfileStatus()
	if err != nil || status.IPVersion != "ipv4" {
		t.Fatalf("IP version update failed: %+v, %v", status, err)
	}
}

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
	if got := session.MTU(); got != 1280 {
		t.Fatalf("default MTU = %d, want 1280", got)
	}
	client, ctx := attachTestClient(t, session, "198.18.0.2")

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

func TestPacketFlowConfiguredMTU(t *testing.T) {
	const mtu, nextMTU = 4064, 1500
	t.Cleanup(func() {
		if !SetMTU(DefaultMTU) {
			t.Error("could not restore default MTU")
		}
	})
	if !SetMTU(mtu) {
		t.Fatalf("rejected supported MTU %d", mtu)
	}
	for _, invalid := range []int{-1, 0, 1279, 4065} {
		if SetMTU(invalid) {
			t.Fatalf("accepted out-of-range MTU %d", invalid)
		}
	}

	snapshot := prepareSnapshot(t, "rules: ['MATCH,REJECT']\n")
	controls := profile.Controls{}
	session, err := StartProfile(snapshot, controls, false)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if got := session.MTU(); got != mtu {
		t.Fatalf("configured MTU = %d, want %d", got, mtu)
	}
	if !SetMTU(nextMTU) {
		t.Fatalf("rejected supported MTU %d", nextMTU)
	}
	if err := session.ReplaceProfile(snapshot, controls); err != nil {
		t.Fatal(err)
	}
	if got := session.MTU(); got != mtu {
		t.Fatalf("active session MTU = %d, want %d", got, mtu)
	}
	if got := session.device.endpoint.MTU(); got != mtu {
		t.Fatalf("active link MTU = %d, want %d", got, mtu)
	}
	probe, err := StartProbeProfile(snapshot, controls)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if got := probe.MTU(); got != nextMTU {
		t.Fatalf("new probe session MTU = %d, want %d", got, nextMTU)
	}

	makePacket := func(size int) []byte {
		data := bytes.Repeat([]byte{byte(size)}, size)
		header.IPv6(data).Encode(&header.IPv6Fields{
			PayloadLength:     uint16(size - header.IPv6MinimumSize),
			TransportProtocol: tcpip.TransportProtocolNumber(header.IPv6NoNextHeaderIdentifier),
			HopLimit:          64,
			SrcAddr:           tun.AddressFromAddr(netip.MustParseAddr("2001:db8::2")),
			DstAddr:           tun.AddressFromAddr(netip.MustParseAddr("2001:db8::1")),
		})
		return data
	}
	small, large, oversized := makePacket(64), makePacket(mtu), makePacket(mtu+1)
	if !session.Submit(large) {
		t.Fatalf("Submit rejected a %d-byte packet", len(large))
	}
	if session.Submit(oversized) {
		t.Fatalf("Submit accepted a %d-byte packet", len(oversized))
	}
	for _, data := range [][]byte{small, oversized, large} {
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		_, err := session.device.WritePacket(packet)
		packet.DecRef()
		if err != nil {
			t.Fatal(err)
		}
	}
	var lengths [2]uint16
	if got := session.ReadBatch(make([]byte, len(lengths)*DefaultMTU), lengths[:]); got != 0 {
		t.Fatalf("ReadBatch returned %d packets with undersized slots", got)
	}
	output := make([]byte, len(lengths)*mtu)
	if got := session.ReadBatch(output, lengths[:]); got != len(lengths) {
		t.Fatalf("ReadBatch returned %d packets, want %d", got, len(lengths))
	}
	for slot, want := range [][]byte{small, large} {
		offset := slot * mtu
		if n := int(lengths[slot]); n != len(want) || !bytes.Equal(output[offset:offset+len(want)], want) {
			t.Fatalf("read slot %d: got %d bytes, want %d matching bytes", slot, n, len(want))
		}
	}
}

func TestPacketFlowAnswersDNSFromSuccessiveUDPClients(t *testing.T) {
	snapshot := prepareSnapshot(t, `
dns: {enable: true, enhanced-mode: fake-ip, nameserver: [1.1.1.1]}
rules:
  - MATCH,DIRECT
`)
	session, err := StartProfile(snapshot, profile.Controls{Mode: "rule"}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	client, _ := attachTestClient(t, session, "192.0.2.2")
	server := tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tun.AddressFromAddr(netip.MustParseAddr("172.27.255.2")), Port: 53}
	for number := range 12 {
		source := tcpip.FullAddress{Port: uint16(59000 + number)}
		conn, err := gonet.DialUDP(client, &source, &server, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		query := new(dns.Msg).SetQuestion("probe-"+strconv.Itoa(number)+".example.test.", dns.TypeA)
		payload, err := query.Pack()
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		if _, err := conn.Write(payload); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		reply := make([]byte, 512)
		n, err := conn.Read(reply)
		conn.Close()
		if err != nil {
			t.Fatalf("DNS query %d: %v", number+1, err)
		}
		answer := new(dns.Msg)
		if err := answer.Unpack(reply[:n]); err != nil || answer.Id != query.Id || len(answer.Answer) != 1 {
			t.Fatalf("invalid DNS reply to query %d: %v", number+1, err)
		}
	}
}

func prepareSnapshot(t *testing.T, raw string) []byte {
	t.Helper()
	dir := t.TempDir()
	input, output := filepath.Join(dir, "profile.yaml"), filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(input, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := profile.PrepareFile(context.Background(), input, output, dir); err != nil {
		t.Fatal(err)
	}
	snapshot, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func attachTestClient(t *testing.T, session *Session, ip string) (*stack.Stack, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	t.Cleanup(cancel)

	mtu := session.MTU()
	endpoint := channel.New(64, uint32(mtu), "")
	t.Cleanup(endpoint.Close)
	client, err := tun.NewGVisorStack(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	address := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address: tun.AddressFromAddr(netip.MustParseAddr(ip)), PrefixLen: 30,
		},
	}
	if failure := client.AddProtocolAddress(tun.DefaultNIC, address, stack.AddressProperties{}); failure != nil {
		t.Fatal(failure)
	}

	inputDone, outputDone := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
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
	})
	go func() {
		defer close(inputDone)
		packet := make([]byte, mtu)
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
		packets := make([]byte, mtu*MaxBatch)
		lengths := make([]uint16, MaxBatch)
		for {
			count := session.ReadBatch(packets, lengths)
			if count == 0 {
				return
			}
			for i, length := range lengths[:count] {
				offset := i * mtu
				p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packets[offset : offset+int(length)])})
				endpoint.InjectInbound(ipv4.ProtocolNumber, p)
				p.DecRef()
			}
		}
	}()
	return client, ctx
}
