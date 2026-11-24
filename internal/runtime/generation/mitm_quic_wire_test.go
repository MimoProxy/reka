//go:build with_gvisor

package generation

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
)

func TestMITMQUICPacketFlowWire(t *testing.T) {
	e := NewEngine(EngineOptions{HostPacketFlow: true})
	t.Cleanup(e.Close)
	store := newMITMTestStore(t)
	saveMITMTestCA(t, store)
	const profile = `schema-version: 1
mitm: {hostnames: [origin.test], quic-block: true}
rules: [{match: {all: true}, outbound: reject-drop}]
`
	gen := activateMITMTestConfig(t, e, store, profile, 1)
	const mtu = 1280
	device := &ruleDNSTestDevice{Endpoint: channel.New(4, mtu, "")}
	flow, err := e.AttachPacketFlow(device, mtu, netip.MustParsePrefix("198.18.0.1/30"), netip.MustParsePrefix("2001:db8::1/64"), 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = flow.Close() })
	fakeRange := netip.MustParsePrefix("198.19.0.0/24")
	allowed, err := e.fake.Allocate(gen, "origin.test", fakeRange)
	if err != nil {
		t.Fatal(err)
	}
	unmatched, err := e.fake.Allocate(gen, "other.test", fakeRange)
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddr("198.18.0.2")
	send := func(target netip.Addr, sourcePort uint16, reject bool) {
		t.Helper()
		packet := header.IPv4(make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+1))
		packet.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(packet)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber),
			SrcAddr: tun.AddressFromAddr(source), DstAddr: tun.AddressFromAddr(target),
		})
		packet.SetChecksum(^packet.CalculateChecksum())
		udp := header.UDP(packet.Payload())
		udp.Encode(&header.UDPFields{SrcPort: sourcePort, DstPort: 443, Length: uint16(len(udp))})
		message := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		device.InjectInbound(header.IPv4ProtocolNumber, message)
		message.DecRef()
		reply := device.Endpoint.Read()
		if reply != nil {
			defer reply.DecRef()
		}
		if (reply != nil) != reject {
			t.Fatalf("ICMP reply present = %v, want %v", reply != nil, reject)
		}
		if reply != nil {
			view := reply.ToView()
			defer view.Release()
			ip := header.IPv4(view.AsSlice())
			icmp := header.ICMPv4(ip.Payload())
			if ip.TransportProtocol() != header.ICMPv4ProtocolNumber || len(icmp) < header.ICMPv4MinimumSize ||
				icmp.Type() != header.ICMPv4DstUnreachable || icmp.Code() != header.ICMPv4PortUnreachable ||
				!bytes.Equal(icmp.Payload(), packet) {
				t.Fatalf("unexpected QUIC refusal: %x", []byte(ip))
			}
		}
	}
	send(allowed, 50000, true)
	send(unmatched, 50001, false)
	e.mitmBypasses.insert("origin.test", "unknown_ca")
	send(allowed, 50002, false)
}
