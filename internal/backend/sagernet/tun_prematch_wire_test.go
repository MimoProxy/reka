//go:build with_gvisor

package sagernet

import (
	"bytes"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
)

func TestPacketFlowPreMatchWire(t *testing.T) {
	const mtu = 1280
	source := netip.MustParseAddrPort("198.18.0.2:50000")
	target := netip.MustParseAddrPort("192.0.2.1:8000")
	for _, tc := range []struct {
		name     string
		protocol tcpip.TransportProtocolNumber
		action   PreMatchAction
	}{
		{"TCPReject", header.TCPProtocolNumber, PreMatchReject},
		{"TCPDrop", header.TCPProtocolNumber, PreMatchDrop},
		{"UDPReject", header.UDPProtocolNumber, PreMatchReject},
		{"UDPDrop", header.UDPProtocolNumber, PreMatchDrop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := New(Options{})
			t.Cleanup(func() { _ = backend.Close() })
			var judged atomic.Int32
			backend.SetPreMatch(func(Metadata) PreMatchVerdict {
				judged.Add(1)
				return PreMatchVerdict{Action: tc.action}
			})
			device := &packetFlowTestDevice{Endpoint: channel.New(1, mtu, "")}
			flow, err := backend.AttachPacketFlow(device, mtu, netip.MustParsePrefix("198.18.0.1/30"), netip.MustParsePrefix("2001:db8::1/64"), 1, 1, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = flow.Close() })

			request := preMatchWireIPv4Packet(tc.protocol, source, target)
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(request)})
			device.InjectInbound(header.IPv4ProtocolNumber, packet)
			packet.DecRef()
			if got := judged.Load(); got != 1 {
				t.Fatalf("pre-match callback calls = %d, want 1", got)
			}

			// The dispatcher flushes packet replies before InjectInbound returns.
			reply := device.Endpoint.Read()
			if reply != nil {
				defer reply.DecRef()
			}
			if tc.action == PreMatchDrop {
				if reply != nil {
					t.Fatal("drop sent a reply")
				}
				return
			}
			if reply == nil {
				t.Fatal("reject did not send a reply")
			}
			view := reply.ToView()
			defer view.Release()
			ip := header.IPv4(view.AsSlice())
			if !ip.IsValid(len(ip)) || ip.SourceAddress() != tun.AddressFromAddr(target.Addr()) || ip.DestinationAddress() != tun.AddressFromAddr(source.Addr()) {
				t.Fatalf("unexpected reply IP header: %x", []byte(ip))
			}
			switch tc.protocol {
			case header.TCPProtocolNumber:
				tcp := header.TCP(ip.Payload())
				if ip.TransportProtocol() != header.TCPProtocolNumber || len(tcp) < header.TCPMinimumSize ||
					tcp.Flags() != header.TCPFlagRst|header.TCPFlagAck || tcp.AckNumber() != 1 ||
					tcp.SourcePort() != target.Port() || tcp.DestinationPort() != source.Port() {
					t.Fatalf("expected TCP RST with acknowledgment, got %x", []byte(ip))
				}
			case header.UDPProtocolNumber:
				icmp := header.ICMPv4(ip.Payload())
				if ip.TransportProtocol() != header.ICMPv4ProtocolNumber || len(icmp) < header.ICMPv4MinimumSize ||
					icmp.Type() != header.ICMPv4DstUnreachable || icmp.Code() != header.ICMPv4PortUnreachable ||
					!bytes.Equal(icmp.Payload(), request) {
					t.Fatalf("expected ICMP port unreachable quoting the UDP packet, got %x", []byte(ip))
				}
			}
		})
	}
}

func preMatchWireIPv4Packet(protocol tcpip.TransportProtocolNumber, source, target netip.AddrPort) []byte {
	transportSize := header.TCPMinimumSize
	if protocol == header.UDPProtocolNumber {
		transportSize = header.UDPMinimumSize + 1
	}
	ip := header.IPv4(make([]byte, header.IPv4MinimumSize+transportSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(ip)), TTL: 64, Protocol: uint8(protocol),
		SrcAddr: tun.AddressFromAddr(source.Addr()), DstAddr: tun.AddressFromAddr(target.Addr()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	if protocol == header.TCPProtocolNumber {
		tcp := header.TCP(ip.Payload())
		tcp.Encode(&header.TCPFields{
			SrcPort: source.Port(), DstPort: target.Port(), DataOffset: header.TCPMinimumSize,
			Flags: header.TCPFlagSyn, WindowSize: 1024,
		})
		pseudo := header.PseudoHeaderChecksum(protocol, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(tcp)))
		tcp.SetChecksum(^tcp.CalculateChecksum(pseudo))
	} else {
		udp := header.UDP(ip.Payload())
		udp.Encode(&header.UDPFields{SrcPort: source.Port(), DstPort: target.Port(), Length: uint16(len(udp))})
		udp.Payload()[0] = 'x'
	}
	return ip
}
