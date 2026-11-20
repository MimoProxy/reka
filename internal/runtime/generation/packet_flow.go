//go:build with_gvisor

package generation

import (
	"io"
	"net/netip"

	tun "github.com/sagernet/sing-tun"
)

// AttachPacketFlow gives an already activated engine the host's packet link.
// The host owns settings and closes the link before retiring the engine.
func (e *Engine) AttachPacketFlow(device tun.GVisorTun, mtu int, v4, v6 netip.Prefix, tcpLimit, udpLimit int) (io.Closer, error) {
	return e.backend.AttachPacketFlow(device, mtu, v4, v6, tcpLimit, udpLimit, e.ExchangeDNS)
}

func (e *Engine) PacketFlowTraffic() (uint64, uint64) {
	return e.backend.Traffic()
}

func (e *Engine) PacketFlowConnections() int {
	return e.backend.ConnectionCount()
}
