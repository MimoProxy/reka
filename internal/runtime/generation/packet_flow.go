//go:build with_gvisor

package generation

import (
	"net/netip"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	tun "github.com/sagernet/sing-tun"
)

// ActivatePacketFlowProfile keeps the profile's immutable display names with
// the generation so a connection can keep its labels during a profile change.
func (e *Engine) ActivatePacketFlowProfile(p *Prepared, revision uint64, profileID string, names map[string]string) (uint64, error) {
	return e.activateProfile(p, revision, profileID, names)
}

// AttachPacketFlow gives an already activated engine the host's packet link.
// The host owns settings and closes the link before retiring the engine.
func (e *Engine) AttachPacketFlow(device tun.GVisorTun, mtu int, v4, v6 netip.Prefix, tcpLimit, udpLimit int) (*sagernet.PacketFlow, error) {
	e.packetNetworks.Store(&[2]netip.Prefix{v4.Masked(), v6.Masked()})
	return e.backend.AttachPacketFlow(device, mtu, v4, v6, tcpLimit, udpLimit, e.ExchangeDNS)
}

func (e *Engine) PacketFlowTraffic() (uint64, uint64) {
	return e.backend.Traffic()
}

func (e *Engine) PacketFlowConnections() int {
	return e.backend.ConnectionCount()
}

func (e *Engine) WithPacketFlowConnections(visit func([]sagernet.ConnInfo)) {
	e.backend.WithConnectionSnapshot(visit)
}

// SetPacketFlowRealDNS keeps ordinary client addresses available to the host
// routing table when NetworkExtension routes only a subset of destinations.
func (e *Engine) SetPacketFlowRealDNS(real bool) {
	e.packetFlowRealDNS.Store(real)
}

// ClosePacketFlowConnectionsBefore closes connections routed by a generation
// older than gen and reports how many it closed. Connections hold leases on
// their generation's outbounds, so closing them lets a retired generation be
// released without waiting for the drain timeout.
func (e *Engine) ClosePacketFlowConnectionsBefore(gen uint64) int {
	var ids []uint64
	e.backend.WithConnectionSnapshot(func(conns []sagernet.ConnInfo) {
		for _, c := range conns {
			if info, ok := c.Info.(*FlowInfo); ok && info.Generation < gen {
				ids = append(ids, c.ID)
			}
		}
	})
	if len(ids) == 0 {
		return 0
	}
	return e.backend.CloseConnections(ids)
}
