//go:build with_gvisor

package sagernet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/platform"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	tun "github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// AttachPacketFlow uses a host-owned network interface. The host installs
// routes and DNS. All IP traffic, including DNS, uses the ordinary relay.
func (b *Backend) AttachPacketFlow(device tun.GVisorTun, mtu int, v4, v6 netip.Prefix, tcpLimit, udpLimit int) (io.Closer, error) {
	ctx, cancel := context.WithCancel(b.ctx)
	inbound := &TUNInbound{
		b: b, dev: device, ctx: ctx, cancel: cancel,
		cfg: platform.TUNConfig{Address4: v4.String(), Address6: v6.String()},
	}
	handler := &packetFlowHandler{
		TUNInbound: inbound,
		tcp:        make(chan struct{}, tcpLimit),
		udp:        make(chan struct{}, udpLimit),
	}
	options := tun.Options{
		MTU: uint32(mtu), Inet4Address: []netip.Prefix{v4}, Inet6Address: []netip.Prefix{v6},
		EXP_DisableDNSHijack: true, Logger: newLogger(b.slog, "packet-flow"),
	}
	var err error
	inbound.stack, err = tun.NewGVisor(tun.StackOptions{
		Context: ctx, Tun: device, TunOptions: options, Handler: handler, Logger: options.Logger,
		UDPTimeout: 30 * time.Second, UDPNATMax: uint32(udpLimit),
	})
	if err == nil {
		err = inbound.stack.Start()
	}
	if err != nil {
		_ = inbound.Close()
		return nil, err
	}
	return inbound, nil
}

type packetFlowHandler struct {
	*TUNInbound
	tcp chan struct{}
	udp chan struct{}
}

var errPacketFlowLimit = errors.New("packet tunnel connection limit reached")

func (h *packetFlowHandler) JudgeFlow(protocol uint8, source, target netip.AddrPort, first []byte) tun.FlowVerdict {
	switch protocol {
	case uint8(header.TCPProtocolNumber):
		if len(h.tcp) == cap(h.tcp) {
			return tun.FlowVerdict{Action: tun.ActionReject}
		}
	case uint8(header.UDPProtocolNumber):
		if len(h.udp) == cap(h.udp) {
			return tun.FlowVerdict{Action: tun.ActionReject}
		}
	}
	return h.TUNInbound.JudgeFlow(protocol, source, target, first)
}

func (h *packetFlowHandler) NewConnectionEx(ctx context.Context, c net.Conn, source, target M.Socksaddr, onClose N.CloseHandlerFunc) {
	done, ok := admitPacketFlow(h.tcp, onClose)
	if !ok {
		N.CloseOnHandshakeFailure(c, onClose, errPacketFlowLimit)
		return
	}
	h.TUNInbound.NewConnectionEx(ctx, c, source, target, done)
}

func (h *packetFlowHandler) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, source, target M.Socksaddr, onClose N.CloseHandlerFunc) {
	done, ok := admitPacketFlow(h.udp, onClose)
	if !ok {
		N.CloseOnHandshakeFailure(c, onClose, errPacketFlowLimit)
		return
	}
	h.TUNInbound.NewPacketConnectionEx(ctx, c, source, target, done)
}

func admitPacketFlow(slots chan struct{}, onClose N.CloseHandlerFunc) (N.CloseHandlerFunc, bool) {
	select {
	case slots <- struct{}{}:
		var once sync.Once
		return func(err error) {
			once.Do(func() {
				<-slots
				if onClose != nil {
					onClose(err)
				}
			})
		}, true
	default:
		return nil, false
	}
}
