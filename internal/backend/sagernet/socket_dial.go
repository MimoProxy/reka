package sagernet

import (
	"context"
	"net"
	"net/http/httptrace"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
)

type socketDialKey struct{}

// Keep temporary connect timings within the same budget as retained events.
// A DNS answer can supply more candidates than this. In that case the winning
// socket can still provide addresses even if its timing was not retained.
const maxSocketTimings = maxConnectionEvents

type socketDial struct {
	mu             sync.Mutex
	closed         bool
	timingOverflow bool
	connects       []socketConnect
	tls            []socketTLS
	carrier        net.Conn
	quicSocket     net.Conn
	muxAt          time.Time
	muxCode        string
}

type socketConnect struct {
	address   netip.AddrPort
	network   string
	started   time.Time
	finished  time.Time
	ambiguous bool
}

type socketTLS struct {
	socket   net.Conn
	finished time.Time
	event    connectionEvent
}

type socketDialResult struct {
	server, local netip.AddrPort
	interfaceName string
	connect       socketConnect
	tcp           bool
	tls           []socketTLS
	muxAt         time.Time
	muxCode       string
}

func withSocketDial(ctx context.Context) (context.Context, *socketDial) {
	dial := new(socketDial)
	// Go's net.Dialer calls the net hooks installed by httptrace around each
	// candidate socket dial, including non-HTTP dials through DefaultDialer.
	// This keeps timing in the caller's context. The upstream control hook
	// has no context, and ConnectionManager is also used for routing and
	// connection lifecycle operations.
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		ConnectStart: dial.connectStart,
		ConnectDone:  dial.connectDone,
	})
	return context.WithValue(ctx, socketDialKey{}, dial), dial
}

func socketDialFromContext(ctx context.Context) *socketDial {
	dial, _ := ctx.Value(socketDialKey{}).(*socketDial)
	if dial != nil && attemptFromContext(ctx) != nil {
		return dial
	}
	return nil
}

func (d *socketDial) connectStart(network, address string) {
	started := time.Now()
	key, err := netip.ParseAddrPort(address)
	network = N.NetworkName(network)
	if err != nil || (network != N.NetworkTCP && network != N.NetworkUDP) {
		return
	}
	key = normalizeSocketAddress(key)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.timingOverflow {
		return
	}
	for i := range d.connects {
		timing := &d.connects[i]
		if timing.address == key && timing.network == network {
			// The hooks carry an address, so overlapping or repeated successful
			// dials to the same endpoint cannot identify a particular socket.
			timing.ambiguous = true
			return
		}
	}
	if len(d.connects) == maxSocketTimings {
		// Once a start is discarded, a later completion could be mistaken
		// for a retry to that address.
		d.timingOverflow, d.connects = true, nil
		return
	}
	d.connects = append(d.connects, socketConnect{network: network, address: key, started: started})
}

func (d *socketDial) connectDone(network, address string, dialErr error) {
	finished := time.Now()
	key, err := netip.ParseAddrPort(address)
	if err != nil {
		return
	}
	key = normalizeSocketAddress(key)
	network = N.NetworkName(network)
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.connects {
		timing := &d.connects[i]
		if timing.address != key || timing.network != network {
			continue
		}
		if !timing.ambiguous {
			if dialErr != nil {
				last := len(d.connects) - 1
				d.connects[i] = d.connects[last]
				d.connects[last] = socketConnect{}
				d.connects = d.connects[:last]
			} else {
				timing.finished = finished
			}
		}
		return
	}
}

func (d *socketDial) multiplex(carrier net.Conn, reused bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	if reused {
		d.muxCode, d.muxAt, d.carrier = "reuse", time.Now(), nil
	} else if d.muxCode != "reuse" {
		if d.muxCode == "" {
			d.muxCode, d.muxAt = "new", time.Now()
		}
		if carrier != nil {
			d.carrier = carrier
		}
	}
}

func observeTLS(ctx context.Context, conn net.Conn, started, finished time.Time, name, kind string) {
	d := socketDialFromContext(ctx)
	if d == nil {
		return
	}
	name = strings.TrimRight(name, ".")
	if _, err := netip.ParseAddr(strings.Trim(name, "[]")); err == nil {
		name = "" // IP literals are not carried in SNI.
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed && len(d.tls) < maxConnectionEvents {
		d.tls = append(d.tls, socketTLS{
			socket: underlyingSocket(conn), finished: finished,
			event: connectionEvent{
				kind: eventTLS, name: name, code: kind,
				duration: finished.Sub(started), hasDuration: true,
			},
		})
	}
}

func (d *socketDial) finish(conn any, err error) socketDialResult {
	d.mu.Lock()
	d.closed = true
	result := socketDialResult{muxCode: d.muxCode, muxAt: d.muxAt}
	connects, tls, socket := d.connects, d.tls, d.carrier
	d.connects, d.tls, d.carrier, d.quicSocket = nil, nil, nil, nil
	d.mu.Unlock()

	if err != nil {
		return socketDialResult{}
	}
	if result.muxCode == "reuse" {
		return result
	}
	if result.muxCode == "" {
		socket = underlyingSocket(conn)
	}
	if socket == nil && result.muxCode != "" {
		return result
	}
	if socket != nil {
		result.server = nativeSocketAddress(socket.RemoteAddr())
		result.local = nativeSocketAddress(socket.LocalAddr())
		result.interfaceName = localInterfaces.lookup(result.local.Addr())
		network := N.NetworkUDP
		if _, result.tcp = socket.(*net.TCPConn); result.tcp {
			network = N.NetworkTCP
		}
		// Some protocols can hand back an existing socket. Emit connect
		// events only when this dial observed a matching completion.
		for _, timing := range connects {
			if result.server.IsValid() && timing.address == result.server && timing.network == network && !timing.ambiguous {
				result.connect = timing
				break
			}
		}
	}
	for _, handshake := range tls {
		if socket == nil || handshake.socket == nil || handshake.socket == socket {
			result.tls = append(result.tls, handshake)
		}
	}
	return result
}

func nativeSocketAddress(addr net.Addr) netip.AddrPort {
	var endpoint netip.AddrPort
	switch a := addr.(type) {
	case *net.TCPAddr:
		if a != nil {
			endpoint = a.AddrPort()
		}
	case *net.UDPAddr:
		if a != nil {
			endpoint = a.AddrPort()
		}
	}
	return normalizeSocketAddress(endpoint)
}

func normalizeSocketAddress(endpoint netip.AddrPort) netip.AddrPort {
	ip := endpoint.Addr().Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || endpoint.Port() == 0 {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip, endpoint.Port())
}

// Walk only explicit wrapper links. A protocol can use a TCPAddr or UDPAddr
// for its logical destination, so its address methods alone are insufficient.
// Bound the walk in case a wrapper links back to itself.
func underlyingSocket(conn any) net.Conn {
	for range 32 {
		switch c := conn.(type) {
		case *net.TCPConn:
			if c == nil {
				return nil
			}
			return c
		case *net.UDPConn:
			if c == nil {
				return nil
			}
			return c
		case interface{ NetConn() net.Conn }:
			conn = c.NetConn()
		case common.WithUpstream:
			conn = c.Upstream()
		// Reka's own wrappers can be inspected without adding upstream
		// methods that would also affect sing's reader/writer unwrapping.
		case *leasedConn:
			conn = c.Conn
		case *pinnedPacketConn:
			conn = c.PacketConn
		case *httpObfsConn:
			conn = c.Conn
		case *pluginUpgradeConn:
			conn = c.Conn
		case *shadowTLSV2Recorder:
			conn = c.Conn
		case *shadowTLSV2DataConn:
			conn = c.Conn
		case *xhttpOwnedConn:
			conn = c.Conn
		default:
			return nil
		}
	}
	return nil
}
