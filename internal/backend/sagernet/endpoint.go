package sagernet

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// An outbound-only endpoint has no path to Reka's inbound rule engine.
type endpointRouter struct{ routerServices }

var errEndpointInbound = errors.New("reka: inbound connections to an outbound endpoint are disabled")

func (endpointRouter) PreMatch(adapter.InboundContext, []byte) adapter.PreMatchResult {
	return adapter.PreMatchResult{Action: adapter.PreMatchReject}
}

func (endpointRouter) HijackDNSPacket(context.Context, []byte, N.PacketWriter, adapter.InboundContext) {
}

func (endpointRouter) RouteConnection(_ context.Context, conn net.Conn, _ adapter.InboundContext) error {
	return N.CloseOnHandshakeFailure(conn, nil, errEndpointInbound)
}

func (endpointRouter) RoutePacketConnection(_ context.Context, conn N.PacketConn, _ adapter.InboundContext) error {
	return N.CloseOnHandshakeFailure(conn, nil, errEndpointInbound)
}

func (endpointRouter) RouteConnectionEx(_ context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	N.CloseOnHandshakeFailure(conn, onClose, errEndpointInbound)
}

func (endpointRouter) RoutePacketConnectionEx(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	N.CloseOnHandshakeFailure(conn, onClose, errEndpointInbound)
}

func (b *Backend) endpointContext(ctx context.Context, protect control.Func) context.Context {
	ctx = service.ExtendContext(ctx)
	service.MustRegister[adapter.Router](ctx, endpointRouter{})
	// NewDefault skips auto-detect for an explicit BindInterface (including
	// WireGuard's CreateDialer). Its unconditional socket control covers both
	// that case and the UDP listener. Disabling upstream auto-detect also
	// disables its multi-interface UDP egress pool, which requires a non-nil
	// InterfaceMonitor. Reka selects the physical interface in protect.
	service.MustRegister[adapter.NetworkManager](ctx, &networkManager{protect: protect, explicitProtect: true})
	return ctx
}

type endpointFactory func(context.Context, adapter.Router) (adapter.Endpoint, error)

type outboundEndpoint struct {
	backend  *Backend
	create   endpointFactory
	endpoint adapter.Endpoint
}

func (e *outboundEndpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		ctx := e.backend.endpointContext(scope.Context(), e.backend.endpointControl(scope))
		var err error
		e.endpoint, err = e.create(ctx, service.FromContext[adapter.Router](ctx))
		if err != nil {
			return err
		}
		e.create = nil
	}
	if err := e.endpoint.Start(stage, scope); err != nil {
		// WireGuard's IpcSet error includes the full device configuration.
		if strings.Contains(err.Error(), "\nprivate_key=") {
			return errors.New("endpoint rejected its device configuration")
		}
		return err
	}
	if stage == adapter.StartStateStarted {
		if listener, ok := e.endpoint.(adapter.InterfaceUpdateListener); ok {
			e.backend.endpointListeners.add(scope, listener)
		}
	}
	return nil
}

func (b *Backend) newEndpointOutbound(tag, typ string, create endpointFactory) (*Outbound, error) {
	scope := adapter.NewScope(b.ctx, b.componentLogger("endpoint", typ, tag))
	out := &lazyEndpoint{
		Adapter: outbound.NewAdapter(typ, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		backend: b, create: create, ctx: scope.Context(), access: make(chan struct{}, 1),
	}
	scope.Add(out.close)
	return scopedOutbound(tag, typ, out, scope), nil
}

// Endpoint tunnels own a stack and long-lived workers. Prepare can construct
// large subscriptions, so only allocate the stack when a flow uses the tunnel.
type lazyEndpoint struct {
	outbound.Adapter
	backend *Backend
	create  endpointFactory
	ctx     context.Context
	access  chan struct{}
	active  adapter.Endpoint
	scope   *adapter.Scope
}

func (e *lazyEndpoint) get(ctx context.Context) (adapter.Endpoint, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.ctx.Done():
		return nil, net.ErrClosed
	case e.access <- struct{}{}:
	}
	defer func() { <-e.access }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if e.active == nil {
		component := &outboundEndpoint{backend: e.backend, create: e.create}
		scope, err := startComponent(e.ctx, "endpoint/"+e.Type()+"["+e.Tag()+"]", component, e.backend.componentLogger("endpoint", e.Type(), e.Tag()))
		if err != nil {
			return nil, err
		}
		e.active, e.scope, e.create = component.endpoint, scope, nil
		if e.ctx.Err() != nil {
			return nil, net.ErrClosed
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return e.active, nil
}

func (e *lazyEndpoint) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	ep, err := e.get(ctx)
	if err != nil {
		return nil, err
	}
	return ep.DialContext(ctx, network, dest)
}

func (e *lazyEndpoint) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	ep, err := e.get(ctx)
	if err != nil {
		return nil, err
	}
	return ep.ListenPacket(ctx, dest)
}

func (e *lazyEndpoint) close() error {
	e.access <- struct{}{}
	defer func() { <-e.access }()
	scope := e.scope
	e.active, e.scope, e.create = nil, nil, nil
	if scope != nil {
		return scope.Close()
	}
	return nil
}

type endpointListeners struct {
	mu     sync.RWMutex
	scopes map[*adapter.Scope]adapter.InterfaceUpdateListener
}

func (l *endpointListeners) add(scope *adapter.Scope, listener adapter.InterfaceUpdateListener) {
	l.mu.Lock()
	if l.scopes == nil {
		l.scopes = make(map[*adapter.Scope]adapter.InterfaceUpdateListener)
	}
	l.scopes[scope] = listener
	l.mu.Unlock()
	// Remove before the upstream scope cleanups stop the device.
	scope.Add(func() error {
		l.mu.Lock()
		delete(l.scopes, scope)
		l.mu.Unlock()
		return nil
	})
}

// NotifyEndpointNetworkChanged refreshes physical sockets after a network
// change, including endpoints that still service draining generations.
func (b *Backend) NotifyEndpointNetworkChanged(ctx context.Context) {
	l := &b.endpointListeners
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, listener := range l.scopes {
		listener.InterfaceUpdated(ctx)
	}
}

type endpointSocket struct {
	address string
	conn    syscall.RawConn
}

type endpointSocketRegistry struct {
	mu     sync.Mutex
	scopes map[*adapter.Scope]map[endpointSocketKey]endpointSocket
}

type endpointSocketKey struct {
	network string
	fd      uintptr
}

func (b *Backend) endpointControl(scope *adapter.Scope) control.Func {
	return b.registerEndpointControl(scope, false)
}

func (b *Backend) registerEndpointControl(scope *adapter.Scope, multiple bool) control.Func {
	if b.protect == nil {
		return nil
	}
	registry := &b.endpointSockets
	registry.mu.Lock()
	if registry.scopes == nil {
		registry.scopes = make(map[*adapter.Scope]map[endpointSocketKey]endpointSocket)
	}
	registry.scopes[scope] = make(map[endpointSocketKey]endpointSocket)
	registry.mu.Unlock()
	scope.Add(func() error {
		registry.mu.Lock()
		delete(registry.scopes, scope)
		registry.mu.Unlock()
		return nil
	})
	return func(network, address string, conn syscall.RawConn) error {
		registry.mu.Lock()
		defer registry.mu.Unlock()
		sockets, exists := registry.scopes[scope]
		if !exists {
			return net.ErrClosed
		}
		if err := b.protect(network, address, conn); err != nil {
			return err
		}
		key := endpointSocketKey{network: network}
		if multiple {
			// Tailscale can hold multiple TCP and UDP sockets per family.
			// Scrub closed descriptors so reconnects cannot grow the set.
			for previous, socket := range sockets {
				if errors.Is(socket.conn.Control(func(uintptr) {}), net.ErrClosed) {
					delete(sockets, previous)
				}
			}
			if err := conn.Control(func(fd uintptr) { key.fd = fd }); err != nil {
				return err
			}
		}
		// WireGuard closes its old socket for each family before rebinding.
		sockets[key] = endpointSocket{address: address, conn: conn}
		return nil
	}
}

// ReprotectEndpointSockets applies the active guard to persistent sockets
// that an endpoint may already have opened before TUN takeover.
func (b *Backend) ReprotectEndpointSockets() error {
	registry := &b.endpointSockets
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for _, sockets := range registry.scopes {
		for key, socket := range sockets {
			err := b.protect(key.network, socket.address, socket.conn)
			if errors.Is(err, net.ErrClosed) {
				delete(sockets, key)
			} else if err != nil {
				return err
			}
		}
	}
	return nil
}
