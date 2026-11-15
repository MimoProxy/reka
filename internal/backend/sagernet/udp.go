package sagernet

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	defaultUDPTimeout = 60 * time.Second
	// pendingPackets bounds what a flow queues while its outbound is still
	// connecting; later packets are dropped, as a congested link would.
	pendingPackets = 16
	// rejectTTL is how long a rejected destination is remembered before
	// it is routed again.
	rejectTTL = 10 * time.Second
)

// udpSession relays one inbound packet session (a SOCKS5 UDP ASSOCIATE)
// as independent flows, one per destination. Each flow is routed on its
// own, so different destinations in one association can match different
// rules and outbounds, and each flow binds the generation current when it
// was created. Replies from a flow only go back to this session.
type udpSession struct {
	b        *Backend
	r        *router
	ctx      context.Context
	cancel   context.CancelFunc
	conn     N.PacketConn
	metadata adapter.InboundContext
	onClose  N.CloseHandlerFunc

	writeMu  sync.Mutex
	mu       sync.Mutex
	flows    map[M.Socksaddr]*udpFlow
	rejected map[M.Socksaddr]time.Time
	closed   bool
}

type udpFlow struct {
	s       *udpSession
	dest    M.Socksaddr
	rt      Route
	remote  N.PacketConn
	ready   chan struct{} // closed once remote is set or the dial failed
	pending []*buf.Buffer
	failed  bool

	up, down atomic.Int64
	last     atomic.Int64
	once     sync.Once
	untrack  func()
}

func (b *Backend) relayUDP(ctx context.Context, r *router, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx, cancel := context.WithCancel(ctx)
	s := &udpSession{
		b: b, r: r, ctx: ctx, cancel: cancel, conn: conn, metadata: metadata, onClose: onClose,
		flows: map[M.Socksaddr]*udpFlow{}, rejected: map[M.Socksaddr]time.Time{},
	}
	if err := N.ReportPacketConnHandshakeSuccess(conn, nil); err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, E.Cause(err, "report handshake success"))
		cancel()
		return
	}
	go s.reap()
	go s.run()
}

func (s *udpSession) run() {
	var err error
	for {
		buffer := buf.NewPacket()
		var dest M.Socksaddr
		dest, err = s.conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			break
		}
		f := s.flow(dest)
		if f == nil {
			buffer.Release()
			continue
		}
		f.send(buffer)
	}
	s.close(err)
}

func (s *udpSession) close(err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	flows := make([]*udpFlow, 0, len(s.flows))
	for _, f := range s.flows {
		flows = append(flows, f)
	}
	s.mu.Unlock()
	s.cancel()
	for _, f := range flows {
		f.close()
	}
	s.conn.Close()
	if s.onClose != nil {
		s.onClose(err)
	}
}

// flow returns the flow for dest, routing and creating it if needed. It
// returns nil when dest is rejected.
func (s *udpSession) flow(dest M.Socksaddr) *udpFlow {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if f, ok := s.flows[dest]; ok {
		return f
	}
	if at, ok := s.rejected[dest]; ok {
		if time.Since(at) < rejectTTL {
			return nil
		}
		delete(s.rejected, dest)
	}
	md := toMetadata(s.metadata)
	md.Network = N.NetworkUDP
	md.Destination = toDestination(dest)
	rt := s.r.pick(s.ctx, md)
	if rt.Outbound == nil {
		s.rejected[dest] = time.Now()
		s.b.logger.DebugContext(s.ctx, "reject packets to ", dest)
		return nil
	}
	f := &udpFlow{s: s, dest: dest, rt: rt, ready: make(chan struct{})}
	f.touch()
	f.untrack = s.b.conns.add(&tracked{md: md, out: rt.Outbound, info: rt.Info, up: &f.up, down: &f.down, close: f.close})
	s.flows[dest] = f
	go f.dial()
	return f
}

func (f *udpFlow) touch() { f.last.Store(time.Now().UnixNano()) }

func (f *udpFlow) dial() {
	s := f.s
	metadata := s.metadata
	metadata.Destination = f.dest
	metadata.Network = N.NetworkUDP
	ctx := adapter.WithContext(s.ctx, &metadata)
	ctx = WithLookup(ctx, f.rt.Lookup)
	dialDest := f.dest
	if f.rt.Destination != nil {
		dialDest = M.ParseSocksaddr(f.rt.Destination.String())
	}
	remote, err := f.rt.Outbound.out.ListenPacket(ctx, dialDest)
	s.mu.Lock()
	if err != nil {
		f.failed = true
	} else {
		f.remote = bufio.NewPacketConn(remote)
	}
	pending := f.pending
	f.pending = nil
	close(f.ready)
	s.mu.Unlock()
	if err != nil {
		for _, b := range pending {
			b.Release()
		}
		s.b.logger.ErrorContext(ctx, E.Cause(err, "open packet connection to ", f.dest, " using outbound/", f.rt.Outbound.Type(), "[", f.rt.Outbound.Tag(), "]"))
		f.close()
		return
	}
	for _, b := range pending {
		f.write(b)
	}
	go f.receive()
}

// send forwards one client packet, queueing it while the flow connects.
func (f *udpFlow) send(b *buf.Buffer) {
	f.touch()
	f.s.mu.Lock()
	select {
	case <-f.ready:
	default:
		if len(f.pending) < pendingPackets {
			f.pending = append(f.pending, b)
		} else {
			b.Release()
		}
		f.s.mu.Unlock()
		return
	}
	failed := f.failed
	f.s.mu.Unlock()
	if failed {
		b.Release()
		return
	}
	f.write(b)
}

func (f *udpFlow) write(b *buf.Buffer) {
	n := int64(b.Len())
	b = N.NewReadWaitOptions(nil, f.remote).Copy(b)
	destination := f.dest
	if f.rt.Destination != nil {
		destination = M.ParseSocksaddr(f.rt.Destination.String())
	}
	if err := f.remote.WritePacket(b, destination); err != nil {
		b.Leak()
		f.close()
		return
	}
	f.up.Add(n)
}

func (f *udpFlow) receive() {
	opts := N.NewReadWaitOptions(f.remote, f.s.conn)
	for {
		b := opts.NewPacketBuffer()
		src, err := f.remote.ReadPacket(b)
		if err != nil {
			b.Release()
			f.close()
			return
		}
		opts.PostReturn(b)
		f.touch()
		n := int64(b.Len())
		if !src.IsValid() || f.rt.Destination != nil {
			src = f.dest
		}
		f.s.writeMu.Lock()
		err = f.s.conn.WritePacket(b, src)
		f.s.writeMu.Unlock()
		if err != nil {
			b.Leak()
			f.s.close(err)
			return
		}
		f.down.Add(n)
	}
}

func (f *udpFlow) close() {
	f.once.Do(func() {
		s := f.s
		s.mu.Lock()
		if s.flows[f.dest] == f {
			delete(s.flows, f.dest)
		}
		remote := f.remote
		s.mu.Unlock()
		if remote != nil {
			remote.Close()
		}
		f.untrack()
		f.rt.Release()
	})
}

// reap closes flows that have been idle for the UDP timeout.
func (s *udpSession) reap() {
	timeout := s.b.udpTimeout
	tick := time.NewTicker(timeout / 4)
	defer tick.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-tick.C:
			s.mu.Lock()
			var idle []*udpFlow
			for _, f := range s.flows {
				if now.Sub(time.Unix(0, f.last.Load())) >= timeout {
					idle = append(idle, f)
				}
			}
			s.mu.Unlock()
			for _, f := range idle {
				f.close()
			}
		}
	}
}
