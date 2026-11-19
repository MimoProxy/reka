package sagernet

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MimoProxy/reka/internal/history"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
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
	s            *udpSession
	ctx          context.Context
	cancel       context.CancelFunc
	dest         M.Socksaddr
	md           Metadata
	prepared     PreparedFlow
	attempt      *connectionAttempt
	sniff        SniffOptions
	rt           Route
	remote       N.PacketConn
	ready        chan struct{} // closed once remote is set or the dial failed
	pending      []*buf.Buffer
	pendingBytes int
	notify       chan struct{}
	readyOnce    sync.Once
	sendMu       sync.Mutex
	failed       bool

	processTraffic *processTrafficCounter
	up, down       atomic.Int64
	last           atomic.Int64
	once           sync.Once
	untrack        func()
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
		f.closeWithReason(connectionReason(err, "eof"), "")
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
	md.InboundProtocol = inboundProtocol(s.ctx, md.InboundType)
	md.Network = N.NetworkUDP
	md.Destination = toDestination(dest)
	ctx, cancel := context.WithCancel(s.ctx)
	attempt := s.b.beginConnection(md)
	ctx = history.WithFlow(ctx, attempt.ID)
	prepared := s.r.prepareFlow(ctx, md)
	f := &udpFlow{attempt: attempt, s: s, ctx: ctx, cancel: cancel, dest: dest, md: md, prepared: prepared, sniff: prepared.Sniff, ready: make(chan struct{}), notify: make(chan struct{}, 1)}
	f.touch()
	s.flows[dest] = f
	go f.routeAndDial()
	return f
}

func (f *udpFlow) touch() { f.last.Store(time.Now().UnixNano()) }

func (f *udpFlow) routeAndDial() {
	prepared := f.prepared
	f.prepared = PreparedFlow{}
	defer prepared.Release()
	md := f.md
	if prepared.Sniff.Enabled && prepared.Sniff.protocol("quic") && f.s.r.takeSniffSlot() {
		md = f.sniffQUIC(md, prepared.Sniff)
		f.s.r.releaseSniffSlot()
	}
	if f.ctx.Err() != nil {
		f.closeWithReason(connectionReason(f.ctx.Err(), "cancelled"), "route")
		return
	}
	rt := prepared.pick(f.ctx, md)
	prepared.Release()
	if prepared.Sniff.OverrideDestination && md.SniffedDomain != "" && rt.Outbound != nil {
		destination := Destination{Domain: md.SniffedDomain, Port: md.Destination.Port}
		rt.Destination = &destination
	}
	f.s.mu.Lock()
	if f.failed {
		f.s.mu.Unlock()
		if rt.Release != nil {
			rt.Release()
		}
		return
	}
	f.attempt.setRoute(rt)
	if rt.Outbound == nil {
		f.s.rejected[f.dest] = time.Now()
		f.s.mu.Unlock()
		f.closeWithReason("rejected", "route")
		return
	}
	f.md, f.rt = md, rt
	var finishProcess func()
	f.processTraffic, finishProcess = f.s.b.beginProcessTraffic(rt.Owner)
	untrack := f.s.b.conns.add(&tracked{id: f.attempt.ID, start: time.Now(), md: md, out: rt.Outbound, info: rt.Info, up: &f.up, down: &f.down, close: f.close})
	f.untrack = func() { untrack(); finishProcess() }
	f.s.mu.Unlock()
	f.dial()
}

// sniffQUIC examines only packets retained in the ordinary flow queue. Each
// datagram is copied before parsing so closing the flow can release buffers
// immediately. The sing-box parser carries fragmented CRYPTO state in parsed.
func (f *udpFlow) sniffQUIC(md Metadata, o SniffOptions) Metadata {
	timer := time.NewTimer(o.Timeout)
	defer timer.Stop()
	var parsed adapter.InboundContext
	index, total := 0, 0
	for index < o.MaxPackets && total < o.MaxBytes {
		select {
		case <-f.ctx.Done():
			return md
		case <-timer.C:
			return md
		default:
		}
		f.s.mu.Lock()
		if f.failed {
			f.s.mu.Unlock()
			return md
		}
		var packet []byte
		if index < len(f.pending) {
			b := f.pending[index]
			if b.Len() > o.MaxBytes-total {
				f.s.mu.Unlock()
				return md
			}
			packet = make([]byte, b.Len())
			copy(packet, b.Bytes())
		}
		f.s.mu.Unlock()
		if packet == nil {
			select {
			case <-f.ctx.Done():
				return md
			case <-timer.C:
				return md
			case <-f.notify:
				continue
			}
		}
		index++
		total += len(packet)
		err := sniff.QUICClientHello(f.ctx, &parsed, packet)
		if err == nil {
			return sniffResult(md, parsed)
		}
		if !errors.Is(err, sniff.ErrNeedMoreData) {
			return md
		}
	}
	return md
}

func (f *udpFlow) dial() {
	s := f.s
	metadata := s.metadata
	metadata.Destination = f.dest
	metadata.Network = N.NetworkUDP
	metadata.Domain, metadata.Protocol = f.md.SniffedDomain, f.md.Protocol
	ctx := f.ctx
	if f.rt.Context != nil {
		ctx = f.rt.Context(ctx)
	}
	ctx = adapter.WithContext(ctx, &metadata)
	ctx = WithLookup(ctx, f.rt.Lookup)
	dialDest := f.dest
	if f.rt.Destination != nil {
		dialDest = M.ParseSocksaddr(f.rt.Destination.String())
	}
	dialStart := time.Now()
	remote, err := f.rt.Outbound.out.ListenPacket(ctx, dialDest)
	f.sendMu.Lock()
	s.mu.Lock()
	if f.failed {
		s.mu.Unlock()
		if remote != nil {
			remote.Close()
		}
		f.sendMu.Unlock()
		return
	}
	f.attempt.dialed(dialStart, err)
	if err != nil {
		f.sendMu.Unlock()
		f.failed = true
	} else {
		f.remote = bufio.NewPacketConn(remote)
	}
	pending := f.pending
	f.pending = nil
	f.pendingBytes = 0
	f.readyOnce.Do(func() { close(f.ready) })
	s.mu.Unlock()
	if err != nil {
		if remote != nil {
			remote.Close()
		}
		for _, b := range pending {
			b.Release()
		}
		s.b.logger.ErrorContext(ctx, E.Cause(err, "open packet connection to ", f.dest, " using outbound/", f.rt.Outbound.Type(), "[", f.rt.Outbound.Tag(), "]"))
		f.closeWithReason(connectionReason(err, "error"), "dial")
		return
	}
	for _, b := range pending {
		f.writeLocked(b)
	}
	f.sendMu.Unlock()
	go f.receive()
}

// send forwards one client packet, queueing it while the flow connects.
func (f *udpFlow) send(b *buf.Buffer) {
	f.touch()
	f.s.mu.Lock()
	if f.failed {
		f.s.mu.Unlock()
		b.Release()
		return
	}
	select {
	case <-f.ready:
	default:
		limit := pendingPackets
		if f.sniff.Enabled {
			limit = max(limit, f.sniff.MaxPackets)
		}
		withinBytes := !f.sniff.Enabled || len(f.pending) == 0 || f.pendingBytes+b.Len() <= f.sniff.MaxBytes
		if len(f.pending) < limit && withinBytes {
			f.pending = append(f.pending, b)
			f.pendingBytes += b.Len()
			select {
			case f.notify <- struct{}{}:
			default:
			}
		} else {
			b.Release()
		}
		f.s.mu.Unlock()
		return
	}
	f.s.mu.Unlock()
	f.write(b)
}

func (f *udpFlow) write(b *buf.Buffer) {
	f.sendMu.Lock()
	defer f.sendMu.Unlock()
	f.writeLocked(b)
}

func (f *udpFlow) writeLocked(b *buf.Buffer) {
	f.s.mu.Lock()
	failed := f.failed
	f.s.mu.Unlock()
	if failed {
		b.Release()
		return
	}
	n := int64(b.Len())
	b = N.NewReadWaitOptions(nil, f.remote).Copy(b)
	destination := f.dest
	if f.rt.Destination != nil {
		destination = M.ParseSocksaddr(f.rt.Destination.String())
	}
	if err := f.remote.WritePacket(b, destination); err != nil {
		b.Leak()
		f.closeWithReason(connectionReason(err, "error"), "relay")
		return
	}
	f.up.Add(n)
	f.s.b.trafficUpload.Add(uint64(n))
	f.processTraffic.upload.Add(uint64(n))
}

func (f *udpFlow) receive() {
	opts := N.NewReadWaitOptions(f.remote, f.s.conn)
	for {
		b := opts.NewPacketBuffer()
		src, err := f.remote.ReadPacket(b)
		if err != nil {
			b.Release()
			f.closeWithReason(connectionReason(err, "error"), "relay")
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
		f.s.b.trafficDownload.Add(uint64(n))
		f.processTraffic.download.Add(uint64(n))
	}
}

func (f *udpFlow) close() { f.closeWithReason("manual", "") }

func (f *udpFlow) closeWithReason(reason, stage string) {
	f.once.Do(func() {
		s := f.s
		s.mu.Lock()
		f.failed = true
		if s.flows[f.dest] == f {
			delete(s.flows, f.dest)
		}
		remote := f.remote
		pending := f.pending
		f.pending = nil
		f.pendingBytes = 0
		untrack, release := f.untrack, f.rt.Release
		f.readyOnce.Do(func() { close(f.ready) })
		s.mu.Unlock()
		f.cancel()
		for _, b := range pending {
			b.Release()
		}
		if remote != nil {
			remote.Close()
		}
		if untrack != nil {
			untrack()
		}
		if release != nil {
			release()
		}
		f.attempt.complete(reason, stage, f.up.Load(), f.down.Load())
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
				f.closeWithReason("idle_timeout", "")
			}
		}
	}
}
