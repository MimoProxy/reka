package sagernet

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	M "github.com/sagernet/sing/common/metadata"
)

// SniffOptions belongs to a prepared flow's immutable configuration. Parsing
// only supplies a routing hint unless OverrideDestination is explicitly set.
type SniffOptions struct {
	Enabled             bool
	Protocols           []string
	Timeout             time.Duration
	MaxBytes            int
	MaxPackets          int
	OverrideDestination bool
	SkipDomain          func(string) bool
}

// PreparedFlow pins the routing generation while bounded sniffing takes place.
// Route must acquire the chosen outbound's own lease before returning. Release
// releases preparation resources, independently of the returned Route.Release.
type PreparedFlow struct {
	Sniff   SniffOptions
	Route   RouteFunc
	Release func()
}

type PrepareFlowFunc func(context.Context, Metadata) PreparedFlow

// SetPrepareFlow installs a generation-aware flow preparation callback. A nil
// callback restores the ordinary SetRoute path.
func (b *Backend) SetPrepareFlow(fn PrepareFlowFunc) { b.router.prepare.Store(&fn) }

func (r *router) prepareFlow(ctx context.Context, md Metadata) PreparedFlow {
	if fn := r.prepare.Load(); fn != nil && *fn != nil {
		p := (*fn)(ctx, md)
		p.Sniff = p.Sniff.normalized()
		if p.Release != nil {
			release := p.Release
			var once sync.Once
			p.Release = func() { once.Do(release) }
		} else {
			p.Release = func() {}
		}
		return p
	}
	var route RouteFunc
	if fn := r.route.Load(); fn != nil {
		route = *fn
	}
	return PreparedFlow{Route: route, Release: func() {}}
}

func (p PreparedFlow) pick(ctx context.Context, md Metadata) Route {
	if p.Route == nil {
		return Route{}
	}
	return normalizeRoute(p.Route(ctx, md))
}

func (r *router) takeSniffSlot() bool {
	r.sniffOnce.Do(func() { r.sniffSlots = make(chan struct{}, 64) })
	select {
	case r.sniffSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (r *router) releaseSniffSlot() { <-r.sniffSlots }

func (o SniffOptions) normalized() SniffOptions {
	if len(o.Protocols) == 0 {
		o.Protocols = []string{"http", "tls", "quic"}
	}
	if o.Timeout <= 0 {
		o.Timeout = 300 * time.Millisecond
	}
	if o.Timeout > 5*time.Second {
		o.Timeout = 5 * time.Second
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = 65536
	}
	if o.MaxBytes > 262144 {
		o.MaxBytes = 262144
	}
	if o.MaxPackets <= 0 {
		o.MaxPackets = 8
	}
	if o.MaxPackets > 32 {
		o.MaxPackets = 32
	}
	return o
}

func (o SniffOptions) protocol(name string) bool {
	for _, p := range o.Protocols {
		if strings.EqualFold(p, name) {
			return true
		}
	}
	return false
}

func (o SniffOptions) streamEligible(md Metadata) bool {
	if !o.Enabled || (!o.protocol("http") && !o.protocol("tls")) {
		return false
	}
	// FTP, SSH, Telnet, MySQL and VNC do not need domain recovery and may
	// wait for a server greeting before sending application bytes.
	switch md.Destination.Port {
	case 21, 22, 23, 3306, 5900:
		return false
	}
	return !sniff.Skip(&adapter.InboundContext{Destination: M.Socksaddr{Port: md.Destination.Port}})
}

func sniffResult(md Metadata, parsed adapter.InboundContext, options SniffOptions) Metadata {
	domain := strings.ToLower(strings.TrimSuffix(parsed.Domain, "."))
	if options.SkipDomain != nil && options.SkipDomain(domain) {
		return md
	}
	md.Protocol = parsed.Protocol
	if _, err := netip.ParseAddr(domain); domain != "" && err != nil && M.IsDomainName(domain) {
		md.SniffedDomain = domain
	}
	return md
}

// sniffStream retains every read byte, including malformed/unknown input and
// partial records at the timeout. The wrapper forwards half-close operations
// and releases its prefix when consumed or closed.
func sniffStream(ctx context.Context, conn net.Conn, md Metadata, o SniffOptions) (net.Conn, Metadata) {
	o = o.normalized()
	if !o.streamEligible(md) {
		return conn, md
	}
	deadline := time.Now().Add(o.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return conn, md
	}
	cancelled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetReadDeadline(time.Now())
		close(cancelled)
	})
	defer func() {
		if !stop() {
			<-cancelled
		}
		_ = conn.SetReadDeadline(time.Time{})
	}()
	var prefix []byte
	for len(prefix) < o.MaxBytes && ctx.Err() == nil {
		chunk := make([]byte, min(4096, o.MaxBytes-len(prefix)))
		n, readErr := conn.Read(chunk)
		prefix = append(prefix, chunk[:n]...)
		if n > 0 {
			var parsed adapter.InboundContext
			var parseErr error
			switch {
			case prefix[0] == 0x16 && o.protocol("tls"):
				parseErr = sniff.TLSClientHello(ctx, &parsed, bytes.NewReader(prefix))
			case prefix[0] >= 'A' && prefix[0] <= 'Z' && o.protocol("http"):
				if !bytes.Contains(prefix, []byte("\r\n\r\n")) {
					parseErr = sniff.ErrNeedMoreData
				} else {
					parseErr = sniff.HTTPHost(ctx, &parsed, bytes.NewReader(prefix))
				}
			default:
				parseErr = errors.New("unrecognized stream")
			}
			if parseErr == nil {
				md = sniffResult(md, parsed, o)
				break
			}
			if !errors.Is(parseErr, sniff.ErrNeedMoreData) && !errors.Is(parseErr, io.ErrUnexpectedEOF) && !errors.Is(parseErr, io.EOF) {
				break
			}
		}
		if readErr != nil || n == 0 {
			break
		}
	}
	if len(prefix) == 0 {
		return conn, md
	}
	return &sniffReplayConn{Conn: conn, prefix: prefix}, md
}

type sniffReplayConn struct {
	net.Conn
	mu     sync.Mutex
	prefix []byte
}

func (c *sniffReplayConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			c.prefix = nil
		}
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.Conn.Read(p)
}

func (c *sniffReplayConn) Close() error {
	c.mu.Lock()
	c.prefix = nil
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *sniffReplayConn) Upstream() any { return c.Conn }

func (c *sniffReplayConn) ReaderReplaceable() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.prefix) == 0
}

func (c *sniffReplayConn) WriterReplaceable() bool { return true }
