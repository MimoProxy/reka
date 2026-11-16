package sagernet

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	JT "github.com/metacubex/jls-tls"
	RT "github.com/metacubex/restls-client-go"
	UT "github.com/metacubex/utls"
	S "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	ST "github.com/sagernet/sing/common/tls"
)

type TLSCarrierSpec struct {
	Type, Username, Password, VersionHint, Script string
	Version                                       int
}

func configureTLSCarrierContext(ctx context.Context, s *TLSSpec) (context.Context, *atomic.Bool) {
	if s == nil || s.Carrier == nil {
		return ctx, nil
	}
	configured := &atomic.Bool{}
	factory := func(_ context.Context, log logger.ContextLogger, server string, options option.OutboundTLSOptions) (S.Config, error) {
		if s.Reality != nil || s.ECH != nil {
			return nil, errors.New("TLS security carriers are mutually exclusive with REALITY and ECH")
		}
		configured.Store(true)
		copy := *s
		copy.ALPN = slices.Clone(s.ALPN)
		if options.ServerName != "" {
			copy.ServerName = options.ServerName
		} else if copy.ServerName == "" {
			copy.ServerName = server
		}
		if options.ALPN != nil {
			copy.ALPN = slices.Clone(options.ALPN)
		}
		return &carrierTLSConfig{spec: copy, logger: log, timeout: 15 * time.Second}, nil
	}
	return context.WithValue(ctx, "reka.tls.client.v1", factory), configured
}

type carrierTLSConfig struct {
	mu      sync.Mutex
	spec    TLSSpec
	logger  logger.ContextLogger
	timeout time.Duration
}

func (c *carrierTLSConfig) ServerName() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.spec.ServerName
}
func (c *carrierTLSConfig) SetServerName(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.spec.ServerName = name
}
func (c *carrierTLSConfig) NextProtos() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.spec.ALPN)
}
func (c *carrierTLSConfig) SetNextProtos(values []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.spec.ALPN = slices.Clone(values)
}
func (c *carrierTLSConfig) HandshakeTimeout() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.timeout
}
func (c *carrierTLSConfig) SetHandshakeTimeout(timeout time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timeout = timeout
}
func (c *carrierTLSConfig) STDConfig() (*tls.Config, error) {
	return nil, errors.New("this security carrier requires its own handshake")
}
func (c *carrierTLSConfig) Clone() S.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	copy := c.spec
	copy.ALPN = slices.Clone(copy.ALPN)
	return &carrierTLSConfig{spec: copy, logger: c.logger, timeout: c.timeout}
}
func (c *carrierTLSConfig) Client(raw net.Conn) (S.Conn, error) {
	clone := c.Clone().(*carrierTLSConfig)
	lazy := ST.NewLazyConn(raw, &carrierServerAdapter{client: clone})
	return &lazyCarrierConn{LazyConn: lazy, raw: raw}, nil
}
func (c *carrierTLSConfig) ClientHandshake(ctx context.Context, raw net.Conn) (S.Conn, error) {
	clone := c.Clone().(*carrierTLSConfig)
	if clone.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, clone.timeout)
		defer cancel()
	}
	spec := clone.spec
	carrier := spec.Carrier
	spec.Carrier = nil
	plugin := SSPluginSpec{Type: carrier.Type, Host: spec.ServerName, Version: carrier.Version, Password: carrier.Password, Username: carrier.Username, VersionHint: carrier.VersionHint, RestlsScript: carrier.Script, ALPN: spec.ALPN, ClientFingerprint: spec.Fingerprint}
	if carrier.Type != "jls" {
		if carrier.Type == "restls" {
			spec.Fingerprint = ""
		}
		plugin.TLS = &spec
	}
	// The physical socket has already traversed ProtectFD/interface/detour.
	// Its security handshake must not recursively request another carrier.
	ctx = context.WithValue(ctx, "reka.tls.client.v1", nil)
	p, err := newSSPlugin(ctx, clone.logger, &existingSocketDialer{raw: raw}, M.SocksaddrFromNet(raw.RemoteAddr()), plugin)
	if err != nil {
		raw.Close()
		return nil, err
	}
	conn, err := p.DialContext(ctx)
	if err != nil {
		raw.Close()
		return nil, err
	}
	state := tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, ServerName: spec.ServerName}
	switch typed := conn.(type) {
	case *RT.UConn:
		v := typed.ConnectionState()
		state.Version = v.Version
		state.NegotiatedProtocol = v.NegotiatedProtocol
		state.PeerCertificates = v.PeerCertificates
	case *JT.Conn:
		v := typed.ConnectionState()
		state.Version = v.Version
		state.NegotiatedProtocol = v.NegotiatedProtocol
		state.PeerCertificates = v.PeerCertificates
	case *UT.UConn:
		v := typed.ConnectionState()
		state.Version = v.Version
		state.NegotiatedProtocol = v.NegotiatedProtocol
		state.PeerCertificates = v.PeerCertificates
	default:
		if len(spec.ALPN) > 0 {
			state.NegotiatedProtocol = spec.ALPN[0]
		}
		if carrier.Type == "shadow-tls" && carrier.Version == 1 {
			state.Version = tls.VersionTLS12
		}
	}
	return &carrierConn{Conn: conn, raw: raw, state: state}, nil
}

type existingSocketDialer struct {
	raw  net.Conn
	used bool
	mu   sync.Mutex
}

func (d *existingSocketDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.used {
		return nil, errors.New("security carrier tried to redial a protected socket")
	}
	d.used = true
	return d.raw, nil
}
func (d *existingSocketDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("security carrier requires a stream")
}

type carrierConn struct {
	net.Conn
	raw   net.Conn
	state tls.ConnectionState
}

func (c *carrierConn) NetConn() net.Conn                      { return c.raw }
func (c *carrierConn) HandshakeContext(context.Context) error { return nil }
func (c *carrierConn) ConnectionState() tls.ConnectionState   { return c.state }
func (c *carrierConn) Upstream() any                          { return c.Conn }
func (c *carrierConn) ReaderReplaceable() bool                { return true }
func (c *carrierConn) WriterReplaceable() bool                { return true }

type carrierServerAdapter struct {
	ST.ServerConfig
	client *carrierTLSConfig
}

func (c *carrierServerAdapter) HandshakeTimeout() time.Duration { return c.client.HandshakeTimeout() }
func (c *carrierServerAdapter) ServerHandshake(ctx context.Context, raw net.Conn) (ST.Conn, error) {
	return c.client.ClientHandshake(ctx, raw)
}

type lazyCarrierConn struct {
	*ST.LazyConn
	raw net.Conn
}

func (c *lazyCarrierConn) NetConn() net.Conn { return c.raw }
func (c *lazyCarrierConn) ConnectionState() tls.ConnectionState {
	if conn, ok := c.Upstream().(S.Conn); ok {
		return conn.ConnectionState()
	}
	return tls.ConnectionState{}
}
