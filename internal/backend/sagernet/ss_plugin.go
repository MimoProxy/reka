package sagernet

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	JLS "github.com/MimoProxy/reka/internal/compat/jls"
	KC "github.com/MimoProxy/reka/internal/compat/kcptun"
	"github.com/sagernet/sing-box/adapter"
	S "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	OB "github.com/sagernet/sing-box/transport/simple-obfs"
	"github.com/sagernet/sing-box/transport/sip003"
	"github.com/sagernet/sing-box/transport/v2ray"
	SH "github.com/sagernet/sing-shadowtls"
	VM "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/smux"
)

type SSPluginSpec struct {
	Username, ClientFingerprint, VersionHint, RestlsScript string
	ForceTLS12                                             bool
	ALPN                                                   []string
	KCP                                                    *KC.Config

	Type, Mode, Host, Path, Password string
	Version                          int
	TLS                              *TLSSpec
	Mux, HTTPUpgrade, FastOpen       bool
	Headers                          http.Header
}

type ssPluginFactoryKey struct{}

func init() {
	// Only the registry entry is global. Configuration, transport and lifetime
	// are supplied by each outbound's immutable context, never a global node.
	sip003.RegisterPlugin("reka-scoped", func(ctx context.Context, _ sip003.Args, _ adapter.Router, base N.Dialer, dst M.Socksaddr) (sip003.Plugin, error) {
		factory, ok := ctx.Value(ssPluginFactoryKey{}).(func(context.Context, N.Dialer, M.Socksaddr) (sip003.Plugin, error))
		if !ok {
			return nil, errors.New("missing scoped SS plugin factory")
		}
		return factory(ctx, base, dst)
	})
}

type ssPlugin struct {
	dial     func(context.Context) (net.Conn, error)
	resource outboundResource
	once     sync.Once
	err      error
}

func (p *ssPlugin) DialContext(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	sockets := &handshakeSockets{}
	ctx = context.WithValue(ctx, handshakeSocketsKey{}, sockets)
	conn, err := p.dial(ctx)
	if err == nil {
		err = ctx.Err()
	}
	sockets.finish(err != nil)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, err
	}
	return conn, nil
}
func (p *ssPlugin) Close() error {
	p.once.Do(func() {
		if p.resource != nil {
			p.err = p.resource.Close()
		}
	})
	return p.err
}
func (p *ssPlugin) Reset() {
	if p.resource != nil {
		p.resource.Reset()
	}
}
func (p *ssPlugin) SetKeepIdleConnections(keep bool) {
	if p.resource != nil {
		p.resource.SetKeepIdleConnections(keep)
	}
}
func (p *ssPlugin) CloseIdleConnections() {
	if p.resource != nil {
		p.resource.CloseIdleConnections()
	}
}

type handshakeSocketsKey struct{}
type handshakeSockets struct {
	mu          sync.Mutex
	connections []net.Conn
	stops       []func() bool
}

func (s *handshakeSockets) track(ctx context.Context, c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connections = append(s.connections, c)
	s.stops = append(s.stops, context.AfterFunc(ctx, func() { c.Close() }))
}
func (s *handshakeSockets) finish(failed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, stop := range s.stops {
		stop()
	}
	if failed {
		for _, c := range s.connections {
			c.Close()
		}
	}
}

type pluginHandshakeDialer struct{ N.Dialer }

func (d *pluginHandshakeDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	c, err := d.Dialer.DialContext(ctx, network, dst)
	if err == nil {
		if sockets, ok := ctx.Value(handshakeSocketsKey{}).(*handshakeSockets); ok {
			sockets.track(ctx, c)
		}
	}
	return c, err
}

func newSSPlugin(ctx context.Context, logger log.ContextLogger, base N.Dialer, dst M.Socksaddr, s SSPluginSpec) (*ssPlugin, error) {
	if s.TLS != nil && s.TLS.Carrier != nil {
		return nil, errors.New("SS plugin already selects its security carrier")
	}
	base = &pluginHandshakeDialer{base}
	p := &ssPlugin{}
	var tlsConfig S.Config
	if s.Type != "restls" && (s.TLS != nil || s.Type == "shadow-tls") {
		spec := s.TLS
		if spec == nil {
			spec = &TLSSpec{ServerName: s.Host}
		}
		tlsCtx, configured := configureTLSContext(configureECHContext(ctx, spec), spec)
		options := spec.build()
		if s.Type == "shadow-tls" && s.Version == 1 {
			options.MinVersion, options.MaxVersion = "1.2", "1.2"
		}
		var err error
		tlsConfig, err = S.NewClient(tlsCtx, logger, s.Host, *options)
		if err != nil {
			return nil, err
		}
		if configured != nil && !configured.Load() {
			return nil, errors.New("required plugin TLS verification overlay is unavailable")
		}
	}
	switch s.Type {
	case "restls":
		var err error
		p.dial, err = newRestlsPlugin(base, dst, s)
		if err != nil {
			return nil, err
		}
	case "jls":
		config := &JLS.ClientConfig{ServerName: s.Host, User: JLS.User{Username: s.Username, Password: s.Password}, ALPN: s.ALPN, ClientFingerprint: s.ClientFingerprint}
		p.dial = func(ctx context.Context) (net.Conn, error) {
			raw, err := base.DialContext(ctx, "tcp", dst)
			if err != nil {
				return nil, err
			}
			started := time.Now()
			conn, err := JLS.NewClient(ctx, raw, config)
			if err != nil {
				raw.Close()
			} else {
				observeTLS(ctx, raw, started, time.Now(), config.ServerName, "jls")
			}
			return conn, err
		}
	case "kcptun":
		config := KC.Config{}
		if s.KCP != nil {
			config = *s.KCP
		}
		client, err := KC.NewClient(config, func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			pc, err := base.ListenPacket(ctx, dst)
			var remote net.Addr = dst
			if dst.IsIP() {
				remote = dst.UDPAddr()
			}
			return pc, remote, err
		})
		if err != nil {
			return nil, err
		}
		p.resource = client
		p.dial = client.DialContext

	case "obfs":
		p.dial = func(ctx context.Context) (net.Conn, error) {
			c, err := base.DialContext(ctx, "tcp", dst)
			if err != nil {
				return nil, err
			}
			if s.Mode == "tls" {
				return OB.NewTLSObfs(c, s.Host), nil
			}
			key := make([]byte, 16)
			rand.Read(key)
			host := s.Host
			if dst.Port != 80 {
				host = net.JoinHostPort(host, strconv.Itoa(int(dst.Port)))
			}
			return newHTTPObfsConn(c, host, httpObfsOptions{Method: "GET", Headers: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Sec-WebSocket-Key": {base64.URLEncoding.EncodeToString(key)}}}), nil
		}
	case "v2ray-plugin", "gost-plugin":
		headers := s.Headers.Clone()
		if headers == nil {
			headers = http.Header{}
		}
		if headers.Get("Host") == "" {
			headers.Set("Host", s.Host)
		}
		var transport adapter.V2RayClientTransport
		if s.HTTPUpgrade {
			transport = &pluginUpgradeTransport{base: base, dst: dst, host: headers.Get("Host"), path: s.Path, headers: headers, tls: tlsConfig, fast: s.FastOpen}
		} else {
			options := option.V2RayTransportOptions{Type: "ws", WebsocketOptions: option.V2RayWebsocketOptions{Path: s.Path, Headers: map[string]badoption.Listable[string]{}}}
			for key, values := range headers {
				options.WebsocketOptions.Headers[key] = values
			}
			var err error
			transport, err = v2ray.NewClientTransport(ctx, base, dst, options, tlsConfig)
			if err != nil {
				return nil, err
			}
		}
		p.resource = &transportResource{transport}
		p.dial = func(ctx context.Context) (net.Conn, error) {
			conn, err := transport.DialContext(ctx)
			if err != nil {
				return nil, err
			}
			if !s.Mux {
				return conn, nil
			}
			if s.Type == "v2ray-plugin" {
				return &pluginChunkConn{Conn: VM.NewMuxConnWrapper(conn, M.Socksaddr{Addr: netip.MustParseAddr("127.0.0.1")})}, nil
			}
			config := smux.DefaultConfig()
			config.KeepAliveDisabled = true
			session, err := smux.Client(conn, config)
			if err != nil {
				conn.Close()
				return nil, err
			}
			stream, err := session.OpenStream()
			if err != nil {
				session.Close()
				return nil, err
			}
			return &pluginSessionConn{Conn: stream, session: session}, nil
		}
	case "shadow-tls":
		handshake := func(ctx context.Context, c net.Conn, generator SH.TLSSessionIDGeneratorFunc) error {
			config := tlsConfig.Clone()
			handshakeTLS := func(conn net.Conn) (S.Conn, error) {
				started := time.Now()
				tlsConn, err := S.ClientHandshake(ctx, conn, config)
				if err == nil {
					observeTLS(ctx, c, started, time.Now(), tlsConn.ConnectionState().ServerName, "shadowtls")
				}
				return tlsConn, err
			}
			if s.Version == 2 {
				setter, ok := c.(interface{ SetPostHandshakeConn(func(net.Conn) net.Conn) })
				if !ok {
					return errors.New("required ShadowTLS v2 record transition overlay is unavailable")
				}
				recorder := &shadowTLSV2Recorder{Conn: c}
				tlsConn, err := handshakeTLS(recorder)
				if err != nil {
					return err
				}
				recorder.finished = true
				setter.SetPostHandshakeConn(func(raw net.Conn) net.Conn {
					return &shadowTLSV2DataConn{Conn: raw, tls: tlsConn, recorder: recorder}
				})
				return nil
			}
			if s.Version != 3 {
				return common.Error(handshakeTLS(c))
			}
			if customizable, ok := config.(S.WithSessionIDGenerator); ok {
				customizable.SetSessionIDGenerator(generator)
				return common.Error(handshakeTLS(c))
			}
			standard, err := config.STDConfig()
			if err != nil {
				return err
			}
			tlsHandshake := SH.DefaultTLSHandshakeFunc(s.Password, standard)
			started := time.Now()
			err = tlsHandshake(ctx, c, generator)
			if err == nil {
				observeTLS(ctx, c, started, time.Now(), standard.ServerName, "shadowtls")
			}
			return err
		}
		client, err := SH.NewClient(SH.ClientConfig{Version: s.Version, Password: s.Password, Server: dst, Dialer: base, TLSHandshake: handshake, Logger: logger})
		if err != nil {
			return nil, err
		}
		p.dial = client.DialContext
	default:
		return nil, errors.New("unsupported scoped SS plugin")
	}
	return p, nil
}

type transportResource struct{ adapter.V2RayClientTransport }

func (t *transportResource) Reset()                      { t.Close() }
func (t *transportResource) SetKeepIdleConnections(bool) {}
func (t *transportResource) CloseIdleConnections()       {}

type pluginSessionConn struct {
	net.Conn
	session *smux.Session
}

func (c *pluginSessionConn) Close() error { return c.session.Close() }

type pluginChunkConn struct {
	net.Conn
	mu sync.Mutex
}

func (c *pluginChunkConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := 0
	for len(p) > 0 {
		size := min(len(p), 32768)
		n, err := c.Conn.Write(p[:size])
		total += n
		if err != nil {
			return total, err
		}
		if n != size {
			return total, io.ErrShortWrite
		}
		p = p[size:]
	}
	return total, nil
}
