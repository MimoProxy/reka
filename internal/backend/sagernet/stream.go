package sagernet

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	S "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type httpObfsOptions struct {
	Method  string      `json:"method"`
	Paths   []string    `json:"paths"`
	Host    string      `json:"host"`
	Headers http.Header `json:"headers"`
}

// streamContext inserts a generation-local physical stream decorator. Packet
// sockets still use the original dialer (SOCKS UDP ASSOCIATE is not TLS).
func streamContext(ctx context.Context, logger log.ContextLogger, values map[string]any, server string, port uint16) (context.Context, error) {
	var obfs *httpObfsOptions
	if value, ok := values["reka_http"]; ok {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		obfs = &httpObfsOptions{}
		if err = json.Unmarshal(raw, obfs); err != nil {
			return nil, err
		}
		delete(values, "reka_http")
	}
	socksTLS := values["version"] == "5" && values["tls"] != nil
	if obfs == nil && !socksTLS {
		return ctx, nil
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	var opts option.DialerOptions
	if err = json.Unmarshal(raw, &opts); err != nil {
		return nil, err
	}
	base, err := dialer.New(ctx, opts, M.ParseSocksaddrHostPort(server, port).IsDomain())
	if err != nil {
		return nil, err
	}
	stream := N.Dialer(base)
	if value := values["tls"]; value != nil {
		raw, err = json.Marshal(value)
		if err != nil {
			return nil, err
		}
		var tlsOptions option.OutboundTLSOptions
		if err = json.Unmarshal(raw, &tlsOptions); err != nil {
			return nil, err
		}
		if obfs != nil && len(tlsOptions.ALPN) == 0 {
			tlsOptions.ALPN = []string{"http/1.1"}
		}
		stream, err = S.NewDialerFromOptions(ctx, logger, base, server, tlsOptions)
		if err != nil {
			return nil, err
		}
		delete(values, "tls")
	}
	wrapped := &decoratedStream{Adapter: outbound.NewAdapter("direct", "reka-stream", []string{"tcp", "udp"}, nil), base: base, stream: stream, http: obfs, host: server}
	ctx = service.ExtendContext(ctx)
	service.MustRegister[adapter.OutboundManager](ctx, &singleOutboundManager{out: wrapped})
	// The physical options already belong to base. Re-applying them above a
	// detour would either be rejected or apply protection twice.
	for _, key := range []string{"bind_interface", "routing_mark", "tcp_fast_open", "tcp_multi_path", "domain_strategy"} {
		delete(values, key)
	}
	values["detour"] = "reka-stream"
	return ctx, nil
}

type singleOutboundManager struct{ out adapter.Outbound }

func (m *singleOutboundManager) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (m *singleOutboundManager) Outbounds() []adapter.Outbound                  { return []adapter.Outbound{m.out} }
func (m *singleOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	return m.out, tag == m.out.Tag()
}
func (m *singleOutboundManager) Default() adapter.Outbound { return m.out }
func (m *singleOutboundManager) Create(context.Context, adapter.Router, log.ContextLogger, string, string, any) error {
	return fmt.Errorf("fixed internal stream")
}

type decoratedStream struct {
	outbound.Adapter
	base, stream N.Dialer
	http         *httpObfsOptions
	host         string
}

func (d *decoratedStream) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return d.base.DialContext(ctx, network, dst)
	}
	c, err := d.stream.DialContext(ctx, network, dst)
	if err != nil {
		return nil, err
	}
	if d.http != nil && N.NetworkName(network) == N.NetworkTCP {
		c = newHTTPObfsConn(c, d.host, *d.http)
	}
	return c, nil
}
func (d *decoratedStream) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	return d.base.ListenPacket(ctx, dst)
}

// Clash HTTP obfuscation sends the first protocol write as a fixed-length
// request body, then switches to a raw stream. Lists select one value per
// connection. Keep buffered response bytes, including protocol handshake data.
type httpObfsConn struct {
	net.Conn
	opts     httpObfsOptions
	host     string
	reader   *bufio.Reader
	readOnce sync.Once
	readErr  error
	writeMu  sync.Mutex
	written  bool
}

func newHTTPObfsConn(c net.Conn, host string, o httpObfsOptions) net.Conn {
	return &httpObfsConn{Conn: c, host: host, opts: o}
}
func (c *httpObfsConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() {
		c.reader = bufio.NewReader(c.Conn)
		reader := textproto.NewReader(c.reader)
		_, c.readErr = reader.ReadLine()
		if c.readErr == nil {
			_, c.readErr = reader.ReadMIMEHeader()
		}
	})
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.reader.Read(p)
}
func (c *httpObfsConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.written {
		return c.Conn.Write(p)
	}
	path := "/"
	if len(c.opts.Paths) > 0 {
		path = c.opts.Paths[rand.IntN(len(c.opts.Paths))]
	}
	headers := http.Header{}
	for k, values := range c.opts.Headers {
		if len(values) > 0 {
			headers.Set(k, values[rand.IntN(len(values))])
		}
	}
	host := c.host
	if c.opts.Host != "" {
		host = c.opts.Host
	}
	if h := headers.Get("Host"); h != "" {
		host = h
	}
	request := &http.Request{Method: c.opts.Method, Host: host, URL: &url.URL{Scheme: "http", Host: host, Path: path}, Header: headers, Body: io.NopCloser(bytes.NewReader(p)), ContentLength: int64(len(p))}
	if err := request.Write(c.Conn); err != nil {
		return 0, err
	}
	c.written = true
	return len(p), nil
}
