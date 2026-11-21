package sagernet

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"github.com/sagernet/sing-box/adapter"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	KC "github.com/MimoProxy/reka/internal/compat/kcptun"
	"github.com/MimoProxy/reka/internal/testnet"
	JT "github.com/metacubex/jls-tls"
	"github.com/metacubex/kcp-go"
	RT "github.com/metacubex/restls-client-go"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/smux"
)

func legacyPluginCases() []SSPluginSpec {
	var cases []SSPluginSpec
	for _, version := range []string{"tls12", "tls13"} {
		for _, fp := range []string{"chrome", "firefox"} {
			cases = append(cases, SSPluginSpec{Type: "restls", VersionHint: version, ClientFingerprint: fp, Password: "plugin-secret"})
		}
	}
	cases = append(cases, SSPluginSpec{Type: "restls", VersionHint: "tls13", Password: "plugin-secret", RestlsScript: "100?20<1,300~100,500~200"}, SSPluginSpec{Type: "restls", VersionHint: "tls12", Password: "plugin-secret", ForceTLS12: true})
	for _, fp := range []string{"", "chrome", "firefox"} {
		cases = append(cases, SSPluginSpec{Type: "jls", Username: "plugin-user", Password: "plugin-secret", ClientFingerprint: fp})
	}
	cases = append(cases, SSPluginSpec{Type: "jls", Username: "plugin-user", Password: "plugin-secret", ClientFingerprint: "chrome", ALPN: []string{}})
	for _, crypt := range []string{"aes", "aes-128", "aes-192", "aes-128-gcm", "null", "none", "tea", "xor", "blowfish", "twofish", "cast5", "3des", "xtea", "salsa20"} {
		cases = append(cases, SSPluginSpec{Type: "kcptun", KCP: &KC.Config{Key: "plugin-secret", Crypt: crypt}})
	}
	for _, version := range []int{1, 2} {
		for _, comp := range []bool{false, true} {
			cases = append(cases, SSPluginSpec{Type: "kcptun", KCP: &KC.Config{Key: "plugin-secret", SmuxVer: version, NoComp: comp, Mode: "manual", NoDelay: 1, Interval: 10, Resend: 2, NoCongestion: 1, MTU: 1200, SndWnd: 64, RcvWnd: 256, DataShard: 5, ParityShard: 2, FrameSize: 4096, SmuxBuf: 1 << 20, StreamBuf: 256 << 10, KeepAlive: 2}})
		}
	}
	return cases
}

func legacyPluginPeer(t *testing.T, s SSPluginSpec, ss netip.AddrPort) (uint16, *TLSSpec) {
	t.Helper()
	forward := pluginForwardHandler{target: ss.String()}
	var mu sync.Mutex
	var sockets []net.Conn
	track := func(c net.Conn) { mu.Lock(); sockets = append(sockets, c); mu.Unlock() }
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range sockets {
			c.Close()
		}
	})
	if s.Type == "kcptun" {
		cfg := KC.Config{}
		if s.KCP != nil {
			cfg = *s.KCP
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatal(err)
		}
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pc.Close() })
		listener, err := kcp.ServeConn(cfg.NewBlock(), cfg.DataShard, cfg.ParityShard, pc)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			for {
				c, err := listener.AcceptKCP()
				if err != nil {
					return
				}
				track(c)
				c.SetStreamMode(true)
				c.SetWriteDelay(false)
				c.SetNoDelay(cfg.NoDelay, cfg.Interval, cfg.Resend, cfg.NoCongestion)
				c.SetWindowSize(cfg.SndWnd, cfg.RcvWnd)
				c.SetMtu(cfg.MTU)
				c.SetACKNoDelay(cfg.AckNodelay)
				c.SetRateLimit(uint32(cfg.RateLimit))
				go func() {
					var raw net.Conn = c
					if !cfg.NoComp {
						raw = KC.NewCompStream(raw)
					}
					opts := smux.DefaultConfig()
					opts.Version = cfg.SmuxVer
					opts.MaxReceiveBuffer = cfg.SmuxBuf
					opts.MaxStreamBuffer = cfg.StreamBuf
					opts.MaxFrameSize = cfg.FrameSize
					session, err := smux.Server(raw, opts)
					if err != nil {
						raw.Close()
						return
					}
					defer session.Close()
					for {
						stream, err := session.AcceptStream()
						if err != nil {
							return
						}
						forward.NewConnectionEx(context.Background(), stream, M.Socksaddr{}, M.Socksaddr{}, nil)
					}
				}()
			}
		}()
		return uint16(pc.LocalAddr().(*net.UDPAddr).Port), nil
	}
	listener, front := testnet.ListenTCPUDP(t)
	pluginUDPFront(t, front, ss.String())
	var handshake func(context.Context, net.Conn) (net.Conn, error)
	var clientTLS *TLSSpec
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	target.EnableHTTP2 = true
	if s.Type == "restls" {
		version := uint16(tls.VersionTLS13)
		if s.VersionHint == "tls12" {
			version = tls.VersionTLS12
		}
		target.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
	}
	target.StartTLS()
	t.Cleanup(target.Close)
	if s.Type == "restls" {
		digest := sha256.Sum256(target.TLS.Certificates[0].Certificate[0])
		clientTLS = &TLSSpec{ServerName: "plugin.test", CertificatePin: hex.EncodeToString(digest[:])}
		config := &RT.RestlsServerConfig{ServerHostname: target.Listener.Addr().String(), Password: s.Password, RestlsScript: s.RestlsScript}
		handshake = func(ctx context.Context, c net.Conn) (net.Conn, error) { return RT.RestlsServer(ctx, c, config) }
	} else {
		certificate := target.TLS.Certificates[0]
		config := &JT.Config{Certificates: []JT.Certificate{{Certificate: certificate.Certificate, PrivateKey: certificate.PrivateKey}}, MinVersion: JT.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}, JLSConfig: &JT.JLSConfig{Enable: true, Users: []JT.JLSUser{{Username: s.Username, Password: s.Password}}, ServerName: "plugin.test"}}
		handshake = func(ctx context.Context, raw net.Conn) (net.Conn, error) {
			c := JT.Server(raw, config)
			if err := c.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			if c.ConnectionState().JLS.Status != JT.JLSAuthenticated {
				return nil, fmt.Errorf("unauthenticated JLS")
			}
			return c, nil
		}
	}
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			track(raw)
			go func() {
				ctx := context.Background()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				c, err := handshake(ctx, raw)
				raw.SetDeadline(time.Time{})
				if err != nil {
					raw.Close()
					return
				}
				forward.NewConnectionEx(context.Background(), c, M.Socksaddr{}, M.Socksaddr{}, nil)
			}()
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port), clientTLS
}

func TestKCPPluginWrongKeyAndNetworkReset(t *testing.T) {
	var server *Server
	ss := testnet.RetryAddr(t, func(address netip.AddrPort) (err error) {
		server, err = StartShadowsocksServer(address, "aes-128-gcm", "test", testLogger(t))
		return err
	})
	defer server.Close()
	spec := SSPluginSpec{Type: "kcptun", KCP: &KC.Config{Key: "correct-key"}}
	port, _ := legacyPluginPeer(t, spec, ss)
	var protected atomic.Int32
	b := New(Options{Logger: testLogger(t), ProtectFD: func(int) error { protected.Add(1); return nil }})
	defer b.Close()
	create := func(spec SSPluginSpec) *Outbound {
		t.Helper()
		o, err := b.NewOutbound("kcp", ProxySpec{Type: "shadowsocks", Server: "127.0.0.1", Port: port, Method: "aes-128-gcm", Password: "test", Plugin: &spec})
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	out := create(spec)
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	target := echoServer(t).String()
	round := func(o *Outbound) net.Conn {
		t.Helper()
		c, err := o.Dial(ctx, "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		if _, err = c.Write([]byte("reset")); err != nil {
			c.Close()
			t.Fatal(err)
		}
		reply := make([]byte, 5)
		if _, err = io.ReadFull(c, reply); err != nil || string(reply) != "reset" {
			c.Close()
			t.Fatal("KCP echo", err)
		}
		return c
	}
	old := round(out)
	defer old.Close()
	out.out.(adapter.InterfaceUpdateListener).InterfaceUpdated(ctx)
	fresh := round(out)
	fresh.Close()
	if protected.Load() != 2 {
		t.Fatal("network reset did not reopen one protected UDP carrier", protected.Load())
	}
	badSpec := spec
	badConfig := *spec.KCP
	badConfig.Key = "wrong-key"
	badSpec.KCP = &badConfig
	bad := create(badSpec)
	defer bad.Close()
	c, err := bad.Dial(ctx, "tcp", target)
	if err == nil {
		defer c.Close()
		c.SetDeadline(time.Now().Add(250 * time.Millisecond))
		c.Write([]byte("bad"))
		_, err = io.ReadFull(c, make([]byte, 3))
	}
	if err == nil {
		t.Fatal("wrong kcptun key authenticated")
	}
	if protected.Load() != 3 {
		t.Fatal("wrong-key path bypassed socket protector")
	}
}
