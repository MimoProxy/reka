package sagernet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	S "github.com/sagernet/sing-box/common/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	OB "github.com/sagernet/sing-box/transport/simple-obfs"
	VWS "github.com/sagernet/sing-box/transport/v2raywebsocket"
	ST "github.com/sagernet/sing-shadowtls"
	VM "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/smux"
	"github.com/sagernet/ws"
)

type pluginForwardHandler struct{ target string }

func (h pluginForwardHandler) NewConnectionEx(_ context.Context, c net.Conn, _, _ M.Socksaddr, close N.CloseHandlerFunc) {
	go func() {
		defer c.Close()
		up, err := net.DialTimeout("tcp", h.target, time.Second)
		if err != nil {
			if close != nil {
				close(err)
			}
			return
		}
		defer up.Close()
		go func() { io.Copy(up, c); up.Close() }()
		_, err = io.Copy(c, up)
		if close != nil {
			close(err)
		}
	}()
}
func (h pluginForwardHandler) NewPacketConnectionEx(_ context.Context, c N.PacketConn, _, _ M.Socksaddr, close N.CloseHandlerFunc) {
	c.Close()
	if close != nil {
		close(fmt.Errorf("unexpected VMess-mux UDP"))
	}
}

type pluginReadConn struct {
	net.Conn
	reader io.Reader
}

func (c *pluginReadConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type pluginFragmentConn struct {
	net.Conn
	first atomic.Bool
}

func (c *pluginFragmentConn) Write(p []byte) (int, error) {
	if !c.first.CompareAndSwap(false, true) {
		return c.Conn.Write(p)
	}
	count := 0
	for count < min(len(p), 200) {
		n, err := c.Conn.Write(p[count : count+1])
		count += n
		if err != nil {
			return count, err
		}
		time.Sleep(100 * time.Microsecond)
	}
	if count < len(p) {
		n, err := c.Conn.Write(p[count:])
		return count + n, err
	}
	return count, nil
}

func pluginUDPFront(t *testing.T, listen, target string) {
	t.Helper()
	front, err := net.ListenPacket("udp4", listen)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		t.Fatal(err)
	}
	up, err := net.DialUDP("udp4", nil, destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { front.Close(); up.Close() })
	var mu sync.Mutex
	var peer net.Addr
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, addr, err := front.ReadFrom(buffer)
			if err != nil {
				return
			}
			mu.Lock()
			peer = addr
			mu.Unlock()
			up.Write(buffer[:n])
		}
	}()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, err := up.Read(buffer)
			if err != nil {
				return
			}
			mu.Lock()
			addr := peer
			mu.Unlock()
			if addr != nil {
				front.WriteTo(buffer[:n], addr)
			}
		}
	}()
}

func pluginTestPeer(t *testing.T, s SSPluginSpec, ss netip.AddrPort) (uint16, *TLSSpec) {
	t.Helper()
	if s.Type == "restls" || s.Type == "jls" || s.Type == "kcptun" {
		return legacyPluginPeer(t, s, ss)
	}
	handler := pluginForwardHandler{target: ss.String()}
	listener, err := net.Listen("tcp4", loopback(freePort(t)).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	pluginUDPFront(t, listener.Addr().String(), ss.String())
	var connectionsMu sync.Mutex
	var connections []net.Conn
	track := func(c net.Conn) { connectionsMu.Lock(); connections = append(connections, c); connectionsMu.Unlock() }
	t.Cleanup(func() {
		connectionsMu.Lock()
		defer connectionsMu.Unlock()
		for _, c := range connections {
			c.Close()
		}
	})
	var clientTLS *TLSSpec
	if s.Type == "v2ray-plugin" || s.Type == "gost-plugin" {
		httpServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.TLS != nil && s.TLS.ECH != nil && (r.TLS == nil || !r.TLS.ECHAccepted || r.TLS.ServerName != "plugin.test") {
				http.Error(w, "ECH required", 403)
				return
			}
			if r.URL.Path != "/plugin" || r.Host != "plugin.test" || r.Header.Get("X-Reka") != "node-header" {
				http.Error(w, "wrong plugin headers", 400)
				return
			}
			var c net.Conn
			if s.HTTPUpgrade {
				raw, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				track(raw)
				var prefix []byte
				if s.FastOpen {
					first, err := rw.Reader.ReadByte()
					if err != nil {
						raw.Close()
						return
					}
					prefix = []byte{first}
				}
				fmt.Fprint(raw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
				c = &pluginReadConn{Conn: raw, reader: io.MultiReader(bytes.NewReader(prefix), rw.Reader)}
			} else {
				raw, _, _, err := ws.UpgradeHTTP(r, w)
				if err != nil {
					return
				}
				track(raw)
				c = VWS.NewConn(raw, raw.RemoteAddr(), ws.StateServerSide)
			}
			if s.Mux {
				if s.Type == "v2ray-plugin" {
					go func() { VM.HandleMuxConnection(context.Background(), c, M.Socksaddr{}, handler); c.Close() }()
					return
				}
				config := smux.DefaultConfig()
				config.KeepAliveDisabled = true
				session, err := smux.Server(c, config)
				if err != nil {
					c.Close()
					return
				}
				go func() {
					defer session.Close()
					for {
						stream, err := session.AcceptStream()
						if err != nil {
							return
						}
						handler.NewConnectionEx(context.Background(), stream, M.Socksaddr{}, M.Socksaddr{}, nil)
					}
				}()
				return
			}
			handler.NewConnectionEx(context.Background(), c, M.Socksaddr{}, M.Socksaddr{}, nil)
		}))
		httpServer.Listener.Close()
		httpServer.Listener = listener
		var echConfig []byte
		if s.TLS != nil {
			if s.TLS.Certificate != "" {
				httpServer.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
			}
			if s.TLS.ECH != nil {
				public, key, err := S.ECHKeygenDefault("public.test")
				if err != nil {
					t.Fatal(err)
				}
				list, _ := pem.Decode([]byte(public))
				private, _ := pem.Decode([]byte(key))
				keys, err := S.UnmarshalECHKeys(private.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				if httpServer.TLS == nil {
					httpServer.TLS = &tls.Config{}
				}
				httpServer.TLS.EncryptedClientHelloKeys = keys
				echConfig = list.Bytes
			}
			httpServer.StartTLS()
			digest := sha256.Sum256(httpServer.TLS.Certificates[0].Certificate[0])
			clientTLS = &TLSSpec{ServerName: "plugin.test", CertificatePin: hex.EncodeToString(digest[:]), ALPN: []string{"http/1.1"}, Certificate: s.TLS.Certificate, PrivateKey: s.TLS.PrivateKey}
			clientTLS.Fingerprint = s.TLS.Fingerprint
			if s.TLS.ECH != nil {
				ech := &ECHSpec{Config: base64.StdEncoding.EncodeToString(echConfig)}
				if s.TLS.ECH.QueryServerName != "" {
					query := s.TLS.ECH.QueryServerName
					ech.Config = ""
					ech.QueryServerName = query
					ech.Lookup = func(_ context.Context, name string) ([]byte, error) {
						if name != query {
							return nil, fmt.Errorf("plugin ECH query name lost")
						}
						return bytes.Clone(echConfig), nil
					}
				}
				clientTLS.ECH = ech
			}
		} else {
			httpServer.Start()
		}
		t.Cleanup(httpServer.Close)
	} else if s.Type == "obfs" {
		go func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				track(c)
				c = &pluginFragmentConn{Conn: c}
				if s.Mode == "tls" {
					c = NewTLSObfsServer(c)
				} else {
					c = NewHTTPObfsServer(c)
				}
				handler.NewConnectionEx(context.Background(), c, M.Socksaddr{}, M.Socksaddr{}, nil)
			}
		}()
	} else if s.Type == "shadow-tls" {
		target := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		target.EnableHTTP2 = true
		if s.Version == 1 || s.ForceTLS12 {
			target.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
		}
		target.StartTLS()
		t.Cleanup(target.Close)
		digest := sha256.Sum256(target.TLS.Certificates[0].Certificate[0])
		clientTLS = &TLSSpec{ServerName: "plugin.test", CertificatePin: hex.EncodeToString(digest[:])}
		if s.TLS != nil {
			clientTLS.Fingerprint = s.TLS.Fingerprint
		}
		b := New(Options{Logger: testLogger(t)})
		t.Cleanup(func() { b.Close() })
		service, err := ST.NewService(ST.ServiceConfig{Version: s.Version, Password: s.Password, Users: []ST.User{{Name: "test", Password: s.Password}}, Handshake: ST.HandshakeConfig{Server: M.ParseSocksaddr(target.Listener.Addr().String()), Dialer: N.SystemDialer}, Handler: handler, Logger: b.logger})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				track(c)
				go func() {
					if err := service.NewConnection(context.Background(), c, M.Socksaddr{}, M.Socksaddr{}, nil); err != nil {
						c.Close()
					}
				}()
			}
		}()
	}
	return uint16(listener.Addr().(*net.TCPAddr).Port), clientTLS
}

func TestSSPluginsRealTCPNativeUDPAndUOT(t *testing.T) {
	cases := []SSPluginSpec{{Type: "obfs", Mode: "http"}, {Type: "obfs", Mode: "tls"}, {Type: "shadow-tls", Version: 1}, {Type: "shadow-tls", Version: 2, Password: "plugin-secret"}, {Type: "shadow-tls", Version: 3, Password: "plugin-secret"}}
	cases = append(cases, legacyPluginCases()...)
	for _, fingerprint := range []string{"chrome", "firefox"} {
		cases = append(cases, SSPluginSpec{Type: "shadow-tls", Version: 3, Password: "plugin-secret", TLS: &TLSSpec{Fingerprint: fingerprint}})
	}
	for _, kind := range []string{"v2ray-plugin", "gost-plugin"} {
		for _, mux := range []bool{false, true} {
			for _, secured := range []bool{false, true} {
				s := SSPluginSpec{Type: kind, Mode: "websocket", Mux: mux}
				if secured {
					cert, key, _ := testClientCertificate(t)
					s.TLS = &TLSSpec{Certificate: cert, PrivateKey: key}
				}
				cases = append(cases, s)
			}
		}
	}
	for _, kind := range []string{"v2ray-plugin", "gost-plugin"} {
		for _, fingerprint := range []string{"", "chrome"} {
			for _, automatic := range []bool{false, true} {
				ech := &ECHSpec{}
				if automatic {
					ech.QueryServerName = "plugin-query.test"
				}
				cases = append(cases, SSPluginSpec{Type: kind, Mode: "websocket", Mux: true, TLS: &TLSSpec{Fingerprint: fingerprint, ECH: ech}})
			}
		}
	}
	for _, fast := range []bool{false, true} {
		cases = append(cases, SSPluginSpec{Type: "v2ray-plugin", Mode: "websocket", Mux: true, HTTPUpgrade: true, FastOpen: fast})
	}
	for index, s := range cases {
		t.Run(fmt.Sprintf("%02d-%s-%s-v%d-mux%v-tls%v-fast%v", index, s.Type, s.Mode, s.Version, s.Mux, s.TLS != nil, s.FastOpen), func(t *testing.T) {
			ssListen := loopback(freePort(t))
			server, err := StartShadowsocksServer(ssListen, "aes-128-gcm", "test", testLogger(t))
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			s.Host, s.Path = "plugin.test", "/plugin"
			s.Headers = http.Header{"Host": {"plugin.test"}, "X-Reka": {"node-header"}}
			port, tls := pluginTestPeer(t, s, ssListen)
			s.TLS = tls
			var protected atomic.Int32
			b := New(Options{Logger: testLogger(t), ProtectFD: func(int) error { protected.Add(1); return nil }})
			defer b.Close()
			out, err := b.NewOutbound("plugin", ProxySpec{Type: "shadowsocks", Server: "127.0.0.1", Port: port, Method: "aes-128-gcm", Password: "test", Plugin: &s})
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			c, err := out.Dial(ctx, "tcp", echoServer(t).String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte("plugin"), 128<<10)
			done := make(chan error, 1)
			go func() { _, err := c.Write(payload); done <- err }()
			reply := make([]byte, len(payload))
			if _, err = io.ReadFull(c, reply); err != nil || !bytes.Equal(payload, reply) {
				t.Fatal("plugin TCP", err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			go func() {
				buffer := make([]byte, 1500)
				for {
					n, addr, err := udp.ReadFrom(buffer)
					if err != nil {
						return
					}
					udp.WriteTo(buffer[:n], addr)
				}
			}()
			target := M.ParseSocksaddr(udp.LocalAddr().String())
			roundUDP := func(out *Outbound) {
				t.Helper()
				packet, err := out.out.ListenPacket(ctx, target)
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
				packet.SetDeadline(time.Now().Add(2 * time.Second))
				packet.WriteTo([]byte("udp"), target)
				buffer := make([]byte, 1500)
				n, _, err := packet.ReadFrom(buffer)
				if err != nil || string(buffer[:n]) != "udp" {
					t.Fatal("plugin UDP", err)
				}
			}
			roundUDP(out)
			options := []byte(`{"udp_over_tcp":{"enabled":true,"version":2}}`)
			uot, err := b.NewOutbound("uot", ProxySpec{Type: "shadowsocks", Server: "127.0.0.1", Port: port, Method: "aes-128-gcm", Password: "test", Plugin: &s, Options: options})
			if err != nil {
				t.Fatal(err)
			}
			defer uot.Close()
			roundUDP(uot)
			expected := int32(3)
			if s.Type == "kcptun" {
				expected = 2
			}
			if protected.Load() != expected {
				t.Fatal("plugin protection was bypassed or applied twice", protected.Load())
			}
			if s.TLS != nil {
				invalid := s
				invalidTLS := *s.TLS
				invalidTLS.CertificatePin = strings.Repeat("0", 64)
				invalid.TLS = &invalidTLS
				bad, err := b.NewOutbound("bad-pin", ProxySpec{Type: "shadowsocks", Server: "127.0.0.1", Port: port, Method: "aes-128-gcm", Password: "test", Plugin: &invalid})
				if err != nil {
					t.Fatal(err)
				}
				badConn, err := bad.Dial(ctx, "tcp", echoServer(t).String())
				bad.Close()
				if err == nil {
					badConn.Close()
					t.Fatal("wrong plugin pin accepted")
				}
				if s.TLS.Certificate != "" {
					invalidTLS = *s.TLS
					invalidTLS.Certificate, invalidTLS.PrivateKey = "", ""
					invalid.TLS = &invalidTLS
					bad, err = b.NewOutbound("missing-identity", ProxySpec{Type: "shadowsocks", Server: "127.0.0.1", Port: port, Method: "aes-128-gcm", Password: "test", Plugin: &invalid})
					if err != nil {
						t.Fatal(err)
					}
					badConn, err = bad.Dial(ctx, "tcp", echoServer(t).String())
					bad.Close()
					if err == nil {
						badConn.Close()
						t.Fatal("required plugin client identity ignored")
					}
				}
			}
			if s.TLS != nil && s.TLS.ECH != nil {
				public, _, err := S.ECHKeygenDefault("public.test")
				if err != nil {
					t.Fatal(err)
				}
				list, _ := pem.Decode([]byte(public))
				invalid := s
				invalidTLS := *s.TLS
				invalidTLS.ECH = &ECHSpec{Config: base64.StdEncoding.EncodeToString(list.Bytes)}
				invalid.TLS = &invalidTLS
				bad, err := b.NewOutbound("wrong-ech", ProxySpec{Type: "shadowsocks", Server: "127.0.0.1", Port: port, Method: "aes-128-gcm", Password: "test", Plugin: &invalid})
				if err != nil {
					t.Fatal(err)
				}
				c, err := bad.Dial(ctx, "tcp", echoServer(t).String())
				bad.Close()
				if err == nil {
					c.Close()
					t.Fatal("wrong plugin ECH key accepted")
				}
			}
			if s.Type == "shadow-tls" && s.Version > 1 || s.Type == "restls" || s.Type == "jls" {
				invalid := s
				invalid.Password = "wrong-secret"
				bad, err := b.NewOutbound("bad-secret", ProxySpec{Type: "shadowsocks", Server: "127.0.0.1", Port: port, Method: "aes-128-gcm", Password: "test", Plugin: &invalid})
				if err != nil {
					t.Fatal(err)
				}
				badConn, err := bad.Dial(ctx, "tcp", echoServer(t).String())
				if err == nil {
					badConn.SetDeadline(time.Now().Add(time.Second))
					badConn.Write([]byte("wrong"))
					reply := make([]byte, 5)
					_, err = io.ReadFull(badConn, reply)
					badConn.Close()
				}
				bad.Close()
				if err == nil {
					t.Fatal("wrong ShadowTLS secret accepted")
				}
			}

		})
	}
}

func TestSSPluginUpgradeCancellationAndTLSObfsTruncation(t *testing.T) {
	for _, secured := range []bool{false, true} {
		t.Run(fmt.Sprint(secured), func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				c, err := listener.Accept()
				if err == nil {
					accepted <- c
				}
			}()
			s := &SSPluginSpec{Type: "v2ray-plugin", Mode: "websocket", Host: "plugin.test", HTTPUpgrade: true}
			if secured {
				s.TLS = &TLSSpec{Insecure: true, ServerName: "plugin.test"}
			}
			b := New(Options{Logger: testLogger(t)})
			defer b.Close()
			out, err := b.NewOutbound("cancel", ProxySpec{Type: "shadowsocks", Server: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port), Method: "aes-128-gcm", Password: "test", Plugin: s})
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				c, err := out.Dial(ctx, "tcp", "127.0.0.1:80")
				if c != nil {
					c.Close()
				}
				done <- err
			}()
			peer := <-accepted
			defer peer.Close()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("stalled handshake succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("plugin handshake ignored cancellation")
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			_, err = io.Copy(io.Discard, peer)
			if err != nil {
				t.Fatal("canceled plugin socket remained open", err)
			}
		})
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	obfs := OB.NewTLSObfs(left, "plugin.test")
	go func() { right.Write(make([]byte, 105)); right.Write([]byte{0}); right.Close() }()
	buffer := make([]byte, 1)
	if _, err := obfs.Read(buffer); err == nil {
		t.Fatal("truncated TLS-obfs length returned a successful empty read")
	}
}
