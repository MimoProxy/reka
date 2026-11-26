package sagernet

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/sagernet/sing-box/adapter"
	MX "github.com/sagernet/sing-box/common/mux"
	S "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
	PHTTP "github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/snell"
	PSOCKS "github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/testnet"
)

func TestProtocolInteroperability(t *testing.T) {
	// SSH exposes TCP channels only. Its fixture forwards each channel to a loopback echo server.
	t.Run("ssh", func(t *testing.T) { testSSHInteroperability(t, true) })
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := tlsServer.TLS.Certificates[0]
	tlsServer.Close()
	key, e := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	serverTLS := map[string]any{"enabled": true, "certificate": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))}, "key": []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))}}
	echConfigPEM, echKeyPEM, err := S.ECHKeygenDefault("public.test")
	if err != nil {
		t.Fatal(err)
	}
	echConfig, _ := pem.Decode([]byte(echConfigPEM))
	uuid := "b831381d-6324-4d53-ad4f-8cda48b30811"
	password := "test-password-with-enough-entropy"
	cases := []struct {
		typ, transport string
		mux            bool
		version        int
	}{
		{"vmess", "", false, 0}, {"trojan", "", false, 0},
		{"anytls", "", false, 0}, {"anytls", "ech", false, 0},
		{"hysteria2", "", false, 0}, {"tuic", "", false, 0},
		{"snell", "", false, 5}, {"snell", "", false, 6},
	}
	for _, tc := range []struct {
		typ     string
		version int
	}{{"shadowsocks", 0}, {"hysteria2", 0}, {"tuic", 0}, {"snell", 5}, {"snell", 6}, {"http", 0}, {"socks", 0}} {
		cases = append(cases, struct {
			typ, transport string
			mux            bool
			version        int
		}{tc.typ, "", true, tc.version})
	}
	for _, typ := range []string{"hysteria2", "tuic"} {
		for _, transport := range []string{"ech", "ech-dns"} {
			cases = append(cases, struct {
				typ, transport string
				mux            bool
				version        int
			}{typ, transport, false, 0})
		}
	}
	for _, typ := range []string{"vmess", "trojan", "vless"} {
		for _, tr := range []string{"ws", "grpc", "httpupgrade"} {
			cases = append(cases, struct {
				typ, transport string
				mux            bool
				version        int
			}{typ, tr, false, 0})
		}
		cases = append(cases, struct {
			typ, transport string
			mux            bool
			version        int
		}{typ, "", true, 0})
	}
	for _, typ := range []string{"vmess", "vless"} {
		for _, tr := range []string{"http", "http-tls", "h2"} {
			cases = append(cases, struct {
				typ, transport string
				mux            bool
				version        int
			}{typ, tr, false, 0})
		}
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%s/mux-%v/v%d", tc.typ, tc.transport, tc.mux, tc.version), func(t *testing.T) {
			base := map[string]any{"listen": "127.0.0.1"}
			opts := map[string]any{}
			users := []map[string]any{{"name": "test", "uuid": uuid, "password": password}}
			base["users"] = users
			if tc.typ == "trojan" || tc.typ == "anytls" || tc.typ == "hysteria2" || tc.typ == "tuic" || tc.transport == "http-tls" || tc.transport == "h2" {
				tlsOptions := map[string]any{}
				for k, v := range serverTLS {
					tlsOptions[k] = v
				}
				if tc.transport == "ech" || tc.transport == "ech-dns" {
					tlsOptions["ech"] = map[string]any{"enabled": true, "key": []string{echKeyPEM}}
				}
				if tc.typ == "hysteria2" || tc.typ == "tuic" {
					tlsOptions["alpn"] = []string{"h3"}
				}
				base["tls"] = tlsOptions
			}
			if tc.typ == "shadowsocks" {
				delete(base, "users")
				base["method"] = "aes-128-gcm"
				base["password"] = password
			}
			if tc.typ == "http" || tc.typ == "socks" {
				delete(base, "users")
			}
			if tc.typ == "snell" {
				delete(base, "users")
				base["psk"], base["version"] = password, tc.version
				clientVersion := tc.version
				if clientVersion == 5 {
					clientVersion = 4
				}
				opts["version"] = clientVersion
			}
			if tc.typ == "vmess" {
				opts["security"] = "auto"
			}
			if tc.transport != "" && tc.transport != "ech" && tc.transport != "ech-dns" {
				transport := map[string]any{"type": tc.transport}
				if tc.transport == "grpc" {
					transport["service_name"] = "reka-test"
				} else {
					transport["path"] = "/reka-test"
				}
				if tc.transport == "http" || tc.transport == "http-tls" || tc.transport == "h2" {
					transport["type"] = "http"
				}
				base["transport"], opts["transport"] = transport, transport
				if tc.transport == "http" || tc.transport == "http-tls" {
					delete(opts, "transport")
					opts["reka_http"] = map[string]any{"method": "POST", "paths": []string{"/reka-test"}, "headers": map[string][]string{"X-Test": []string{"proof"}}}
					transport["method"] = "POST"
				}
			}
			if tc.mux {
				opts["multiplex"] = map[string]any{"enabled": true, "protocol": "smux"}
			}
			var server *Server
			port := testnet.Retry(t, func(port uint16) (err error) {
				base["listen_port"] = port
				raw, _ := json.Marshal(base)
				server, err = startNode(testLogger(t), func(b *Backend) (adapter.Inbound, string, error) {
					var in adapter.Inbound
					var err error
					logger := b.componentLogger("inbound", tc.typ, "test")
					var route adapter.Router = b.router
					if tc.mux {
						routed, err := MX.NewRouterWithOptions(b.router, logger, option.InboundMultiplexOptions{Enabled: true})
						if err != nil {
							return nil, tc.typ, err
						}
						route = &multiplexTestRouter{Router: b.router, mux: routed}
					}
					switch tc.typ {
					case "shadowsocks":
						var o option.ShadowsocksInboundOptions
						err = json.Unmarshal(raw, &o)
						if err == nil {
							in, err = shadowsocks.NewInbound(b.ctx, route, logger, "test", o)
						}
					case "http":
						var o option.HTTPMixedInboundOptions
						err = json.Unmarshal(raw, &o)
						if err == nil {
							in, err = PHTTP.NewInbound(b.ctx, route, logger, "test", o)
						}
					case "socks":
						var o option.SocksInboundOptions
						err = json.Unmarshal(raw, &o)
						if err == nil {
							in, err = PSOCKS.NewInbound(b.ctx, route, logger, "test", o)
						}
					case "vmess":
						var o option.VMessInboundOptions
						err = json.Unmarshal(raw, &o)
						if err == nil {
							in, err = vmess.NewInbound(b.ctx, route, logger, "test", o)
						}
					case "trojan":
						var o option.TrojanInboundOptions
						err = json.Unmarshal(raw, &o)
						if err == nil {
							in, err = trojan.NewInbound(b.ctx, route, logger, "test", o)
						}
					case "anytls":
						var o option.AnyTLSInboundOptions
						err = json.Unmarshal(raw, &o)
						if err == nil {
							in, err = anytls.NewInbound(b.ctx, route, logger, "test", o)
						}
					case "vless":
						var o option.VLESSInboundOptions
						err = json.Unmarshal(raw, &o)
						if err == nil {
							in, err = vless.NewInbound(b.ctx, route, logger, "test", o)
						}
					case "hysteria2":
						var o option.Hysteria2InboundOptions
						err = json.Unmarshal(raw, &o)
						if err == nil {
							in, err = hysteria2.NewInbound(b.ctx, route, logger, "test", o)
						}
					case "tuic":
						var o option.TUICInboundOptions
						err = json.Unmarshal(raw, &o)
						if err == nil {
							in, err = tuic.NewInbound(b.ctx, route, logger, "test", o)
						}
					case "snell":
						var o option.SnellInboundOptions
						err = json.Unmarshal(raw, &o)
						if err == nil {
							in, err = snell.NewInbound(b.ctx, route, logger, "test", o)
						}
					}
					return in, tc.typ, err
				})
				return err
			})
			defer server.Close()
			b := New(Options{Logger: testLogger(t)})
			defer b.Close()
			optionBytes, _ := json.Marshal(opts)
			spec := ProxySpec{Type: tc.typ, Server: "127.0.0.1", Port: port, UUID: uuid, Password: password, Options: optionBytes}
			if tc.typ == "shadowsocks" {
				spec.Method = "aes-128-gcm"
			}
			if base["tls"] != nil {
				pin := sha256.Sum256(cert.Certificate[0])
				spec.TLS = &TLSSpec{CertificatePin: hex.EncodeToString(pin[:]), ServerName: "localhost"}
				if tc.typ == "hysteria2" || tc.typ == "tuic" {
					spec.TLS.ALPN = []string{"h3"}
				}
				if tc.transport == "ech" || tc.transport == "ech-dns" {
					spec.TLS.ECH = &ECHSpec{Config: base64.StdEncoding.EncodeToString(echConfig.Bytes)}
					if tc.transport == "ech-dns" {
						spec.TLS.ECH.Config = ""
						spec.TLS.ECH.Lookup = func(context.Context, string) ([]byte, error) { return echConfig.Bytes, nil }
					}
				}
			}
			out, err := b.NewOutbound("test", spec)
			if err != nil {
				t.Fatal("client", err)
			}
			defer out.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := out.Dial(ctx, "tcp", echoServer(t).String())
			if err != nil {
				t.Fatal("dial", err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte("reka-interoperability\n"), 128)
			if _, err = conn.Write(payload); err != nil {
				t.Fatal("write", err)
			}
			reply := make([]byte, len(payload))
			if _, err = io.ReadFull(conn, reply); err != nil {
				t.Fatal("read", err)
			}
			if !bytes.Equal(reply, payload) {
				t.Fatal("payload mismatch")
			}
			inner, err := out.Dial(ctx, "tcp", tlsEchoServer(t).String())
			if err != nil {
				t.Fatal("inner TLS dial", err)
			}
			secure := tls.Client(inner, &tls.Config{InsecureSkipVerify: true})
			defer secure.Close()
			secure.SetDeadline(time.Now().Add(5 * time.Second))
			if err := secure.HandshakeContext(ctx); err != nil {
				t.Fatal("inner TLS handshake", err)
			}
			if _, err = secure.Write(payload); err != nil {
				t.Fatal("inner TLS write", err)
			}
			if _, err = io.ReadFull(secure, reply); err != nil {
				t.Fatal("inner TLS read", err)
			}
			if !bytes.Equal(reply, payload) {
				t.Fatal("inner TLS payload mismatch")
			}
			web := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			defer web.Close()
			tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: out.Dial, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			res, err := client.Get(web.URL)
			if err != nil {
				t.Fatal("HTTPS over protocol", err)
			}
			res.Body.Close()
			if res.StatusCode != 204 {
				t.Fatal(res.StatusCode)
			}

			udp, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			go func() {
				buffer := make([]byte, 2048)
				for {
					n, addr, e := udp.ReadFrom(buffer)
					if e != nil {
						return
					}
					_, _ = udp.WriteTo(buffer[:n], addr)
				}
			}()
			target := M.ParseSocksaddr(udp.LocalAddr().String())
			packet, err := out.out.ListenPacket(ctx, target)
			if err != nil {
				t.Fatal("UDP dial", err)
			}
			defer packet.Close()
			packet.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err = packet.WriteTo([]byte("udp-protocol-check"), target); err != nil {
				t.Fatal("UDP write", err)
			}
			buffer := make([]byte, 2048)
			n, _, err := packet.ReadFrom(buffer)
			if err != nil || string(buffer[:n]) != "udp-protocol-check" {
				t.Fatal("UDP echo", err, string(buffer[:n]))
			}
			other, err := b.NewOutbound("other", spec)
			if err != nil {
				t.Fatal(err)
			}
			second, err := other.Dial(ctx, "tcp", echoServer(t).String())
			if err != nil {
				other.Close()
				t.Fatal(err)
			}
			second.Write([]byte("other"))
			other.Close()
			second.Close()
			if _, err = conn.Write([]byte("still-alive")); err != nil {
				t.Fatal("closing new instance broke old", err)
			}
			buffer = make([]byte, len("still-alive"))
			if _, err = io.ReadFull(conn, buffer); err != nil || string(buffer) != "still-alive" {
				t.Fatal("old instance stopped", err)
			}
			if tc.transport == "ech" || tc.transport == "ech-dns" {
				wrongPEM, _, _ := S.ECHKeygenDefault("public.test")
				wrong, _ := pem.Decode([]byte(wrongPEM))
				spec.TLS.ECH = &ECHSpec{Config: base64.StdEncoding.EncodeToString(wrong.Bytes)}
				negative, err := b.NewOutbound("wrong-ech", spec)
				if err != nil {
					t.Fatal(err)
				}
				defer negative.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				c, err := negative.Dial(ctx, "tcp", echoServer(t).String())
				if err == nil {
					c.SetDeadline(time.Now().Add(time.Second))
					_, err = c.Write([]byte("must-not-fallback"))
					if err == nil {
						_, err = io.ReadFull(c, make([]byte, 17))
					}
					c.Close()
				}
				if err == nil {
					t.Fatal("invalid ECH fell back to clear SNI")
				}
			}

		})
	}
}

func TestRealityTransportAndMux(t *testing.T) {
	for _, typ := range []string{"ws", "grpc", "httpupgrade", "http", "h2", "smux"} {
		t.Run(typ, func(t *testing.T) {
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			target.EnableHTTP2 = true
			target.StartTLS()
			defer target.Close()
			address := netip.MustParseAddrPort(target.Listener.Addr().String())
			private, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			opts := map[string]any{}
			var transport json.RawMessage
			if typ == "smux" {
				opts["multiplex"] = map[string]any{"enabled": true, "protocol": "smux"}
			} else {
				value := map[string]any{"type": typ, "path": "/reka"}
				if typ == "grpc" {
					value = map[string]any{"type": typ, "service_name": "reka"}
				}
				if typ == "h2" {
					value["type"] = "http"
				}
				transport, _ = json.Marshal(value)
				if typ == "http" {
					opts["reka_http"] = map[string]any{"paths": []string{"/reka"}}
				} else {
					opts["transport"] = value
				}
			}
			var server *Server
			port := testnet.Retry(t, func(port uint16) (err error) {
				server, err = StartRealityServer(RealityServerOptions{Listen: loopback(port), UUID: testUUID, ServerName: "reality.test", Target: address, PrivateKey: private.Bytes(), ShortID: "abcd", Transport: transport, Multiplex: typ == "smux"}, testLogger(t))
				return err
			})
			defer server.Close()
			b := New(Options{Logger: testLogger(t)})
			defer b.Close()
			raw, _ := json.Marshal(opts)
			out, err := b.NewOutbound("reality", VLESSSpec{Server: "127.0.0.1", Port: port, UUID: testUUID, TLS: &TLSSpec{ServerName: "reality.test", Fingerprint: "chrome", Reality: &RealitySpec{PublicKey: base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), ShortID: "abcd"}}, Options: raw})
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := out.Dial(ctx, "tcp", echoServer(t).String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			conn.Write([]byte("reality-transport"))
			got := make([]byte, len("reality-transport"))
			if _, err = io.ReadFull(conn, got); err != nil || string(got) != "reality-transport" {
				t.Fatal(err, string(got))
			}
		})
	}
}

func TestSSRProtocolConstruction(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	spec := ProxySpec{Type: "ssr", Server: "proxy.example", Port: 8388, Method: "aes-256-cfb", Password: "test-password"}
	dst := M.ParseSocksaddr("target.example:53")
	for _, tc := range []struct {
		name, options string
		udp           bool
	}{
		{"tcp", "{}", false},
		{"udp", `{"obfs":"http_simple","obfs_param":"cdn.example","protocol":"auth_aes128_md5","protocol_param":"64:key","udp":true}`, true},
		{"network", `{"network":["tcp","udp"]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := spec
			opts.Options = json.RawMessage(tc.options)
			out, err := b.NewOutbound("test", opts)
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			if got := out.out.Network(); !slices.Contains(got, "tcp") || slices.Contains(got, "udp") != tc.udp || out.out.Type() != "ssr" {
				t.Fatalf("unexpected adapter type %s or networks %v", out.out.Type(), got)
			}
			if !tc.udp {
				if _, err := out.out.ListenPacket(context.Background(), dst); err == nil || !strings.Contains(err.Error(), "UDP is disabled") {
					t.Fatalf("disabled UDP listen: %v", err)
				}
				if _, err := out.out.DialContext(context.Background(), "udp", dst); err == nil || !strings.Contains(err.Error(), "UDP is disabled") {
					t.Fatalf("disabled UDP dial: %v", err)
				}
			}
		})
	}
	for _, key := range []string{"tls", "transport", "multiplex", "plugin", "realm"} {
		opts := spec
		opts.Options, _ = json.Marshal(map[string]any{key: map[string]any{}})
		if _, err := b.NewOutbound("test", opts); err == nil {
			t.Fatalf("accepted %s option", key)
		}
	}
	for _, set := range []func(*ProxySpec){
		func(s *ProxySpec) { s.TLS = &TLSSpec{} },
		func(s *ProxySpec) { s.Plugin = &SSPluginSpec{} },
		func(s *ProxySpec) { s.Realm = &RealmSpec{} },
	} {
		opts := spec
		set(&opts)
		if _, err := b.NewOutbound("test", opts); err == nil {
			t.Fatal("accepted incompatible scoped options")
		}
	}
}

func TestSSRDetourDialCancellation(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	dialed := make(chan struct{})
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	out, err := b.NewOutbound("test", ProxySpec{
		Type: "ssr", Server: "proxy.example", Port: 8388, Method: "none", Password: "password",
		Detour: &DetourSpec{Dial: func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "proxy.example:8388" {
				return nil, fmt.Errorf("unexpected dial to %s %s", network, address)
			}
			close(dialed)
			return client, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := out.out.DialContext(ctx, "tcp", M.ParseSocksaddr("target.example:80"))
		done <- err
	}()
	select {
	case <-dialed:
	case <-ctx.Done():
		t.Fatal("SSR did not use the detour")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("dial did not cancel while writing the destination")
	}
}
