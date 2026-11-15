package sagernet

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/snell"
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
	"testing"
	"time"
)

func TestProtocolInteroperability(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := tlsServer.TLS.Certificates[0]
	tlsServer.Close()
	key, e := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	serverTLS := map[string]any{"enabled": true, "certificate": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))}, "key": []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))}}
	uuid := "b831381d-6324-4d53-ad4f-8cda48b30811"
	password := "test-password-with-enough-entropy"
	cases := []struct {
		typ, transport string
		mux            bool
		version        int
	}{{"vmess", "", false, 0}, {"trojan", "", false, 0}, {"hysteria2", "", false, 0}, {"tuic", "", false, 0}, {"snell", "", false, 5}, {"snell", "", false, 6}}
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
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%s/mux-%v/v%d", tc.typ, tc.transport, tc.mux, tc.version), func(t *testing.T) {
			port := freePort(t)
			base := map[string]any{"listen": "127.0.0.1", "listen_port": port}
			opts := map[string]any{}
			users := []map[string]any{{"name": "test", "uuid": uuid, "password": password}}
			base["users"] = users
			if tc.typ == "trojan" || tc.typ == "hysteria2" || tc.typ == "tuic" {
				tlsOptions := map[string]any{}
				for k, v := range serverTLS {
					tlsOptions[k] = v
				}
				if tc.typ == "hysteria2" || tc.typ == "tuic" {
					tlsOptions["alpn"] = []string{"h3"}
				}
				base["tls"] = tlsOptions
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
			if tc.transport != "" {
				transport := map[string]any{"type": tc.transport}
				if tc.transport == "grpc" {
					transport["service_name"] = "reka-test"
				} else {
					transport["path"] = "/reka-test"
				}
				base["transport"], opts["transport"] = transport, transport
			}
			if tc.mux {
				base["multiplex"] = map[string]any{"enabled": true}
				opts["multiplex"] = map[string]any{"enabled": true, "protocol": "smux"}
			}
			raw, _ := json.Marshal(base)
			server, err := startNode(testLogger(t), func(b *Backend) (adapter.Inbound, string, error) {
				var in adapter.Inbound
				var e error
				logger := b.componentLogger("inbound", tc.typ, "test")
				switch tc.typ {
				case "vmess":
					var o option.VMessInboundOptions
					e = json.Unmarshal(raw, &o)
					if e == nil {
						in, e = vmess.NewInbound(b.ctx, b.router, logger, "test", o)
					}
				case "trojan":
					var o option.TrojanInboundOptions
					e = json.Unmarshal(raw, &o)
					if e == nil {
						in, e = trojan.NewInbound(b.ctx, b.router, logger, "test", o)
					}
				case "vless":
					var o option.VLESSInboundOptions
					e = json.Unmarshal(raw, &o)
					if e == nil {
						in, e = vless.NewInbound(b.ctx, b.router, logger, "test", o)
					}
				case "hysteria2":
					var o option.Hysteria2InboundOptions
					e = json.Unmarshal(raw, &o)
					if e == nil {
						in, e = hysteria2.NewInbound(b.ctx, b.router, logger, "test", o)
					}
				case "tuic":
					var o option.TUICInboundOptions
					e = json.Unmarshal(raw, &o)
					if e == nil {
						in, e = tuic.NewInbound(b.ctx, b.router, logger, "test", o)
					}
				case "snell":
					var o option.SnellInboundOptions
					e = json.Unmarshal(raw, &o)
					if e == nil {
						in, e = snell.NewInbound(b.ctx, b.router, logger, "test", o)
					}
				}
				return in, tc.typ, e
			})
			if err != nil {
				t.Fatal("server", err)
			}
			defer server.Close()
			b := New(Options{Logger: testLogger(t)})
			defer b.Close()
			optionBytes, _ := json.Marshal(opts)
			spec := ProxySpec{Type: tc.typ, Server: "127.0.0.1", Port: port, UUID: uuid, Password: password, Options: optionBytes}
			if base["tls"] != nil {
				spec.TLS = &TLSSpec{ServerName: "localhost", Insecure: true, ALPN: []string{"h3"}}
				if tc.typ == "trojan" {
					spec.TLS.ALPN = nil
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

		})
	}
}

func TestRealityTransportAndMux(t *testing.T) {
	for _, typ := range []string{"ws", "grpc", "httpupgrade", "smux"} {
		t.Run(typ, func(t *testing.T) {
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			target.EnableHTTP2 = true
			target.StartTLS()
			defer target.Close()
			address := netip.MustParseAddrPort(target.Listener.Addr().String())
			private, e := ecdh.X25519().GenerateKey(rand.Reader)
			if e != nil {
				t.Fatal(e)
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
				transport, _ = json.Marshal(value)
				opts["transport"] = value
			}
			port := freePort(t)
			server, e := StartRealityServer(RealityServerOptions{Listen: loopback(port), UUID: testUUID, ServerName: "reality.test", Target: address, PrivateKey: private.Bytes(), ShortID: "abcd", Transport: transport, Multiplex: typ == "smux"}, testLogger(t))
			if e != nil {
				t.Fatal(e)
			}
			defer server.Close()
			b := New(Options{Logger: testLogger(t)})
			defer b.Close()
			raw, _ := json.Marshal(opts)
			out, e := b.NewOutbound("reality", VLESSSpec{Server: "127.0.0.1", Port: port, UUID: testUUID, TLS: &TLSSpec{ServerName: "reality.test", Fingerprint: "chrome", Reality: &RealitySpec{PublicKey: base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), ShortID: "abcd"}}, Options: raw})
			if e != nil {
				t.Fatal(e)
			}
			defer out.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, e := out.Dial(ctx, "tcp", echoServer(t).String())
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			conn.Write([]byte("reality-transport"))
			got := make([]byte, len("reality-transport"))
			if _, e = io.ReadFull(conn, got); e != nil || string(got) != "reality-transport" {
				t.Fatal(e, string(got))
			}
		})
	}
}
