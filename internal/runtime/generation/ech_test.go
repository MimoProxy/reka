package generation

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	Native "github.com/MimoProxy/reka/internal/backend/sagernet"
	VWS "github.com/sagernet/sing-box/transport/v2raywebsocket"
	"github.com/sagernet/ws"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/compile"
	D "github.com/miekg/dns"
	S "github.com/sagernet/sing-box/common/tls"
)

func TestECHUsesActiveProxyServerDNSAfterResolverOnlyRevision(t *testing.T) {
	for _, plugin := range []bool{false, true} {
		t.Run(fmt.Sprintf("plugin-%v", plugin), func(t *testing.T) {
			var ssAddress string
			target, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			go func() {
				for {
					c, err := target.Accept()
					if err != nil {
						return
					}
					go func() { defer c.Close(); io.Copy(c, c) }()
				}
			}()
			if plugin {
				// The Shadowsocks peer binds both transports to the same port.
				// A TCP-only ephemeral reservation may select an occupied UDP port.
				var listen netip.AddrPort
				for attempts := 0; attempts < 100; attempts++ {
					temporary, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", 1024+mrand.IntN(65536-1024)))
					if err != nil {
						continue
					}
					candidate := temporary.Addr().(*net.TCPAddr).AddrPort()
					packet, err := net.ListenPacket("udp4", candidate.String())
					temporary.Close()
					if err == nil {
						packet.Close()
						listen = candidate
						break
					}
				}
				if !listen.IsValid() {
					t.Fatal("could not reserve a TCP/UDP peer port")
				}
				server, err := Native.StartShadowsocksServer(listen, "aes-128-gcm", "test", nil)
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				ssAddress = listen.String()
			}

			config, key, err := S.ECHKeygenDefault("public.test")
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode([]byte(config))
			keyBlock, _ := pem.Decode([]byte(key))
			keys, err := S.UnmarshalECHKeys(keyBlock.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || !r.TLS.ECHAccepted {
					w.WriteHeader(403)
					return
				}
				if plugin {
					raw, _, _, err := ws.UpgradeHTTP(r, w)
					if err != nil {
						return
					}
					c := VWS.NewConn(raw, raw.RemoteAddr(), ws.StateServerSide)
					up, err := net.Dial("tcp", ssAddress)
					if err != nil {
						c.Close()
						return
					}
					go func() { defer c.Close(); defer up.Close(); go func() { io.Copy(up, c); up.Close() }(); io.Copy(c, up) }()
					return
				}
				c, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer c.Close()
				io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				io.Copy(c, c)
			}))
			origin.TLS = &tls.Config{EncryptedClientHelloKeys: keys}
			origin.StartTLS()
			defer origin.Close()
			var goodQueries, badQueries atomic.Int32
			dnsServer := func(valid bool) string {
				t.Helper()
				socket, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				server := &D.Server{PacketConn: socket, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
					reply := new(D.Msg)
					reply.SetReply(q)
					if valid {
						goodQueries.Add(1)
					} else {
						badQueries.Add(1)
					}
					if valid && q.Question[0].Qtype == D.TypeHTTPS && q.Question[0].Name == "ech-query.example." {
						reply.Answer = []D.RR{&D.HTTPS{SVCB: D.SVCB{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeHTTPS, Class: D.ClassINET, Ttl: 30}, Priority: 1, Target: ".", Value: []D.SVCBKeyValue{&D.SVCBECHConfig{ECH: block.Bytes}}}}}
					}
					w.WriteMsg(reply)
				})}
				go server.ActivateAndServe()
				t.Cleanup(func() { server.Shutdown(); socket.Close() })
				return socket.LocalAddr().String()
			}
			good, bad := dnsServer(true), dnsServer(false)
			port := origin.Listener.Addr().(*net.TCPAddr).Port
			pin := sha256.Sum256(origin.TLS.Certificates[0].Certificate[0])
			input := func(proxyDNS string) []byte {
				if plugin {
					return []byte(fmt.Sprintf(`schema-version: 1
outbounds: [{id: node, type: shadowsocks, server: 127.0.0.1, port: %d, method: aes-128-gcm, password: test, plugin: {type: v2ray-plugin, mode: websocket, mux: false, host: example.com, tls: {server-name: example.com, certificate-sha256: %q, ech: {enabled: true, query-server-name: ech-query.example}}}}]
dns: {nameserver: [%q], proxy-server-nameserver: [%q]}
`, port, hex.EncodeToString(pin[:]), bad, proxyDNS))
				}
				return []byte(fmt.Sprintf(`schema-version: 1
outbounds: [{id: node, type: http, server: 127.0.0.1, port: %d, tls: {server-name: example.com, certificate-sha256: %q, ech: {enabled: true, query-server-name: ech-query.example}}}]
dns: {nameserver: [%q], proxy-server-nameserver: [%q]}
`, port, hex.EncodeToString(pin[:]), bad, proxyDNS))
			}
			e := NewEngine(EngineOptions{})
			defer e.Close()
			activate := func(proxyDNS string, revision uint64) {
				t.Helper()
				eff, ds := compile.Compile(input(proxyDNS), nil, compile.Options{})
				if ds.HasErrors() {
					t.Fatal(ds)
				}
				p, err := e.Prepare(eff)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = e.Activate(p, revision); err != nil {
					t.Fatal(err)
				}
			}
			activate(good, 1)
			out := e.OutboundInstance("node")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := out.Dial(ctx, "tcp", target.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if goodQueries.Load() != 1 || badQueries.Load() != 0 {
				t.Fatal("ECH escaped proxy DNS scope", goodQueries.Load(), badQueries.Load())
			}
			activate(bad, 2)
			if out != e.OutboundInstance("node") {
				t.Fatal("resolver-only change rebuilt node")
			}
			if unexpected, err := out.Dial(ctx, "tcp", target.Addr().String()); err == nil {
				unexpected.Close()
				t.Fatal("reused node kept the old ECH DNS snapshot")
			}
			c.SetDeadline(time.Now().Add(time.Second))
			c.Write([]byte("old"))
			response := make([]byte, 3)
			if _, err = io.ReadFull(c, response); err != nil || string(response) != "old" {
				t.Fatal("resolver revision interrupted established ECH connection", err)
			}
			if badQueries.Load() != 1 {
				t.Fatal("new DNS scope was not observed", badQueries.Load())
			}
		})
	}
}
