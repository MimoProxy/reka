package sagernet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/testnet"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	TR "github.com/sagernet/sing-box/protocol/trojan"
	VL "github.com/sagernet/sing-box/protocol/vless"
	VM "github.com/sagernet/sing-box/protocol/vmess"
	M "github.com/sagernet/sing/common/metadata"
)

func tlsCarrierCases() []SSPluginSpec {
	return []SSPluginSpec{
		{Type: "shadow-tls", Version: 1}, {Type: "shadow-tls", Version: 2, Password: "outer-secret"}, {Type: "shadow-tls", Version: 3, Password: "outer-secret", TLS: &TLSSpec{Fingerprint: "chrome"}},
		{Type: "restls", VersionHint: "tls12", Password: "outer-secret", ClientFingerprint: "chrome"}, {Type: "restls", VersionHint: "tls13", Password: "outer-secret", ClientFingerprint: "firefox", RestlsScript: "100~20,200~50"},
		{Type: "jls", Username: "outer-user", Password: "outer-secret"}, {Type: "jls", Username: "outer-user", Password: "outer-secret", ClientFingerprint: "chrome"},
		{Type: "shadow-tls", Version: 2, Password: "outer-secret", TLS: &TLSSpec{Fingerprint: "chrome"}},
	}
}
func carrierNode(t *testing.T, protocol, transport string) (*Server, netip.AddrPort, json.RawMessage) {
	t.Helper()
	opts := map[string]any{}
	var stream *option.V2RayTransportOptions
	if transport != "" {
		value := map[string]any{"type": transport, "path": "/carrier"}
		if transport == "grpc" {
			delete(value, "path")
			value["service_name"] = "carrier"
		}
		raw, _ := json.Marshal(value)
		stream = &option.V2RayTransportOptions{}
		if err := json.Unmarshal(raw, stream); err != nil {
			t.Fatal(err)
		}
		opts["transport"] = value
	}
	var server *Server
	listen := testnet.RetryAddr(t, func(listen netip.AddrPort) (err error) {
		server, err = startNode(testLogger(t), func(b *Backend) (adapter.Inbound, string, error) {
			logger := b.componentLogger("inbound", protocol, "carrier")
			switch protocol {
			case "vless":
				in, err := VL.NewInbound(b.ctx, b.router, logger, "carrier", option.VLESSInboundOptions{ListenOptions: listenOpts(listen), Users: []option.VLESSUser{{UUID: testUUID}}, Transport: stream})
				return in, protocol, err
			case "vmess":
				in, err := VM.NewInbound(b.ctx, b.router, logger, "carrier", option.VMessInboundOptions{ListenOptions: listenOpts(listen), Users: []option.VMessUser{{UUID: testUUID}}, Transport: stream})
				return in, protocol, err
			default:
				in, err := TR.NewInbound(b.ctx, b.router, logger, "carrier", option.TrojanInboundOptions{ListenOptions: listenOpts(listen), Users: []option.TrojanUser{{Password: "inner-secret"}}, Transport: stream})
				return in, protocol, err
			}
		})
		return err
	})
	raw, _ := json.Marshal(opts)
	return server, listen, raw
}
func TestTLSCarriersProtocolsTransportsTCPUDP(t *testing.T) {
	target := echoServer(t).String()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, addr, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			udp.WriteTo(b[:n], addr)
		}
	}()
	destination := M.ParseSocksaddr(udp.LocalAddr().String())
	for _, protocol := range []string{"vmess", "vless", "trojan"} {
		for _, transport := range []string{"", "ws", "httpupgrade", "grpc", "http"} {
			for i, carrier := range tlsCarrierCases() {
				t.Run(fmt.Sprintf("%s/%s/%02d-%s", protocol, transport, i, carrier.Type), func(t *testing.T) {
					server, inner, options := carrierNode(t, protocol, transport)
					defer server.Close()
					carrier.Host = "plugin.test"
					port, security := pluginTestPeer(t, carrier, inner)
					if security == nil {
						security = &TLSSpec{ServerName: "plugin.test"}
					}
					if carrier.Type == "restls" || carrier.Type == "jls" {
						security.Fingerprint = carrier.ClientFingerprint
					}
					if transport == "http" || transport == "grpc" {
						security.ALPN = []string{"h2"}
					} else if transport != "" {
						security.ALPN = []string{"http/1.1"}
					}
					security.Carrier = &TLSCarrierSpec{Type: carrier.Type, Username: carrier.Username, Password: carrier.Password, Version: carrier.Version, VersionHint: carrier.VersionHint, Script: carrier.RestlsScript}
					var protected atomic.Int32
					b := New(Options{Logger: testLogger(t), ProtectFD: func(int) error { protected.Add(1); return nil }})
					defer b.Close()
					spec := ProxySpec{Type: protocol, Server: "127.0.0.1", Port: port, UUID: testUUID, Password: "inner-secret", TLS: security, Options: options}
					out, err := b.NewOutbound("carrier", spec)
					if err != nil {
						t.Fatal(err)
					}
					defer out.Close()
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					conn, err := out.Dial(ctx, "tcp", target)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					data := bytes.Repeat([]byte("secure-carrier"), 16384)
					written := make(chan error, 1)
					go func() { _, err := conn.Write(data); written <- err }()
					got := make([]byte, len(data))
					if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(data, got) {
						t.Fatal("carrier TCP", err)
					}
					if err := <-written; err != nil {
						t.Fatal(err)
					}
					packet, err := out.out.ListenPacket(ctx, destination)
					if err != nil {
						t.Fatal(err)
					}
					defer packet.Close()
					packet.SetDeadline(time.Now().Add(2 * time.Second))
					packet.WriteTo([]byte("carrier-udp"), destination)
					reply := make([]byte, 128)
					n, _, err := packet.ReadFrom(reply)
					if err != nil || string(reply[:n]) != "carrier-udp" {
						t.Fatal("carrier UDP", err)
					}
					expected := int32(2)
					if transport == "grpc" || transport == "http" {
						expected = 1
					}
					if protected.Load() != expected {
						t.Fatal("physical socket protection count", protected.Load(), expected)
					}
					if transport == "" && (carrier.Password != "" || carrier.Type == "jls") {
						invalid := *security
						wrong := *security.Carrier
						wrong.Password = "incorrect-outer-secret"
						invalid.Carrier = &wrong
						badSpec := spec
						badSpec.TLS = &invalid
						bad, err := b.NewOutbound("bad-carrier", badSpec)
						if err != nil {
							t.Fatal(err)
						}
						defer bad.Close()
						badCtx, stop := context.WithTimeout(context.Background(), 500*time.Millisecond)
						defer stop()
						c, err := bad.Dial(badCtx, "tcp", target)
						if err == nil {
							c.SetDeadline(time.Now().Add(300 * time.Millisecond))
							c.Write([]byte("bad"))
							reply := make([]byte, 3)
							_, err = io.ReadFull(c, reply)
							if err == nil && string(reply) != "bad" {
								err = fmt.Errorf("camouflage response did not reach authenticated echo")
							}
							c.Close()
						}
						if err == nil {
							t.Fatal("incorrect security carrier password accepted")
						}
					}
				})
			}
		}
	}
}

func TestTLSCarrierConfigCloneAndLazyHandshakeCancellation(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	config := &carrierTLSConfig{spec: TLSSpec{ServerName: "plugin.test", ALPN: []string{"h2"}, Carrier: &TLSCarrierSpec{Type: "jls", Username: "u", Password: "p"}}, logger: b.logger, timeout: time.Second}
	clone := config.Clone()
	clone.SetServerName("other.test")
	clone.SetNextProtos([]string{"http/1.1"})
	if config.ServerName() != "plugin.test" || config.NextProtos()[0] != "h2" {
		t.Fatal("clone mutated live config")
	}
	raw, peer := net.Pipe()
	defer peer.Close()
	conn, err := config.Client(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err == nil {
		t.Fatal("stalled security handshake ignored cancellation")
	}
}
