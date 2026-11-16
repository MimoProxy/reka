package sagernet

import (
	"bufio"
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
	"fmt"
	ST "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
)

func startXHTTPReference(t *testing.T, cfg *XHTTPConfig, protocol string) (string, *x509.CertPool) {
	address, certificate := startXHTTPReferenceMode(t, cfg, protocol, false)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(certificate)) {
		t.Fatal("reference certificate")
	}
	return address, roots
}
func startXHTTPReferenceMode(t *testing.T, cfg *XHTTPConfig, protocol string, vless bool) (string, string) {
	return startXHTTPReferenceCustom(t, cfg, protocol, vless, false)
}
func startXHTTPReferenceCustom(t *testing.T, cfg *XHTTPConfig, protocol string, vless, plain bool, forward ...string) (string, string) {
	t.Helper()
	binary := os.Getenv("REKA_XHTTP_REFERENCE")
	if binary == "" {
		t.Skip("set REKA_XHTTP_REFERENCE to the isolated pinned mihomo peer")
	}
	cmd := exec.Command(binary)
	values := map[string]any{"Config": cfg, "Protocol": protocol, "VLESS": vless, "Plain": plain}
	if len(forward) > 0 {
		values["Forward"] = forward[0]
	}
	input, _ := json.Marshal(values)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	var info struct{ Address, Certificate string }
	line := make(chan []byte, 1)
	go func() { raw, _ := bufio.NewReader(output).ReadBytes('\n'); line <- raw }()
	select {
	case raw := <-line:
		if err = json.Unmarshal(raw, &info); err != nil {
			t.Fatalf("reference: %v: %s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reference startup timeout")
	}
	return info.Address, info.Certificate
}

func TestXHTTPPinnedReferenceModes(t *testing.T) {
	for _, protocol := range []string{"http/1.1", "h2", "h3"} {
		for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				cfg := &XHTTPConfig{Host: "xhttp.test", Path: "/reka-xhttp", Mode: mode, ScMaxEachPostBytes: "16384", ScMinPostsIntervalMs: "1"}
				address, roots := startXHTTPReference(t, cfg, protocol)
				var sockets atomic.Int64
				hooks := XHTTPHooks{
					DialTCP: func(ctx context.Context, _ bool, h2 bool) (net.Conn, error) {
						sockets.Add(1)
						raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
						if err != nil {
							return nil, err
						}
						alpn := "http/1.1"
						if h2 {
							alpn = "h2"
						}
						c := tls.Client(raw, &tls.Config{ServerName: "xhttp.test", RootCAs: roots, NextProtos: []string{alpn}})
						if err = c.HandshakeContext(ctx); err != nil {
							raw.Close()
							return nil, err
						}
						return c, nil
					},
					DialQUIC: func(ctx context.Context, _ bool, cfg *quic.Config) (*quic.Conn, error) {
						sockets.Add(1)
						raw, err := (&net.Dialer{}).DialContext(ctx, "udp", address)
						if err != nil {
							return nil, err
						}
						remote, err := net.ResolveUDPAddr("udp", address)
						if err != nil {
							raw.Close()
							return nil, err
						}
						c, err := quic.Dial(ctx, &dnsPacketConn{raw, remote}, remote, &tls.Config{ServerName: "xhttp.test", RootCAs: roots, NextProtos: []string{"h3"}}, cfg)
						if err != nil {
							raw.Close()
							return nil, err
						}
						context.AfterFunc(c.Context(), func() { _ = raw.Close() })
						return c, nil
					},
				}
				client, err := newXHTTPClient(XHTTPClientOptions{Config: cfg, ALPN: []string{protocol}}, hooks)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				conn, err := client.Dial(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				payload := bytes.Repeat([]byte("xhttp-independent-original-peer"), 4096)
				written := make(chan error, 1)
				go func() { _, e := conn.Write(payload); written <- e }()
				reply := make([]byte, len(payload))
				if _, err = io.ReadFull(conn, reply); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(payload, reply) {
					t.Fatal("payload mismatch")
				}
				if err = <-written; err != nil {
					t.Fatal(err)
				}
				if sockets.Load() == 0 {
					t.Fatal("physical dial callback was bypassed")
				}
				conn.Close()
				if err = client.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err = client.Dial(ctx); err == nil {
					t.Fatal("closed client dial succeeded")
				}
			})
		}
	}
}

func TestXHTTPVLESSPinnedReference(t *testing.T) {
	for _, protocol := range []string{"http/1.1", "h2", "h3"} {
		for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				cfg := &XHTTPConfig{Host: "xhttp.test", Path: "/vless", Mode: mode, ScMinPostsIntervalMs: "1", ScMaxEachPostBytes: "16384"}
				address, certificate := startXHTTPReferenceMode(t, cfg, protocol, true)
				endpoint, err := netip.ParseAddrPort(address)
				if err != nil {
					t.Fatal(err)
				}
				block, _ := pem.Decode([]byte(certificate))
				sum := sha256.Sum256(block.Bytes)
				security := &TLSSpec{ServerName: "xhttp.test", CertificatePin: hex.EncodeToString(sum[:]), ALPN: []string{protocol}}
				if protocol != "h3" {
					security.Fingerprint = "chrome"
				}
				options, _ := json.Marshal(map[string]any{"reka_xhttp": cfg})
				var protected atomic.Int64
				b := New(Options{Logger: testLogger(t), Protect: func(string, string, syscall.RawConn) error { protected.Add(1); return nil }})
				defer b.Close()
				out, err := b.NewOutbound("xhttp-reference", VLESSSpec{Server: "127.0.0.1", Port: endpoint.Port(), UUID: "ca302b35-d67e-437a-bbcb-47773e5bc7d6", TLS: security, Options: options})
				if err != nil {
					t.Fatal(err)
				}
				defer out.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				conn, err := out.Dial(ctx, "tcp", "example.test:443")
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				payload := bytes.Repeat([]byte("full-vless-xhttp"), 4096)
				done := make(chan error, 1)
				go func() { _, e := conn.Write(payload); done <- e }()
				reply := make([]byte, len(payload))
				if _, err = io.ReadFull(conn, reply); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(payload, reply) {
					t.Fatal("VLESS TCP mismatch")
				}
				if err = <-done; err != nil {
					t.Fatal(err)
				}
				packet, err := out.out.ListenPacket(ctx, M.ParseSocksaddr("8.8.8.8:53"))
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
				packet.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err = packet.WriteTo([]byte("vless-xhttp-udp"), M.ParseSocksaddr("8.8.8.8:53")); err != nil {
					t.Fatal(err)
				}
				data := make([]byte, 128)
				n, _, err := packet.ReadFrom(data)
				if err != nil || string(data[:n]) != "vless-xhttp-udp" {
					t.Fatalf("VLESS UDP: %q %v", data[:n], err)
				}
				if protected.Load() == 0 {
					t.Fatal("socket protection was bypassed")
				}
			})
		}
	}
}

func xhttpRealityBridge(t *testing.T, destination, protocol string) (uint16, *TLSSpec) {
	t.Helper()
	target := httptest.NewUnstartedServer(http.NotFoundHandler())
	target.EnableHTTP2 = true
	target.StartTLS()
	t.Cleanup(target.Close)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	address := target.Listener.Addr().(*net.TCPAddr).AddrPort()
	b := New(Options{Logger: testLogger(t)})
	t.Cleanup(func() { _ = b.Close() })
	security, err := ST.NewServer(b.ctx, b.componentLogger("test", "reality", "xhttp"), option.InboundTLSOptions{Enabled: true, ServerName: "reality.test", ALPN: []string{protocol}, Reality: &option.InboundRealityOptions{Enabled: true, PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), ShortID: []string{"abcd"}, Handshake: option.InboundRealityHandshakeOptions{ServerOptions: option.ServerOptions{Server: address.Addr().String(), ServerPort: address.Port()}}}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				secured, err := ST.ServerHandshake(context.Background(), raw, security)
				if err != nil {
					return
				}
				remote, err := net.Dial("tcp", destination)
				if err != nil {
					return
				}
				defer remote.Close()
				done := make(chan struct{})
				go func() { _, _ = io.Copy(remote, secured); _ = remote.Close(); close(done) }()
				_, _ = io.Copy(secured, remote)
				_ = secured.Close()
				<-done
			}()
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port), &TLSSpec{ServerName: "reality.test", Fingerprint: "chrome", ALPN: []string{protocol}, Reality: &RealitySpec{PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortID: "abcd"}}
}
func xhttpCheckFlow(t *testing.T, out *Outbound) { xhttpCheckFlowContext(t, out, context.Background()) }
func xhttpCheckFlowContext(t *testing.T, out *Outbound, baseContext context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(baseContext, 5*time.Second)
	defer cancel()
	conn, err := out.Dial(ctx, "tcp", "xhttp.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("xhttp-layered"), 8192)
	done := make(chan error, 1)
	go func() { _, e := conn.Write(payload); done <- e }()
	reply := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, reply) {
		t.Fatal("payload mismatch")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	packet, err := out.out.ListenPacket(ctx, M.ParseSocksaddr("8.8.8.8:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	_ = packet.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = packet.WriteTo([]byte("layered-udp"), M.ParseSocksaddr("8.8.8.8:53"))
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 128)
	n, _, err := packet.ReadFrom(data)
	if err != nil || string(data[:n]) != "layered-udp" {
		t.Fatalf("UDP %q: %v", data[:n], err)
	}
}
func TestXHTTPRealityWithPinnedTransport(t *testing.T) {
	for _, protocol := range []string{"http/1.1", "h2"} {
		for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				cfg := &XHTTPConfig{Host: "xhttp.test", Path: "/reality", Mode: mode, ScMinPostsIntervalMs: "1"}
				peer, _ := startXHTTPReferenceCustom(t, cfg, protocol, true, true)
				port, security := xhttpRealityBridge(t, peer, protocol)
				b := New(Options{Logger: testLogger(t)})
				defer b.Close()
				opts, _ := json.Marshal(map[string]any{"reka_xhttp": cfg})
				out, err := b.NewOutbound("xhttp-reality", VLESSSpec{Server: "127.0.0.1", Port: port, UUID: "ca302b35-d67e-437a-bbcb-47773e5bc7d6", TLS: security, Options: opts})
				if err != nil {
					t.Fatal(err)
				}
				defer out.Close()
				xhttpCheckFlow(t, out)
			})
		}
	}
}
func TestXHTTPSplitDownloadReusePinnedReference(t *testing.T) {
	for _, mode := range []string{"stream-up", "packet-up"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &XHTTPConfig{Host: "xhttp.test", Path: "/split", Mode: mode, ScMinPostsIntervalMs: "1"}
			address, certificate := startXHTTPReferenceMode(t, cfg, "mixed", true)
			endpoint := netip.MustParseAddrPort(address)
			block, remaining := pem.Decode([]byte(certificate))
			downloadBlock, _ := pem.Decode(remaining)
			if downloadBlock == nil {
				t.Fatal("missing independent download certificate")
			}
			downloadSum := sha256.Sum256(downloadBlock.Bytes)
			sum := sha256.Sum256(block.Bytes)
			pin := hex.EncodeToString(sum[:])
			security := &TLSSpec{ServerName: "xhttp.test", CertificatePin: pin, ALPN: []string{"h2"}}
			download := &TLSSpec{ServerName: "xhttp.test", CertificatePin: hex.EncodeToString(downloadSum[:]), ALPN: []string{"h3"}}
			for _, pool := range []string{"both", "upload-only", "download-only", "none"} {
				t.Run(pool, func(t *testing.T) {
					wire := map[string]any{"host": cfg.Host, "path": cfg.Path, "mode": mode, "sc-min-posts-interval-ms": "1"}
					ds := map[string]any{"server": "download-node.test", "port": endpoint.Port(), "reka_tls": download}
					if pool == "both" || pool == "upload-only" {
						wire["xmux"] = map[string]any{"max-connections": "2", "h-keep-alive-period": "-1"}
					}
					if pool == "both" || pool == "download-only" {
						ds["xmux"] = map[string]any{"max-connections": "2", "h-keep-alive-period": "-1"}
					}
					wire["download-settings"] = ds
					opts, _ := json.Marshal(map[string]any{"reka_xhttp": wire})
					b := New(Options{Logger: testLogger(t)})
					defer b.Close()
					out, err := b.NewOutbound("xhttp-split", VLESSSpec{Server: "127.0.0.1", Port: endpoint.Port(), UUID: "ca302b35-d67e-437a-bbcb-47773e5bc7d6", TLS: security, Options: opts})
					if err != nil {
						t.Fatal(err)
					}
					defer out.Close()
					var lookups atomic.Int32
					lookupCtx := WithLookup(context.Background(), func(_ context.Context, name string) ([]netip.Addr, error) {
						if name != "download-node.test" {
							return nil, fmt.Errorf("unexpected native DNS name %s", name)
						}
						lookups.Add(1)
						return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
					})
					for i := 0; i < 2; i++ {
						xhttpCheckFlowContext(t, out, lookupCtx)
					}
					if lookups.Load() == 0 {
						t.Fatal("download endpoint bypassed scoped DNS")
					}
				})
			}

		})
	}
}
