package sagernet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	VE "github.com/MimoProxy/reka/internal/compat/vlessenc"
	"github.com/MimoProxy/reka/internal/testnet"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	V "github.com/sagernet/sing-box/protocol/vless"
	M "github.com/sagernet/sing/common/metadata"
)

func TestXHTTPEncryptedVisionPinnedTransportTCPUDP(t *testing.T) {
	web := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("vision-inner-tls"), 4096))
	}))
	defer web.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, addr, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(buffer[:n], addr)
		}
	}()
	for _, protocol := range []string{"http/1.1", "h2", "h3"} {
		for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				private, public, _, err := VE.GenX25519("")
				if err != nil {
					t.Fatal(err)
				}
				seed, mlkem, _, err := VE.GenMLKEM768("")
				if err != nil {
					t.Fatal(err)
				}
				decrypt, err := VE.NewServer("mlkem768x25519plus.native.60s." + private + "." + seed + ".100-35-35")
				if err != nil {
					t.Fatal(err)
				}
				defer decrypt.Close()
				var server *Server
				port := testnet.Retry(t, func(port uint16) (err error) {
					server, err = startNode(testLogger(t), func(b *Backend) (adapter.Inbound, string, error) {
						ctx := context.WithValue(b.ctx, "reka.vless.decrypt.v1", func(ctx context.Context, c net.Conn) (net.Conn, error) {
							ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
							defer cancel()
							stop := context.AfterFunc(ctx, func() { _ = c.Close() })
							defer stop()
							return decrypt.Handshake(c, nil)
						})
						in, err := V.NewInbound(ctx, b.router, b.componentLogger("inbound", "vless", "xhttp-encrypted"), "xhttp-encrypted", option.VLESSInboundOptions{ListenOptions: listenOpts(loopback(port)), Users: []option.VLESSUser{{UUID: testUUID, Flow: "xtls-rprx-vision"}}})
						return in, "vless", err
					})
					return err
				})
				defer server.Close()
				cfg := &XHTTPConfig{Host: "xhttp.test", Path: "/encrypted", Mode: mode, ScMinPostsIntervalMs: "1"}
				address, certificate := startXHTTPReferenceCustom(t, cfg, protocol, false, false, net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
				cert, _ := pem.Decode([]byte(certificate))
				pin := sha256.Sum256(cert.Bytes)
				endpoint := netip.MustParseAddrPort(address)
				b := New(Options{Logger: testLogger(t)})
				defer b.Close()
				raw, _ := json.Marshal(map[string]any{"reka_xhttp": cfg, "flow": "xtls-rprx-vision", "packet_encoding": "xudp"})
				out, err := b.NewOutbound("xhttp-encrypted", VLESSSpec{Server: "127.0.0.1", Port: endpoint.Port(), UUID: testUUID, Flow: "xtls-rprx-vision", Encryption: "mlkem768x25519plus.native.0rtt." + public + "." + mlkem + ".100-35-35", TLS: &TLSSpec{ServerName: "xhttp.test", ALPN: []string{protocol}, CertificatePin: hex.EncodeToString(pin[:])}, Options: raw})
				if err != nil {
					t.Fatal(err)
				}
				defer out.Close()
				transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: out.Dial, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
				defer transport.CloseIdleConnections()
				response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get(web.URL)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || !bytes.Equal(body, bytes.Repeat([]byte("vision-inner-tls"), 4096)) {
					t.Fatal("Vision inner TLS stream mismatch", err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				destination := M.ParseSocksaddr(udp.LocalAddr().String())
				packet, err := out.out.ListenPacket(ctx, destination)
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
				_ = packet.SetDeadline(time.Now().Add(3 * time.Second))
				_, err = packet.WriteTo([]byte("encrypted-xhttp-xudp"), destination)
				if err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 2048)
				n, _, err := packet.ReadFrom(buffer)
				if err != nil || string(buffer[:n]) != "encrypted-xhttp-xudp" {
					t.Fatal("encrypted Vision XUDP mismatch", err)
				}
			})
		}
	}
}
