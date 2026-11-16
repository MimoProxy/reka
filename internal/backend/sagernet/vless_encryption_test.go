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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	VE "github.com/MimoProxy/reka/internal/compat/vlessenc"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	V "github.com/sagernet/sing-box/protocol/vless"
	M "github.com/sagernet/sing/common/metadata"
)

func TestEncryptedVLESSVisionTransportsTCPUDPAndWrongKey(t *testing.T) {
	web := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(bytes.Repeat([]byte("inner-TLS"), 4096)) }))
	web.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	web.EnableHTTP2 = true
	web.StartTLS()
	defer web.Close()
	cert := web.TLS.Certificates[0]
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	pin := sha256.Sum256(cert.Certificate[0])
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
			udp.WriteTo(buffer[:n], addr)
		}
	}()
	for _, mode := range []string{"native", "xorpub", "random"} {
		for _, tc := range []struct {
			transport, tlsMode, flow string
			mux                      bool
		}{
			{"", "", "", false}, {"", "", "xtls-rprx-vision", false}, {"ws", "", "xtls-rprx-vision", false}, {"httpupgrade", "", "xtls-rprx-vision", false}, {"grpc", "", "xtls-rprx-vision", false}, {"h2", "tls", "xtls-rprx-vision", false}, {"", "tls", "xtls-rprx-vision", false}, {"", "reality", "xtls-rprx-vision", false},
			{"http", "", "xtls-rprx-vision", false}, {"http", "tls", "xtls-rprx-vision", false}, {"http", "reality", "xtls-rprx-vision", false}, {"ws", "reality", "xtls-rprx-vision", false}, {"h2", "reality", "xtls-rprx-vision", false},
			{"", "tls", "xtls-rprx-vision", true}, {"", "reality", "xtls-rprx-vision", true}, {"ws", "reality", "xtls-rprx-vision", true},
			{"", "shadow-tls", "xtls-rprx-vision", true}, {"ws", "restls", "xtls-rprx-vision", false}, {"h2", "jls", "xtls-rprx-vision", true},
		} {
			t.Run(fmt.Sprintf("%s/%s/%s/%s/mux%v", mode, tc.transport, tc.tlsMode, tc.flow, tc.mux), func(t *testing.T) {
				private, public, _, err := VE.GenX25519("")
				if err != nil {
					t.Fatal(err)
				}
				seed, mlkemPublic, _, err := VE.GenMLKEM768("")
				if err != nil {
					t.Fatal(err)
				}
				decryption, err := VE.NewServer("mlkem768x25519plus." + mode + ".60s." + private + "." + seed + ".100-35-35")
				if err != nil {
					t.Fatal(err)
				}
				defer decryption.Close()
				encryption := "mlkem768x25519plus." + mode + ".0rtt." + public + "." + mlkemPublic + ".100-35-35"
				port := freePort(t)
				serverOptions := option.VLESSInboundOptions{ListenOptions: listenOpts(loopback(port)), Users: []option.VLESSUser{{UUID: testUUID, Flow: tc.flow}}}
				clientOptions := map[string]any{"flow": tc.flow, "packet_encoding": "xudp"}
				if tc.mux {
					serverOptions.Multiplex = &option.InboundMultiplexOptions{Enabled: true}
					clientOptions["multiplex"] = map[string]any{"enabled": true, "protocol": "smux", "padding": true}
				}
				var clientTLS *TLSSpec
				if tc.tlsMode == "tls" {
					serverOptions.TLS = &option.InboundTLSOptions{Enabled: true, Certificate: []string{certPEM}, Key: []string{keyPEM}}
					clientTLS = &TLSSpec{ServerName: "example.com", CertificatePin: hex.EncodeToString(pin[:])}
				} else if tc.tlsMode == "reality" {
					key, err := ecdh.X25519().GenerateKey(rand.Reader)
					if err != nil {
						t.Fatal(err)
					}
					serverOptions.TLS = &option.InboundTLSOptions{Enabled: true, ServerName: "example.com", Reality: &option.InboundRealityOptions{Enabled: true, PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), ShortID: []string{"abcd"}, Handshake: option.InboundRealityHandshakeOptions{ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(web.Listener.Addr().(*net.TCPAddr).Port)}}}}
					clientTLS = &TLSSpec{ServerName: "example.com", Fingerprint: "chrome", Reality: &RealitySpec{PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortID: "abcd"}}
				}
				if tc.transport != "" {
					transport := map[string]any{"type": tc.transport, "path": "/encrypted"}
					if tc.transport == "h2" {
						transport["type"] = "http"
					}
					if tc.transport == "grpc" {
						delete(transport, "path")
						transport["service_name"] = "encrypted"
					}
					raw, _ := json.Marshal(transport)
					serverOptions.Transport = &option.V2RayTransportOptions{}
					if err = json.Unmarshal(raw, serverOptions.Transport); err != nil {
						t.Fatal(err)
					}
					if tc.transport == "http" {
						clientOptions["reka_http"] = map[string]any{"method": "POST", "paths": []string{"/encrypted"}}
					} else {
						clientOptions["transport"] = transport
					}
				}
				server, err := startNode(testLogger(t), func(b *Backend) (adapter.Inbound, string, error) {
					decrypt := func(ctx context.Context, c net.Conn) (net.Conn, error) {
						ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
						defer cancel()
						stop := context.AfterFunc(ctx, func() { c.Close() })
						defer stop()
						return decryption.Handshake(c, nil)
					}
					ctx := context.WithValue(b.ctx, "reka.vless.decrypt.v1", decrypt)
					in, err := V.NewInbound(ctx, b.router, b.componentLogger("inbound", "vless", "encrypted"), "encrypted", serverOptions)
					return in, "vless", err
				})
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				if tc.tlsMode == "shadow-tls" || tc.tlsMode == "restls" || tc.tlsMode == "jls" {
					carrier := SSPluginSpec{Type: tc.tlsMode, Host: "plugin.test", Version: 3, Password: "outer-secret", Username: "outer-user", VersionHint: "tls13", ClientFingerprint: "chrome"}
					external, tls := pluginTestPeer(t, carrier, loopback(port))
					port = external
					clientTLS = tls
					if clientTLS == nil {
						clientTLS = &TLSSpec{ServerName: "plugin.test"}
					}
					clientTLS.Fingerprint = "chrome"
					clientTLS.Carrier = &TLSCarrierSpec{Type: carrier.Type, Version: carrier.Version, Password: carrier.Password, Username: carrier.Username, VersionHint: carrier.VersionHint}
				}
				b := New(Options{Logger: testLogger(t)})
				defer b.Close()
				raw, _ := json.Marshal(clientOptions)
				var spec any = ProxySpec{Type: "vless", Server: "127.0.0.1", Port: port, UUID: testUUID, Encryption: encryption, TLS: clientTLS, Options: raw}
				if tc.tlsMode == "reality" {
					spec = VLESSSpec{Server: "127.0.0.1", Port: port, UUID: testUUID, Flow: tc.flow, Encryption: encryption, TLS: clientTLS, Options: raw}
				}
				out, err := b.NewOutbound("encrypted", spec)
				if err != nil {
					t.Fatal(err)
				}
				defer out.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				// Real inner TLS exercises Vision's switch from the encryption
				// buffers to the underlying transport, including non-TCP carriers.
				tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: out.Dial, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
				defer tr.CloseIdleConnections()
				client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
				response, err := client.Get(web.URL)
				if err != nil {
					t.Fatal("inner TLS", err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || !bytes.Equal(body, bytes.Repeat([]byte("inner-TLS"), 4096)) {
					t.Fatal("inner TLS payload", err)
				}
				destination := M.ParseSocksaddr(udp.LocalAddr().String())
				packet, err := out.out.ListenPacket(ctx, destination)
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
				packet.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = packet.WriteTo([]byte("encrypted-udp"), destination); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 1024)
				n, _, err := packet.ReadFrom(buffer)
				if err != nil || string(buffer[:n]) != "encrypted-udp" {
					t.Fatal("UDP", err)
				}
				if tc.transport == "" && tc.tlsMode == "" && tc.flow == "" {
					_, wrong, _, _ := VE.GenX25519("")
					bad := spec.(ProxySpec)
					bad.Encryption = "mlkem768x25519plus." + mode + ".1rtt." + wrong + ".100-35-35"
					negative, err := b.NewOutbound("wrong-key", bad)
					if err != nil {
						t.Fatal(err)
					}
					defer negative.Close()
					if c, err := negative.Dial(ctx, "tcp", echoServer(t).String()); err == nil {
						c.Close()
						t.Fatal("wrong VLESS encryption key accepted")
					}
				}
			})
		}
	}
}
