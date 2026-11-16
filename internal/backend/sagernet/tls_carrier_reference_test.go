package sagernet

import (
	"bytes"
	"context"
	"fmt"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestTLSCarriersAgainstPinnedReference(t *testing.T) {
	if os.Getenv("REKA_REFERENCE_PEER") == "" {
		t.Skip("pinned original peers run in the compatibility-reference job")
	}
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
		for _, transport := range []string{"", "grpc", "http"} {
			for i, carrier := range tlsCarrierCases() {
				t.Run(fmt.Sprintf("%s/%s/%02d-%s", protocol, transport, i, carrier.Type), func(t *testing.T) {
					server, inner, options := carrierNode(t, protocol, transport)
					defer server.Close()
					address, pin := startPinnedCarrierPeer(t, map[string]any{"Type": carrier.Type, "Version": carrier.Version, "Username": carrier.Username, "Password": carrier.Password, "VersionHint": carrier.VersionHint, "Script": carrier.RestlsScript, "Forward": inner.String()})
					endpoint, err := netip.ParseAddrPort(address)
					if err != nil {
						t.Fatal(err)
					}
					security := &TLSSpec{ServerName: "plugin.test", CertificatePin: pin, Carrier: &TLSCarrierSpec{Type: carrier.Type, Username: carrier.Username, Password: carrier.Password, Version: carrier.Version, VersionHint: carrier.VersionHint, Script: carrier.RestlsScript}}
					if transport != "" {
						security.ALPN = []string{"h2"}
					}
					security.Fingerprint = carrier.ClientFingerprint
					if carrier.TLS != nil {
						security.Fingerprint = carrier.TLS.Fingerprint
					}
					b := New(Options{Logger: testLogger(t)})
					defer b.Close()
					out, err := b.NewOutbound("reference-carrier", ProxySpec{Type: protocol, Server: "127.0.0.1", Port: endpoint.Port(), UUID: testUUID, Password: "inner-secret", TLS: security, Options: options})
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
					payload := bytes.Repeat([]byte("original-security-carrier"), 16384)
					done := make(chan error, 1)
					go func() { _, err := conn.Write(payload); done <- err }()
					reply := make([]byte, len(payload))
					if _, err = io.ReadFull(conn, reply); err != nil || !bytes.Equal(payload, reply) {
						t.Fatal("original security TCP", err)
					}
					if err = <-done; err != nil {
						t.Fatal(err)
					}
					packet, err := out.out.ListenPacket(ctx, destination)
					if err != nil {
						t.Fatal(err)
					}
					defer packet.Close()
					packet.SetDeadline(time.Now().Add(2 * time.Second))
					packet.WriteTo([]byte("reference-udp"), destination)
					data := make([]byte, 64)
					n, _, err := packet.ReadFrom(data)
					if err != nil || string(data[:n]) != "reference-udp" {
						t.Fatal("original security UDP", err)
					}
				})
			}
		}
	}
}
