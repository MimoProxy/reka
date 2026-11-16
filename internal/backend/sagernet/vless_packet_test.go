package sagernet

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/vless"
)

func TestVLESSUDPPacketEncodings(t *testing.T) {
	plain := startServer(t, "vless", func(b *Backend, listen netip.AddrPort) error {
		return adopt(t, b, "plain", "vless", func() (adapter.Inbound, error) {
			return vless.NewInbound(b.ctx, b.router, b.componentLogger("inbound", "vless", "plain"), "plain", option.VLESSInboundOptions{ListenOptions: listenOptions(listen), Users: []option.VLESSUser{{UUID: testUUID}}})
		})
	})
	reality, pub, sid := realityServer(t, testUUID, "")
	for _, family := range []string{"udp4", "udp6"} {
		address := "127.0.0.1:0"
		if family == "udp6" {
			address = "[::1]:0"
		}
		echo, e := net.ListenPacket(family, address)
		if e != nil {
			if family == "udp6" {
				continue
			}
			t.Fatal(e)
		}
		defer echo.Close()
		go func() {
			buf := make([]byte, 2048)
			for {
				n, a, e := echo.ReadFrom(buf)
				if e != nil {
					return
				}
				echo.WriteTo(buf[:n], a)
			}
		}()
		for _, security := range []string{"plain", "reality"} {
			for _, encoding := range []string{"xudp", "", "packetaddr"} {
				t.Run(family+"/"+security+"/"+encoding, func(t *testing.T) {
					b := New(Options{Logger: testLogger(t)})
					defer b.Close()
					options, _ := json.Marshal(map[string]any{"packet_encoding": encoding})
					var spec any = ProxySpec{Type: "vless", Server: "127.0.0.1", Port: plain.Port(), UUID: testUUID, Options: options}
					if security == "reality" {
						s := realitySpec(reality, testUUID, "", pub, sid)
						s.Options = options
						spec = s
					}
					out, e := b.NewOutbound("packet", spec)
					if e != nil {
						t.Fatal(e)
					}
					defer out.Close()
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					conn, e := out.Dial(ctx, "udp", echo.LocalAddr().String())
					if e != nil {
						t.Fatal(e)
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					const payload = "packet-encoding-check"
					if _, e = conn.Write([]byte(payload)); e != nil {
						t.Fatal(e)
					}
					buf := make([]byte, 2048)
					n, e := conn.Read(buf)
					if e != nil || string(buf[:n]) != payload {
						t.Fatal("UDP framing", encoding, e, string(buf[:n]))
					}
				})
			}
		}
	}
}
