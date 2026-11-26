package ssr

import (
	"bytes"
	"net"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestClientValidation(t *testing.T) {
	valid := Config{Server: "proxy.example", Port: 8388, Method: "NoNe", Password: "password"}
	for _, tc := range []struct {
		change func(*Config)
		want   []string
	}{
		{func(c *Config) { c.Method = "aes-256-gcm" }, []string{"SSR requires a stream cipher", "rc4-md5", "xchacha20", "none"}},
		{func(c *Config) { c.Method = "" }, []string{"stream cipher", "aes-128-cfb"}},
		{func(c *Config) { c.Password = "" }, []string{"password"}},
		{func(c *Config) { c.Obfs = "tls" }, []string{"plain", "http_post", "tls1.2_ticket_fastauth"}},
		{func(c *Config) { c.Protocol = "verify_simple" }, []string{"origin", "auth_chain_b", "auth_aes128_md5"}},
	} {
		cfg := valid
		tc.change(&cfg)
		_, err := New(cfg)
		for _, s := range tc.want {
			if err == nil || !strings.Contains(err.Error(), s) {
				t.Fatalf("expected diagnostic containing %q, got %v", s, err)
			}
		}
	}
	for _, name := range []string{"plain", "http_simple", "http_post", "random_head", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"} {
		cfg := valid
		cfg.Obfs = name
		if _, err := New(cfg); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b"} {
		cfg := valid
		cfg.Protocol, cfg.ProtocolParam = name, "64:key"
		if _, err := New(cfg); err != nil {
			t.Fatal(err)
		}
	}
}

type memoryDatagram struct {
	net.PacketConn
	wire []byte
	addr net.Addr
}

func (p *memoryDatagram) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.wire, p.addr = bytes.Clone(b), addr
	return len(b), nil
}

func (p *memoryDatagram) ReadFrom(b []byte) (int, net.Addr, error) {
	return copy(b, p.wire), p.addr, nil
}

func TestPacketAddressAndCipher(t *testing.T) {
	for method := range methods {
		t.Run(method, func(t *testing.T) {
			config := Config{Server: "proxy.example", Port: 8388, Method: method, Password: "packet-password", Obfs: "http_post"}
			client, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			raw := &memoryDatagram{}
			server := M.ParseSocksaddr("proxy.example:8388")
			packet := client.PacketConn(raw, server)
			for _, address := range []string{"target.example:53", "192.0.2.1:80", "[2001:db8::1]:443"} {
				dst := M.ParseSocksaddr(address)
				payload := []byte("packet data")
				n, err := packet.WriteTo(payload, dst)
				if err != nil || n != len(payload) || raw.addr != server {
					t.Fatalf("write %d to %v: %v", n, raw.addr, err)
				}
				expected := client.method.ivSize + M.SocksaddrSerializer.AddrPortLen(dst) + len(payload)
				if len(raw.wire) != expected {
					t.Fatalf("UDP wire length = %d, want %d", len(raw.wire), expected)
				}
				// Even a short application buffer must receive the decoded
				// payload prefix, including when the address or IV is longer.
				got := make([]byte, 4)
				n, addr, err := packet.ReadFrom(got)
				if err != nil || n != len(got) || string(got) != "pack" || M.SocksaddrFromNet(addr) != dst {
					t.Fatalf("read %q from %v: %v", got, addr, err)
				}
			}
		})
	}
}
