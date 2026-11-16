package sagernet

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestExplicitInterfaceKeepsSocketProtection(t *testing.T) {
	interfaces, e := net.Interfaces()
	if e != nil {
		t.Fatal(e)
	}
	loopback := ""
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			loopback = iface.Name
			break
		}
	}
	if loopback == "" {
		t.Skip("host has no loopback interface")
	}
	target := echoServer(t)
	for _, bind := range []bool{false, true} {
		var protected atomic.Int32
		b := New(Options{Logger: testLogger(t), ProtectFD: func(fd int) error {
			if fd < 0 {
				t.Error("invalid descriptor")
			}
			protected.Add(1)
			return nil
		}})
		options := map[string]any{}
		if bind {
			options["bind_interface"] = loopback
		}
		raw, _ := json.Marshal(options)
		out, e := b.NewOutbound("protected", ProxySpec{Type: "direct", Options: raw})
		if e != nil {
			b.Close()
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, e := out.Dial(ctx, "tcp", target.String())
		if e != nil {
			cancel()
			out.Close()
			b.Close()
			t.Fatal(bind, e)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		conn.Write([]byte("protected"))
		reply := make([]byte, len("protected"))
		_, e = io.ReadFull(conn, reply)
		conn.Close()
		cancel()
		out.Close()
		b.Close()
		if e != nil || string(reply) != "protected" || protected.Load() != 1 {
			t.Fatal("socket protection lost or duplicated", bind, e, protected.Load())
		}
	}
}

func TestNodeIPFamilyPolicyUsesActualResolverResults(t *testing.T) {
	target := echoServer(t)
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	out, e := b.NewOutbound("ipv4", ProxySpec{Type: "direct", Options: json.RawMessage(`{"domain_strategy":"ipv4_only"}`)})
	if e != nil {
		t.Fatal(e)
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx = WithLookup(ctx, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("127.0.0.1")}, nil
	})
	conn, e := out.Dial(ctx, "tcp", net.JoinHostPort("family.test", strconv.Itoa(int(target.Port()))))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte("ipv4"))
	reply := make([]byte, 4)
	if _, e = io.ReadFull(conn, reply); e != nil || string(reply) != "ipv4" {
		t.Fatal(string(reply), e)
	}
}

func TestTFOAndMPTCPOptionsPreserveTCP(t *testing.T) {
	target := echoServer(t)
	for _, options := range []string{`{"tcp_fast_open":true}`, `{"tcp_multi_path":true}`, `{"tcp_fast_open":true,"tcp_multi_path":true}`} {
		t.Run(options, func(t *testing.T) {
			var protected atomic.Int32
			b := New(Options{Logger: testLogger(t), ProtectFD: func(int) error { protected.Add(1); return nil }})
			defer b.Close()
			out, e := b.NewOutbound("dial", ProxySpec{Type: "direct", Options: json.RawMessage(options)})
			if e != nil {
				t.Fatal(e)
			}
			defer out.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c, e := out.Dial(ctx, "tcp", target.String())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			payload := strings.Repeat("tcp", 1024)
			if _, e = c.Write([]byte(payload)); e != nil {
				t.Fatal(e)
			}
			reply := make([]byte, len(payload))
			if _, e = io.ReadFull(c, reply); e != nil || string(reply) != payload || protected.Load() != 1 {
				t.Fatal(e, string(reply))
			}
		})
	}
}
