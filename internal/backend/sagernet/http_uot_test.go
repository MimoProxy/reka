package sagernet

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing/common/control"
	"syscall"
)

func TestHTTPConnectCustomHeadersAndCredentialPrecedence(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			done <- e
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(conn)
		line, e := reader.ReadString('\n')
		if e != nil {
			done <- e
			return
		}
		headers, e := textproto.NewReader(reader).ReadMIMEHeader()
		if e != nil {
			done <- e
			return
		}
		if line != "CONNECT 198.51.100.1:443 HTTP/1.1\r\n" || headers.Get("Host") != "front.test" || headers.Get("X-Test") != "header-check" || headers.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("user:password")) || len(headers["Proxy-Authorization"]) != 1 {
			done <- fmt.Errorf("CONNECT headers did not preserve configured semantics")
			return
		}
		if _, e = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); e != nil {
			done <- e
			return
		}
		payload := make([]byte, 4)
		if _, e = io.ReadFull(reader, payload); e == nil {
			_, e = conn.Write(payload)
		}
		done <- e
	}()
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	out, e := b.NewOutbound("http", ProxySpec{Type: "http", Server: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).AddrPort().Port(), Username: "user", Password: "password", Options: json.RawMessage(`{"headers":{"Host":["front.test"],"X-Test":["header-check"],"Proxy-Authorization":["discarded-header-auth"]}}`)})
	if e != nil {
		t.Fatal(e)
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, e := out.Dial(ctx, "tcp", "198.51.100.1:443")
	if e != nil {
		t.Fatal(e, <-done)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte("echo"))
	reply := make([]byte, 4)
	if _, e = io.ReadFull(conn, reply); e != nil || string(reply) != "echo" {
		t.Fatal(e, string(reply))
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestShadowsocksUOTVersionsUseOnlyTCPToNode(t *testing.T) {
	const method = "aes-128-gcm"
	const password = "controlled-uot-test"
	server := startServer(t, "shadowsocks", func(b *Backend, listen netip.AddrPort) error {
		return adopt(t, b, "ss-uot", "shadowsocks", func() (adapter.Inbound, error) {
			return shadowsocks.NewInbound(b.ctx, b.router, b.componentLogger("inbound", "shadowsocks", "ss-uot"), "ss-uot", option.ShadowsocksInboundOptions{ListenOptions: listenOptions(listen), Method: method, Password: password})
		})
	})
	echo, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
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
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			var tcp, udp atomic.Int32
			protect := control.Func(func(network, address string, c syscall.RawConn) error {
				if strings.HasPrefix(network, "tcp") {
					tcp.Add(1)
				}
				if strings.HasPrefix(network, "udp") {
					udp.Add(1)
				}
				return nil
			})
			b := New(Options{Logger: testLogger(t), Protect: protect})
			defer b.Close()
			options, _ := json.Marshal(map[string]any{"udp_over_tcp": map[string]any{"enabled": true, "version": version}})
			out, e := b.NewOutbound("uot", ProxySpec{Type: "shadowsocks", Server: "127.0.0.1", Port: server.Port(), Method: method, Password: password, Options: options})
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
			conn.Write([]byte("uot-echo"))
			reply := make([]byte, 2048)
			n, e := conn.Read(reply)
			if e != nil || string(reply[:n]) != "uot-echo" || tcp.Load() == 0 || udp.Load() != 0 {
				t.Fatal("UoT did not use only TCP", e, string(reply[:n]), tcp.Load(), udp.Load())
			}
		})
	}
}
