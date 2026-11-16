package sagernet

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestSOCKSTLSControlsTCPAndPreservesUDP(t *testing.T) {
	backend := New(Options{Logger: testLogger(t)})
	defer backend.Close()
	direct, err := backend.NewOutbound("direct", DirectSpec{})
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	backend.SetRoute(Fixed(direct))
	listen := loopback(freePort(t))
	inbound, err := backend.NewInbound("socks", "socks", listen)
	if err != nil {
		t.Fatal(err)
	}
	defer inbound.Close()
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := certServer.TLS.Certificates
	certServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: cert})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(4 * time.Second))
				raw, e := net.Dial("tcp", listen.String())
				if e != nil {
					return
				}
				defer raw.Close()
				go io.Copy(raw, c)
				io.Copy(c, raw)
			}()
		}
	}()
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		p := make([]byte, 2048)
		for {
			n, a, e := echo.ReadFrom(p)
			if e != nil {
				return
			}
			echo.WriteTo(p[:n], a)
		}
	}()
	var protected atomic.Int32
	client := New(Options{Logger: testLogger(t), Protect: func(string, string, syscall.RawConn) error { protected.Add(1); return nil }})
	defer client.Close()
	for _, insecure := range []bool{false, true} {
		out, e := client.NewOutbound("tls-socks", ProxySpec{Type: "socks", Server: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).AddrPort().Port(), TLS: &TLSSpec{ServerName: "localhost", Insecure: insecure}})
		if e != nil {
			t.Fatal(e)
		}
		for _, network := range []string{"tcp", "udp"} {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			target := echoServer(t).String()
			if network == "udp" {
				target = echo.LocalAddr().String()
			}
			c, e := out.Dial(ctx, network, target)
			cancel()
			if !insecure {
				if e == nil {
					c.Close()
					t.Fatal("untrusted certificate accepted")
				}
				continue
			}
			if e != nil {
				t.Fatal(network, e)
			}
			c.SetDeadline(time.Now().Add(3 * time.Second))
			if _, e = c.Write([]byte("proof")); e != nil {
				t.Fatal(e)
			}
			reply := make([]byte, 5)
			if network == "udp" {
				reply = make([]byte, 2048)
				n, err := c.Read(reply)
				e = err
				reply = reply[:n]
			} else {
				_, e = io.ReadFull(c, reply)
			}
			if e != nil || string(reply) != "proof" {
				t.Fatalf("%s %T %v %q", network, c.(*leasedConn).Conn, e, reply)
			}
			c.Close()
		}
		out.Close()
	}
	if protected.Load() < 5 {
		t.Fatal("decorated dialer bypassed socket protection", protected.Load())
	}
}
