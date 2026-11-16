package sagernet

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestH2StreamReleasesPendingWrites(t *testing.T) {
	for _, reject := range []bool{false, true} {
		name := "cancelled"
		if reject {
			name = "rejected"
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if reject {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				<-r.Context().Done()
			}))
			server.Config.Protocols = new(http.Protocols)
			server.Config.Protocols.SetUnencryptedHTTP2(true)
			server.Start()
			defer server.Close()
			raw, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			conn, err := newH2Stream(ctx, raw, option.V2RayHTTPOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			done := make(chan error, 1)
			go func() { _, err := conn.Write(make([]byte, 2<<20)); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("pending write accepted after failed handshake")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("pending writer remained blocked")
			}
			if _, err = conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("failed handshake yielded readable stream")
			}
		})
	}
}

func TestH2StreamFullDuplex(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		b := make([]byte, 1024)
		for {
			n, err := r.Body.Read(b)
			if n > 0 {
				w.Write(b[:n])
				w.(http.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	}))
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	defer server.Close()
	for range 50 {
		raw, err := net.Dial("tcp", server.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := newH2Stream(ctx, raw, option.V2RayHTTPOptions{})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = conn.Write([]byte("hello")); err != nil {
			conn.Close()
			cancel()
			t.Fatal(err)
		}
		got := make([]byte, 5)
		_, err = io.ReadFull(conn, got)
		conn.Close()
		cancel()
		if err != nil || string(got) != "hello" {
			t.Fatalf("full duplex %q: %v", got, err)
		}
	}
}
