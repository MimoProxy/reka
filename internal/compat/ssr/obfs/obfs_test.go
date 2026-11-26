package obfs

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func pipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	client, peer := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	client.SetDeadline(deadline)
	peer.SetDeadline(deadline)
	t.Cleanup(func() { client.Close(); peer.Close() })
	return client, peer
}

func TestHTTPObfsParameters(t *testing.T) {
	for _, test := range []struct{ obfs, param, method, host string }{
		{"http_simple", "", "GET", "proxy.example:8388"},
		{"http_post", "cdn.example#X-Test: yes\\nX-Other: value", "POST", "cdn.example:8388"},
	} {
		t.Run(test.obfs, func(t *testing.T) {
			raw, peer := pipe(t)
			o, _, err := PickObfs(test.obfs, &Base{Host: "proxy.example", Port: 8388, Param: test.param})
			if err != nil {
				t.Fatal(err)
			}
			conn := o.StreamConn(raw)
			done := make(chan error, 1)
			go func() { _, err := conn.Write([]byte{1, 2}); done <- err }()
			req, err := http.ReadRequest(bufio.NewReader(peer))
			if err != nil {
				t.Fatal(err)
			}
			if req.Method != test.method || req.Host != test.host || req.RequestURI != "/%01%02" {
				t.Fatalf("unexpected request %s %s %s", req.Method, req.Host, req.RequestURI)
			}
			if test.param != "" && (req.Header.Get("X-Test") != "yes" || req.Header.Get("X-Other") != "value") {
				t.Fatal("missing custom obfs headers")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			go func() {
				for _, data := range []string{"HTTP/1.1 200 OK\r", "\nConnection: keep-alive\r\n\r", "\nhello"} {
					if _, err := io.WriteString(peer, data); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			got := make([]byte, 5)
			if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hello" {
				t.Fatalf("fragmented response %q, %v", got, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTicketObfsSNI(t *testing.T) {
	for _, test := range []struct{ name, param, host string }{
		{"default", "", "proxy.example"}, {"override", "cdn.example", "cdn.example"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, peer := pipe(t)
			o, _, err := PickObfs("tls1.2_ticket_auth", &Base{Host: "proxy.example", Port: 443, Key: make([]byte, 16), Param: test.param})
			if err != nil {
				t.Fatal(err)
			}
			conn := o.StreamConn(raw)
			done := make(chan error, 1)
			go func() { _, err := conn.Write([]byte("data")); done <- err }()
			var header [5]byte
			if _, err := io.ReadFull(peer, header[:]); err != nil {
				t.Fatal(err)
			}
			record := make([]byte, binary.BigEndian.Uint16(header[3:5]))
			if _, err := io.ReadFull(peer, record); err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(record, []byte(test.host)) {
				t.Fatal("client hello lacks expected SNI")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTicketObfsFragmentedRecords(t *testing.T) {
	raw, peer := pipe(t)
	// Exercise the record decoder after handshake authentication.
	conn := &tls12TicketConn{Conn: raw, receivedHello: true}
	go func() {
		for _, part := range [][]byte{{0x17, 3}, {3, 0, 3, 'a'}, {'b', 'c', 0x17, 3, 3, 0, 2, 'd', 'e'}} {
			if _, err := peer.Write(part); err != nil {
				return
			}
		}
	}()
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "abcde" {
		t.Fatalf("fragmented records %q, %v", got, err)
	}
}

func TestPendingObfsWriteConcurrentClose(t *testing.T) {
	for _, name := range []string{"random_head", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"} {
		t.Run(name, func(t *testing.T) {
			raw, peer := pipe(t)
			o, _, err := PickObfs(name, &Base{Host: "proxy.example", Port: 443})
			if err != nil {
				t.Fatal(err)
			}
			conn := o.StreamConn(raw)
			done := make(chan error, 1)
			go func() { _, err := conn.Write([]byte("first")); done <- err }()
			if _, err := peer.Read(make([]byte, 2048)); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
			wrote := make(chan error, 1)
			go func() {
				for range 16 {
					if _, err := fmt.Fprint(conn, "pending"); err != nil {
						wrote <- err
						return
					}
				}
				wrote <- nil
			}()
			conn.Close()
			if err := <-done; err == nil {
				t.Fatal("read after close succeeded")
			}
			if err := <-wrote; err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
			if _, err := conn.Write([]byte("closed")); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after close: %v", err)
			}
		})
	}
}

func TestPendingObfsLimit(t *testing.T) {
	for _, name := range []string{"random_head", "tls1.2_ticket_auth"} {
		t.Run(name, func(t *testing.T) {
			raw, peer := pipe(t)
			o, _, err := PickObfs(name, &Base{})
			if err != nil {
				t.Fatal(err)
			}
			conn := o.StreamConn(raw)
			if _, err := conn.Write(make([]byte, maxPending+1)); !errors.Is(err, errPendingFull) {
				t.Fatalf("oversize write: %v", err)
			}
			if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("expected closed transport: %v", err)
			}
		})
	}
}
