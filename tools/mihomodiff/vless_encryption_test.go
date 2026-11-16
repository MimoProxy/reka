package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	Native "github.com/MimoProxy/reka/internal/compat/vlessenc"
	Reference "github.com/metacubex/mihomo/transport/vless/encryption"
)

// The reference stays in this separate module and is never linked into a
// product binary. Both directions verify the standard ML-KEM/BLAKE3 adaptation
// against the unmodified pinned peer, including resumed sessions.
func TestVLESSEncryptionAgainstPinnedReference(t *testing.T) {
	private, public, _, err := Reference.GenX25519("")
	if err != nil {
		t.Fatal(err)
	}
	seed, mlkemPublic, _, err := Reference.GenMLKEM768("")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"native", "xorpub", "random"} {
		for _, rtt := range []string{"1rtt", "0rtt"} {
			for _, nativeClient := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%s/native-client-%v", mode, rtt, nativeClient), func(t *testing.T) {
					clientConfig := "mlkem768x25519plus." + mode + "." + rtt + "." + public + "." + mlkemPublic + ".100-35-35"
					serverConfig := "mlkem768x25519plus." + mode + ".60s." + private + "." + seed + ".100-35-35"
					var client, server func(net.Conn) (net.Conn, error)
					if nativeClient {
						c, err := Native.NewClient(clientConfig)
						if err != nil {
							t.Fatal(err)
						}
						s, err := Reference.NewServer(serverConfig)
						if err != nil {
							t.Fatal(err)
						}
						defer s.Close()
						client = func(conn net.Conn) (net.Conn, error) { return c.Handshake(conn) }
						server = func(conn net.Conn) (net.Conn, error) { return s.Handshake(conn, nil) }
					} else {
						c, err := Reference.NewClient(clientConfig)
						if err != nil {
							t.Fatal(err)
						}
						s, err := Native.NewServer(serverConfig)
						if err != nil {
							t.Fatal(err)
						}
						defer s.Close()
						client = func(conn net.Conn) (net.Conn, error) { return c.Handshake(conn) }
						server = func(conn net.Conn) (net.Conn, error) { return s.Handshake(conn, nil) }
					}
					for round := range 3 {
						listener, err := net.Listen("tcp", "127.0.0.1:0")
						if err != nil {
							t.Fatal(err)
						}
						deadline := time.Now().Add(3 * time.Second)
						result := make(chan error, 1)
						go func() {
							right, err := listener.Accept()
							listener.Close()
							if err != nil {
								result <- err
								return
							}
							right.SetDeadline(deadline)
							defer right.Close()
							conn, err := server(right)
							if err != nil {
								result <- err
								return
							}
							_, err = io.Copy(conn, conn)
							if err == io.EOF || err == io.ErrClosedPipe {
								err = nil
							}
							result <- err
						}()
						left, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
						if err != nil {
							listener.Close()
							t.Fatal(err)
						}
						left.SetDeadline(deadline)
						conn, err := client(left)
						if err != nil {
							left.Close()
							t.Fatal(err)
						}
						payload := []byte(fmt.Sprintf("reference encrypted round %d", round))
						if _, err = conn.Write(payload); err != nil {
							left.Close()
							t.Fatal(err)
						}
						reply := make([]byte, len(payload))
						if _, err = io.ReadFull(conn, reply); err != nil || !bytes.Equal(payload, reply) {
							left.Close()
							t.Fatal("wire mismatch", err)
						}
						left.Close()
						if err = <-result; err != nil {
							t.Fatal("reference peer", err)
						}
					}
				})
			}
		}
	}
}
