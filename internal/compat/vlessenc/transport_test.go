package encryption

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestEncryptedTransportModesKeysAndResumedConcurrency(t *testing.T) {
	for _, mode := range []string{"native", "xorpub", "random"} {
		for _, keyKind := range []string{"x25519", "mlkem768"} {
			for _, rtt := range []string{"1rtt", "0rtt"} {
				t.Run(mode+"/"+keyKind+"/"+rtt, func(t *testing.T) {
					var private, public string
					var err error
					if keyKind == "x25519" {
						private, public, _, err = GenX25519("")
					} else {
						private, public, _, err = GenMLKEM768("")
					}
					if err != nil {
						t.Fatal(err)
					}
					server, err := NewServer("mlkem768x25519plus." + mode + ".60s." + private + ".100-35-35")
					if err != nil {
						t.Fatal(err)
					}
					defer server.Close()
					client, err := NewClient("mlkem768x25519plus." + mode + "." + rtt + "." + public + ".100-35-35")
					if err != nil {
						t.Fatal(err)
					}
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					var workers sync.WaitGroup
					acceptDone := make(chan struct{})
					go func() {
						defer close(acceptDone)
						for {
							c, err := listener.Accept()
							if err != nil {
								return
							}
							workers.Add(1)
							go func() {
								defer workers.Done()
								defer c.Close()
								c.SetDeadline(time.Now().Add(5 * time.Second))
								encrypted, err := server.Handshake(c, nil)
								if err == nil {
									io.Copy(encrypted, encrypted)
								}
							}()
						}
					}()
					defer func() { listener.Close(); <-acceptDone; workers.Wait() }()
					roundTrip := func(index int) error {
						ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer cancel()
						c, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
						if err != nil {
							return err
						}
						defer c.Close()
						c.SetDeadline(time.Now().Add(3 * time.Second))
						encrypted, err := client.HandshakeContext(ctx, c)
						if err != nil {
							return err
						}
						payload := bytes.Repeat([]byte(fmt.Sprintf("encrypted-%d-", index)), 1500)
						if _, err = encrypted.Write(payload); err != nil {
							return err
						}
						reply := make([]byte, len(payload))
						if _, err = io.ReadFull(encrypted, reply); err != nil {
							return err
						}
						if !bytes.Equal(payload, reply) {
							return fmt.Errorf("encrypted payload changed")
						}
						return nil
					}
					if err = roundTrip(0); err != nil {
						t.Fatal(err)
					}
					// The first 1-RTT exchange installs the resumable ticket. Parallel
					// connections must not append into a shared session key backing array.
					results := make(chan error, 8)
					for index := range 8 {
						go func() { results <- roundTrip(index + 1) }()
					}
					for range 8 {
						if err = <-results; err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}

func TestEncryptedHandshakeCancellationInterruptsPadding(t *testing.T) {
	_, public, _, _ := GenX25519("")
	client, err := NewClient("mlkem768x25519plus.native.1rtt." + public + ".100-35-35.100-60000-60000.100-0-0")
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, right); close(done) }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = client.HandshakeContext(ctx, left)
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("padding ignored context cancellation", err)
	}
	<-done
}
