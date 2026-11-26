package ssr

import (
	"bytes"
	"crypto/md5"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	reference "github.com/sagernet/sing-shadowsocks/shadowstream"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/crypto/chacha20"
)

func TestDummyAuthenticationKey(t *testing.T) {
	const password = "auth-password"
	want := md5.Sum([]byte(password))
	for _, name := range []string{"none", "dummy"} {
		method, err := newMethod(name, password)
		if err != nil {
			t.Fatal(err)
		}
		if method.ivSize != 0 || !bytes.Equal(method.key, want[:]) {
			t.Fatalf("%s did not derive the SSR authentication key with a zero-length IV", name)
		}
	}
}

func TestCipherRoundTrip(t *testing.T) {
	for name := range methods {
		t.Run(name, func(t *testing.T) {
			method, err := newMethod(strings.ToUpper(name), "password")
			if err != nil {
				t.Fatal(err)
			}
			iv := bytes.Repeat([]byte{0xad}, method.ivSize)
			enc, err := method.stream(iv, false)
			if err != nil {
				t.Fatal(err)
			}
			dec, err := method.stream(iv, true)
			if err != nil {
				t.Fatal(err)
			}
			input := bytes.Repeat([]byte("split at different offsets"), 91)
			wire := make([]byte, len(input))
			if err := enc.xor(wire[:19], input[:19]); err != nil {
				t.Fatal(err)
			}
			if err := enc.xor(wire[19:], input[19:]); err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(wire, input) != (method.ivSize == 0) {
				t.Fatal("unexpected ciphertext")
			}
			if err := dec.xor(wire, wire); err != nil || !bytes.Equal(wire, input) {
				t.Fatalf("decryption mismatch: %v", err)
			}
		})
	}
}

func TestChaCha20LegacyNonce(t *testing.T) {
	method, err := newMethod("chacha20", "password")
	if err != nil {
		t.Fatal(err)
	}
	iv := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	stream, err := method.stream(iv, false)
	if err != nil {
		t.Fatal(err)
	}
	ietf, err := chacha20.NewUnauthenticatedCipher(method.key, append(make([]byte, 4), iv...))
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte{0x93}, 301)
	actual, want := make([]byte, len(plain)), make([]byte, len(plain))
	if err := stream.xor(actual, plain); err != nil {
		t.Fatal(err)
	}
	ietf.XORKeyStream(want, plain)
	if !bytes.Equal(actual, want) || stream.remaining != chachaLimit-uint64(len(plain)) {
		t.Fatal("legacy nonce stream differs from the zero-prefixed IETF nonce")
	}
}

func TestChaCha20CounterLimitClosesStream(t *testing.T) {
	for _, direction := range []string{"read", "write"} {
		t.Run(direction, func(t *testing.T) {
			method, err := newMethod("chacha20", "password")
			if err != nil {
				t.Fatal(err)
			}
			raw, peer := net.Pipe()
			defer peer.Close()
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(3 * time.Second))
			peer.SetDeadline(time.Now().Add(3 * time.Second))
			wrapped, _, err := method.wrapStream(raw)
			if err != nil {
				t.Fatal(err)
			}
			conn := wrapped.(*streamConn)
			// Start at the last block, then drain it in two uneven parts.
			stream := conn.writer
			stream.stream.(*chacha20.Cipher).SetCounter(^uint32(0))
			stream.remaining = 64
			var transfer func([]byte) (int, error)
			switch direction {
			case "write":
				conn.writeIV = nil
				go io.Copy(io.Discard, peer)
				transfer = conn.Write
			case "read":
				conn.reader = stream
				go peer.Write(make([]byte, 65))
				transfer = conn.Read
			}
			for _, size := range []int{13, 51} {
				if n, err := transfer(make([]byte, size)); err != nil || n != size {
					t.Fatalf("last block: n=%d err=%v", n, err)
				}
			}
			if n, err := transfer(make([]byte, 1)); n != 0 || !errors.Is(err, errCounterLimit) {
				t.Fatalf("exhausted stream: n=%d err=%v", n, err)
			}
			if _, err := peer.Write([]byte{1}); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("underlying stream remained open: %v", err)
			}
		})
	}
}

func TestShadowsocksStreamCompatibility(t *testing.T) {
	for _, name := range reference.List {
		t.Run(name, func(t *testing.T) {
			const password = "stream-password"
			config := Config{Server: "proxy.example", Port: 8388, Password: password, Method: name, Obfs: "plain", Protocol: "origin"}
			client, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			method, err := reference.New(name, nil, password)
			if err != nil {
				t.Fatal(err)
			}
			raw, other := net.Pipe()
			defer raw.Close()
			defer other.Close()
			deadline := time.Now().Add(3 * time.Second)
			raw.SetDeadline(deadline)
			other.SetDeadline(deadline)
			dst := M.ParseSocksaddr("service.example:443")
			reverse := M.ParseSocksaddr("[2001:db8::1]:8443")
			ref := method.DialEarlyConn(other, reverse)
			input := bytes.Repeat([]byte("from Reka"), 10000)
			reply := bytes.Repeat([]byte("from reference"), 400)
			done := make(chan error, 1)
			go func() {
				defer other.Close()
				if err := readAddressAndData(ref, dst, input); err != nil {
					done <- err
					return
				}
				// The independent client emits a SOCKS address as its first
				// encrypted bytes. Verify it on the return path as well.
				_, err := ref.Write(bytes.Clone(reply))
				done <- err
			}()
			conn, err := client.StreamConn(raw, dst)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(input); err != nil {
				t.Fatal(err)
			}
			if err = readAddressAndData(conn, reverse, reply); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func readAddressAndData(r io.Reader, want M.Socksaddr, data []byte) error {
	addr, err := M.SocksaddrSerializer.ReadAddrPort(r)
	if err != nil {
		return err
	}
	if addr != want {
		return errors.New("SOCKS address mismatch")
	}
	got := make([]byte, len(data))
	if _, err := io.ReadFull(r, got); err != nil {
		return err
	}
	if !bytes.Equal(got, data) {
		return errors.New("payload mismatch")
	}
	return nil
}
