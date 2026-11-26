//go:build with_gvisor

package generation

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/platform"
)

func TestWireGuardExistingSocketProtectedBeforeTUN(t *testing.T) {
	var bypass atomic.Bool
	opened := make(chan uintptr, 1)
	protected := make(chan uintptr, 1)
	protect := func(network, _ string, conn syscall.RawConn) error {
		if network != "udp4" {
			return nil
		}
		return conn.Control(func(fd uintptr) {
			ch := opened
			if bypass.Load() {
				ch = protected
			}
			select {
			case ch <- fd:
			default:
			}
		})
	}
	var original uintptr
	hooks := &platform.NetworkHooks{
		Bypass: func(enabled bool, _ platform.TUNConfig) error { bypass.Store(enabled); return nil },
		StartTUN: func(platform.TUNConfig) (io.Closer, string, error) {
			select {
			case fd := <-protected:
				if fd != original {
					return nil, "", errors.New("protection applied to a different socket")
				}
			default:
				return nil, "", errors.New("TUN started with an unprotected endpoint socket")
			}
			return io.NopCloser(strings.NewReader("")), "test", nil
		},
	}
	e := NewEngine(EngineOptions{StateRoot: t.TempDir(), NetworkHooks: hooks, Backend: sagernet.Options{Protect: protect}})
	defer e.Close()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	profile := []byte(fmt.Sprintf(`schema-version: 1
outbounds:
  - id: tunnel
    type: wireguard
    server: 127.0.0.1
    port: %d
    protocol:
      private-key: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
      public-key: Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=
      address: [192.0.2.2/32]
      reserved: [1, 128, 255]
rules: [{match: {all: true}, outbound: tunnel}]
`, peer.LocalAddr().(*net.UDPAddr).Port))
	activate := func(tun bool, rev uint64) {
		t.Helper()
		eff, ds := compile.Compile(profile, nil, compile.Options{})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		if tun {
			eff.Network = platform.Network{Mode: "tun"}
		}
		p, err := e.Prepare(eff)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = e.Activate(p, rev); err != nil {
			t.Fatal(err)
		}
	}
	activate(false, 1)
	out := e.OutboundInstance("tunnel")
	conn, err := out.Dial(t.Context(), "udp", "192.0.2.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case original = <-opened:
	case <-time.After(3 * time.Second):
		t.Fatal("WireGuard did not open an IPv4 socket")
	}
	checkWireGuardHandshake(t, conn, peer, [3]byte{1, 128, 255})
	activate(true, 2)
	if out.Type() != "wireguard" || e.OutboundInstance("tunnel") != out {
		t.Fatal("TUN activation lost the existing WireGuard outbound")
	}
	activate(false, 3)
	select {
	case <-opened:
	case <-time.After(3 * time.Second):
		t.Fatal("WireGuard did not refresh its socket after TUN stopped")
	}
}

func checkWireGuardHandshake(t *testing.T, conn net.Conn, peer *net.UDPConn, reserved [3]byte) {
	t.Helper()
	// Upstream brings the virtual interface up asynchronously. Keep sending
	// until the local peer sees the first handshake, then check its WARP bytes.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := conn.Write([]byte("activate tunnel")); err != nil {
			t.Fatal(err)
		}
		peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		var handshake [256]byte
		n, _, err := peer.ReadFromUDP(handshake[:])
		if errors.Is(err, os.ErrDeadlineExceeded) && time.Now().Before(deadline) {
			continue
		}
		if err != nil || n < 4 || !bytes.Equal(handshake[:4], []byte{1, reserved[0], reserved[1], reserved[2]}) {
			t.Fatalf("WireGuard handshake header %x, length %d, error %v", handshake[:4], n, err)
		}
		break
	}
}
