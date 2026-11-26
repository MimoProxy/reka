//go:build with_gvisor

package sagernet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/net/netmon"
	"github.com/sagernet/tailscale/net/netns"
	"github.com/sagernet/tailscale/types/key"
)

func TestTailscaleStatus(t *testing.T) {
	status := &ipnstate.Status{
		BackendState: ipn.NeedsLogin.String(),
		AuthURL:      "https://login.example.test/start",
	}
	result := tailscaleStatus(status, "")
	if result.State != api.TailscaleNeedsLogin || result.AuthURL != status.AuthURL {
		t.Fatalf("unexpected authentication status: %+v", result)
	}

	peer := key.NewNode().Public()
	peerIP := netip.MustParseAddr("100.100.0.2")
	status.BackendState = ipn.Running.String()
	status.TailscaleIPs = []netip.Addr{netip.MustParseAddr("100.100.0.1")}
	status.Peer = map[key.NodePublic]*ipnstate.PeerStatus{
		peer: {
			HostName: "example", TailscaleIPs: []netip.Addr{peerIP}, Online: true,
			Relay: "test", CurAddr: "192.0.2.2:12345",
		},
	}
	result = tailscaleStatus(status, "previous error")
	if result.State != api.TailscaleRunning || result.AuthURL != "" || result.LastError != "previous error" {
		t.Fatalf("unexpected running status: %+v", result)
	}
	want := api.TailscalePeer{
		Hostname: "example", TailscaleIPs: []netip.Addr{peerIP}, Online: true, DirectAddress: "192.0.2.2:12345",
	}
	if !reflect.DeepEqual(result.Peers, []api.TailscalePeer{want}) {
		t.Fatalf("unexpected peers: %+v", result.Peers)
	}
	status.Peer[peer].CurAddr = ""
	if got := tailscaleStatus(status, "").Peers[0]; got.DirectAddress != "" || got.DERPRegion != "test" {
		t.Fatalf("unexpected relay status: %+v", got)
	}
}

func TestTailscalePeerDNSRejected(t *testing.T) {
	h := rejectTailscalePeerDNS{}
	response, err := h.HandlePeerDNSQuery(context.Background(), []byte{1}, netip.AddrPort{}, nil)
	if response != nil || !errors.Is(err, errEndpointInbound) {
		t.Fatalf("peer DNS result = %x, %v", response, err)
	}
}

type tailscaleTestSocket struct {
	fd     uintptr
	closed bool
}

func (*tailscaleTestSocket) Read(func(uintptr) bool) error  { return io.ErrNoProgress }
func (*tailscaleTestSocket) Write(func(uintptr) bool) error { return io.ErrNoProgress }
func (s *tailscaleTestSocket) Control(fn func(uintptr)) error {
	if s.closed {
		return net.ErrClosed
	}
	fn(s.fd)
	return nil
}

func TestTailscaleUnderlayReprotectsAllOpenSockets(t *testing.T) {
	calls := make(map[uintptr]int)
	b := New(Options{Protect: func(_ string, _ string, conn syscall.RawConn) error {
		return conn.Control(func(fd uintptr) { calls[fd]++ })
	}})
	defer b.Close()
	scope := adapter.NewScope(b.ctx, b.componentLogger("endpoint", tailscaleType, "test"))
	defer scope.Close()
	monitor := netmon.NewStatic()
	logf := func(string, ...any) {}
	b.tailscaleUnderlay(scope, false)
	underlayControl := netns.Listener(logf, monitor).Control
	if netns.ListenPacketFunc() == nil || underlayControl == nil {
		t.Fatal("missing protected socket hooks")
	}
	tcp1 := &tailscaleTestSocket{fd: 1}
	tcp2 := &tailscaleTestSocket{fd: 2}
	udp := &tailscaleTestSocket{fd: 3}
	tcp3 := &tailscaleTestSocket{fd: 4}
	for _, socket := range []*tailscaleTestSocket{tcp1, tcp2, tcp3} {
		if err := underlayControl("tcp4", "192.0.2.1:443", socket); err != nil {
			t.Fatal(err)
		}
	}
	if err := underlayControl("udp4", "0.0.0.0:0", udp); err != nil {
		t.Fatal(err)
	}
	tcp3.closed = true
	if err := b.ReprotectEndpointSockets(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, map[uintptr]int{1: 2, 2: 2, 3: 2, 4: 1}) {
		t.Fatalf("unexpected protection calls: %v", calls)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	restoredControl := netns.Listener(logf, monitor).Control
	if netns.ListenPacketFunc() != nil || restoredControl != nil &&
		reflect.ValueOf(underlayControl).Pointer() == reflect.ValueOf(restoredControl).Pointer() {
		t.Fatal("Tailscale netns hooks remain installed")
	}
	if len(b.endpointSockets.scopes) != 0 {
		t.Fatal("Tailscale sockets remain registered")
	}
}

func TestTailscaleFailedStartReleasesProcessSlot(t *testing.T) {
	b := New(Options{})
	defer b.Close()
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := b.NewTailscaleNode("tailscale/test", TailscaleOptions{StateDirectory: path})
	if err == nil || !strings.Contains(err.Error(), "create Tailscale state directory") {
		t.Fatalf("unexpected error: %v", err)
	}
	if tailscaleInProcess.Load() {
		t.Fatal("startup failure kept the process slot")
	}
}
