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
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/net/netmon"
	"github.com/sagernet/tailscale/net/netns"
	"github.com/sagernet/tailscale/net/tsaddr"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/types/key"
	"github.com/sagernet/tailscale/types/netmap"
	"github.com/sagernet/tailscale/wgengine"
)

func TestTailscaleStatus(t *testing.T) {
	status := &ipnstate.Status{
		BackendState: ipn.NeedsLogin.String(),
		AuthURL:      "https://login.example.test/start",
	}
	result := tailscaleStatus(status, "", "", "")
	if result.State != api.TailscaleNeedsLogin || result.AuthURL != status.AuthURL {
		t.Fatalf("unexpected authentication status: %+v", result)
	}

	peer := key.NewNode().Public()
	peerIP := netip.MustParseAddr("100.100.0.2")
	status.BackendState = ipn.Running.String()
	status.TailscaleIPs = []netip.Addr{netip.MustParseAddr("100.100.0.1")}
	status.Peer = map[key.NodePublic]*ipnstate.PeerStatus{
		peer: {
			ID: "peer", HostName: "example", TailscaleIPs: []netip.Addr{peerIP}, Online: true,
			ExitNodeOption: true, ExitNode: true,
			Relay: "test", CurAddr: "192.0.2.2:12345",
		},
	}
	result = tailscaleStatus(status, "previous error", "peer", "")
	if result.State != api.TailscaleRunning || result.AuthURL != "" || result.LastError != "previous error" || result.ExitNode != "example" {
		t.Fatalf("unexpected running status: %+v", result)
	}
	want := api.TailscalePeer{
		Hostname: "example", TailscaleIPs: []netip.Addr{peerIP}, Online: true, DirectAddress: "192.0.2.2:12345",
		ExitNodeOption: true, ExitNode: true,
	}
	if !reflect.DeepEqual(result.Peers, []api.TailscalePeer{want}) {
		t.Fatalf("unexpected peers: %+v", result.Peers)
	}
	status.Peer[peer].CurAddr = ""
	if got := tailscaleStatus(status, "", "", "").Peers[0]; got.DirectAddress != "" || got.DERPRegion != "test" || got.ExitNode {
		t.Fatalf("unexpected relay status: %+v", got)
	}
}

type tailscaleTestLocal struct {
	prefs     ipn.Prefs
	nm        *netmap.NetworkMap
	edits     int
	editErr   error
	peerRoute wgengine.PeerForIP
}

func (b *tailscaleTestLocal) State() ipn.State { return ipn.Running }
func (b *tailscaleTestLocal) Status() *ipnstate.Status {
	return &ipnstate.Status{BackendState: ipn.Running.String()}
}
func (b *tailscaleTestLocal) Prefs() ipn.PrefsView                { return b.prefs.View() }
func (b *tailscaleTestLocal) NetMapWithPeers() *netmap.NetworkMap { return b.nm }
func (b *tailscaleTestLocal) PeerForIP(addr netip.Addr) (wgengine.PeerForIP, bool) {
	return b.peerRoute, b.peerRoute.Route.Contains(addr)
}
func (b *tailscaleTestLocal) EditPrefs(p *ipn.MaskedPrefs) (ipn.PrefsView, error) {
	b.edits++
	if b.editErr != nil {
		return b.Prefs(), b.editErr
	}
	b.prefs.ApplyEdits(p)
	return b.Prefs(), nil
}

func TestTailscaleExitNodePreferences(t *testing.T) {
	local := &tailscaleTestLocal{prefs: ipn.Prefs{CorpDNS: true, ExitNodeIP: netip.MustParseAddr("100.64.0.7")}}
	node := &tailscaleNode{local: local}
	want := TailscalePreferences{ExitNode: "auto", ExitNodeAllowLANAccess: true}
	update := func(exitID tailcfg.StableNodeID, reason string) {
		t.Helper()
		if err := node.SetPreferences(want); err != nil {
			t.Fatal(err)
		}
		if local.prefs.ExitNodeID != exitID || local.prefs.ExitNodeIP.IsValid() ||
			local.prefs.ExitNodeAllowLANAccess != want.ExitNodeAllowLANAccess || local.prefs.RouteAll != want.AcceptRoutes ||
			!local.prefs.ShieldsUp || local.prefs.CorpDNS {
			t.Fatalf("unexpected preferences: %+v", local.prefs)
		}
		got := node.Status().ExitNodeError
		if reason == "" && got != "" || !strings.Contains(got, reason) {
			t.Fatalf("exit status = %q, want %q", got, reason)
		}
	}
	update("", "waiting")
	local.nm = &netmap.NetworkMap{}
	update("", "no online")
	online := true
	exit := &tailcfg.Node{
		StableID: "first", Name: "gateway.tailnet.test.", Online: &online,
		Hostinfo:   (&tailcfg.Hostinfo{Hostname: "router"}).View(),
		Addresses:  []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd7a:115c:a1e0::1/128")},
		AllowedIPs: slices.Clone(tsaddr.ExitRoutes()),
	}
	second := exit.Clone()
	second.StableID = "second"
	second.AllowedIPs = nil
	local.nm.Peers = []tailcfg.NodeView{exit.View(), second.View()}
	update("first", "")
	edits := local.edits
	update("first", "")
	if local.edits != edits {
		t.Fatal("unchanged selection rewrote local preferences")
	}
	second.AllowedIPs = slices.Clone(tsaddr.ExitRoutes())
	update("", "multiple online")
	second.Online = nil
	update("first", "")
	local.nm.Peers = local.nm.Peers[:1]
	for _, selector := range []string{"Router", "GATEWAY", "Gateway.tailnet.test", "gateway.tailnet.test.", "100.64.0.1", "fd7a:115c:a1e0::1"} {
		want.ExitNode = selector
		update("first", "")
	}
	exit.Online = nil
	update("", "offline")
	exit.Online = &online
	want.ExitNode = "absent"
	update("", "not found")
	want.ExitNode = "router"
	local.nm.Peers = append(local.nm.Peers, second.View())
	update("", "ambiguous")
	local.nm.Peers = local.nm.Peers[:1]
	update("first", "")
	want.ExitNode, want.AcceptRoutes, want.ExitNodeAllowLANAccess = "", true, false
	local.editErr = errors.New("preference store unavailable")
	if err := node.SetPreferences(want); err != local.editErr || node.exitID != "" || !strings.Contains(node.Status().ExitNodeError, local.editErr.Error()) {
		t.Fatalf("failed preference update lost its error or allowed a stale exit: %v", err)
	}
	local.editErr = nil
	update("", "")
}

func TestTailscaleRoutePreflight(t *testing.T) {
	target := M.ParseSocksaddr("203.0.113.5:443")
	local := &tailscaleTestLocal{}
	node := &tailscaleNode{local: local}
	checkFailure := func(err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "no Tailscale route to "+target.Addr.String()) {
			t.Fatalf("missing route error: %v", err)
		}
	}
	for _, network := range []string{"tcp", "udp"} {
		_, err := node.DialContext(t.Context(), network, target)
		checkFailure(err)
	}
	_, err := node.ListenPacket(t.Context(), target)
	checkFailure(err)
	packet := &tailscalePacketConn{node: node}
	_, err = packet.WriteTo([]byte("payload"), target.UDPAddr())
	checkFailure(err)
	online := true
	peer := (&tailcfg.Node{StableID: "gateway", Online: &online, AllowedIPs: tsaddr.ExitRoutes()}).View()
	local.peerRoute = wgengine.PeerForIP{Node: peer, Route: netip.MustParsePrefix("203.0.113.0/24")}
	if err := node.checkRoute(target.Addr); err != nil {
		t.Fatal("installed subnet:", err)
	}
	local.peerRoute.Route = netip.MustParsePrefix("0.0.0.0/0")
	checkFailure(node.checkRoute(target.Addr))
	node.exitID = "gateway"
	if err := node.checkRoute(target.Addr); err != nil {
		t.Fatal("installed exit:", err)
	}
	online = false
	checkFailure(node.checkRoute(target.Addr))
}

func TestTailscaleOutboundUDP(t *testing.T) {
	b := New(Options{})
	defer b.Close()
	node := &tailscaleNode{local: &tailscaleTestLocal{}}
	target := "203.0.113.5:443"
	for _, udp := range []bool{false, true} {
		out := b.NewTailscaleOutbound("ts", node, udp)
		defer out.Close()
		pin, err := out.Pin()
		if err != nil {
			t.Fatal(err)
		}
		defer pin.Close()
		if got := out.out.Network(); !slices.Contains(got, "tcp") || slices.Contains(got, "udp") != udp {
			t.Fatalf("networks with udp=%t: %v", udp, got)
		}
		checkError := func(err error, disabled bool) {
			t.Helper()
			if disabled {
				if !errors.Is(err, errTailscaleUDPDisabled) {
					t.Fatalf("disabled UDP reached the node: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "no Tailscale route") {
				t.Fatalf("enabled network did not reach the node: %v", err)
			}
		}
		_, err = out.Dial(t.Context(), "tcp", target)
		checkError(err, false)
		_, err = out.Dial(t.Context(), "udp4", target)
		checkError(err, !udp)
		_, err = pin.ListenPacket(t.Context(), target)
		checkError(err, !udp)
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
	_, err := b.NewTailscaleNode("tailscale/test", TailscaleOptions{TailscaleIdentity: TailscaleIdentity{StateDirectory: path}})
	if err == nil || !strings.Contains(err.Error(), "create Tailscale state directory") {
		t.Fatalf("unexpected error: %v", err)
	}
	if tailscaleInProcess.Load() {
		t.Fatal("startup failure kept the process slot")
	}
}
